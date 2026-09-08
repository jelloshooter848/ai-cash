"""JOURNEY 6 — fleet operator (spec §6.1, Supervision Profile).

Produced during a COLD USABILITY TEST of the AICash reference implementation:
an agent with no prior knowledge of the repo integrated it from the spec,
component docs, and public source only.

What this script demonstrates, end to end, against a REAL in-process mint
(SupervisionServer over HTTP on 127.0.0.1, sqlite ledger, fake clock):

  1. Mount the Supervision Profile on a mint; descriptor advertises it.
  2. Register operator ATLAS-OPS and 3 agents (scout, builder, courier),
     plus a second operator SERVICE-CO with a payee agent (metrics-svc).
  3. Fund the fleet: /admin/issue mints bearer tokens (§7.1 operator
     funding), each agent deposits them into its custodial balance.
  4. Set per-hour/per-day caps; an over-cap spend fails atomically
     (agent_cap_exceeded), and the trailing window releases after 61 min.
  5. Freeze one agent: its transfers AND pulls against it fail
     (account_frozen); other agents keep working; unfreeze restores.
  6. The no-bearer-withdrawal flag blocks exfiltration to bearer tokens
     (withdrawal_disabled, no ledger change); an unflagged agent's by-hash
     withdrawal succeeds and the mint never learns the new secret.
  7. A service provider pulls against a §6.1(6) authorization; the per-auth
     day cap is enforced (pull_cap_exceeded).
  8. Signed §6.1(7) statements (per-agent and fleet) are produced on demand,
     verified against the mint's published key, and their kind-partition /
     balance invariants are re-checked independently.

Run:  PYTHONPATH=/home/lando/projects/aicash/impl python3 fleet_operator_journey.py
"""

import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/home/lando/projects/aicash/impl")

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig
from aicash.signing import generate_keypair, verify_obj
from aicash.supervision import CREDIT_KINDS, DEBIT_KINDS, SupervisionServer
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    new_secret,
)

HOUR_MS = 3_600_000
ADMIN_TOKEN = "atlas-ops-admin-secret"

PASSES = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}" + (f"  ({detail})" if detail else ""))
    PASSES.append((label, bool(cond)))
    if not cond:
        raise SystemExit(f"check failed: {label} {detail}")


class Mint:
    """Tiny HTTP client for the mint (urllib, stdlib only)."""

    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"

    def call(self, method, path, body=None, key=None, params=None, admin=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if key:
            req.add_header("Authorization", "Bearer " + key)
        if admin:
            req.add_header("X-Admin-Token", admin)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, {"raw": raw.decode(errors="replace")}


def main():
    # ------------------------------------------------------------------
    # 1. Build and mount a Supervision Profile mint (in-process, real HTTP)
    # ------------------------------------------------------------------
    print("== 1. Mount the mint with the Supervision Profile ==")
    clock = FakeClock(1_756_000_000_000)  # deterministic time, L17
    policy = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10)
    priv, pub = generate_keypair()
    dbdir = tempfile.mkdtemp(prefix="aicash-j6-")
    ledger = Ledger(
        os.path.join(dbdir, "mint.db"),
        clock,
        policy,
        recovery_window_ms=90 * 86_400_000,
        max_lock_expiry_ms=30 * 86_400_000,
    )
    config = MintConfig(
        mint_id="atlas-fleet-mint",
        baseline_model_class="test",
        burn_policy=policy,
        signing_private=priv,
        signing_public=pub,
        admin_token=ADMIN_TOKEN,
    )
    server = SupervisionServer(config, ledger)
    port = server.start()
    m = Mint(port)
    st, desc = m.call("GET", "/v3/mints")
    check("descriptor advertises supervision profile",
          st == 200 and "supervision" in desc["profiles"], str(desc.get("profiles")))
    mint_pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
    check("descriptor pubkey matches our keypair", mint_pub == pub)

    # ------------------------------------------------------------------
    # 2. Register operator + 3 agents, and a payee under a second operator
    # ------------------------------------------------------------------
    print("\n== 2. Register ATLAS-OPS, 3 agents, and a service provider ==")
    st, r = m.call("POST", "/v3/operator/register", {"operator_name": "ATLAS-OPS"})
    check("operator registered", st == 200, r.get("operator_id", ""))
    atlas_id, atlas_key = r["operator_id"], r["operator_key"]

    agents = {}
    for name in ("scout", "builder", "courier"):
        st, r = m.call("POST", "/v3/operator/agents", {"agent_name": name}, key=atlas_key)
        check(f"agent '{name}' registered", st == 200, r.get("agent_id", ""))
        agents[name] = {"id": r["agent_id"], "key": r["agent_key"]}

    st, r = m.call("POST", "/v3/operator/register", {"operator_name": "SERVICE-CO"})
    svc_key = r["operator_key"]
    st, r = m.call("POST", "/v3/operator/agents", {"agent_name": "metrics-svc"}, key=svc_key)
    check("payee custodial account registered (other operator)", st == 200)
    payee = {"id": r["agent_id"], "key": r["agent_key"]}

    # Credential separation: an agent key must not drive operator routes.
    st, r = m.call("POST", "/v3/operator/agents", {"agent_name": "evil"},
                   key=agents["scout"]["key"])
    check("agent key on operator route -> 403", st == 403, str(r))

    # ------------------------------------------------------------------
    # 3. Fund the fleet: admin-issue bearer tokens, agents deposit them
    # ------------------------------------------------------------------
    print("\n== 3. Fund each agent with 10,000 mc (issue -> deposit) ==")
    FUND = 10_000
    deposit_burn = compute_burn(FUND, policy)  # 10 mc at 0.1%
    for name, a in agents.items():
        secret = new_secret()
        st, r = m.call("POST", "/admin/issue",
                       {"outputs": [{"amount_mc": FUND, "secret": b64u_encode(secret)}]},
                       admin=ADMIN_TOKEN)
        check(f"admin-issue {FUND} mc for {name}", st == 200, str(r))
        token = format_token("atlas-fleet-mint", FUND, secret)
        st, r = m.call("POST", "/v3/agent/deposit", {"tokens": [token]}, key=a["key"])
        check(f"{name} deposit credited net of burn", st == 200
              and r.get("balance_mc") == FUND - deposit_burn, str(r))
    bal0 = FUND - deposit_burn  # 9,990 each

    # ------------------------------------------------------------------
    # 4. Caps: over-cap spend fails atomically; trailing window releases
    # ------------------------------------------------------------------
    print("\n== 4. Caps: over-cap spend fails; trailing hour window ==")
    st, r = m.call("POST", "/v3/operator/caps",
                   {"agent_id": agents["scout"]["id"], "per_hour_mc": 2_000,
                    "per_day_mc": 5_000, "absolute_mc": None}, key=atlas_key)
    check("caps set on scout (2,000/h, 5,000/d)", st == 200, str(r.get("caps")))
    m.call("POST", "/v3/operator/caps",
           {"agent_id": agents["builder"]["id"], "per_hour_mc": 2_000,
            "per_day_mc": 5_000}, key=atlas_key)
    m.call("POST", "/v3/operator/caps",
           {"agent_id": agents["courier"]["id"], "per_day_mc": 8_000}, key=atlas_key)

    st, r = m.call("POST", "/v3/agent/transfer",
                   {"to_account": agents["courier"]["id"], "amount_mc": 1_500,
                    "ref": "job-441 payout"}, key=agents["scout"]["key"])
    check("scout transfer 1,500 under cap succeeds", st == 200, str(r))
    st, r = m.call("POST", "/v3/agent/transfer",
                   {"to_account": agents["courier"]["id"], "amount_mc": 800,
                    "ref": "job-442 payout"}, key=agents["scout"]["key"])
    check("scout transfer 800 would breach 2,000/h -> agent_cap_exceeded",
          st == 400 and r.get("reason") == "agent_cap_exceeded", str(r))
    st, r = m.call("GET", "/v3/agent/balance", key=agents["scout"]["key"])
    check("failed spend was atomic (balance untouched)",
          r["balance_mc"] == bal0 - 1_500, str(r["balance_mc"]))

    clock.advance(61 * 60_000)  # 61 minutes: the 1,500 ages out of the hour
    st, r = m.call("POST", "/v3/agent/transfer",
                   {"to_account": agents["courier"]["id"], "amount_mc": 800,
                    "ref": "job-442 payout retry"}, key=agents["scout"]["key"])
    check("same 800 succeeds after 61 min (trailing window, not calendar)",
          st == 200, str(r))

    # ------------------------------------------------------------------
    # 5. Service provider pull against an authorization (§6.1(6))
    # ------------------------------------------------------------------
    print("\n== 5. Pull authorization: metered billing by metrics-svc ==")
    st, r = m.call("POST", "/v3/agent/authorize_pull",
                   {"payee_account": payee["id"], "cap_mc_per_day": 500,
                    "expires_at": clock() + 7 * 86_400_000},
                   key=agents["builder"]["key"])
    check("builder authorizes metrics-svc (500/day)", st == 200, str(r))
    auth_id = r["auth_id"]
    st, r = m.call("POST", "/v3/pull",
                   {"auth_id": auth_id, "amount_mc": 200, "ref": "api-usage-h1"},
                   key=payee["key"])
    check("provider pulls 200 mc", st == 200, str(r))
    st, r = m.call("GET", "/v3/agent/balance", key=payee["key"])
    check("payee balance credited 200", r["balance_mc"] == 200, str(r["balance_mc"]))

    # ------------------------------------------------------------------
    # 6. Freeze builder: its spends fail, pulls against it fail, others fine
    # ------------------------------------------------------------------
    print("\n== 6. Freeze one agent; others unaffected ==")
    st, r = m.call("POST", "/v3/operator/freeze",
                   {"agent_id": agents["builder"]["id"]}, key=atlas_key)
    check("operator freezes builder", st == 200, str(r))
    st, r = m.call("POST", "/v3/agent/transfer",
                   {"to_account": agents["scout"]["id"], "amount_mc": 50,
                    "ref": "should-fail"}, key=agents["builder"]["key"])
    check("frozen builder transfer -> account_frozen",
          st == 400 and r.get("reason") == "account_frozen", str(r))
    st, r = m.call("POST", "/v3/pull",
                   {"auth_id": auth_id, "amount_mc": 100, "ref": "api-usage-h2"},
                   key=payee["key"])
    check("pull against frozen builder -> account_frozen (nothing queues)",
          st == 400 and r.get("reason") == "account_frozen", str(r))
    st, r = m.call("POST", "/v3/agent/transfer",
                   {"to_account": agents["scout"]["id"], "amount_mc": 100,
                    "ref": "unaffected"}, key=agents["courier"]["key"])
    check("courier (not frozen) still spends fine", st == 200, str(r))

    st, r = m.call("POST", "/v3/operator/unfreeze",
                   {"agent_id": agents["builder"]["id"]}, key=atlas_key)
    check("unfreeze builder", st == 200)
    st, r = m.call("POST", "/v3/pull",
                   {"auth_id": auth_id, "amount_mc": 100, "ref": "api-usage-h2-retry"},
                   key=payee["key"])
    check("NEW pull after unfreeze succeeds (frozen one never executed)",
          st == 200, str(r))
    st, r = m.call("POST", "/v3/pull",
                   {"auth_id": auth_id, "amount_mc": 300, "ref": "api-usage-h3"},
                   key=payee["key"])
    check("pull beyond the 500/day auth cap -> pull_cap_exceeded",
          st == 400 and r.get("reason") == "pull_cap_exceeded", str(r))

    # ------------------------------------------------------------------
    # 7. No-bearer-withdrawal flag blocks exfiltration (§6.1(4))
    # ------------------------------------------------------------------
    print("\n== 7. No-bearer-withdrawal flag ==")
    st, r = m.call("POST", "/v3/operator/flags",
                   {"agent_id": agents["scout"]["id"], "no_bearer_withdrawal": True},
                   key=atlas_key)
    check("flag set on scout by operator", st == 200, str(r))
    exfil_secret = new_secret()
    exfil_hash = ledger_key(exfil_secret)
    st, r = m.call("POST", "/v3/agent/withdraw",
                   {"outputs": [{"amount_mc": 1_000, "secret_hash": exfil_hash}]},
                   key=agents["scout"]["key"])
    check("scout withdrawal -> withdrawal_disabled",
          st == 400 and r.get("reason") == "withdrawal_disabled", str(r))
    st, r = m.call("GET", f"/v3/status/{exfil_hash}")
    check("no ledger entry was created (state unknown)",
          st == 200 and r["result"]["state"] == "unknown", str(r))
    # agent cannot lift the flag itself
    st, r = m.call("POST", "/v3/operator/flags",
                   {"agent_id": agents["scout"]["id"], "no_bearer_withdrawal": False},
                   key=agents["scout"]["key"])
    check("agent cannot clear its own flag -> 403", st == 403, str(r))

    # contrast: an unflagged agent CAN withdraw, by-hash, secret never sent
    wd_secret = new_secret()
    wd_hash = ledger_key(wd_secret)
    st, before = m.call("GET", "/v3/agent/balance", key=agents["courier"]["key"])
    st, r = m.call("POST", "/v3/agent/withdraw",
                   {"outputs": [{"amount_mc": 5_000, "secret_hash": wd_hash}]},
                   key=agents["courier"]["key"])
    wd_burn = compute_burn(5_000, policy)  # charged on requested amount (§7.3)
    check("courier (no flag) withdraws 5,000 mc to a by-hash bearer entry",
          st == 200, str(r))
    st, r = m.call("GET", f"/v3/status/{wd_hash}")
    check("bearer entry live on the ledger, correct amount",
          r["result"]["state"] == "unspent"
          and r["result"]["amount_mc"] == 5_000, str(r))
    st, after = m.call("GET", "/v3/agent/balance", key=agents["courier"]["key"])
    check("courier debited amount + burn (gross)",
          before["balance_mc"] - after["balance_mc"] == 5_000 + wd_burn,
          f"burn={wd_burn}")

    # ------------------------------------------------------------------
    # 8. Signed statements (§6.1(7)): per-agent and fleet, verified
    # ------------------------------------------------------------------
    print("\n== 8. Signed statements for the period ==")
    t_from, t_to = 1_756_000_000_000 - 1_000, clock()

    st, stmt = m.call("GET", "/v3/operator/statement", key=atlas_key,
                      params={"agent_id": agents["builder"]["id"],
                              "from": t_from, "to": t_to})
    check("per-agent statement produced on demand", st == 200)
    check("statement signature verifies against published mint key",
          verify_obj(dict(stmt), mint_pub))
    kinds = [ln["kind"] for ln in stmt["lines"]]
    check("freeze/unfreeze appear as amount-0 non-monetary lines",
          "freeze" in kinds and "unfreeze" in kinds
          and all(ln["amount_mc"] == 0 for ln in stmt["lines"]
                  if ln["kind"] in ("freeze", "unfreeze")))
    credit = sum(l["amount_mc"] for l in stmt["lines"] if l["kind"] in CREDIT_KINDS)
    debit = sum(l["amount_mc"] for l in stmt["lines"] if l["kind"] in DEBIT_KINDS)
    check("kind-partition invariant: credits - debits == closing - opening",
          credit - debit == stmt["closing_balance_mc"] - stmt["opening_balance_mc"],
          f"{credit}-{debit} vs {stmt['closing_balance_mc']}-{stmt['opening_balance_mc']}")

    st, fleet = m.call("GET", "/v3/operator/statement", key=atlas_key,
                       params={"agent_id": "fleet", "from": t_from, "to": t_to})
    check("fleet statement produced and signature verifies",
          st == 200 and verify_obj(dict(fleet), mint_pub))
    # Independently recompute: fleet closing balance == sum of live balances
    live_total = 0
    for name, a in agents.items():
        st, r = m.call("GET", "/v3/agent/balance",
                       params={"agent_id": a["id"]}, key=atlas_key)
        live_total += r["balance_mc"]
        print(f"    {name}: balance={r['balance_mc']} "
              f"spend_rate={r['spend_rate']}")
    check("fleet closing balance equals sum of live agent balances",
          fleet["closing_balance_mc"] == live_total,
          f"{fleet['closing_balance_mc']} == {live_total}")
    # Tamper check: a mutated statement must fail verification
    tampered = dict(fleet)
    tampered["closing_balance_mc"] += 1
    check("tampered statement fails verification", not verify_obj(tampered, mint_pub))

    # withdrawal recorded net-of-burn with separate burn line (§6.1(7))
    st, cstmt = m.call("GET", "/v3/operator/statement", key=atlas_key,
                       params={"agent_id": agents["courier"]["id"],
                               "from": t_from, "to": t_to})
    wlines = [l for l in cstmt["lines"] if l["kind"] == "withdrawal"]
    blines = [l for l in cstmt["lines"] if l["kind"] == "burn"]
    check("withdrawal line net of burn + separate burn line",
          wlines and blines and wlines[-1]["amount_mc"] == 5_000
          and blines[-1]["amount_mc"] == wd_burn,
          f"w={wlines[-1]['amount_mc']} burn={blines[-1]['amount_mc']}")

    server.stop()
    print(f"\nAll {len(PASSES)} checks passed. Fleet supervision journey complete:")
    print("  real money issued, deposited, capped, frozen, pulled, withdrawn,")
    print("  and reconciled under a mint-signed statement.")


if __name__ == "__main__":
    main()
