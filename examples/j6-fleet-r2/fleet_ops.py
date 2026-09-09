"""
JOURNEY 6 (round 2) — Fleet operator: ATLAS-OPS supervises a custodial fleet (§6.1).

Demonstrates, end to end over real HTTP against a live SupervisionServer, that an
enterprise operator can:
  1. Mount the Supervision Profile on a mint (SupervisionServer) and confirm the
     descriptor advertises "supervision".
  2. Register an operator identity (ATLAS-OPS) + 3 fleet agents + 1 payee service.
  3. Fund each agent: admin-issue bearer value -> deposit into custody (real money).
  4. Set per-hour / per-day / absolute caps.
  5. Trip a cap: a transfer over the per-hour ceiling fails atomically
     (agent_cap_exceeded), no partial debit.
  6. Freeze an agent and assert the freeze response lists it under the field
     `frozen` (the pre-1.0 `freezed` typo is gone); a frozen account's outflow
     fails with account_frozen; credits IN still land.
  7. Set the no-bearer-withdrawal flag; a withdraw then fails withdrawal_disabled.
  8. A third party pulls against a §6.1(6) authorization (real custodial move,
     debit granting agent / credit payee), and enforce it counts against caps.
  9. Fetch a mint-signed statement for an agent and for the fleet, verify the
     Ed25519 signature with the mint's published key, and check the pinned
     balance invariant sum(credit-like) - sum(debit-like) == closing - opening.

Run:  PYTHONPATH=impl python3 fleet_ops.py

Uses ONLY package-root public API (aicash.__all__) + the documented supervision
HTTP routes (components/C10-supervision.md). No implementation source is read.
"""
import json
import os
import tempfile
import time
import urllib.request
import urllib.error

from aicash import (
    BurnPolicy, MintConfig, SupervisionServer, Ledger,
    generate_keypair, system_clock,
    new_secret, ledger_key, format_token, verify_obj,
)

MINT_ID = "atlas-mint"


def now_ms() -> int:
    return int(time.time() * 1000)


class Sup:
    """Tiny HTTP client for the supervision + admin routes on one mint."""

    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, key=None, admin=None, params=None):
        url = self.base + path
        if params:
            from urllib.parse import urlencode
            url += "?" + urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if key is not None:
            req.add_header("Authorization", "Bearer " + key)  # per-principal bearer key
        if admin is not None:
            req.add_header("X-Admin-Token", admin)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())


def balance(sup, key, agent_id=None, op_key=None):
    params = {"agent_id": agent_id} if agent_id else None
    st, r = sup.call("GET", "/v3/agent/balance", key=(op_key or key), params=params)
    assert st == 200, (st, r)
    return r["balance_mc"]


def main():
    tmp = tempfile.mkdtemp(prefix="j6r2-")
    db = os.path.join(tmp, "atlas.db")
    admin_token = "atlas-admin-secret"

    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="atlas-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv, signing_public=pub,
        admin_token=admin_token,
        # NOTE: profiles intentionally NOT listing "supervision" — C10 says
        # mounting adds it automatically.
    )
    # Build the Ledger from the config (C04 Public API), then mount the profile.
    ledger = Ledger(
        db, clock=system_clock, burn_policy=config.burn_policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
    )
    server = SupervisionServer(config, ledger)
    port = server.start()
    sup = Sup(f"http://127.0.0.1:{port}")
    t0 = now_ms()

    try:
        # --- 1. Descriptor advertises the profile ---
        st, desc = sup.call("GET", "/v3/mints")
        assert st == 200, (st, desc)
        assert "supervision" in desc["profiles"], desc["profiles"]
        print(f"1. Profile mounted; descriptor profiles = {desc['profiles']}")

        # --- 2. Register operator + fleet ---
        st, r = sup.call("POST", "/v3/operator/register", {"operator_name": "ATLAS-OPS"})
        assert st == 200, (st, r)
        op_id, op_key = r["operator_id"], r["operator_key"]
        print(f"2. Registered operator ATLAS-OPS -> {op_id}")

        agents = {}
        for name in ("builder", "courier", "analyst"):
            st, r = sup.call("POST", "/v3/operator/agents", {"agent_name": name}, key=op_key)
            assert st == 200, (st, r)
            agents[name] = {"id": r["agent_id"], "key": r["agent_key"]}
        # payee service (custodial account at same mint, required for pulls)
        st, r = sup.call("POST", "/v3/operator/agents", {"agent_name": "metrics-svc"}, key=op_key)
        assert st == 200, (st, r)
        payee = {"id": r["agent_id"], "key": r["agent_key"]}
        print(f"   Registered 3 agents {[a['id'] for a in agents.values()]} + payee {payee['id']}")

        # --- 3. Fund each agent: admin-issue -> deposit into custody ---
        def fund(agent_key, amount):
            s = new_secret()
            st, r = sup.call("POST", "/admin/issue",
                             {"outputs": [{"amount_mc": amount, "secret_hash": ledger_key(s)}]},
                             admin=admin_token)
            assert st == 200 and r.get("status") == "ok", (st, r)
            tok = format_token(MINT_ID, amount, s)
            st, r = sup.call("POST", "/v3/agent/deposit", {"tokens": [tok]}, key=agent_key)
            assert st == 200, (st, r)
            return r

        for name, a in agents.items():
            r = fund(a["key"], 5_000)
            print(f"3. Funded {name}: deposited_mc={r['deposited_mc']} burn_mc={r['burn_mc']} "
                  f"balance={balance(sup, a['key'])}")
        fund(payee["key"], 100)  # small starting balance so we can see it grow via pull

        # --- 4. Set caps ---
        st, r = sup.call("POST", "/v3/operator/caps",
                         {"agent_id": agents["builder"]["id"], "per_hour_mc": 2_000,
                          "per_day_mc": 5_000, "absolute_mc": None}, key=op_key)
        assert st == 200, (st, r)
        for nm, day in (("courier", 8_000), ("analyst", 5_000)):
            st, r = sup.call("POST", "/v3/operator/caps",
                             {"agent_id": agents[nm]["id"], "per_hour_mc": None,
                              "per_day_mc": day, "absolute_mc": None}, key=op_key)
            assert st == 200, (st, r)
        print("4. Caps set (builder: 2000/hr, 5000/day).")

        # --- 5. Over-cap fail (atomic) ---
        bal_before = balance(sup, agents["builder"]["key"])
        st, r = sup.call("POST", "/v3/agent/transfer",
                         {"to_account": agents["courier"]["id"], "amount_mc": 3_000,
                          "ref": "over-cap-attempt"}, key=agents["builder"]["key"])
        assert st == 400 and r.get("reason") == "agent_cap_exceeded", (st, r)
        assert balance(sup, agents["builder"]["key"]) == bal_before, "partial debit on cap fail!"
        print(f"5. Over-cap transfer 3000 (>2000/hr) rejected: {r['reason']}; balance unchanged "
              f"({bal_before}).")

        # A within-cap transfer succeeds (real custodial money movement, burn-free)
        courier_before = balance(sup, agents["courier"]["key"])
        st, r = sup.call("POST", "/v3/agent/transfer",
                         {"to_account": agents["courier"]["id"], "amount_mc": 1_000,
                          "ref": "payroll"}, key=agents["builder"]["key"])
        assert st == 200, (st, r)
        assert balance(sup, agents["courier"]["key"]) == courier_before + 1_000
        print(f"   Within-cap transfer 1000 builder->courier ok; courier now "
              f"{balance(sup, agents['courier']['key'])}.")

        # --- 6. Freeze (assert response field is `frozen`) ---
        st, r = sup.call("POST", "/v3/operator/freeze",
                         {"agent_id": agents["courier"]["id"]}, key=op_key)
        assert st == 200, (st, r)
        assert "frozen" in r, f"freeze response missing `frozen` field: {r}"
        assert "freezed" not in r, f"legacy typo `freezed` still present: {r}"
        assert agents["courier"]["id"] in r["frozen"], r
        print(f"6. Froze courier; response field `frozen`={r['frozen']}")

        # Frozen account cannot move value out
        st, r = sup.call("POST", "/v3/agent/transfer",
                         {"to_account": agents["builder"]["id"], "amount_mc": 100,
                          "ref": "escape"}, key=agents["courier"]["key"])
        assert st == 400 and r.get("reason") == "account_frozen", (st, r)
        print(f"   Frozen courier outflow rejected: {r['reason']}.")

        # Credits IN to a frozen account still land
        frozen_before = balance(sup, agents["courier"]["key"])
        st, r = sup.call("POST", "/v3/agent/transfer",
                         {"to_account": agents["courier"]["id"], "amount_mc": 50,
                          "ref": "still-lands"}, key=agents["builder"]["key"])
        assert st == 200, (st, r)
        assert balance(sup, agents["courier"]["key"]) == frozen_before + 50
        print("   Credit IN to frozen courier still landed (+50).")

        # unfreeze so later checks are clean
        st, r = sup.call("POST", "/v3/operator/unfreeze",
                         {"agent_id": agents["courier"]["id"]}, key=op_key)
        assert st == 200 and "unfrozen" in r, (st, r)
        print(f"   Unfroze courier; response field `unfrozen`={r['unfrozen']}")

        # --- 7. No-bearer-withdrawal flag ---
        st, r = sup.call("POST", "/v3/operator/flags",
                         {"agent_id": agents["analyst"]["id"], "no_bearer_withdrawal": True},
                         key=op_key)
        assert st == 200, (st, r)
        wd_secret = new_secret()
        st, r = sup.call("POST", "/v3/agent/withdraw",
                         {"outputs": [{"amount_mc": 500, "secret_hash": ledger_key(wd_secret)}]},
                         key=agents["analyst"]["key"])
        assert st == 400 and r.get("reason") == "withdrawal_disabled", (st, r)
        print(f"7. no_bearer_withdrawal set; analyst withdraw rejected: {r['reason']}.")

        # --- 8. Pull against a §6.1(6) authorization ---
        expires = now_ms() + 3_600_000
        st, r = sup.call("POST", "/v3/agent/authorize_pull",
                         {"payee_account": payee["id"], "cap_mc_per_day": 1_000,
                          "expires_at": expires}, key=agents["analyst"]["key"])
        assert st == 200, (st, r)
        auth_id = r["auth_id"]
        analyst_before = balance(sup, agents["analyst"]["key"])
        payee_before = balance(sup, payee["key"])
        st, r = sup.call("POST", "/v3/pull",
                         {"auth_id": auth_id, "amount_mc": 500, "ref": "april-metering"},
                         key=payee["key"])
        assert st == 200, (st, r)
        analyst_after = balance(sup, agents["analyst"]["key"])
        payee_after = balance(sup, payee["key"])
        assert analyst_after == analyst_before - 500, (analyst_before, analyst_after)
        assert payee_after == payee_before + 500, (payee_before, payee_after)
        print(f"8. Pull 500 by metrics-svc against auth {auth_id}: analyst "
              f"{analyst_before}->{analyst_after}, payee {payee_before}->{payee_after}.")
        # Over the per-auth day cap -> rejected
        st, r = sup.call("POST", "/v3/pull",
                         {"auth_id": auth_id, "amount_mc": 600, "ref": "over-auth"},
                         key=payee["key"])
        assert st == 400 and r.get("reason") == "pull_cap_exceeded", (st, r)
        print(f"   Second pull 600 (auth day cap 1000, 500 used) rejected: {r['reason']}.")

        # --- 9. Signed statement + invariant ---
        t_end = now_ms() + 1_000
        st, stmt = sup.call("GET", "/v3/operator/statement", key=op_key,
                            params={"agent_id": agents["analyst"]["id"],
                                    "from": t0, "to": t_end})
        assert st == 200, (st, stmt)
        assert verify_obj(stmt, pub), "statement signature failed to verify with mint key!"
        credit_like = {"credit", "pull_in", "deposit", "issuance"}
        debit_like = {"debit", "pull_out", "withdrawal", "burn"}
        cin = sum(l["amount_mc"] for l in stmt["lines"] if l["kind"] in credit_like)
        cout = sum(l["amount_mc"] for l in stmt["lines"] if l["kind"] in debit_like)
        delta = stmt["closing_balance_mc"] - stmt["opening_balance_mc"]
        assert cin - cout == delta, (cin, cout, delta, stmt["lines"])
        kinds = sorted({l["kind"] for l in stmt["lines"]})
        print(f"9. analyst statement v{stmt['v']} verified (sig ok); lines kinds={kinds}; "
              f"credit-debit={cin - cout} == closing-opening={delta}. "
              f"closing={stmt['closing_balance_mc']}")

        # Fleet statement too
        st, fleet = sup.call("GET", "/v3/operator/statement", key=op_key,
                             params={"fleet": "1", "from": t0, "to": t_end})
        assert st == 200, (st, fleet)
        assert verify_obj(fleet, pub), "fleet statement sig failed!"
        assert fleet["scope"]["agent_id"] == "fleet" or fleet["scope"].get("agent_id") == "fleet"
        print(f"   Fleet statement verified; scope={fleet['scope']}, {len(fleet['lines'])} lines.")

        print("\nALL ASSERTIONS PASSED — real custodial money moved and verified.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
