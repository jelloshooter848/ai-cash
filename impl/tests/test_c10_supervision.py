"""C10 — supervision tests: the Supervision Profile over real HTTP.

Every test drives a real SupervisionServer (a C06 mint with the profile
mounted) on 127.0.0.1 with stdlib http.client. All time comes from a
FakeClock injected through the Ledger (L17). Benchmark items B1–B9 from
components/C10-supervision.md are named in each test's docstring.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import unittest
from typing import NamedTuple

from aicash.burncalc import BurnPolicy
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig
from aicash.signing import generate_keypair, verify_obj
from aicash.supervision import SupervisionServer
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    new_secret,
)

T0 = 1_756_000_000_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000
MINT_ID = "testmint"

#: Burn-free policy (rate 0) so cap/pull arithmetic is exact.
NO_BURN = BurnPolicy(rate_ppm=0, cap_mc=0, exempt_below_mc=10)
#: 1% capped burn for the bridge/round-trip/statement tests.
BURN = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)

CREDIT_KINDS = {"credit", "pull_in", "deposit", "issuance"}
DEBIT_KINDS = {"debit", "pull_out", "withdrawal", "burn"}

STATEMENT_KEYS = {
    "v",
    "mint_id",
    "scope",
    "period",
    "opening_balance_mc",
    "closing_balance_mc",
    "lines",
    "signature",
}
LINE_KEYS = {"t", "kind", "amount_mc", "counterparty_account", "ref"}


def api(port, method, path, obj=None, key=None):
    """One HTTP round trip; returns (status, parsed json body)."""
    headers = {}
    if key is not None:
        headers["Authorization"] = "Bearer " + key
    body = None if obj is None else json.dumps(obj).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    ledger: Ledger
    pub: bytes
    db_path: str
    server: object
    burn: object  # the BurnPolicy the mint runs


class SupervisionTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------ #
    # harness                                                            #
    # ------------------------------------------------------------------ #

    def start_mint(self, *, burn_policy=NO_BURN, clock=None, profiles=()):
        clock = clock or FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "ledger.sqlite3")
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            clock,
            burn_policy,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=burn_policy,
            signing_private=priv,
            signing_public=pub,
            profiles=profiles,
        )
        server = SupervisionServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, ledger, pub, db_path, server, burn_policy)

    def restart_mint(self, m):
        """Simulate a process restart: stop the server and bring up a
        fresh SupervisionServer over the SAME database and clock. The new
        _SupCore runs the §5.3 startup reconciliation of staged ops."""
        m.server.stop()
        priv, pub = generate_keypair()
        ledger = Ledger(
            m.db_path,
            m.clock,
            m.burn,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=m.burn,
            signing_private=priv,
            signing_public=pub,
            profiles=(),
        )
        server = SupervisionServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, m.clock, ledger, pub, m.db_path, server, m.burn)

    def sup_rows(self, m, sql, args=()):
        """Read supervision tables through an independent connection (what
        durable state a crashed process would leave behind)."""
        conn = sqlite3.connect(m.db_path)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def new_operator(self, m, name="op"):
        status, r = api(
            m.port, "POST", "/v3/operator/register", {"operator_name": name}
        )
        self.assertEqual(status, 200)
        return r["operator_id"], r["operator_key"]

    def new_agent(self, m, op_key, name="agent"):
        status, r = api(
            m.port,
            "POST",
            "/v3/operator/agents",
            {"agent_name": name},
            key=op_key,
        )
        self.assertEqual(status, 200)
        return r["agent_id"], r["agent_key"]

    def issue_token(self, m, amount_mc):
        """Operator-fund a bearer token via C06's /admin/issue."""
        secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/admin/issue",
            {"outputs": [{"amount_mc": amount_mc, "secret_hash": ledger_key(secret)}]},
        )
        self.assertEqual(status, 200, r)
        return format_token(MINT_ID, amount_mc, secret)

    def fund(self, m, agent_key, amount_mc):
        """Issue a bearer token and deposit it into the agent's balance."""
        token = self.issue_token(m, amount_mc)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/deposit",
            {"tokens": [token]},
            key=agent_key,
        )
        self.assertEqual(status, 200, r)
        return r

    def balance(self, m, key, agent_id=None):
        path = "/v3/agent/balance"
        if agent_id is not None:
            path += "?agent_id=" + agent_id
        status, r = api(m.port, "GET", path, key=key)
        self.assertEqual(status, 200, r)
        return r

    def transfer(self, m, key, to_account, amount_mc, ref=None):
        body = {"to_account": to_account, "amount_mc": amount_mc}
        if ref is not None:
            body["ref"] = ref
        return api(m.port, "POST", "/v3/agent/transfer", body, key=key)

    def assertRejected(self, resp, reason, status=400):
        code, body = resp
        self.assertEqual(code, status, body)
        self.assertEqual(body, {"status": "rejected", "reason": reason})

    def statement(self, m, op_key, t_from, t_to, agent_id=None):
        path = "/v3/operator/statement?from=%d&to=%d" % (t_from, t_to)
        if agent_id is not None:
            path += "&agent_id=" + agent_id
        return api(m.port, "GET", path, key=op_key)

    def check_statement(self, m, stmt, operator_id, agent_scope):
        """Schema + signature + §6.1(7) partition invariant."""
        self.assertEqual(set(stmt), STATEMENT_KEYS)
        self.assertEqual(stmt["v"], 4)
        self.assertEqual(stmt["mint_id"], MINT_ID)
        self.assertEqual(
            stmt["scope"], {"operator_id": operator_id, "agent_id": agent_scope}
        )
        self.assertEqual(set(stmt["period"]), {"from", "to"})
        for line in stmt["lines"]:
            self.assertEqual(set(line), LINE_KEYS)
            self.assertGreaterEqual(line["t"], stmt["period"]["from"])
            self.assertLessEqual(line["t"], stmt["period"]["to"])
            if line["kind"] in ("freeze", "unfreeze"):
                self.assertEqual(line["amount_mc"], 0)
        credit = sum(
            ln["amount_mc"] for ln in stmt["lines"] if ln["kind"] in CREDIT_KINDS
        )
        debit = sum(
            ln["amount_mc"] for ln in stmt["lines"] if ln["kind"] in DEBIT_KINDS
        )
        self.assertEqual(
            credit - debit,
            stmt["closing_balance_mc"] - stmt["opening_balance_mc"],
        )
        # Signature verifies against the key the descriptor publishes.
        status, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
        self.assertTrue(verify_obj(stmt, pub))

    # ------------------------------------------------------------------ #
    # B1 — the three coherence clauses                                   #
    # ------------------------------------------------------------------ #

    def test_b1a_freeze_suspends_pulls_nothing_queues(self):
        """B1(a): freeze suspends pulls with account_frozen; nothing queues;
        after unfreeze a NEW pull succeeds and the failed one never ran."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        self.fund(m, g_key, 100)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": p_id, "cap_mc_per_day": 100, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_id = r["auth_id"]

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": g_id}, key=op_key
        )
        self.assertEqual(status, 200)
        self.assertRejected(
            api(m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 30}, key=p_key),
            "account_frozen",
        )
        # Nothing queued, nothing moved.
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 100)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 0)

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": g_id}, key=op_key
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 30}, key=p_key
        )
        self.assertEqual(status, 200, r)
        # Exactly ONE pull executed: the suspended one did not run later.
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 70)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 30)

    def test_b1b_pull_counts_against_granter_caps_atomically(self):
        """B1(b): pulls count against the granting agent's caps; a pull that
        would exceed per-hour fails atomically (no partial debit)."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        self.fund(m, g_key, 500)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": g_id, "per_hour_mc": 100, "per_day_mc": None, "absolute_mc": None},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": p_id, "cap_mc_per_day": 1000, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_id = r["auth_id"]

        status, _ = self.transfer(m, g_key, p_id, 60)
        self.assertEqual(status, 200)
        # 60 already in the trailing hour; a 50 pull would make 110 > 100.
        self.assertRejected(
            api(m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 50}, key=p_key),
            "agent_cap_exceeded",
        )
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 440)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 60)
        status, r = api(
            m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 40}, key=p_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 400)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 100)

    def test_b1c_statement_on_demand_for_just_closed_period(self):
        """B1(c): a statement for a just-closed period is produced on demand
        and verifies — schema, mint signature, balance invariant."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")
        self.fund(m, a_key, 100)
        status, _ = self.transfer(m, a_key, b_id, 25, ref="job-1")
        self.assertEqual(status, 200)
        t_close = m.clock()
        m.clock.advance(HOUR_MS)  # the period is now closed

        status, stmt = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 75)
        self.assertEqual(
            [(ln["kind"], ln["amount_mc"], ln["counterparty_account"], ln["ref"]) for ln in stmt["lines"]],
            [("deposit", 100, None, ""), ("debit", 25, b_id, "job-1")],
        )

    # ------------------------------------------------------------------ #
    # B2 — no-bearer-withdrawal flag                                     #
    # ------------------------------------------------------------------ #

    def test_b2_withdrawal_flag(self):
        """B2: flag set -> withdraw fails withdrawal_disabled with no ledger
        change; deposits still land; unset -> withdraw succeeds; the flag is
        settable by the operator key only (agent attempt -> 403)."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)

        # Agent keys cannot set flags (§6.1(1)).
        status, body = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True},
            key=a_key,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, {"status": "forbidden"})

        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True},
            key=op_key,
        )
        self.assertEqual(status, 200)

        supply_before = m.ledger.supply()
        secret = new_secret()
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 10, "secret_hash": ledger_key(secret)}]},
                key=a_key,
            ),
            "withdrawal_disabled",
        )
        self.assertEqual(m.ledger.supply(), supply_before)  # no ledger change
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 100)
        # Deposits still allowed while the flag is set (§6.1(4)).
        self.fund(m, a_key, 20)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 120)

        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": False},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 10, "secret_hash": ledger_key(secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 10)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 110)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 10)

    # ------------------------------------------------------------------ #
    # B3 — rolling trailing windows with the fake clock                  #
    # ------------------------------------------------------------------ #

    def test_b3_trailing_hour_window_and_not_calendar(self):
        """B3: cap 100/hour; 60 at t=0 and 40 at t=30min fill it; +1 fails;
        at t=61min the t=0 spend ages out and 60 more succeeds. Windows are
        trailing, never calendar: 100 spent at 23:59 still blocks at 00:01."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "hourly")
        z_id, _ = self.new_agent(m, op_key, "sink")
        self.fund(m, a_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 100, "per_day_mc": None, "absolute_mc": None},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertEqual(self.transfer(m, a_key, z_id, 60)[0], 200)  # t=0
        m.clock.advance(30 * 60_000)  # t = 30min
        self.assertEqual(self.transfer(m, a_key, z_id, 40)[0], 200)
        self.assertRejected(self.transfer(m, a_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(31 * 60_000)  # t = 61min: the 60 has aged out
        self.assertEqual(self.transfer(m, a_key, z_id, 60)[0], 200)
        self.assertRejected(self.transfer(m, a_key, z_id, 1), "agent_cap_exceeded")

        # Trailing, not calendar: fresh agent, spend right before a UTC
        # midnight, cross it, cap still binds two minutes later.
        b_id, b_key = self.new_agent(m, op_key, "midnight")
        self.fund(m, b_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": b_id, "per_hour_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        midnight = (m.clock() // DAY_MS + 1) * DAY_MS
        m.clock.set(midnight - 60_000)  # 23:59 UTC
        self.assertEqual(self.transfer(m, b_key, z_id, 100)[0], 200)
        m.clock.advance(120_000)  # 00:01 UTC next day
        self.assertRejected(self.transfer(m, b_key, z_id, 1), "agent_cap_exceeded")

    def test_b3_trailing_day_window_and_absolute(self):
        """B3: per-day trailing 86400s window behaves like the hour window;
        the absolute cap is a lifetime total that never ages out."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        d_id, d_key = self.new_agent(m, op_key, "daily")
        e_id, e_key = self.new_agent(m, op_key, "lifetime")
        z_id, _ = self.new_agent(m, op_key, "sink")
        self.fund(m, d_key, 1000)
        self.fund(m, e_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": d_id, "per_day_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": e_id, "absolute_mc": 200},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertEqual(self.transfer(m, d_key, z_id, 60)[0], 200)  # t
        m.clock.advance(12 * HOUR_MS)
        self.assertEqual(self.transfer(m, d_key, z_id, 40)[0], 200)  # t+12h
        self.assertRejected(self.transfer(m, d_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(12 * HOUR_MS + 60_000)  # t+24h+1min: 60 aged out
        self.assertEqual(self.transfer(m, d_key, z_id, 60)[0], 200)
        self.assertRejected(self.transfer(m, d_key, z_id, 1), "agent_cap_exceeded")

        # Absolute = lifetime: aging never frees it.
        self.assertEqual(self.transfer(m, e_key, z_id, 150)[0], 200)
        m.clock.advance(3 * DAY_MS)
        self.assertEqual(self.transfer(m, e_key, z_id, 50)[0], 200)
        self.assertRejected(self.transfer(m, e_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(30 * DAY_MS)
        self.assertRejected(self.transfer(m, e_key, z_id, 1), "agent_cap_exceeded")

    # ------------------------------------------------------------------ #
    # B4 — operator-wide freeze                                          #
    # ------------------------------------------------------------------ #

    def test_b4_operator_wide_freeze_scoped_to_one_operator(self):
        """B4: freeze ALL halts every agent of that operator in one call and
        only that operator's agents; credits INTO frozen accounts still land
        (incoming transfer and deposit)."""
        m = self.start_mint()
        op1_id, op1_key = self.new_operator(m, "op1")
        op2_id, op2_key = self.new_operator(m, "op2")
        a_id, a_key = self.new_agent(m, op1_key, "a")
        b_id, b_key = self.new_agent(m, op1_key, "b")
        c_id, c_key = self.new_agent(m, op2_key, "c")
        for k in (a_key, b_key, c_key):
            self.fund(m, k, 100)

        # Cross-operator targeting is refused.
        status, _ = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": c_id}, key=op1_key
        )
        self.assertEqual(status, 404)

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": "ALL"}, key=op1_key
        )
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["frozen"]), sorted([a_id, b_id]))

        self.assertRejected(self.transfer(m, a_key, c_id, 10), "account_frozen")
        self.assertRejected(self.transfer(m, b_key, c_id, 10), "account_frozen")
        # Only op1's agents are frozen: op2's agent still spends freely.
        self.assertEqual(self.transfer(m, c_key, a_id, 10)[0], 200)
        # ... and that credit INTO frozen a landed.
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 110)
        # Deposits into a frozen account land too (§6.1(3): credits in).
        self.fund(m, a_key, 5)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 115)

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": "ALL"}, key=op1_key
        )
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["unfrozen"]), sorted([a_id, b_id]))
        self.assertEqual(self.transfer(m, a_key, c_id, 10)[0], 200)
        self.assertEqual(self.transfer(m, b_key, c_id, 10)[0], 200)

    # ------------------------------------------------------------------ #
    # B5 — deposit/withdraw round trip through the real ledger           #
    # ------------------------------------------------------------------ #

    def test_b5_deposit_withdraw_round_trip(self):
        """B5: bearer -> custodial -> bearer conserves value minus exactly
        the two exchange burns; the custodial transfer in between burns
        nothing; withdrawal is by-hash and the withdrawn secret never
        appears anywhere in the mint database."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")

        # Deposit 1000: burn 1% = 10, net credit 990.
        token = self.issue_token(m, 1000)
        status, r = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 10)
        self.assertEqual(r["deposited_mc"], 990)
        self.assertEqual(r["balance_mc"], 990)
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_issued_mc"], 1000)
        self.assertEqual(supply["cumulative_burned_mc"], 10)
        self.assertEqual(supply["outstanding_mc"], 990)

        # Custodial transfer burns NOTHING (§7.3).
        status, _ = self.transfer(m, a_key, b_id, 490)
        self.assertEqual(status, 200)
        self.assertEqual(m.ledger.supply()["cumulative_burned_mc"], 10)

        # Withdraw 480 by hash: the agent is charged burn(480) = 4 on the
        # REQUESTED amount (§7.3/R17); the ledger's exchange still burns
        # burn(990) = 9 on the custody input, mint custody absorbs 5.
        secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 480, "secret_hash": ledger_key(secret)}]},
            key=b_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 480)
        self.assertEqual(r["burn_mc"], 4)  # compute_burn(480), not burn(990)
        self.assertEqual(r["balance_mc"], 6)  # 490 - 484

        # Conservation: 1000 in, 10 + 9 burned across the two exchanges.
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_burned_mc"], 19)
        self.assertEqual(supply["outstanding_mc"], 981)
        # Outstanding = withdrawn bearer entry (480) + mint custody (501);
        # custody equals the sum of balances (500 + 6) minus the 5 mc the
        # mint absorbed (ledger burn 9 vs agent-charged 4 — §7.3/R17).
        self.assertEqual(supply["outstanding_mc"] - 480, 501)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 500)
        self.assertEqual(self.balance(m, b_key)["balance_mc"], 6)
        ((absorbed,),) = self.sup_rows(m, "SELECT absorbed_mc FROM sup_mint")
        self.assertEqual(absorbed, 5)
        self.assertEqual(501, 500 + 6 - absorbed)

        # The new entry exists, unspent, at the requested hash.
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 480)

        # By-hash means the mint NEVER saw the secret: neither the raw
        # bytes nor its b64u encoding occur anywhere in the mint database.
        with open(m.db_path, "rb") as fh:
            db_bytes = fh.read()
        self.assertNotIn(secret, db_bytes)
        self.assertNotIn(b64u_encode(secret).encode("ascii"), db_bytes)

        # And it is real bearer value: an unregistered Layer 0 exchange
        # of the withdrawn token succeeds (burn 1% of 480 = 4).
        fresh = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/exchange",
            {
                "idempotency_key": "roundtrip-1",
                "inputs": [format_token(MINT_ID, 480, secret)],
                "outputs": [{"amount_mc": 476, "secret_hash": ledger_key(fresh)}],
            },
        )
        self.assertEqual(status, 200, r)

    # ------------------------------------------------------------------ #
    # B6 — pull lifecycle                                                #
    # ------------------------------------------------------------------ #

    def test_b6_pull_lifecycle(self):
        """B6: authorize -> pull ok -> revoke -> authorization_revoked;
        expiry via the fake clock -> authorization_expired; the per-auth
        trailing-day cap is enforced atomically."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        p2_id, p2_key = self.new_agent(m, op_key, "payee2")
        self.fund(m, g_key, 500)

        def authorize(payee, cap, expires_at):
            status, r = api(
                m.port,
                "POST",
                "/v3/agent/authorize_pull",
                {"payee_account": payee, "cap_mc_per_day": cap, "expires_at": expires_at},
                key=g_key,
            )
            self.assertEqual(status, 200, r)
            return r["auth_id"]

        def pull(key, auth_id, amount):
            return api(
                m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": amount}, key=key
            )

        auth1 = authorize(p_id, 100, T0 + 20 * DAY_MS)
        self.assertEqual(pull(p_key, auth1, 60)[0], 200)
        # Per-auth trailing-day cap: 60 + 50 > 100 fails atomically.
        self.assertRejected(pull(p_key, auth1, 50), "pull_cap_exceeded")
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 440)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 60)
        self.assertEqual(pull(p_key, auth1, 40)[0], 200)
        self.assertRejected(pull(p_key, auth1, 1), "pull_cap_exceeded")
        # The day window is trailing: 24h+1min later it has emptied.
        m.clock.advance(DAY_MS + 60_000)
        self.assertEqual(pull(p_key, auth1, 100)[0], 200)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 300)

        # Revocation is immediate.
        status, _ = api(
            m.port, "POST", "/v3/agent/revoke_pull", {"auth_id": auth1}, key=g_key
        )
        self.assertEqual(status, 200)
        self.assertRejected(pull(p_key, auth1, 10), "authorization_revoked")

        # Expiry against the mint clock; the boundary belongs to expiry.
        auth2 = authorize(p_id, 100, m.clock() + HOUR_MS)
        self.assertEqual(pull(p_key, auth2, 5)[0], 200)
        m.clock.advance(61 * 60_000)
        self.assertRejected(pull(p_key, auth2, 5), "authorization_expired")

        # Unknown auth, and an auth granted to a DIFFERENT payee, both
        # answer authorization_missing.
        self.assertRejected(pull(p_key, "auth-nope", 5), "authorization_missing")
        auth3 = authorize(p2_id, 100, m.clock() + DAY_MS)
        self.assertRejected(pull(p_key, auth3, 5), "authorization_missing")
        self.assertEqual(pull(p2_key, auth3, 5)[0], 200)

    # ------------------------------------------------------------------ #
    # B7 — scripted-week statement cross-check                           #
    # ------------------------------------------------------------------ #

    def test_b7_statement_week_cross_check(self):
        """B7: a scripted week (issue+deposit, transfer, pull, withdrawal
        with burn, freeze period); the statement's lines reproduce it
        exactly, the pinned partition sums match, and an independently
        recomputed balance equals closing_balance_mc."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")

        t0 = m.clock()
        # Day 0: operator issues a 1000 mc bearer token; A deposits it
        # (burn 10, net 990).
        self.fund(m, a_key, 1000)
        # Day 1: A transfers 200 to B.
        m.clock.set(t0 + 1 * DAY_MS)
        t1 = m.clock()
        self.assertEqual(self.transfer(m, a_key, b_id, 200, ref="wages")[0], 200)
        # Day 2: A grants B a pull authorization; B pulls 50.
        m.clock.set(t0 + 2 * DAY_MS)
        t2 = m.clock()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": b_id, "cap_mc_per_day": 100, "expires_at": t0 + 30 * DAY_MS},
            key=a_key,
        )
        self.assertEqual(status, 200)
        status, _ = api(
            m.port,
            "POST",
            "/v3/pull",
            {"auth_id": r["auth_id"], "amount_mc": 50, "ref": "meter"},
            key=b_key,
        )
        self.assertEqual(status, 200)
        # Day 3: A withdraws 100 — charged burn(100) = 1 on the requested
        # amount (§7.3/R17), gross 101; the ledger burns 9 on the 990
        # custody input and the mint absorbs the 8 mc difference.
        m.clock.set(t0 + 3 * DAY_MS)
        t3 = m.clock()
        w_secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(w_secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 1)
        # Day 4: freeze A; half a day later unfreeze.
        m.clock.set(t0 + 4 * DAY_MS)
        t4 = m.clock()
        status, _ = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id}, key=op_key
        )
        self.assertEqual(status, 200)
        m.clock.set(t0 + 4 * DAY_MS + 12 * HOUR_MS)
        t5 = m.clock()
        status, _ = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": a_id}, key=op_key
        )
        self.assertEqual(status, 200)

        # Close the week; produce statements on demand (§8(c)).
        m.clock.set(t0 + 8 * DAY_MS)
        status, stmt = self.statement(m, op_key, t0, t0 + 7 * DAY_MS, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["period"], {"from": t0, "to": t0 + 7 * DAY_MS})
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 639)  # 990-200-50-100-1
        expected_lines = [
            {"t": t0, "kind": "deposit", "amount_mc": 990, "counterparty_account": None, "ref": ""},
            {"t": t1, "kind": "debit", "amount_mc": 200, "counterparty_account": b_id, "ref": "wages"},
            {"t": t2, "kind": "pull_out", "amount_mc": 50, "counterparty_account": b_id, "ref": "meter"},
            {"t": t3, "kind": "withdrawal", "amount_mc": 100, "counterparty_account": None, "ref": ""},
            {"t": t3, "kind": "burn", "amount_mc": 1, "counterparty_account": None, "ref": ""},
            {"t": t4, "kind": "freeze", "amount_mc": 0, "counterparty_account": None, "ref": ""},
            {"t": t5, "kind": "unfreeze", "amount_mc": 0, "counterparty_account": None, "ref": ""},
        ]
        self.assertEqual(stmt["lines"], expected_lines)
        # Independent recomputation of the closing balance.
        recomputed = stmt["opening_balance_mc"]
        for ln in stmt["lines"]:
            if ln["kind"] in CREDIT_KINDS:
                recomputed += ln["amount_mc"]
            elif ln["kind"] in DEBIT_KINDS:
                recomputed -= ln["amount_mc"]
        self.assertEqual(recomputed, stmt["closing_balance_mc"])
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 639)

        # Fleet statement: both agents, same invariant, closing = 639+250.
        status, fleet = self.statement(m, op_key, t0, t0 + 7 * DAY_MS)
        self.assertEqual(status, 200, fleet)
        self.check_statement(m, fleet, op_id, "fleet")
        self.assertEqual(fleet["opening_balance_mc"], 0)
        self.assertEqual(fleet["closing_balance_mc"], 889)
        self.assertEqual(len(fleet["lines"]), 9)  # + B's credit and pull_in
        b_kinds = [
            (ln["kind"], ln["amount_mc"])
            for ln in fleet["lines"]
            if ln["counterparty_account"] == a_id
        ]
        self.assertEqual(b_kinds, [("credit", 200), ("pull_in", 50)])

    # ------------------------------------------------------------------ #
    # B8 — auth separation matrix                                        #
    # ------------------------------------------------------------------ #

    def test_b8_auth_separation_matrix(self):
        """B8 (and requirement 1): every supervision route crossed with
        {no key, agent key, operator key} yields the expected 401/403/200."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "matrix-op")
        a_id, a_key = self.new_agent(m, op_key, "actor")
        s_id, s_key = self.new_agent(m, op_key, "sacrificial")
        g_id, g_key = self.new_agent(m, op_key, "granter")
        self.fund(m, a_key, 100)
        self.fund(m, g_key, 100)
        # granter -> actor pull authorization (for the /v3/pull row).
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": a_id, "cap_mc_per_day": 50, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_pull = r["auth_id"]
        # actor -> granter authorization (for the revoke row).
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": g_id, "cap_mc_per_day": 50, "expires_at": T0 + 10 * DAY_MS},
            key=a_key,
        )
        self.assertEqual(status, 200)
        auth_rev = r["auth_id"]
        deposit_token = self.issue_token(m, 50)
        far = T0 + 30 * DAY_MS

        # (method, path, body, per-role query, {role: expected status})
        rows = [
            ("POST", "/v3/operator/register", {"operator_name": "x"}, None,
             {"none": 200, "agent": 200, "operator": 200}),
            ("POST", "/v3/operator/agents", {"agent_name": "x"}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/caps",
             {"agent_id": s_id, "per_hour_mc": 1_000_000}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/flags",
             {"agent_id": s_id, "no_bearer_withdrawal": False}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("GET", "/v3/agent/balance", None,
             {"agent": "", "operator": "?agent_id=" + a_id},
             {"none": 401, "agent": 200, "operator": 200}),
            ("POST", "/v3/agent/authorize_pull",
             {"payee_account": g_id, "cap_mc_per_day": 10, "expires_at": far}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/revoke_pull", {"auth_id": auth_rev}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/pull", {"auth_id": auth_pull, "amount_mc": 5}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/transfer", {"to_account": g_id, "amount_mc": 5}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/deposit", {"tokens": [deposit_token]}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/withdraw",
             {"outputs": [{"amount_mc": 5, "secret_hash": ledger_key(new_secret())}]},
             None, {"none": 401, "agent": 200, "operator": 403}),
            ("GET", "/v3/operator/statement", None,
             {"operator": "?agent_id=%s&from=0&to=%d" % (s_id, far),
              "agent": "?agent_id=%s&from=0&to=%d" % (s_id, far),
              "none": "?agent_id=%s&from=0&to=%d" % (s_id, far)},
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/freeze", {"agent_id": s_id}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/unfreeze", {"agent_id": s_id}, None,
             {"none": 401, "agent": 403, "operator": 200}),
        ]
        keys = {"none": None, "agent": a_key, "operator": op_key}
        for method, path, body, queries, expected in rows:
            # Wrong/absent credentials first so only the correct role mutates.
            for role in ("none", "agent", "operator"):
                want = expected[role]
                query = (queries or {}).get(role, "") if queries else ""
                with self.subTest(route=path, role=role):
                    status, resp = api(
                        m.port, method, path + query, body, key=keys[role]
                    )
                    self.assertEqual(status, want, (path, role, resp))
                    if want == 401:
                        self.assertEqual(resp, {"status": "unauthorized"})
                    elif want == 403:
                        self.assertEqual(resp, {"status": "forbidden"})

        # A garbage bearer key is 401 (unknown), not 403.
        status, resp = api(
            m.port, "POST", "/v3/agent/transfer",
            {"to_account": g_id, "amount_mc": 1}, key="not-a-real-key",
        )
        self.assertEqual(status, 401)

    # ------------------------------------------------------------------ #
    # B9 — L13 scope: Layer 0 stays authless and un-capped               #
    # ------------------------------------------------------------------ #

    def test_b9_bearer_layer0_unaffected_and_profile_advertised(self):
        """B9 (and requirement 8): on a Supervision mint, bearer-mode Layer 0
        calls by unregistered callers stay fully functional and un-capped
        even while agents carry tiny caps; the descriptor advertises the
        'supervision' profile."""
        m = self.start_mint()  # note: config passed WITHOUT the profile
        status, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertIn("supervision", desc["profiles"])

        # Register an agent and give it a 1 mc/hour cap: L13 says this must
        # not leak onto bearer callers.
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 1},
            key=op_key,
        )
        self.assertEqual(status, 200)

        # Unregistered bearer caller: repeated large exchanges, no auth
        # header, no caps, no burn under NO_BURN policy.
        secret = new_secret()
        token = self.issue_token(m, 50_000)
        for i in range(3):
            nxt = new_secret()
            status, r = api(
                m.port,
                "POST",
                "/v3/exchange",
                {
                    "idempotency_key": "bearer-%d" % i,
                    "inputs": [token],
                    "outputs": [{"amount_mc": 50_000, "secret_hash": ledger_key(nxt)}],
                },
            )
            self.assertEqual(status, 200, r)
            token = format_token(MINT_ID, 50_000, nxt)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(nxt))
        self.assertEqual(entry["result"]["state"], "unspent")

    # ------------------------------------------------------------------ #
    # requirement sweep: errors, scoping, invariant enforcement          #
    # ------------------------------------------------------------------ #

    def test_transfer_and_withdraw_errors(self):
        """Requirements 2/5/6: bad_format on malformed amounts, unknown
        target account, insufficient_balance on transfer and withdraw."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        b_id, b_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 50)

        self.assertRejected(self.transfer(m, a_key, "nobody", 10), "unknown_account")
        for bad in (0, -5, "x", 5.5, True, None):
            self.assertRejected(self.transfer(m, a_key, b_id, bad), "bad_format")
        self.assertRejected(self.transfer(m, a_key, b_id, 51), "insufficient_balance")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 50)

        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 51, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "insufficient_balance",
        )
        self.assertRejected(
            api(m.port, "POST", "/v3/agent/withdraw", {"outputs": []}, key=a_key),
            "bad_format",
        )
        # Withdrawals are by-hash ONLY: a by-secret output shape is refused.
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 5, "secret": b64u_encode(new_secret())}]},
                key=a_key,
            ),
            "bad_format",
        )
        # Pull authorization requires a custodial payee at this mint (§6.1(6)).
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/authorize_pull",
                {"payee_account": "nobody", "cap_mc_per_day": 10, "expires_at": T0 + DAY_MS},
                key=a_key,
            ),
            "unknown_account",
        )

    def test_statement_scoping_and_bad_params(self):
        """Requirement 7/1: an operator cannot obtain another operator's
        agent statement; malformed periods are rejected."""
        m = self.start_mint()
        op1_id, op1_key = self.new_operator(m, "op1")
        op2_id, op2_key = self.new_operator(m, "op2")
        a_id, a_key = self.new_agent(m, op1_key)

        status, _ = self.statement(m, op2_key, T0, T0 + DAY_MS, agent_id=a_id)
        self.assertEqual(status, 404)
        status, _ = api(
            m.port, "GET", "/v3/operator/statement?from=5", key=op1_key
        )
        self.assertEqual(status, 400)
        status, _ = api(
            m.port,
            "GET",
            "/v3/operator/statement?from=10&to=5&agent_id=" + a_id,
            key=op1_key,
        )
        self.assertEqual(status, 400)
        # Operators can read their own agents' balances; agents cannot read
        # each other's (auth separation, §6.1(1)/(5)).
        b_id, b_key = self.new_agent(m, op1_key, "b")
        r = self.balance(m, op1_key, agent_id=a_id)
        self.assertEqual(r["balance_mc"], 0)
        status, _ = api(
            m.port, "GET", "/v3/agent/balance?agent_id=" + a_id, key=b_key
        )
        self.assertEqual(status, 403)

    def test_statement_invariant_enforced_at_generation(self):
        """Requirement 7: the balance invariant is enforced when the
        statement is generated — a tampered stored balance makes the mint
        refuse (500) rather than sign a wrong statement."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)
        t_close = m.clock()
        m.clock.advance(1000)
        status, _ = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200)

        # Corrupt the stored balance behind the journal's back.
        conn = sqlite3.connect(m.db_path)
        conn.execute(
            "UPDATE sup_agents SET balance_mc = balance_mc + 1 WHERE agent_id = ?",
            (a_id,),
        )
        conn.commit()
        conn.close()
        status, body = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"status": "error"})

    def test_withdrawal_burn_counts_against_caps(self):
        """Requirement 2 + §7.3/R17: the withdrawal GROSS charged against
        caps is amount + compute_burn(amount) — the burn on the REQUESTED
        amount, never on the mint's internally selected custody inputs.
        Withdrawing 95 against a single 990 mc custody entry charges
        burn(95) = 0 (the superseded input-sum rule would have charged
        burn(990) = 9 and tripped the cap); the ledger still burns 9 on
        the actual input per L12 and mint custody absorbs the difference.
        Statement invariant and ledger supply invariant both still hold."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # burn 10 -> balance 990, ONE 990 custody entry
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        supply_before = m.ledger.supply()
        # burn(100) = 1: withdrawing 100 costs 100 + 1 = 101 > 100 — the
        # requested amount's OWN burn trips the cap, atomically (no ledger
        # or balance change).
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "agent_cap_exceeded",
        )
        self.assertEqual(m.ledger.supply(), supply_before)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 990)
        # burn(95) = 0: gross 95 <= 100 passes even though the only custody
        # input the mint can select is the 990 entry with burn(990) = 9 —
        # under the old input-sum rule this was gross 104 and failed.
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 95, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 95)
        self.assertEqual(r["burn_mc"], 0)  # compute_burn(95), NOT burn(990)
        self.assertEqual(r["balance_mc"], 895)  # charged exactly 95
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 895)
        # ...and the spend-rate shows the new gross (95 + 0).
        rate = self.balance(m, a_key)["spend_rate"]
        self.assertEqual(rate["trailing_hour_mc"], 95)
        self.assertEqual(rate["lifetime_mc"], 95)

        # Ledger supply invariant: the exchange still burned per L12 on its
        # actual 990 input (9), on top of the deposit's 10.
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_issued_mc"], 1000)
        self.assertEqual(supply["cumulative_burned_mc"], 19)
        self.assertEqual(supply["outstanding_mc"], 981)
        self.assertEqual(
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
            supply["outstanding_mc"],
        )
        # Mint custody absorbed ALL of the ledger-level burn (9 - 0):
        # unspent custody is 990 - 95 - 9 = 886 = balance - absorbed, and
        # outstanding = withdrawn bearer entry + custody.
        ((custody_sum,),) = self.sup_rows(
            m,
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_custody"
            " WHERE state = 'unspent'",
        )
        self.assertEqual(custody_sum, 886)
        ((absorbed,),) = self.sup_rows(m, "SELECT absorbed_mc FROM sup_mint")
        self.assertEqual(absorbed, 9)
        self.assertEqual(custody_sum, 895 - absorbed)
        self.assertEqual(supply["outstanding_mc"], 95 + custody_sum)

        # Statement invariant still holds: withdrawal line is the net 95,
        # and a zero agent-charged burn produces NO burn line.
        t_close = m.clock()
        m.clock.advance(1000)
        status, stmt = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 895)
        self.assertEqual(
            [(ln["kind"], ln["amount_mc"]) for ln in stmt["lines"]],
            [("deposit", 990), ("withdrawal", 95)],
        )

    # ------------------------------------------------------------------ #
    # self-transfer is refused (nets to zero, would eat cap headroom)    #
    # ------------------------------------------------------------------ #

    def test_self_transfer_rejected(self):
        """A transfer to the caller's own account is bad_format: nothing
        moves, no journal lines are written, no cap headroom is consumed."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 50},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertRejected(self.transfer(m, a_key, a_id, 10), "bad_format")
        r = self.balance(m, a_key)
        self.assertEqual(r["balance_mc"], 100)
        # No debit line landed: the full cap is still available.
        self.assertEqual(r["spend_rate"]["trailing_hour_mc"], 0)
        self.assertEqual(self.transfer(m, a_key, a_id, 50)[0], 400)
        # ...and a real transfer of the full headroom still succeeds.
        b_id, _ = self.new_agent(m, op_key, "b")
        self.assertEqual(self.transfer(m, a_key, b_id, 50)[0], 200)

    # ------------------------------------------------------------------ #
    # API keys are stored hashed (lookup by digest, no raw keys at rest) #
    # ------------------------------------------------------------------ #

    def test_api_keys_stored_hashed(self):
        """Raw operator/agent bearer keys never appear in the mint
        database — only sha256 digests are stored and looked up — while
        both keys keep authenticating normally."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        with open(m.db_path, "rb") as fh:
            db_bytes = fh.read()
        self.assertNotIn(op_key.encode("ascii"), db_bytes)
        self.assertNotIn(a_key.encode("ascii"), db_bytes)
        # Digest lookup still authenticates both roles...
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)
        self.assertEqual(self.balance(m, op_key, agent_id=a_id)["balance_mc"], 0)
        # ...and a garbage key is still just 401.
        status, _ = api(m.port, "GET", "/v3/agent/balance", key="nope")
        self.assertEqual(status, 401)

    # ------------------------------------------------------------------ #
    # §5.1/§5.3 persist-before-send on the custodial/ledger bridge       #
    # ------------------------------------------------------------------ #

    def spy_exchange(self, m):
        """Wrap ledger.exchange to snapshot the durable supervision state
        the moment the exchange is entered (i.e. what a crash during the
        exchange would leave on disk)."""
        real = m.ledger.exchange
        seen = {}

        def spy(idem, digest, inputs, input_amount_hint=None, outputs=None):
            seen["custody"] = self.sup_rows(
                m, "SELECT hash, secret_b64u, amount_mc, state"
                " FROM sup_custody ORDER BY hash"
            )
            seen["ops"] = self.sup_rows(
                m, "SELECT kind FROM sup_pending_ops"
            )
            seen["outputs"] = outputs
            return real(idem, digest, inputs, outputs=outputs)

        m.ledger.exchange = spy
        return seen

    def test_deposit_persists_custody_secret_before_exchange(self):
        """§5.1 mandatory ordering: the mint-custody secret is durable in
        sup_custody (state 'pending', with a staged op) BEFORE the C04
        exchange runs, and is activated afterwards."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)
        seen = self.spy_exchange(m)
        status, r = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        # At exchange time: exactly one custody row, pending, whose stored
        # secret hashes to the exchange's output hash.
        ((h, secret_b64u, amount, state),) = seen["custody"]
        self.assertEqual(state, "pending")
        self.assertEqual(amount, 990)
        self.assertEqual(
            ledger_key(b64u_decode(secret_b64u, expect_len=32)), h
        )
        self.assertEqual([o.secret_hash for o in seen["outputs"]], [h])
        self.assertEqual(seen["ops"], [("deposit",)])
        # Afterwards: activated, staged op cleared.
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("unspent",)]
        )
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])

    def test_withdraw_persists_change_secret_before_exchange(self):
        """§5.3 'no exceptions': the withdrawal's change secret is durable
        (pending) and the selected custody inputs reserved BEFORE the
        exchange runs."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # custody: one 990 entry
        seen = self.spy_exchange(m)
        w_hash = ledger_key(new_secret())
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": w_hash}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 1)  # burn(100) on the REQUESTED amount
        # At exchange time: the 990 input reserved, the 881 change pending
        # (990 - 100 - the ledger's L12 burn(990) = 9) with its secret
        # already durable, staged op present.
        by_state = {state: (h, s, a) for (h, s, a, state) in seen["custody"]}
        self.assertEqual(set(by_state), {"reserved", "pending"})
        self.assertEqual(by_state["reserved"][2], 990)
        ch, cs, ca = by_state["pending"]
        self.assertEqual(ca, 881)  # 990 - 100 - 9
        self.assertEqual(ledger_key(b64u_decode(cs, expect_len=32)), ch)
        self.assertEqual(
            sorted(o.secret_hash for o in seen["outputs"]),
            sorted([w_hash, ch]),
        )
        self.assertEqual(seen["ops"], [("withdraw",)])
        # Afterwards: input spent, change active, staged op cleared.
        self.assertEqual(
            self.sup_rows(
                m, "SELECT state FROM sup_custody ORDER BY state"
            ),
            [("spent",), ("unspent",)],
        )
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])

    def test_deposit_exchange_rejection_discards_staged_secret(self):
        """An ExchangeRejected deposit (already-spent token) cleans up its
        staged custody row and op in-process; nothing was credited."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)
        self.assertEqual(
            api(m.port, "POST", "/v3/agent/deposit", {"tokens": [token]},
                key=a_key)[0],
            200,
        )
        status, body = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["status"], "rejected")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 990)
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("unspent",)]
        )

    def test_deposit_crash_before_exchange_commit_rolls_back(self):
        """Crash while the deposit exchange is in flight and NOT committed:
        the staged secret is discarded at restart, the depositor's tokens
        were never spent, and the same deposit succeeds afterwards."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        secret = new_secret()
        status, _ = api(
            m.port,
            "POST",
            "/admin/issue",
            {"outputs": [{"amount_mc": 1000, "secret_hash": ledger_key(secret)}]},
        )
        self.assertEqual(status, 200)
        token = format_token(MINT_ID, 1000, secret)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before exchange commit")

        m.ledger.exchange = crash
        status, body = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 500)
        # Durable crash state: staged secret + op, no credit.
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("pending",)]
        )
        self.assertEqual(
            self.sup_rows(m, "SELECT kind FROM sup_pending_ops"),
            [("deposit",)],
        )
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)

        m2 = self.restart_mint(m)
        # Reconciliation rolled the op back; the token is still unspent.
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_custody"), [])
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 0)
        _, entry = api(m2.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        # Nothing was lost: the deposit simply retries.
        status, r = api(
            m2.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 990)

    def test_deposit_crash_after_exchange_commit_rolls_forward(self):
        """Crash AFTER the deposit exchange committed but before the
        supervision follow-up: the depositor's tokens are spent into a
        custody entry whose secret was already durable, so restart
        reconciliation credits the balance — no money is stranded."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before finalize")

        m.server.sup._finalize_deposit = crash
        status, _ = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 500)
        # The exchange DID commit: custody entry exists on the ledger...
        ((custody_hash,),) = self.sup_rows(
            m, "SELECT hash FROM sup_custody WHERE state = 'pending'"
        )
        _, entry = api(m.port, "GET", "/v3/status/" + custody_hash)
        self.assertEqual(entry["result"]["state"], "unspent")
        # ...but the balance was not yet credited.
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)

        m2 = self.restart_mint(m)
        # Rolled forward: credited, journaled, activated, staging cleared.
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 990)
        self.assertEqual(
            self.sup_rows(m2, "SELECT state FROM sup_custody"), [("unspent",)]
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 889)  # 990 - (100 + burn(100))

    def test_withdraw_crash_after_exchange_commit_rolls_forward(self):
        """Crash AFTER the withdrawal exchange committed but before the
        supervision follow-up: the caller already holds real bearer value;
        the reserved inputs are never re-selected (no retry wedge); restart
        reconciliation debits the gross and restores the invariant."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # balance 990, custody 990

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before finalize")

        m.server.sup._finalize_withdraw = crash
        w_secret = new_secret()
        status, _ = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(w_secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 500)
        # Persist-before-send held: the caller's bearer output EXISTS.
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(w_secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 100)
        # The consumed input stays reserved — a retry does NOT re-select
        # the ledger-spent rows and 400 on ExchangeRejected forever; it
        # sees no available custody instead.
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 50, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "insufficient_balance",
        )

        m2 = self.restart_mint(m)
        # Rolled forward: gross debited (100 + burn(100) = 101 — §7.3/R17),
        # change activated (881 = 990 - 100 - ledger burn 9).
        r = self.balance(m2, a_key)
        self.assertEqual(r["balance_mc"], 889)
        self.assertEqual(r["spend_rate"]["lifetime_mc"], 101)
        self.assertEqual(
            self.sup_rows(
                m2,
                "SELECT amount_mc FROM sup_custody WHERE state = 'unspent'",
            ),
            [(881,)],
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        # Custody again equals balance minus the mint-absorbed burn (8);
        # further withdrawals work.
        self.assertEqual(
            self.sup_rows(m2, "SELECT absorbed_mc FROM sup_mint"), [(8,)]
        )
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 50, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 0)  # burn(50), not burn(881)
        self.assertEqual(r["balance_mc"], 839)

    def test_withdraw_crash_before_exchange_commit_rolls_back(self):
        """Crash while the withdrawal exchange is in flight and NOT
        committed: restart releases the reserved inputs, discards the
        staged change secret, and the withdrawal simply retries."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before exchange commit")

        m.ledger.exchange = crash
        status, _ = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 500)
        self.assertEqual(
            self.sup_rows(
                m, "SELECT state FROM sup_custody ORDER BY state"
            ),
            [("pending",), ("reserved",)],
        )

        m2 = self.restart_mint(m)
        self.assertEqual(
            self.sup_rows(m2, "SELECT amount_mc, state FROM sup_custody"),
            [(990, "unspent")],
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 990)
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 889)  # 990 - (100 + burn(100))

    # ------------------------------------------------------------------ #
    # Freeze response field name (pre-1.0 wire fix)                      #
    # ------------------------------------------------------------------ #

    def test_freeze_response_field_named_frozen(self):
        """The freeze/unfreeze responses list affected agents under
        'frozen'/'unfrozen' (pre-1.0 wire fix: the field was originally
        misspelled 'freezed'/'unfreezed'). Exact body shape pinned; the
        §6.1(7) journal *kinds* stay 'freeze'/'unfreeze'."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, _a_key = self.new_agent(m, op_key, "a")

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "frozen": [a_id]})
        self.assertNotIn("freezed", r)

        # Idempotent re-freeze: still 'frozen', now empty (no change).
        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "frozen": []})

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "unfrozen": [a_id]})
        self.assertNotIn("unfreezed", r)

        # Journal kinds are unchanged by the wire rename.
        kinds = [
            row[0]
            for row in self.sup_rows(
                m,
                "SELECT kind FROM sup_lines WHERE agent_id = ? ORDER BY seq",
                (a_id,),
            )
        ]
        self.assertEqual(kinds, ["freeze", "unfreeze"])


if __name__ == "__main__":
    unittest.main()
