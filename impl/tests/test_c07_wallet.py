"""C07 — wallet tests: the bearer client against a live in-process C06 mint.

Every test runs a real MintServer over real HTTP.  Benchmark items B1–B8
from components/C07-wallet.md are named in each test's docstring.  All
mint time comes from a FakeClock injected through the Ledger (L17); the
wallet itself never needs a clock.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from typing import NamedTuple

from aicash.burncalc import BurnPolicy
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger, OutputSpec
from aicash.mintapi import MintConfig, MintServer
from aicash.tokencodec import b64u_encode, format_token, ledger_key, new_secret
from aicash.wallet import (
    InsufficientFunds,
    MintClient,
    MintUnavailable,
    PaymentInvalid,
    Wallet,
)

T0 = 1_756_000_000_000
DAY_MS = 86_400_000
MINT_ID = "testmint"

#: 1% rate, cap 1000, exempt <= 10 — makes burns visible in arithmetic.
POLICY = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)
#: The B5 policy: rate_ppm=1000 with a high exemption so the prescribed
#: held set can be seeded by burn-free receives.
POLICY_B5 = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=1_000)


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    config: MintConfig
    ledger: Ledger


# ---------------------------------------------------------------------------
# instrumented clients
# ---------------------------------------------------------------------------


class RecordingClient(MintClient):
    """Records (method, path) for every request and an ("http_send", key)
    event for every /v3/exchange body that actually goes on the wire."""

    def __init__(self, base_url, events=None):
        super().__init__(base_url)
        self.requests = []  # (method, path)
        self.events = events if events is not None else []

    def _transport(self, method, path, body):
        self.requests.append((method, path))
        if path == "/v3/exchange" and body is not None:
            key = json.loads(body.decode("utf-8"))["idempotency_key"]
            self.events.append(("http_send", key))
        return super()._transport(method, path, body)


class RaiseBeforeSendClient(MintClient):
    """/v3/exchange raises WITHOUT delivering; everything else works."""

    def _transport(self, method, path, body):
        if path == "/v3/exchange":
            raise OSError("simulated network failure before send")
        return super()._transport(method, path, body)


class DeliverThenRaiseClient(MintClient):
    """Every /v3/exchange is DELIVERED to the mint, then the response is
    dropped (simulated crash-after-send-before-response)."""

    def _transport(self, method, path, body):
        if path == "/v3/exchange":
            super()._transport(method, path, body)  # mint commits
            raise TimeoutError("simulated response loss")
        return super()._transport(method, path, body)


class DropFirstResponseClient(MintClient):
    """First /v3/exchange delivers but its response is dropped; retries
    pass through.  Records the exact bytes of every exchange body."""

    def __init__(self, base_url):
        super().__init__(base_url)
        self.exchange_bodies = []
        self._dropped = False

    def _transport(self, method, path, body):
        if path == "/v3/exchange":
            self.exchange_bodies.append(body)
            if not self._dropped:
                self._dropped = True
                super()._transport(method, path, body)  # mint commits
                raise TimeoutError("simulated timeout: response dropped")
        return super()._transport(method, path, body)


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------


class WalletTest(unittest.TestCase):
    maxDiff = None

    def start_mint(
        self,
        *,
        burn_policy=POLICY,
        burn_policy_next=None,
        admin_token=None,
    ) -> Mint:
        from aicash.signing import generate_keypair

        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            clock,
            burn_policy,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=burn_policy,
            burn_policy_next=burn_policy_next,
            admin_token=admin_token,
            signing_private=priv,
            signing_public=pub,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, config, ledger)

    def base_url(self, mint: Mint) -> str:
        return f"http://127.0.0.1:{mint.port}"

    def make_wallet(self, mint: Mint, client=None) -> Wallet:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        client = client or MintClient(self.base_url(mint))
        return Wallet(os.path.join(tmp.name, "wallet.sqlite3"), client, MINT_ID)

    def issue_token(self, mint: Mint, amount_mc: int) -> str:
        """Operator funding (§7.1): put `amount_mc` on the ledger and hand
        back the bearer token string, as a payer would."""
        secret = new_secret()
        mint.ledger.issue(
            [OutputSpec(amount_mc=amount_mc, secret_hash=ledger_key(secret))]
        )
        return format_token(MINT_ID, amount_mc, secret)

    def held_multiset(self, wallet: Wallet) -> dict:
        """{amount_mc: count} of confirmed (held) coins, read from disk."""
        db = sqlite3.connect(wallet._store_path)
        try:
            rows = db.execute(
                "SELECT amount_mc, COUNT(*) FROM wallet_tokens"
                " WHERE state = 'confirmed' GROUP BY amount_mc"
            ).fetchall()
        finally:
            db.close()
        return dict(rows)

    def store_states(self, wallet: Wallet) -> dict:
        db = sqlite3.connect(wallet._store_path)
        try:
            rows = db.execute(
                "SELECT state, COUNT(*) FROM wallet_tokens GROUP BY state"
            ).fetchall()
        finally:
            db.close()
        return dict(rows)

    def descriptor(self, mint: Mint) -> dict:
        return MintClient(self.base_url(mint)).descriptor()

    # ------------------------------------------------------------------
    # B1
    # ------------------------------------------------------------------

    def test_b1_happy_path_reconciles(self):
        """B1: issue -> receive -> pay -> counterparty receives; balances
        and mint supply reconcile to the mc with the burn accounted."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        b = self.make_wallet(mint)

        token = self.issue_token(mint, 5_000)
        net_a = a.receive(token)
        self.assertEqual(net_a, 4_950)  # burn 50 = 1% of 5000
        self.assertEqual(a.balance(), 4_950)

        paid = a.pay(1_000)
        self.assertEqual(sum(int(t.split(":")[3]) for t in paid), 1_000)
        # selection 1000+10, burn 10, change 0
        self.assertEqual(a.balance(), 3_940)

        net_b = 0
        for t in paid:
            net_b += b.receive(t)
        self.assertEqual(net_b, 990)  # 1000 - 10 burn on re-exchange
        self.assertEqual(b.balance(), 990)

        supply = self.descriptor(mint)["supply"]
        self.assertEqual(supply["cumulative_issued_mc"], 5_000)
        self.assertEqual(supply["cumulative_burned_mc"], 70)  # 50 + 10 + 10
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )
        self.assertEqual(supply["outstanding_mc"], a.balance() + b.balance())

    # ------------------------------------------------------------------
    # B2
    # ------------------------------------------------------------------

    def test_b2_persist_before_send_ordering(self):
        """B2: record (persist_fsync, http_send) event order over 20 pays;
        every exchange send strictly follows the persistence of the
        outputs it references (correlated by idempotency key)."""
        mint = self.start_mint()
        events = []
        client = RecordingClient(self.base_url(mint), events)
        a = self.make_wallet(mint, client)
        a.event_hook = lambda kind, op: events.append((kind, op))

        a.receive(self.issue_token(mint, 10_000))
        for _ in range(20):
            a.pay(20)

        sends = [
            (i, op) for i, (k, op) in enumerate(events) if k == "http_send"
        ]
        self.assertGreaterEqual(len(sends), 21)  # 1 receive + 20 pays
        for i, op in sends:
            persist_idx = [
                j
                for j, (k, o) in enumerate(events)
                if k == "persist_fsync" and o == op
            ]
            self.assertTrue(
                persist_idx and persist_idx[0] < i,
                f"send of op {op} at event {i} not preceded by its"
                f" persist_fsync",
            )

    def test_b2_transport_raises_before_send_zero_loss(self):
        """B2: a transport that RAISES before sending leaves the wallet
        recoverable with zero loss."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        a.receive(self.issue_token(mint, 5_000))
        self.assertEqual(a.balance(), 4_950)

        a.client = RaiseBeforeSendClient(self.base_url(mint))
        with self.assertRaises(MintUnavailable):
            a.pay(1_000)

        a.client = MintClient(self.base_url(mint))
        summary = a.recover()
        self.assertEqual(summary["ops_orphaned"], 1)
        self.assertEqual(summary["inputs_restored"], 2)  # 1000 + 10 coins
        self.assertEqual(a.balance(), 4_950)  # zero loss
        self.assertEqual(self.store_states(a).get("pending", 0), 0)

    # ------------------------------------------------------------------
    # B3
    # ------------------------------------------------------------------

    def test_b3_crash_after_send_before_response(self):
        """B3: transport delivers to the mint but the response is dropped
        and process state is discarded; a wallet reloaded from disk finds
        the confirmed outputs via /v3/status — no loss, no double-count."""
        mint = self.start_mint()
        a = self.make_wallet(mint, DeliverThenRaiseClient(self.base_url(mint)))
        # fund through an honest client first
        a.client = MintClient(self.base_url(mint))
        a.receive(self.issue_token(mint, 5_000))
        a.client = DeliverThenRaiseClient(self.base_url(mint))

        with self.assertRaises(MintUnavailable):
            a.pay(1_000)

        # "process state discarded": reload purely from the disk store
        a2 = Wallet(a._store_path, MintClient(self.base_url(mint)), MINT_ID)
        summary = a2.recover()
        self.assertEqual(summary["ops_confirmed"], 1)
        self.assertEqual(summary["outputs_confirmed"], 1)  # the 1000 output
        # exchange committed at the mint: burn 10 paid, payment output
        # reclaimed as held (pay() never returned its token strings)
        self.assertEqual(a2.balance(), 4_940)
        # no double-count: recovery is idempotent
        summary2 = a2.recover()
        self.assertEqual(summary2["ops_resolved"], 0)
        self.assertEqual(a2.balance(), 4_940)

    def test_b3_crash_before_send(self):
        """B3 (inverse): crash before the request ever reached the mint —
        recover() marks the outputs orphan and restores the inputs per the
        stored plan."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        a.receive(self.issue_token(mint, 5_000))
        a.client = RaiseBeforeSendClient(self.base_url(mint))
        with self.assertRaises(MintUnavailable):
            a.pay(1_000)

        a2 = Wallet(a._store_path, MintClient(self.base_url(mint)), MINT_ID)
        summary = a2.recover()
        self.assertEqual(summary["ops_orphaned"], 1)
        self.assertEqual(summary["inputs_restored"], 2)
        self.assertEqual(summary["inputs_lost"], 0)
        self.assertEqual(a2.balance(), 4_950)  # zero loss
        states = self.store_states(a2)
        self.assertEqual(states.get("pending", 0), 0)
        self.assertGreaterEqual(states.get("orphan", 0), 1)

    # ------------------------------------------------------------------
    # B4
    # ------------------------------------------------------------------

    def test_b4_received_token_double_spend(self):
        """B4: the same token string handed to two wallets — exactly one
        receive() succeeds; the other raises PaymentInvalid(spent)."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        b = self.make_wallet(mint)
        token = self.issue_token(mint, 500)

        self.assertEqual(a.receive(token), 495)  # burn 5
        with self.assertRaises(PaymentInvalid) as ctx:
            b.receive(token)
        self.assertIn("spent", ctx.exception.reasons)
        self.assertEqual(b.balance(), 0)
        self.assertEqual(a.balance(), 495)

    def test_b4_unknown_token(self):
        """B4/§3.8: a token the ledger never saw raises
        PaymentInvalid(unknown)."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        bogus = format_token(MINT_ID, 100, new_secret())
        with self.assertRaises(PaymentInvalid) as ctx:
            a.receive(bogus)
        self.assertIn("unknown", ctx.exception.reasons)

    # ------------------------------------------------------------------
    # B5
    # ------------------------------------------------------------------

    def seed_b5_wallet(self, mint: Mint) -> Wallet:
        """Seed exactly {1×1000, 5×100, 10×10, 10×1} via burn-free
        receives (POLICY_B5 exempts sums <= 1000)."""
        w = self.make_wallet(mint)
        for amount, count in ((1_000, 1), (100, 5), (10, 10), (1, 10)):
            for _ in range(count):
                self.assertEqual(w.receive(self.issue_token(mint, amount)), amount)
        self.assertEqual(
            self.held_multiset(w), {1_000: 1, 100: 5, 10: 10, 1: 10}
        )
        return w

    def test_b5_coin_selection(self):
        """B5: with held {1×1000, 5×100, 10×10, 10×1}, pay(237) at
        rate_ppm=1000 selects 2×100+3×10+7×1 (burn floor(0.237)=0, no
        change), payment outputs are ladder-decomposed; a follow-up pay
        with overshoot produces ladder-decomposed change."""
        mint = self.start_mint(burn_policy=POLICY_B5)
        w = self.seed_b5_wallet(mint)

        paid = w.pay(237)
        amounts = sorted(int(t.split(":")[3]) for t in paid)
        self.assertEqual(amounts, [1] * 7 + [10] * 3 + [100] * 2)
        self.assertEqual(w.balance(), 1_373)
        # exact-cover selection: no change, held set shrank by the inputs
        self.assertEqual(
            self.held_multiset(w), {1_000: 1, 100: 3, 10: 7, 1: 3}
        )

        # Second pay overshoots (275 needs 2 more than the small coins
        # cover), pulling in a 100: change 98 comes back ladder-decomposed.
        paid2 = w.pay(275)
        self.assertEqual(
            sorted(int(t.split(":")[3]) for t in paid2),
            [1] * 5 + [10] * 7 + [100] * 2,
        )
        self.assertEqual(w.balance(), 1_098)  # 1373 - 275, burn 0
        self.assertEqual(self.held_multiset(w), {1_000: 1, 10: 9, 1: 8})

    def test_b5_fragmentation_bound(self):
        """B5: repeated pays don't fragment unboundedly — the wallet's
        consolidation sweep keeps every rung below the top at no more than
        2*(base-1) = 18 held coins after each pay."""
        mint = self.start_mint()
        w = self.make_wallet(mint)
        w.receive(self.issue_token(mint, 20_000))  # net 19_800

        top = max(self.descriptor(mint)["denominations_mc"])
        amounts = [137, 23, 999, 41, 5, 260, 78, 1234, 9, 55] * 2
        for x in amounts:
            w.pay(x)  # value leaves the wallet (tokens discarded)
            held = self.held_multiset(w)
            for amount, count in held.items():
                if amount < top:
                    self.assertLessEqual(
                        count,
                        18,
                        f"rung {amount} fragmented to {count} coins",
                    )

    # ------------------------------------------------------------------
    # B6
    # ------------------------------------------------------------------

    def test_b6_handle_refused(self):
        """B6: after a payee refuses, re-exchange makes the old strings
        dead — a later redeem attempt fails with `spent`."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        payee = self.make_wallet(mint)
        a.receive(self.issue_token(mint, 5_000))

        paid = a.pay(300)  # 3×100; inputs 310, burn 3, change 7
        self.assertEqual(a.balance(), 4_647)

        result = a.handle_refused(paid)
        self.assertEqual(result, {"recovered_mc": 297, "dead": []})  # burn 3
        self.assertEqual(a.balance(), 4_944)

        # every refused string is now dead at the mint
        for t in paid:
            with self.assertRaises(PaymentInvalid) as ctx:
                payee.receive(t)
            self.assertIn("spent", ctx.exception.reasons)

    def test_b6_handle_refused_partial_redeemed(self):
        """B6: a token the payee redeemed anyway is dropped as dead loss;
        the remaining refused strings are still retired."""
        mint = self.start_mint()
        a = self.make_wallet(mint)
        payee = self.make_wallet(mint)
        a.receive(self.issue_token(mint, 5_000))
        paid = a.pay(300)

        payee.receive(paid[0])  # the payee lied: it redeemed one token
        result = a.handle_refused(paid)
        self.assertEqual(result["dead"], [0])
        self.assertEqual(result["recovered_mc"], 198)  # 200 - burn 2
        self.assertEqual(a.balance(), 4_647 + 198)

        with self.assertRaises(PaymentInvalid) as ctx:
            payee.receive(paid[1])
        self.assertIn("spent", ctx.exception.reasons)

    # ------------------------------------------------------------------
    # B7
    # ------------------------------------------------------------------

    def test_b7_receive_first_fresh_wallet(self):
        """B7: a zero-config, zero-balance wallet receives its first token
        with no auth and no registration — the only HTTP calls are the
        descriptor read and the exchange itself (§7.2)."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        w = self.make_wallet(mint, client)
        self.assertEqual(w.balance(), 0)

        self.assertEqual(w.receive(self.issue_token(mint, 50)), 50)
        self.assertEqual(w.balance(), 50)

        self.assertEqual(
            set(client.requests),
            {("GET", "/v3/mints"), ("POST", "/v3/exchange")},
        )
        # no registration/auth surface exists on the wallet at all
        for name in ("register", "login", "authenticate"):
            self.assertFalse(hasattr(w, name))

    # ------------------------------------------------------------------
    # B8
    # ------------------------------------------------------------------

    def test_b8_idempotent_retry(self):
        """B8: a forced timeout-then-retry of one pay produces no
        double-spend and no duplicate outputs — the retry reuses the same
        idempotency key and identical bytes, and the mint's supply shows
        the burn assessed exactly once."""
        mint = self.start_mint()
        client = DropFirstResponseClient(self.base_url(mint))
        a = self.make_wallet(mint)
        a.receive(self.issue_token(mint, 5_000))
        a.client = client

        paid = a.pay(1_000)
        self.assertEqual(sum(int(t.split(":")[3]) for t in paid), 1_000)
        self.assertEqual(a.balance(), 3_940)  # debited exactly once

        # the wire saw the request twice: same key, byte-identical bodies
        self.assertEqual(len(client.exchange_bodies), 2)
        self.assertEqual(client.exchange_bodies[0], client.exchange_bodies[1])
        key0 = json.loads(client.exchange_bodies[0])["idempotency_key"]
        key1 = json.loads(client.exchange_bodies[1])["idempotency_key"]
        self.assertEqual(key0, key1)

        # effect at the mint happened once: burn 10 (not 20) on the pay
        supply = self.descriptor(mint)["supply"]
        self.assertEqual(supply["cumulative_burned_mc"], 60)  # 50 + 10
        # and the payment output is redeemable exactly once
        b = self.make_wallet(mint)
        self.assertEqual(b.receive(paid[0]), 990)

    # ------------------------------------------------------------------
    # B9
    # ------------------------------------------------------------------

    def test_b9_pay_many_single_exchange(self):
        """B9: pay_many to 20 recipients runs exactly ONE /v3/exchange
        (asserted via the _transport seam), each recipient's token list
        sums to its amount and is receivable, and one burn is assessed on
        the call's input sum — never per recipient."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        a = self.make_wallet(mint, client)
        a.receive(self.issue_token(mint, 10_000))  # net 9_900, burn 100

        amounts = list(range(1, 21))  # 210 mc total
        before = client.requests.count(("POST", "/v3/exchange"))
        groups = a.pay_many(amounts)
        self.assertEqual(
            client.requests.count(("POST", "/v3/exchange")) - before, 1
        )
        self.assertEqual(len(groups), 20)
        for amount, tokens in zip(amounts, groups):
            self.assertEqual(
                sum(int(t.split(":")[3]) for t in tokens), amount
            )
        # selection 3×100 = 300 inputs, burn 3 on the input sum, change 87
        self.assertEqual(a.balance(), 9_900 - 210 - 3)
        supply = self.descriptor(mint)["supply"]
        self.assertEqual(supply["cumulative_burned_mc"], 100 + 3)
        self.assertEqual(self.store_states(a).get("pending", 0), 0)
        # every recipient can redeem its group
        for amount, tokens in zip(amounts, groups):
            b = self.make_wallet(mint)
            got = b.receive_batch(tokens)
            self.assertEqual(got["dead"], [])
            self.assertEqual(got["credited_mc"], amount)  # 1% floors to 0
            self.assertEqual(b.balance(), amount)

    def test_b9_pay_many_max_batch_guard(self):
        """B9: a fan-out whose inputs+outputs would exceed the mint's
        limits.max_batch raises ValueError naming max_batch BEFORE
        anything is persisted or sent — the caller must chunk."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        w = self.make_wallet(mint, client)
        w.receive(self.issue_token(mint, 1_000))  # net 990
        before = client.requests.count(("POST", "/v3/exchange"))
        with self.assertRaises(ValueError) as ctx:
            w.pay_many([9] * 30)  # 270 payment outputs of 1 mc each
        self.assertIn("max_batch", str(ctx.exception))
        self.assertEqual(
            client.requests.count(("POST", "/v3/exchange")), before
        )
        self.assertEqual(w.balance(), 990)
        self.assertEqual(self.store_states(w).get("pending", 0), 0)
        # argument validation mirrors pay
        for bad in ([], [0], [10, -1], [10, "5"], [True], "10"):
            with self.assertRaises((ValueError, TypeError)):
                w.pay_many(bad)

    # ------------------------------------------------------------------
    # B10
    # ------------------------------------------------------------------

    def test_b10_receive_batch_one_burn_with_spent(self):
        """B10 (§9.2): batch-redeem 10 received tokens with one already
        spent — dead enumerates {index, reason}, the other nine are
        credited under ONE burn equal to the final successful call's
        input-sum burn, and exactly two exchange calls hit the wire (the
        enumerated rejection, then the retry under a FRESH idempotency
        key)."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        seller = self.make_wallet(mint, client)
        thief = self.make_wallet(mint)

        tokens = [self.issue_token(mint, 100) for _ in range(10)]
        thief.receive(tokens[3])  # double-spent before the batch (burn 1)

        burned_before = self.descriptor(mint)["supply"]["cumulative_burned_mc"]
        calls_before = client.requests.count(("POST", "/v3/exchange"))
        result = seller.receive_batch(tokens)
        self.assertEqual(
            client.requests.count(("POST", "/v3/exchange")) - calls_before,
            2,  # first call rejected with enumerated indices, then retry
        )
        self.assertEqual(result["dead"], [{"index": 3, "reason": "spent"}])
        self.assertEqual(result["credited_mc"], 891)  # 900 - burn 9
        self.assertEqual(seller.balance(), 891)

        # ONE burn, assessed on the retry's input sum (900 mc → 9 mc at
        # 1%): never per token, and nothing for the rejected attempt
        burned_after = self.descriptor(mint)["supply"]["cumulative_burned_mc"]
        self.assertEqual(burned_after - burned_before, 9)

        # the retry used a FRESH idempotency key (the §3.3 body changed)
        keys = [k for kind, k in client.events if kind == "http_send"]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])

    def test_b10_receive_batch_local_bad_and_empty(self):
        """B10: malformed and foreign-mint strings die locally as
        bad_format with no exchange on the wire; an empty good set
        credits 0."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        w = self.make_wallet(mint, client)
        result = w.receive_batch(
            ["not-a-token", format_token("othermint", 100, new_secret())]
        )
        self.assertEqual(result["credited_mc"], 0)
        self.assertEqual(
            result["dead"],
            [
                {"index": 0, "reason": "bad_format"},
                {"index": 1, "reason": "bad_format"},
            ],
        )
        self.assertNotIn(("POST", "/v3/exchange"), client.requests)
        self.assertEqual(w.balance(), 0)
        self.assertEqual(w.receive_batch([]), {"credited_mc": 0, "dead": []})

    # ------------------------------------------------------------------
    # B11
    # ------------------------------------------------------------------

    def test_b11_quote_matches_pay(self):
        """B11: quote(X) is a read-only dry-run of pay(X)'s selection —
        the subsequent pay debits exactly X + quoted burn, the mint
        assesses exactly the quoted burn (a function of the call's input
        SUM, not of X — here 12 on 1250 mc of inputs for a 1234 mc pay),
        and quote itself leaves no trace in the store."""
        mint = self.start_mint()
        w = self.make_wallet(mint)
        w.receive(self.issue_token(mint, 5_000))  # net 4950: 4×1000+9×100+5×10

        q = w.quote(1_234)
        self.assertEqual(q, {"burn_mc": 12, "change_mc": 4, "inputs_mc": 1_250})
        self.assertEqual(q["inputs_mc"], 1_234 + q["burn_mc"] + q["change_mc"])
        # read-only: balance unchanged, nothing planned or pending
        self.assertEqual(w.balance(), 4_950)
        self.assertEqual(self.store_states(w).get("pending", 0), 0)

        burned_before = self.descriptor(mint)["supply"]["cumulative_burned_mc"]
        paid = w.pay(1_234)
        self.assertEqual(sum(int(t.split(":")[3]) for t in paid), 1_234)
        self.assertEqual(w.balance(), 4_950 - 1_234 - q["burn_mc"])
        burned_after = self.descriptor(mint)["supply"]["cumulative_burned_mc"]
        self.assertEqual(burned_after - burned_before, q["burn_mc"])

    def test_b11_quote_tracks_burn_policy_next(self):
        """B11: quote uses the descriptor's EFFECTIVE policy — once the
        MINT's own mint_time passes burn_policy_next.effective_at, the
        quoted burn follows the announced policy (the wallet never reads
        wall time — L17)."""
        nxt = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
        mint = self.start_mint(burn_policy_next=(nxt, T0 + DAY_MS))
        w = self.make_wallet(mint)
        w.receive(self.issue_token(mint, 5_000))

        q1 = w.quote(1_000)
        self.assertEqual(q1["burn_mc"], 10)  # 1% of the 1010 mc input sum
        mint.clock.advance(2 * DAY_MS)  # announced policy now in force
        q2 = w.quote(1_000)
        self.assertEqual(q2["burn_mc"], 5)  # 0.5% of the 1010 mc input sum

    # ------------------------------------------------------------------
    # B12
    # ------------------------------------------------------------------

    def test_b12_connect_round_trip(self):
        """B12 (§7.2): Wallet.connect(store_path, base_url) needs only the
        URL — it fetches the descriptor, binds to its mint_id, and the
        wallet can receive immediately (zero-config entry point);
        reconnecting the same store finds the money still there."""
        mint = self.start_mint()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "wallet.sqlite3")

        w = Wallet.connect(path, self.base_url(mint))
        self.assertEqual(w.mint_id, MINT_ID)
        self.assertIsInstance(w.client, MintClient)
        self.assertEqual(w.balance(), 0)
        self.assertEqual(w.receive(self.issue_token(mint, 500)), 495)

        w2 = Wallet.connect(path, self.base_url(mint))
        self.assertEqual(w2.mint_id, MINT_ID)
        self.assertEqual(w2.balance(), 495)

    # ------------------------------------------------------------------
    # B13
    # ------------------------------------------------------------------

    def test_b13_admin_issue_funds_end_to_end(self):
        """B13 (§7.1): MintClient.admin_issue puts operator-funded outputs
        on the ledger (X-Admin-Token gated, both §3.3 output forms); the
        funded tokens are then received end-to-end. A wrong or missing
        admin token is refused and issues nothing."""
        mint = self.start_mint(admin_token="op-secret")
        client = MintClient(self.base_url(mint))

        denied = new_secret()
        for bad_kwargs in ({}, {"admin_token": "wrong"}):
            with self.assertRaises(MintUnavailable):
                client.admin_issue(
                    [{"amount_mc": 100, "secret_hash": ledger_key(denied)}],
                    **bad_kwargs,
                )
        self.assertEqual(
            self.descriptor(mint)["supply"]["cumulative_issued_mc"], 0
        )

        s_hash, s_sec = new_secret(), new_secret()
        result = client.admin_issue(
            [
                {"amount_mc": 500, "secret_hash": ledger_key(s_hash), "lock": None},
                {"amount_mc": 300, "secret": b64u_encode(s_sec)},
            ],
            admin_token="op-secret",
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["outputs_confirmed"], 2)
        supply = self.descriptor(mint)["supply"]
        self.assertEqual(supply["cumulative_issued_mc"], 800)

        w = self.make_wallet(mint)
        got = w.receive_batch(
            [
                format_token(MINT_ID, 500, s_hash),
                format_token(MINT_ID, 300, s_sec),
            ]
        )
        self.assertEqual(got, {"credited_mc": 792, "dead": []})  # burn 8
        self.assertEqual(w.balance(), 792)

    # ------------------------------------------------------------------
    # guards and edges
    # ------------------------------------------------------------------

    def test_structural_guard_blocks_unpersisted_send(self):
        """B2 (structural rule): the only path to exchange refuses to send
        when the referenced outputs were never durably persisted."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        w = self.make_wallet(mint, client)
        body = {
            "idempotency_key": "never-persisted",
            "inputs": [self.issue_token(mint, 100)],
            "outputs": [
                {
                    "amount_mc": 100,
                    "secret_hash": ledger_key(new_secret()),
                    "lock": None,
                }
            ],
        }
        with self.assertRaises(RuntimeError):
            w._send_exchange("never-persisted", body)
        self.assertNotIn(("http_send", "never-persisted"), client.events)
        self.assertNotIn(("POST", "/v3/exchange"), client.requests)

    def test_receive_rejects_malformed_and_foreign(self):
        """Req 4: malformed strings and foreign-mint tokens raise
        PaymentInvalid(bad_format) without any exchange attempt."""
        mint = self.start_mint()
        w = self.make_wallet(mint)
        with self.assertRaises(PaymentInvalid) as ctx:
            w.receive("definitely-not-a-token")
        self.assertIn("bad_format", ctx.exception.reasons)
        with self.assertRaises(PaymentInvalid) as ctx:
            w.receive(format_token("othermint", 100, new_secret()))
        self.assertIn("bad_format", ctx.exception.reasons)
        self.assertEqual(w.balance(), 0)

    def test_received_string_never_stored_as_held(self):
        """Req 4: the received token's own secret never appears in the
        store as held value — only its freshly generated replacements."""
        mint = self.start_mint()
        w = self.make_wallet(mint)
        token = self.issue_token(mint, 500)
        secret_b64u = token.split(":")[4]
        w.receive(token)
        db = sqlite3.connect(w._store_path)
        try:
            row = db.execute(
                "SELECT COUNT(*) FROM wallet_tokens WHERE secret = ?",
                (secret_b64u,),
            ).fetchone()
        finally:
            db.close()
        self.assertEqual(row[0], 0)
        self.assertEqual(w.balance(), 495)

    def test_insufficient_funds(self):
        """Coin selection refuses cleanly when amount + burn exceeds the
        held balance, leaving the store untouched."""
        mint = self.start_mint()
        w = self.make_wallet(mint)
        w.receive(self.issue_token(mint, 50))
        with self.assertRaises(InsufficientFunds):
            w.pay(10_000)
        self.assertEqual(w.balance(), 50)
        self.assertEqual(self.store_states(w).get("pending", 0), 0)

    def test_pay_rejects_bad_amounts(self):
        mint = self.start_mint()
        w = self.make_wallet(mint)
        for bad in (0, -5, True, 1.5, "10"):
            with self.assertRaises((ValueError, TypeError)):
                w.pay(bad)


if __name__ == "__main__":
    unittest.main()
