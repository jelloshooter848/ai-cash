"""C11 — swap tests: cross-mint atomic swaps against two live in-process
C06 mints, each with its own injected FakeClock (L17).

Benchmark items B1–B6 from components/C11-swap.md are named in each test's
docstring.  All mint time comes from the two FakeClocks; the swap code
never reads wall time.  The poller is a virtual callback that advances
those clocks — there is no sleeping and no real polling.

Two independent Ledger instances (two sqlite files) with different burn
policies model the two mints; neither ledger knows the other exists.  The
same 32-byte preimage ``x`` is valid at both because §3.4's lock
parameters are pinned (B6).
"""

import hashlib
import inspect
import os
import sqlite3
import tempfile
import unittest
import uuid
from typing import NamedTuple

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger, OutputSpec
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import generate_keypair
from aicash.swap import (
    DEFAULT_LATENCY_FLOOR_MS,
    LATENCY_SAFETY_FACTOR,
    QuoteRefused,
    SwapError,
    SwapParty,
    SwapResult,
    compute_margin,
    run_swap,
)
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    new_secret,
    parse_token,
)
from aicash.wallet import MintClient, MintRejected, Wallet

T0 = 1_756_000_000_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000

MINT1_ID = "mint-one"
MINT2_ID = "mint-two"

#: Mint 1: 1% rate, cap 1000, exempt <= 10.
POLICY1 = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)
#: Mint 2: 0.5% rate, cap 500, exempt <= 20 — a DIFFERENT burn policy (B1).
POLICY2 = BurnPolicy(rate_ppm=5_000, cap_mc=500, exempt_below_mc=20)


class Mint(NamedTuple):
    mint_id: str
    port: int
    clock: FakeClock
    config: MintConfig
    ledger: Ledger


class SwapTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------
    # fixture: two independent mints
    # ------------------------------------------------------------------

    def start_mint(
        self,
        mint_id: str,
        policy: BurnPolicy,
        *,
        grace_ms: int = 5_000,
        max_batch: int = 256,
        recovery_window_ms: int = 90 * DAY_MS,
    ) -> Mint:
        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            clock,
            policy,
            recovery_window_ms=recovery_window_ms,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=mint_id,
            baseline_model_class="frontier-2026",
            burn_policy=policy,
            signing_private=priv,
            signing_public=pub,
            grace_ms=grace_ms,
            max_batch=max_batch,
            recovery_window_ms=recovery_window_ms,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(mint_id, port, clock, config, ledger)

    def base_url(self, mint: Mint) -> str:
        return f"http://127.0.0.1:{mint.port}"

    def client(self, mint: Mint) -> MintClient:
        return MintClient(self.base_url(mint))

    def make_wallet(self, mint: Mint) -> Wallet:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Wallet(
            os.path.join(tmp.name, "wallet.sqlite3"),
            self.client(mint),
            mint.mint_id,
        )

    def fund_wallet(self, mint: Mint, wallet: Wallet, amount_mc: int) -> int:
        secret = new_secret()
        mint.ledger.issue(
            [OutputSpec(amount_mc=amount_mc, secret_hash=ledger_key(secret))]
        )
        return wallet.receive(format_token(mint.mint_id, amount_mc, secret))

    def status_state(self, mint: Mint, h: str) -> dict:
        _mt, results = self.client(mint).status([h])
        return results[0]

    def dump_ledger_db(self, mint: Mint) -> str:
        """Every row of every table in the mint's sqlite ledger, as one
        string — for asserting cross-mint DB isolation (B1)."""
        con = sqlite3.connect(mint.ledger._db_path)
        try:
            tables = [
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            ]
            parts = []
            for table in tables:
                for row in con.execute(f'SELECT * FROM "{table}"'):
                    parts.append(repr(row))
            return "\n".join(parts)
        finally:
            con.close()

    def two_parties(
        self,
        m1: Mint,
        m2: Mint,
        *,
        fund1: int = 100_000,
        fund2: int = 100_000,
        polling_interval_ms: int = 5_000,
        assumed_latency_ms: int | None = 30_000,
        party_a_cls=SwapParty,
        party_b_cls=SwapParty,
    ):
        """A funds at Mint 1 and claims at Mint 2; B the reverse (§11)."""
        wallet_a = self.make_wallet(m1)
        wallet_b = self.make_wallet(m2)
        self.fund_wallet(m1, wallet_a, fund1)
        self.fund_wallet(m2, wallet_b, fund2)
        a = party_a_cls(
            wallet_a,
            self.client(m2),
            m2.mint_id,
            polling_interval_ms=polling_interval_ms,
            assumed_latency_ms=assumed_latency_ms,
        )
        b = party_b_cls(
            wallet_b,
            self.client(m1),
            m1.mint_id,
            polling_interval_ms=polling_interval_ms,
            assumed_latency_ms=assumed_latency_ms,
        )
        return a, b

    # ==================================================================
    # B1 — happy path across two live mints with different burn policies
    # ==================================================================

    def test_b1_happy_path_two_mints(self):
        """B1: A ends holding Mint-2 value, B holds Mint-1 value; both
        legs' burns accounted; neither mint's DB references the other."""
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2)
        a, b = self.two_parties(m1, m2)

        amount1, amount2 = 5_000, 4_000  # Mint-1 leg / Mint-2 leg face values
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS

        def poller(_attempt):  # advance both clocks one polling interval
            m1.clock.advance(5_000)
            m2.clock.advance(5_000)

        result = run_swap(a, b, (amount1, amount2), T, T_prime, poller=poller)
        self.assertIsInstance(result, SwapResult)

        # A holds Mint-2 value; B holds Mint-1 value.
        a_tok = parse_token(result.a_token)
        b_tok = parse_token(result.b_token)
        self.assertEqual(a_tok.mint_id, MINT2_ID)
        self.assertEqual(b_tok.mint_id, MINT1_ID)
        # Net of each mint's own burn on the claim call.
        self.assertEqual(a_tok.amount_mc, amount2 - compute_burn(amount2, POLICY2))
        self.assertEqual(b_tok.amount_mc, amount1 - compute_burn(amount1, POLICY1))

        # Neither DB references the other: every claimed token is scoped to
        # its own mint id.  A's Mint-2 token is unspent at Mint 2 and simply
        # unknown at Mint 1 (no cross reference of any kind).
        self.assertEqual(
            self.status_state(m2, ledger_key(a_tok.secret))["state"], "unspent"
        )
        self.assertEqual(
            self.status_state(m1, ledger_key(a_tok.secret))["state"], "unknown"
        )

        # Stronger isolation check: dump EVERY row of EVERY table in each
        # mint's sqlite ledger and assert the other mint's mint_id appears
        # nowhere, and none of the other leg's ledger hashes appear.
        m1_dump = self.dump_ledger_db(m1)
        m2_dump = self.dump_ledger_db(m2)
        m1_hashes = {  # hashes that live only on Mint 1's ledger
            a._funded["hash"],  # A's funded leg (B's claim output)
            ledger_key(b_tok.secret),  # B's claimed fresh output
        }
        m2_hashes = {  # hashes that live only on Mint 2's ledger
            b._funded["hash"],  # B's funded leg (A's claim output)
            ledger_key(a_tok.secret),  # A's claimed fresh output
        }
        # The scan is not vacuous: each mint's own hashes ARE in its dump.
        for h in m1_hashes:
            self.assertIn(h, m1_dump)
        for h in m2_hashes:
            self.assertIn(h, m2_dump)
        # ... and the other mint's id and hashes are NOT.
        self.assertNotIn(MINT2_ID, m1_dump)
        self.assertNotIn(MINT1_ID, m2_dump)
        for h in m2_hashes:
            self.assertNotIn(h, m1_dump)
        for h in m1_hashes:
            self.assertNotIn(h, m2_dump)

        # The claimed tokens are spendable at their mints (round-trip).
        wa2 = self.make_wallet(m2)
        wb1 = self.make_wallet(m1)
        self.assertEqual(
            wa2.receive(result.a_token),
            a_tok.amount_mc - compute_burn(a_tok.amount_mc, POLICY2),
        )
        self.assertEqual(
            wb1.receive(result.b_token),
            b_tok.amount_mc - compute_burn(b_tok.amount_mc, POLICY1),
        )

        # Each mint's supply reflects only its own leg's burn accounting:
        # the §3.6 invariant outstanding == issued − burned holds per mint,
        # and each mint burned a positive amount (both legs accounted).
        for mint in (m1, m2):
            sup = mint.ledger.supply()
            self.assertEqual(
                sup["outstanding_mc"],
                sup["cumulative_issued_mc"] - sup["cumulative_burned_mc"],
            )
            self.assertGreater(sup["cumulative_burned_mc"], 0)

    # ==================================================================
    # B2 — silent-claim attack defeated (the §11 fix)
    # ==================================================================

    def test_b2_silent_claim_defeated(self):
        """B2: adversarial A claims at Mint 2 and sends nothing; B reads
        claim_witness from Mint 2's public status and claims at Mint 1
        before T.  Worst case: A's claim lands at T′ − ε, B's poll fires
        one full interval later.  B uses ONLY public status data."""
        m1 = self.start_mint(MINT1_ID, POLICY1, grace_ms=1_000)
        m2 = self.start_mint(MINT2_ID, POLICY2, grace_ms=1_000)
        a, b = self.two_parties(m1, m2, polling_interval_ms=5_000)

        amount1, amount2 = 5_000, 4_000
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS

        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)

        # B's leg (funded at Mint 2) — the hash B will poll on.
        poll_hash = b._funded["hash"]

        # Timeline setup: place both clocks a little before T′ − ε, where
        # B's previous poll still saw the entry unspent (so the discovering
        # poll can only be a later one).
        interval = 5_000
        # A claims at T′ − ε, the last moment outside the mint's grace band
        # (grace 1s here), so the preimage spend is still permitted.
        epsilon = 1_001
        pre_poll = T_prime - epsilon - interval
        m1.clock.set(pre_poll)
        m2.clock.set(pre_poll)

        # B polls once and sees its leg still unspent (public status data).
        self.assertEqual(self.status_state(m2, poll_hash)["state"], "unspent")

        # One full interval later, at T′ − ε, adversarial A claims at Mint 2
        # and sends B nothing.
        m1.clock.set(T_prime - epsilon)
        m2.clock.set(T_prime - epsilon)
        a_token = a.a_claim(amount2, T_prime)
        self.assertEqual(parse_token(a_token).mint_id, MINT2_ID)

        # Worst-case discovery (the benchmark's pinned drive): A's claim
        # landed at T′ − ε, an instant AFTER B's poll — so B's next poll
        # fires one FULL polling interval after the claim, and the status
        # response takes one full status latency on top.  Advance BOTH
        # clocks through that dead time before B acts: discovery now lands
        # strictly AFTER T′ (B's own leg at Mint 2 has already expired)
        # but still before T.
        m1.clock.advance(interval + DEFAULT_LATENCY_FLOOR_MS)
        m2.clock.advance(interval + DEFAULT_LATENCY_FLOOR_MS)
        self.assertGreater(m1.clock(), T_prime)  # past B's own leg's expiry
        self.assertGreater(m2.clock(), T_prime)
        self.assertLess(m1.clock(), T)  # the §11 margin still leaves time

        # B's poll fires: it reads spent and recovers x from claim_witness
        # — no channel from A at all.
        witnessed = self.status_state(m2, poll_hash)
        self.assertEqual(witnessed["state"], "spent")
        self.assertIsNotNone(witnessed["claim_witness"])

        # b_poll_and_claim discovers x with NO witness argument available
        # (requirement 2): its only parameters are the virtual poller and a
        # loop bound — there is structurally no side channel for x.
        params = set(inspect.signature(b.b_poll_and_claim).parameters)
        self.assertEqual(params, {"poller", "max_polls"})

        b_token = b.b_poll_and_claim()  # discovery is late, yet before T
        self.assertEqual(parse_token(b_token).mint_id, MINT1_ID)

        # B recovered Mint-1 value; A did NOT get both legs.  A's own
        # funded Mint-1 leg is now claim-spent (by B), not refundable.
        self.assertEqual(
            self.status_state(m1, ledger_key(b._claim_secret))["state"], "spent"
        )
        # The witness B used equals the preimage of the pinned lock hash.
        used = b64u_decode(witnessed["claim_witness"], expect_len=32)
        self.assertEqual(b64u_encode(hashlib.sha256(used).digest()), x_hash)

        # A can no longer refund its Mint-1 leg (B claimed it): the refund
        # path finds the entry already spent.
        with self.assertRaises(MintRejected) as cm:
            a.refund_expired()
        self.assertIn("spent", {e.get("reason") for e in cm.exception.errors})

    # ==================================================================
    # B3 — A stalls entirely: both refund at expiry; nobody refunds early
    # ==================================================================

    def test_b3_both_refund_nobody_early(self):
        """B3: nothing claimed; both legs refund at their expiries; a
        refund attempted before expiry is rejected lock_not_expired."""
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2)
        a, b = self.two_parties(m1, m2)

        amount1, amount2 = 5_000, 4_000
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS

        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)

        # Nobody can refund early — the mint's commit-time clock rejects it
        # (lock_not_expired), before either expiry.
        with self.assertRaises(MintRejected) as ca:
            a.refund_expired()
        self.assertIn("lock_not_expired", {e.get("reason") for e in ca.exception.errors})
        with self.assertRaises(MintRejected) as cb:
            b.refund_expired()
        self.assertIn("lock_not_expired", {e.get("reason") for e in cb.exception.errors})

        # Both legs still unspent after the failed early attempts.
        self.assertEqual(
            self.status_state(m1, ledger_key(b._claim_secret))["state"], "unspent"
        )
        self.assertEqual(
            self.status_state(m2, ledger_key(a._claim_secret))["state"], "unspent"
        )

        # At/after each leg's expiry the funder refunds via its refund
        # secret (§3.4 refund path).  B's Mint-2 leg (T′) first.
        m2.clock.set(T_prime)
        net_b = b.refund_expired()
        self.assertEqual(net_b, amount2 - compute_burn(amount2, POLICY2))
        # A's Mint-1 leg (T).
        m1.clock.set(T)
        net_a = a.refund_expired()
        self.assertEqual(net_a, amount1 - compute_burn(amount1, POLICY1))

        # Refund tokens are the funders' home-mint value.
        self.assertEqual(parse_token(a.refund_tokens[0]).mint_id, MINT1_ID)
        self.assertEqual(parse_token(b.refund_tokens[0]).mint_id, MINT2_ID)
        # Both legs now spent (refund path).
        self.assertEqual(
            self.status_state(m1, ledger_key(b._claim_secret))["state"], "spent"
        )
        self.assertEqual(
            self.status_state(m2, ledger_key(a._claim_secret))["state"], "spent"
        )
        # A refund-path spend discloses NO claim_witness (§3.5).
        self.assertIsNone(
            self.status_state(m1, ledger_key(b._claim_secret))["claim_witness"]
        )

    # ==================================================================
    # B4 — B late within margin still claims; shrink a term → failure
    # ==================================================================

    def test_b4_late_within_margin_claims(self):
        """B4: after A claims, B's Mint-1 leg stays claimable by B until T
        even when B discovers x late — as long as it is within the margin
        the formula budgets."""
        m1 = self.start_mint(MINT1_ID, POLICY1, grace_ms=1_000)
        m2 = self.start_mint(MINT2_ID, POLICY2, grace_ms=1_000)
        a, b = self.two_parties(
            m1, m2, polling_interval_ms=5_000, assumed_latency_ms=30_000
        )
        amount1, amount2 = 5_000, 4_000
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS

        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)

        # A claims at Mint 2 at T′ − ε (last moment outside grace, 1s here).
        m1.clock.set(T_prime - 1_001)
        m2.clock.set(T_prime - 1_001)
        a.a_claim(amount2, T_prime)

        # B discovers x one polling interval + one status latency later:
        # still strictly before T (the margin guarantees this).  Drive the
        # clocks forward by exactly that budget, then let B claim.
        margin_budget = 5_000 + DEFAULT_LATENCY_FLOOR_MS  # poll + status
        m1.clock.advance(margin_budget)
        self.assertLess(m1.clock(), T)  # still time to claim at Mint 1
        b_token = b.b_poll_and_claim()
        self.assertEqual(parse_token(b_token).mint_id, MINT1_ID)
        self.assertEqual(
            self.status_state(m1, ledger_key(b._claim_secret))["state"], "spent"
        )

    def test_b4_shrunk_margin_term_constructs_failure(self):
        """B4: shrink the margin below the formula → the load-bearing
        failure the terms exist to prevent.  With T − T′ too small, B
        discovers x only after T, its Mint-1 claim is refused lock_expired,
        and A refunds that same leg — taking BOTH legs."""

        class MisconfiguredB(SwapParty):
            # Models a B that under-budgets the margin: it drops the
            # polling-interval + status-latency terms entirely, so it
            # accepts a T − T′ that leaves no time to act on a late reveal.
            def _required_margin(self, desc_other, desc_home):
                full = super()._required_margin(desc_other, desc_home)
                # remove one full polling interval + one status latency:
                # exactly the terms that cover "discovers x no later than
                # T′ plus one polling interval plus one status latency".
                return full - self._polling_interval_ms - DEFAULT_LATENCY_FLOOR_MS

        m1 = self.start_mint(MINT1_ID, POLICY1, grace_ms=1_000)
        m2 = self.start_mint(MINT2_ID, POLICY2, grace_ms=1_000)
        a, b = self.two_parties(
            m1,
            m2,
            polling_interval_ms=5_000,
            assumed_latency_ms=30_000,
            party_b_cls=MisconfiguredB,
        )
        amount1, amount2 = 5_000, 4_000

        # Choose T − T′ exactly at the shrunken (too-small) margin: honest
        # B would have refused this, misconfigured B accepts it.
        desc1 = self.client(m1).descriptor()
        desc2 = self.client(m2).descriptor()
        full_margin = compute_margin(desc1, desc2, 5_000, 30_000)
        shrunk = full_margin - 5_000 - DEFAULT_LATENCY_FLOOR_MS
        T = T0 + 5 * full_margin  # comfortably in the future
        T_prime = T - shrunk

        # An honest B would refuse this margin outright.
        honest_b = SwapParty(
            b._wallet, self.client(m1), MINT1_ID,
            polling_interval_ms=5_000, assumed_latency_ms=30_000,
        )
        honest_b.prepare_claim()
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        with self.assertRaises(QuoteRefused):
            honest_b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)

        # Misconfigured B funds anyway.
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)

        # A claims at Mint 2 at T′ − ε (last moment outside grace).
        m1.clock.set(T_prime - 1_001)
        m2.clock.set(T_prime - 1_001)
        a.a_claim(amount2, T_prime)

        # B's real elapsed time from T′ to when its claim would reach Mint 1
        # is (worst case) one polling interval + one status latency + one
        # redemption latency.  With the margin shrunk by exactly the poll +
        # status terms, that worst-case moment lands past T.  Model the
        # elapsed real time on Mint 1's clock:
        m1.clock.set(T_prime + 5_000 + DEFAULT_LATENCY_FLOOR_MS + DEFAULT_LATENCY_FLOOR_MS)
        self.assertGreaterEqual(m1.clock(), T)  # B is now past T — too late

        # B cannot safely claim: it discovered x too late, so its Mint-1
        # leg is already at/after expiry.  b_poll_and_claim refuses (the
        # §3.4 client grace convention over the expired leg).
        with self.assertRaises((SwapError, MintRejected)):
            b.b_poll_and_claim()
        # The leg is unclaimed and past T.
        self.assertEqual(
            self.status_state(m1, ledger_key(b._claim_secret))["state"], "unspent"
        )

        # And now A refunds that very leg — A has BOTH legs (it claimed at
        # Mint 2 and reclaims at Mint 1).  This is the exact loss the
        # margin's polling + status-latency terms exist to prevent.
        net_a_refund = a.refund_expired()
        self.assertEqual(net_a_refund, amount1 - compute_burn(amount1, POLICY1))
        self.assertGreater(len(a.claimed_tokens), 0)  # A also claimed Mint-2

    # ==================================================================
    # B5 — compute_margin
    # ==================================================================

    def _descriptor(
        self,
        *,
        grace_ms,
        precision_ms,
        mint_time,
        performance,
        recovery_window_ms,
    ) -> dict:
        return {
            "mint_time": mint_time,
            "lock_params": {
                "grace_ms": grace_ms,
                "timestamp_precision_ms": precision_ms,
                "max_lock_expiry_ms": 30 * DAY_MS,
            },
            "performance": performance,
            "retention": {
                "recovery_window_ms": recovery_window_ms,
                "prunes_spent_records": False,
                "policy_url": "about:blank",
            },
        }

    def test_b5_compute_margin_numeric(self):
        """B5: the verification-report numeric case (grace 1s×2, precision
        100ms×2, poll 5s, p99 200ms×10, skew 1s) → 14200 ms, computed
        independently here."""
        perf = {
            "p99_exchange_ms": 200,
            "sustained_qps": 10,
            "window_days": 7,
            "measured_at": T0,
        }
        desc1 = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0,
            performance=perf, recovery_window_ms=90 * DAY_MS,
        )
        desc2 = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0 + 1_000,  # skew 1s
            performance=perf, recovery_window_ms=90 * DAY_MS,
        )
        # Independent recomputation of the formula.
        expected = (
            1_000 + 1_000  # grace both
            + 100 + 100  # precision both
            + 5_000  # polling interval
            + 200 * 10  # one status latency (p99 × 10)
            + 2 * (200 * 10)  # 2 × redemption latency
            + 1_000  # clock skew
        )
        self.assertEqual(expected, 14_200)
        self.assertEqual(
            compute_margin(desc1, desc2, 5_000, assumed_latency_ms=None),
            expected,
        )
        # Sanity on the pinned constants used above.
        self.assertEqual(LATENCY_SAFETY_FACTOR, 10)

    def test_b5_null_performance_default_path(self):
        """B5: a null-performance mint uses the 60s default floor under the
        assumed latency; with no assumed latency at all it refuses."""
        desc_null = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0,
            performance=None, recovery_window_ms=365 * DAY_MS,
        )
        perf = {
            "p99_exchange_ms": 100,
            "sustained_qps": 10,
            "window_days": 7,
            "measured_at": T0,
        }
        desc_perf = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0,
            performance=perf, recovery_window_ms=365 * DAY_MS,
        )
        # Null performance + no assumed latency → QuoteRefused (§11).
        with self.assertRaises(QuoteRefused):
            compute_margin(desc_null, desc_perf, 5_000, assumed_latency_ms=None)

        # With an assumed latency below the floor, the 60s floor is used.
        # latency = max(floor 60_000, perf 100×10=1000, assumed 30_000)
        #         = 60_000 (the null mint drives the max).
        margin = compute_margin(desc_null, desc_perf, 5_000, assumed_latency_ms=30_000)
        expected = (
            1_000 + 1_000 + 100 + 100 + 5_000
            + DEFAULT_LATENCY_FLOOR_MS + 2 * DEFAULT_LATENCY_FLOOR_MS + 0
        )
        self.assertEqual(margin, expected)

        # An assumed latency above the floor wins over the floor.
        margin2 = compute_margin(desc_null, desc_perf, 5_000, assumed_latency_ms=90_000)
        expected2 = (
            1_000 + 1_000 + 100 + 100 + 5_000
            + 90_000 + 2 * 90_000 + 0
        )
        self.assertEqual(margin2, expected2)

    def test_b5_insufficient_retention_refused(self):
        """B5: Mint 2's recovery window not covering the horizon →
        QuoteRefused (§11 step 4 / §8): the claim_witness must outlive the
        margin."""
        perf = {
            "p99_exchange_ms": 200,
            "sustained_qps": 10,
            "window_days": 7,
            "measured_at": T0,
        }
        desc1 = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0,
            performance=perf, recovery_window_ms=90 * DAY_MS,
        )
        # desc2 is Mint 2 (the one B polls); its window is too short.
        desc2_short = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0 + 1_000,
            performance=perf, recovery_window_ms=10_000,  # < 14_200
        )
        with self.assertRaises(QuoteRefused):
            compute_margin(desc1, desc2_short, 5_000, assumed_latency_ms=None)

        # A window exactly equal to the margin is sufficient (>=).
        desc2_exact = self._descriptor(
            grace_ms=1_000, precision_ms=100, mint_time=T0 + 1_000,
            performance=perf, recovery_window_ms=14_200,
        )
        self.assertEqual(
            compute_margin(desc1, desc2_exact, 5_000, assumed_latency_ms=None),
            14_200,
        )

    # ==================================================================
    # B6 — same preimage valid at both mints (two independent Ledgers)
    # ==================================================================

    def test_b6_same_preimage_valid_at_both_mints(self):
        """B6: one 32-byte x opens a §3.4 lock at two independent Ledger
        instances — the §3.4 pinning at integration level.  Fund a locked
        output to sha256(x) at each mint and claim each with the same x."""
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2)

        x = os.urandom(32)
        x_hash = b64u_encode(hashlib.sha256(x).digest())
        expiry = T0 + HOUR_MS

        claimed_nets = []
        for mint, policy in ((m1, POLICY1), (m2, POLICY2)):
            # Fund a locked output owned by a fresh output secret, locked to
            # the SAME x_hash at this independent mint.
            out_secret = os.urandom(32)
            refund_secret = os.urandom(32)
            face = 3_000
            mint.ledger.issue(
                [
                    OutputSpec(
                        amount_mc=face,
                        secret_hash=ledger_key(out_secret),
                        lock={
                            "preimage_hash": x_hash,
                            "expiry": expiry,
                            "refund_hash": ledger_key(refund_secret),
                        },
                    )
                ]
            )
            client = self.client(mint)
            # Claim with token secret + the SAME witness x.
            fresh = os.urandom(32)
            net = face - compute_burn(face, policy)
            client.exchange(
                str(uuid.uuid4()),
                [
                    {
                        "token": format_token(mint.mint_id, face, out_secret),
                        "witness": b64u_encode(x),
                    }
                ],
                [{"amount_mc": net, "secret_hash": ledger_key(fresh), "lock": None}],
            )
            # The claim-path spend discloses x as claim_witness (§3.5, L6).
            st = self.status_state(mint, ledger_key(out_secret))
            self.assertEqual(st["state"], "spent")
            self.assertEqual(
                b64u_decode(st["claim_witness"], expect_len=32), x
            )
            claimed_nets.append(net)

        # Both independent mints accepted the identical preimage.
        self.assertEqual(len(claimed_nets), 2)

    # ==================================================================
    # extra guards on the public API
    # ==================================================================

    def test_margin_rejected_when_T_minus_Tprime_below_min(self):
        """b_fund refuses (QuoteRefused) when T − T′ is below the computed
        minimum margin (requirement 3)."""
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2)
        a, b = self.two_parties(m1, m2, assumed_latency_ms=30_000)
        T = T0 + HOUR_MS
        T_prime = T - 10  # absurdly small margin
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(5_000, b_hash, T)
        with self.assertRaises(QuoteRefused):
            b.b_fund(4_000, a_hash, x_hash, T, T_prime, claim_amount_mc=5_000)

    def test_b_fund_refuses_retention_below_actual_horizon(self):
        """b_fund enforces §11 step 4 against the ACTUAL swap horizon:
        Mint 2's recovery window sits ABOVE the minimum margin (so
        compute_margin alone would quote) but BELOW T − T′ + dispute
        margin — the claim_witness could prune before B reads it, so B
        MUST refuse.  The same window is accepted once T − T′ shrinks
        enough for the horizon to fit."""
        short_window = 30 * 60_000  # 30 minutes

        # --- refuse: T − T′ = 1 h, window covers margin but not horizon
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2, recovery_window_ms=short_window)
        a, b = self.two_parties(m1, m2, assumed_latency_ms=30_000)
        margin = compute_margin(
            self.client(m1).descriptor(),
            self.client(m2).descriptor(),
            5_000,
            assumed_latency_ms=30_000,
        )
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS
        # The trap this test pins: the window passes the margin floor
        # (compute_margin would NOT refuse) yet fails the actual horizon.
        self.assertGreater(short_window, margin)
        self.assertGreater(T - T_prime, margin)  # margin check passes too
        self.assertLess(short_window, (T - T_prime) + margin)
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(5_000, b_hash, T)
        with self.assertRaises(QuoteRefused) as cm:
            b.b_fund(4_000, a_hash, x_hash, T, T_prime, claim_amount_mc=5_000)
        self.assertIn("recovery_window", str(cm.exception))

        # --- accept: same window, smaller T − T′ so the horizon fits
        m3 = self.start_mint(MINT1_ID, POLICY1)
        m4 = self.start_mint(MINT2_ID, POLICY2, recovery_window_ms=short_window)
        a2, b2 = self.two_parties(m3, m4, assumed_latency_ms=30_000)
        T2 = T0 + 2 * HOUR_MS
        T2_prime = T2 - 25 * 60_000  # T − T′ = 25 min
        self.assertGreaterEqual(T2 - T2_prime, margin)
        self.assertGreaterEqual(short_window, (T2 - T2_prime) + margin)
        b2_hash = b2.prepare_claim()
        a2_hash = a2.prepare_claim()
        x2_hash = a2.a_fund(5_000, b2_hash, T2)
        b2.b_fund(4_000, a2_hash, x2_hash, T2, T2_prime, claim_amount_mc=5_000)
        self.assertIsNotNone(b2._funded)

    def test_a_claim_refuses_within_grace_of_Tprime(self):
        """a_claim refuses to submit a preimage spend within grace_ms of T′
        (requirement 3, §3.4 client convention)."""
        m1 = self.start_mint(MINT1_ID, POLICY1, grace_ms=5_000)
        m2 = self.start_mint(MINT2_ID, POLICY2, grace_ms=5_000)
        a, b = self.two_parties(m1, m2)
        amount1, amount2 = 5_000, 4_000
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)
        # Move Mint-2 clock inside grace of T′.
        m2.clock.set(T_prime - 4_999)
        with self.assertRaises(SwapError):
            a.a_claim(amount2, T_prime)

    def test_b_fund_verifies_counterparty_leg(self):
        """b_fund verifies A's funded leg on the ledger before committing:
        a wrong claim amount is refused."""
        m1 = self.start_mint(MINT1_ID, POLICY1)
        m2 = self.start_mint(MINT2_ID, POLICY2)
        a, b = self.two_parties(m1, m2)
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(5_000, b_hash, T)
        # Lie about the funded amount → verification fails.
        with self.assertRaises(SwapError):
            b.b_fund(4_000, a_hash, x_hash, T, T_prime, claim_amount_mc=9_999)

    def test_b_poll_refund_path_yields_no_witness(self):
        """If B's own funded leg is refund-spent (A never claimed there),
        b_poll_and_claim finds no claim_witness and reports nothing to
        discover — it never invents x."""
        m1 = self.start_mint(MINT1_ID, POLICY1, grace_ms=1_000)
        m2 = self.start_mint(MINT2_ID, POLICY2, grace_ms=1_000)
        a, b = self.two_parties(m1, m2)
        amount1, amount2 = 5_000, 4_000
        T = T0 + 2 * HOUR_MS
        T_prime = T0 + 1 * HOUR_MS
        b_hash = b.prepare_claim()
        a_hash = a.prepare_claim()
        x_hash = a.a_fund(amount1, b_hash, T)
        b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)
        # B refunds its own Mint-2 leg at expiry (A stalled).
        m2.clock.set(T_prime)
        b.refund_expired()
        # Now polling sees a refund-path spend: no witness, nothing to do.
        with self.assertRaises(SwapError):
            b.b_poll_and_claim(max_polls=1)


if __name__ == "__main__":
    unittest.main()
