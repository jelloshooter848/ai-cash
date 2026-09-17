"""Tests for C04 — ledgerstore (spec §3.2, §3.3, §3.5, §7.1, §7.3, §8).

Benchmark items B1–B11 from components/C04-ledgerstore.md are named in each
test's docstring. All databases live in tempfile directories; all time comes
from the injected FakeClock — no wall time anywhere.
"""

import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
import uuid

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.ledgerstore import (
    ExchangeRejected,
    Ledger,
    OutputSpec,
    _SQLITE_INT_MAX,
    _SQLITE_INT_MIN,
    _storable_int,
)
from aicash.lockeval import InputForm, Lock
from aicash.tokencodec import (
    MAX_AMOUNT_MC,
    Token,
    b64u_encode,
    ledger_key,
    new_secret,
)

T0 = 1_756_000_000_000
WEEK_MS = 7 * 24 * 60 * 60 * 1000
MINT = "mint-a"


def sha_b64u(b: bytes) -> str:
    return b64u_encode(hashlib.sha256(b).digest())


def key(n: str = "") -> str:
    return n + uuid.uuid4().hex


class LedgerTestCase(unittest.TestCase):
    """Shared plumbing: temp-dir ledgers, funding, input/output builders."""

    def make_ledger(
        self,
        rate_ppm=0,
        cap_mc=10**9,
        exempt=10,
        window=WEEK_MS,
        max_lock=None,
        now=T0,
    ):
        clock = FakeClock(now)
        d = tempfile.mkdtemp(prefix="c04-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "ledger.db")
        ledger = Ledger(
            path,
            clock,
            BurnPolicy(rate_ppm=rate_ppm, cap_mc=cap_mc, exempt_below_mc=exempt),
            window,
            max_lock,
        )
        return ledger, clock, path

    def fund(self, ledger, amount, lock=None):
        """Issue one by-hash output; returns its secret."""
        secret = new_secret()
        ledger.issue(
            [OutputSpec(amount_mc=amount, secret_hash=ledger_key(secret), lock=lock)]
        )
        return secret

    def plain(self, secret, amount):
        return InputForm(kind="plain", token=Token(MINT, amount, secret))

    def claim(self, secret, amount, witness):
        return InputForm(
            kind="claim", token=Token(MINT, amount, secret), witness=witness
        )

    def refund(self, hash_, witness):
        return InputForm(kind="refund", hash=hash_, witness=witness)

    def out(self, amount):
        """Fresh by-hash OutputSpec; returns (spec, secret)."""
        s = new_secret()
        return OutputSpec(amount_mc=amount, secret_hash=ledger_key(s)), s

    def reject(self, ledger, inputs, outputs, k=None, digest="d"):
        """Run an exchange expected to fail; return its errors list."""
        with self.assertRaises(ExchangeRejected) as ctx:
            ledger.exchange(k or key(), digest, inputs, outputs=outputs)
        return ctx.exception.errors

    def make_lock(self, expiry, x, r):
        return {
            "preimage_hash": sha_b64u(x),
            "expiry": expiry,
            "refund_hash": sha_b64u(r),
        }

    def fund_locked(self, ledger, amount, lock):
        """Fund a locked by-hash output through exchange; returns its secret."""
        funder = self.fund(ledger, amount)
        payee_secret = new_secret()
        ledger.exchange(
            key(),
            "d",
            [self.plain(funder, amount)],
            outputs=[
                OutputSpec(
                    amount_mc=amount,
                    secret_hash=ledger_key(payee_secret),
                    lock=lock,
                )
            ],
        )
        return payee_secret

    def assert_invariant(self, ledger):
        s = ledger.supply()
        self.assertEqual(
            s["outstanding_mc"],
            s["cumulative_issued_mc"] - s["cumulative_burned_mc"],
            "supply invariant violated: %r" % (s,),
        )

    def entry_count(self, path):
        conn = sqlite3.connect(path)
        try:
            return conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        finally:
            conn.close()


class TestConservationAndBurn(LedgerTestCase):
    def test_exact_conservation_with_burn(self):
        """B1: sum(out) = sum(in) − burn succeeds; burn in response and
        cumulative_burned_mc; supply invariant holds."""
        ledger, clock, _ = self.make_ledger(rate_ppm=1000)  # 0.1%
        secret = self.fund(ledger, 1000)
        spec, _ = self.out(999)  # burn = floor(1000*1000/1e6) = 1
        result = ledger.exchange(
            key(), "d1", [self.plain(secret, 1000)], outputs=[spec]
        )
        self.assertEqual(
            result, {"status": "ok", "outputs_confirmed": 1, "burn_mc": 1}
        )
        s = ledger.supply()
        self.assertEqual(s["cumulative_burned_mc"], 1)
        self.assertEqual(s["cumulative_issued_mc"], 1000)
        self.assertEqual(s["outstanding_mc"], 999)
        self.assert_invariant(ledger)

    def test_off_by_one_either_direction(self):
        """B1: outputs one too small or one too large -> amount_mismatch,
        call-level (index None), carrying the mint-computed
        expected_burn_mc detail (§3.8 usability: public policy arithmetic
        echoed back so the caller can rebalance)."""
        ledger, _, _ = self.make_ledger(rate_ppm=1000)
        for wrong in (998, 1000):
            secret = self.fund(ledger, 1000)
            spec, _ = self.out(wrong)
            errors = self.reject(ledger, [self.plain(secret, 1000)], [spec])
            self.assertEqual(
                errors,
                [{"index": None, "kind": "call",
                  "reason": "amount_mismatch", "expected_burn_mc": 1}],
            )
            # nothing mutated
            _, res = ledger.status([ledger_key(secret)])
            self.assertEqual(res[0]["state"], "unspent")
        self.assert_invariant(ledger)

    def test_exempt_drip_burns_zero(self):
        """B1: sum(in) <= exempt_below_mc -> burn 0, full value through."""
        ledger, _, _ = self.make_ledger(rate_ppm=10_000, exempt=10)
        secret = self.fund(ledger, 10)
        spec, _ = self.out(10)
        result = ledger.exchange(
            key(), "d", [self.plain(secret, 10)], outputs=[spec]
        )
        self.assertEqual(result["burn_mc"], 0)
        self.assert_invariant(ledger)


class TestScheduledBurnPolicyChange(LedgerTestCase):
    """§3.3 step 1 + §7.3: the burn a call is charged is computed from the
    policy in force AT THAT CALL, not from whatever policy the ledger was
    constructed with.

    The ledger used to hold one frozen policy for its whole life, so the
    moment an operator's announced `burn_policy_next` took effect the
    ledger and every client disagreed about the arithmetic in §3.3 step 1
    — every reference client (wallet, channels, swap, escrow) selects
    through burncalc.effective_policy on the descriptor's mint_time, and
    the ledger did not. Result: every client-built exchange, a plain
    receive included, rejected `amount_mismatch` fleet-wide, caused by the
    operator using the change-notice mechanism exactly as §7.3 documents
    it.
    """

    def make_scheduled(self, *, effective_at, now=T0):
        """A ledger at 0.1% with an announced move to 1%."""
        clock = FakeClock(now)
        d = tempfile.mkdtemp(prefix="c04-sched-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ledger = Ledger(
            os.path.join(d, "ledger.db"),
            clock,
            BurnPolicy(rate_ppm=1_000, cap_mc=10**9, exempt_below_mc=10),
            WEEK_MS,
            None,
            burn_policy_next=(
                BurnPolicy(rate_ppm=10_000, cap_mc=10**9, exempt_below_mc=10),
                effective_at,
            ),
        )
        return ledger, clock

    def spend(self, ledger, amount, outputs_mc):
        secret = self.fund(ledger, amount)
        spec, _ = self.out(outputs_mc)
        return ledger.exchange(
            key(), "d", [self.plain(secret, amount)], outputs=[spec]
        )

    def test_the_announced_policy_takes_over_at_effective_at(self):
        """Before effective_at the old policy is charged; from effective_at
        the announced one is, and the flip is exactly at the instant."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.make_scheduled(effective_at=eff)

        # 0.1% of 1000 = 1
        self.assertEqual(self.spend(ledger, 1000, 999)["burn_mc"], 1)

        clock.set(eff - 1)
        self.assertEqual(self.spend(ledger, 1000, 999)["burn_mc"], 1)

        # 1% of 1000 = 10, from the instant itself
        clock.set(eff)
        self.assertEqual(self.spend(ledger, 1000, 990)["burn_mc"], 10)

        clock.set(eff + 10**6)
        self.assertEqual(self.spend(ledger, 1000, 990)["burn_mc"], 10)
        self.assert_invariant(ledger)

    def test_a_call_budgeted_for_the_old_policy_is_rejected_after_the_flip(self):
        """The reciprocal, and the shape of the bug: after the change, a
        batch built against the SUPERSEDED policy is the one that must
        fail, and the rejection quotes the new burn so the caller can
        rebalance."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.make_scheduled(effective_at=eff)
        clock.set(eff)
        secret = self.fund(ledger, 1000)
        spec, _ = self.out(999)  # what the OLD 0.1% policy would allow
        errors = self.reject(ledger, [self.plain(secret, 1000)], [spec])
        self.assertEqual(
            errors,
            [{"index": None, "kind": "call", "reason": "amount_mismatch",
              "expected_burn_mc": 10}],
        )

    def test_the_whole_batch_uses_one_policy_the_calls_own_instant(self):
        """L17 clock discipline extends to the policy: `now` is read once
        per call, so a call that lands on the boundary cannot have its
        inputs priced under one policy and its conservation check under
        another."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.make_scheduled(effective_at=eff)
        clock.set(eff)
        s1 = self.fund(ledger, 600)
        s2 = self.fund(ledger, 400)
        o1, _ = self.out(500)
        o2, _ = self.out(490)  # 1000 - 10 burn
        result = ledger.exchange(
            key(), "d",
            [self.plain(s1, 600), self.plain(s2, 400)],
            outputs=[o1, o2],
        )
        self.assertEqual(result["burn_mc"], 10)
        self.assert_invariant(ledger)

    def test_a_ledger_with_no_notice_is_unchanged(self):
        """No notice, no flip: the ordinary ledger keeps one policy for
        every instant, which is what every existing caller relies on."""
        ledger, clock = self.make_ledger(rate_ppm=1_000)[0:2]
        self.assertIsNone(ledger.burn_policy_next)
        self.assertEqual(self.spend(ledger, 1000, 999)["burn_mc"], 1)
        clock.set(T0 + 10**12)
        self.assertEqual(self.spend(ledger, 1000, 999)["burn_mc"], 1)

    def test_the_notice_is_readable_and_read_only(self):
        """C06 asserts config/ledger consistency on this at boot, so it is
        part of the read-only configuration view beside burn_policy."""
        eff = T0 + WEEK_MS
        ledger, _ = self.make_scheduled(effective_at=eff)
        self.assertEqual(
            ledger.burn_policy_next,
            (BurnPolicy(rate_ppm=10_000, cap_mc=10**9, exempt_below_mc=10), eff),
        )
        with self.assertRaises(AttributeError):
            ledger.burn_policy_next = None

    def test_a_malformed_notice_is_refused_at_construction(self):
        """A policy the ledger cannot evaluate is not a payment-time
        surprise: it fails when the mint is built."""
        d = tempfile.mkdtemp(prefix="c04-bad-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        good = BurnPolicy(rate_ppm=1_000, cap_mc=10**9, exempt_below_mc=10)
        bad_notices = (
            "not-a-pair",
            (good,),
            (good, T0, T0),
            (good, "later"),
            (good, -1),
            (good, 1.0),
            ({"rate_ppm": 1}, T0),
            (BurnPolicy(rate_ppm=10_001, cap_mc=0, exempt_below_mc=10), T0),
        )
        for i, notice in enumerate(bad_notices):
            with self.subTest(notice=notice):
                with self.assertRaises((ValueError, TypeError)):
                    Ledger(
                        os.path.join(d, "l%d.db" % i),
                        FakeClock(T0),
                        good,
                        WEEK_MS,
                        None,
                        burn_policy_next=notice,
                    )

    def test_adopt_completes_a_ledger_but_never_replaces_a_notice(self):
        """The boot-time reconciliation C06 uses for hand-wired mints is
        one-way: it fills an empty schedule and refuses to overwrite one."""
        ledger, clock, _ = self.make_ledger(rate_ppm=1_000)
        eff = T0 + WEEK_MS
        nxt = BurnPolicy(rate_ppm=10_000, cap_mc=10**9, exempt_below_mc=10)
        ledger.adopt_burn_policy_next((nxt, eff))
        self.assertEqual(ledger.burn_policy_next, (nxt, eff))
        clock.set(eff)
        self.assertEqual(self.spend(ledger, 1000, 990)["burn_mc"], 10)

        with self.assertRaises(ValueError) as ctx:
            ledger.adopt_burn_policy_next((nxt, eff + 1))
        self.assertIn("already carries", str(ctx.exception))
        with self.assertRaises(ValueError):
            ledger.adopt_burn_policy_next(None)
        self.assertEqual(ledger.burn_policy_next, (nxt, eff))


class TestEffectiveBurnPolicyAccessor(LedgerTestCase):
    """§7.3: the policy in force at an instant is a PUBLIC question.

    `burn_policy` / `burn_policy_next` are two halves of a configuration;
    answering "what does a call cost right now" from them requires
    re-implementing the selection rule, and the mint-side callers that did
    so (C10's supervision profile pre-computes the burn it will hand to
    `exchange`) read the frozen private `_burn_policy` and therefore
    disagreed with `exchange` from `effective_at` onwards — the same F2
    bug one layer up. `effective_burn_policy(now)` is the single public
    answer, and `exchange` itself prices through it, so a caller that
    budgets through it agrees by construction.
    """

    OLD = BurnPolicy(rate_ppm=1_000, cap_mc=10**9, exempt_below_mc=10)
    NEW = BurnPolicy(rate_ppm=10_000, cap_mc=10**9, exempt_below_mc=10)

    def scheduled(self, *, effective_at, now=T0):
        """A ledger at 0.1% with an announced move to 1%."""
        clock = FakeClock(now)
        d = tempfile.mkdtemp(prefix="c04-eff-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ledger = Ledger(
            os.path.join(d, "ledger.db"),
            clock,
            self.OLD,
            WEEK_MS,
            None,
            burn_policy_next=(self.NEW, effective_at),
        )
        return ledger, clock

    def test_it_answers_for_the_instant_not_for_the_configuration(self):
        """The flip is exactly at effective_at, and `burn_policy` keeps
        reporting the configured value throughout (C06's boot check
        compares configuration to configuration, so that must not move)."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, _ = self.scheduled(effective_at=eff)
        self.assertEqual(ledger.effective_burn_policy(T0), self.OLD)
        self.assertEqual(ledger.effective_burn_policy(eff - 1), self.OLD)
        self.assertEqual(ledger.effective_burn_policy(eff), self.NEW)
        self.assertEqual(ledger.effective_burn_policy(eff + 10**9), self.NEW)
        self.assertEqual(ledger.burn_policy, self.OLD)
        self.assertEqual(ledger.burn_policy_next, (self.NEW, eff))

    def test_it_defaults_to_this_ledgers_own_clock(self):
        """A caller with no instant of its own gets the ledger's."""
        eff = T0 + WEEK_MS
        ledger, clock = self.scheduled(effective_at=eff)
        self.assertEqual(ledger.effective_burn_policy(), self.OLD)
        clock.set(eff)
        self.assertEqual(ledger.effective_burn_policy(), self.NEW)

    def test_a_ledger_with_no_notice_answers_the_same_at_every_instant(self):
        ledger, _, _ = self.make_ledger(rate_ppm=1_000)
        p = BurnPolicy(rate_ppm=1_000, cap_mc=10**9, exempt_below_mc=10)
        self.assertEqual(ledger.effective_burn_policy(0), p)
        self.assertEqual(ledger.effective_burn_policy(T0 + 10**12), p)
        self.assertEqual(ledger.effective_burn_policy(), p)

    def test_a_notice_adopted_at_boot_is_visible_to_the_accessor(self):
        """adopt_burn_policy_next is the hand-wired C06 path; the accessor
        must see what exchange will charge after it, not the value the
        ledger was constructed with."""
        ledger, clock, _ = self.make_ledger(rate_ppm=1_000)
        eff = T0 + WEEK_MS
        ledger.adopt_burn_policy_next((self.NEW, eff))
        self.assertEqual(ledger.effective_burn_policy(eff - 1), self.OLD)
        self.assertEqual(ledger.effective_burn_policy(eff), self.NEW)

    def test_it_rejects_an_instant_that_is_not_a_plain_int(self):
        """Same integer discipline as every other §7.3 entry point: a
        float instant would silently change the comparison."""
        ledger, _ = self.scheduled(effective_at=T0 + WEEK_MS)
        for bad in (1.0, "later", True, None.__class__):
            with self.subTest(now=bad):
                with self.assertRaises(TypeError):
                    ledger.effective_burn_policy(bad)

    # -- the drift the accessor exists to prevent ----------------------

    def budgeted_exchange(self, ledger, policy, amount, now=None):
        """Build an exchange the way a mint-side caller does: pre-compute
        the burn from `policy`, then spend the whole entry."""
        burn = compute_burn(amount, policy)
        secret = self.fund(ledger, amount)
        spec, _ = self.out(amount - burn)
        return ledger.exchange(
            key(), "d", [self.plain(secret, amount)], outputs=[spec]
        )

    def test_a_caller_budgeting_through_the_accessor_agrees_with_exchange(self):
        """Across the flip, in both directions, with no arithmetic of its
        own: the pre-computing caller and the conservation check land on
        the same number."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.scheduled(effective_at=eff)
        for instant, expected in ((T0, 10), (eff - 1, 10), (eff, 100),
                                  (eff + 10**6, 100)):
            with self.subTest(now=instant):
                clock.set(instant)
                result = self.budgeted_exchange(
                    ledger, ledger.effective_burn_policy(clock()), 10_000
                )
                self.assertEqual(result["burn_mc"], expected)
        self.assert_invariant(ledger)

    def test_a_caller_budgeting_from_burn_policy_is_the_bug_being_closed(self):
        """The reciprocal, pinned so the drift cannot come back quietly:
        the SAME caller shape reading the configured policy instead builds
        a batch the mint's own conservation check rejects — after
        effective_at and not before."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.scheduled(effective_at=eff)

        # Before the flip the two agree, which is why the drift is silent
        # until the day an announced change takes effect.
        self.assertEqual(
            self.budgeted_exchange(ledger, ledger.burn_policy, 10_000)["burn_mc"],
            10,
        )

        clock.set(eff)
        burn = compute_burn(10_000, ledger.burn_policy)  # the stale 10
        secret = self.fund(ledger, 10_000)
        spec, _ = self.out(10_000 - burn)
        errors = self.reject(ledger, [self.plain(secret, 10_000)], [spec])
        self.assertEqual(
            errors,
            [{"index": None, "kind": "call", "reason": "amount_mismatch",
              "expected_burn_mc": 100}],
        )

    def test_exchange_prices_every_call_through_this_one_method(self):
        """Behavioral proof that the accessor is the single entry point:
        override it on one instance and the burn `exchange` charges moves
        with it — and it is called with the call's own captured instant,
        not a second clock read."""
        eff = T0 + 30 * 24 * 60 * 60 * 1000
        ledger, clock = self.scheduled(effective_at=eff)
        seen = []
        free = BurnPolicy(rate_ppm=0, cap_mc=0, exempt_below_mc=10)

        def fake(now=None):
            seen.append(now)
            return free

        ledger.effective_burn_policy = fake
        clock.set(eff)  # the announced 1% would charge 100
        secret = self.fund(ledger, 10_000)
        spec, _ = self.out(10_000)  # budgeted for NO burn at all
        result = ledger.exchange(
            key(), "d", [self.plain(secret, 10_000)], outputs=[spec]
        )
        self.assertEqual(result["burn_mc"], 0)
        self.assertEqual(seen, [eff])


class TestDoubleSpendRace(LedgerTestCase):
    def test_eight_threads_fifty_rounds_one_winner(self):
        """B2: 8 threads race exchange calls sharing one input over 50
        rounds: exactly one winner per round, losers' outputs absent, supply
        invariant holds after every round."""
        ledger, _, path = self.make_ledger(rate_ppm=0)
        n_threads, n_rounds = 8, 50
        for _ in range(n_rounds):
            secret = self.fund(ledger, 100)
            barrier = threading.Barrier(n_threads)
            outcomes = [None] * n_threads
            out_secrets = [new_secret() for _ in range(n_threads)]

            def racer(i):
                spec = OutputSpec(
                    amount_mc=100, secret_hash=ledger_key(out_secrets[i])
                )
                barrier.wait()
                try:
                    outcomes[i] = (
                        "ok",
                        ledger.exchange(
                            key(), "d", [self.plain(secret, 100)], outputs=[spec]
                        ),
                    )
                except ExchangeRejected as exc:
                    outcomes[i] = ("rejected", exc.errors)

            threads = [
                threading.Thread(target=racer, args=(i,))
                for i in range(n_threads)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            winners = [i for i, o in enumerate(outcomes) if o[0] == "ok"]
            self.assertEqual(len(winners), 1, "round produced %r" % (outcomes,))
            # losers were rejected as spent
            for i, o in enumerate(outcomes):
                if i not in winners:
                    self.assertEqual(o[0], "rejected")
                    self.assertEqual(
                        o[1],
                        [{"index": 0, "kind": "input", "reason": "spent"}],
                    )
            # distinct successful outputs: exactly the winner's exists
            _, res = ledger.status(
                [ledger_key(s) for s in out_secrets]
            )
            for i, r in enumerate(res):
                if i in winners:
                    self.assertEqual(r["state"], "unspent")
                    self.assertEqual(r["amount_mc"], 100)
                else:
                    self.assertEqual(r, {"state": "unknown"})
            self.assert_invariant(ledger)


class TestEnumeratedRejection(LedgerTestCase):
    def test_multiple_input_failures_enumerated(self):
        """B3: 5-input call with input[1] spent and input[3] unknown returns
        BOTH indices with correct reasons; nothing mutated."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secrets = [self.fund(ledger, 10) for _ in range(5)]
        # spend entry 1 up front
        spec, _ = self.out(10)
        ledger.exchange(key(), "d", [self.plain(secrets[1], 10)], outputs=[spec])
        supply_before = ledger.supply()

        inputs = [self.plain(s, 10) for s in secrets]
        inputs[3] = self.plain(new_secret(), 10)  # unknown
        out_spec, _ = self.out(40)
        errors = self.reject(ledger, inputs, [out_spec])
        input_errors = sorted(
            ((e["index"], e["reason"]) for e in errors if e["kind"] == "input")
        )
        self.assertEqual(input_errors, [(1, "spent"), (3, "unknown")])
        # nothing mutated: the good inputs are still unspent
        _, res = ledger.status(
            [ledger_key(secrets[i]) for i in (0, 2, 4)]
        )
        self.assertTrue(all(r["state"] == "unspent" for r in res))
        self.assertEqual(ledger.supply(), supply_before)

    def test_duplicate_output_within_batch(self):
        """B3: duplicate output hash inside the batch -> output_exists at the
        right index; nothing mutated (input still unspent)."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 10)
        dup = new_secret()
        spec = OutputSpec(amount_mc=5, secret_hash=ledger_key(dup))
        errors = self.reject(ledger, [self.plain(secret, 10)], [spec, spec])
        self.assertIn(
            {"index": 1, "kind": "output", "reason": "output_exists"}, errors
        )
        _, res = ledger.status([ledger_key(secret), ledger_key(dup)])
        self.assertEqual(res[0]["state"], "unspent")  # input untouched
        self.assertEqual(res[1], {"state": "unknown"})  # neither copy inserted
        self.assert_invariant(ledger)

    def test_output_colliding_with_existing_entry(self):
        """B3: an output whose hash already exists in the table (even as an
        input of the same call) -> output_exists."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 10)
        respend = OutputSpec(amount_mc=10, secret_hash=ledger_key(secret))
        errors = self.reject(ledger, [self.plain(secret, 10)], [respend])
        self.assertIn(
            {"index": 0, "kind": "output", "reason": "output_exists"}, errors
        )

    def test_malformed_output_specs(self):
        """B3 (bad_format enumeration): both secret and secret_hash set,
        neither set, zero amount, wrong-length secret -> bad_format at the
        offending output index."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 10)
        s = new_secret()
        bad = [
            OutputSpec(amount_mc=10, secret_hash=ledger_key(s), secret=s),
            OutputSpec(amount_mc=10),
            OutputSpec(amount_mc=0, secret_hash=ledger_key(new_secret())),
            OutputSpec(amount_mc=10, secret=b"short"),
        ]
        for spec in bad:
            errors = self.reject(ledger, [self.plain(secret, 10)], [spec])
            self.assertIn(
                {"index": 0, "kind": "output", "reason": "bad_format"}, errors
            )


class TestIdempotency(LedgerTestCase):
    def test_replay_success_without_reexecution(self):
        """B4: same key+digest after success returns the identical result
        without re-executing (row counts and supply unchanged)."""
        ledger, _, path = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 100)
        spec, out_secret = self.out(100)
        k = key()
        r1 = ledger.exchange(k, "digest-1", [self.plain(secret, 100)], outputs=[spec])
        rows_after = self.entry_count(path)
        supply_after = ledger.supply()

        r2 = ledger.exchange(k, "digest-1", [self.plain(secret, 100)], outputs=[spec])
        self.assertEqual(r1, r2)
        self.assertEqual(self.entry_count(path), rows_after)
        self.assertEqual(ledger.supply(), supply_after)
        # output present exactly once, still unspent
        _, res = ledger.status([ledger_key(out_secret)])
        self.assertEqual(res[0]["state"], "unspent")

    def test_same_key_different_digest_conflicts(self):
        """B4: same key, different digest -> idempotency_conflict."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 100)
        spec, _ = self.out(100)
        k = key()
        ledger.exchange(k, "digest-1", [self.plain(secret, 100)], outputs=[spec])
        errors = self.reject(
            ledger, [self.plain(secret, 100)], [spec], k=k, digest="digest-2"
        )
        self.assertEqual(
            errors,
            [{"index": None, "kind": "call", "reason": "idempotency_conflict"}],
        )

    def test_replay_of_stored_rejection(self):
        """B4: replay of a stored REJECTION reproduces the rejection."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        k = key()
        unknown = self.plain(new_secret(), 10)
        spec, _ = self.out(10)
        e1 = self.reject(ledger, [unknown], [spec], k=k, digest="dg")
        e2 = self.reject(ledger, [unknown], [spec], k=k, digest="dg")
        self.assertEqual(e1, e2)
        self.assertEqual(e1, [{"index": 0, "kind": "input", "reason": "unknown"}])


class TestLockLifecycle(LedgerTestCase):
    def test_claim_before_expiry_and_witness_disclosure(self):
        """B5: locked by-hash funding -> claim-form spend with valid witness
        pre-expiry succeeds and status shows claim_witness == the witness."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        x, r = new_secret(), new_secret()
        expiry = T0 + 10_000
        payee = self.fund_locked(ledger, 50, self.make_lock(expiry, x, r))
        clock.set(T0 + 5_000)
        spec, _ = self.out(50)
        result = ledger.exchange(
            key(), "d", [self.claim(payee, 50, x)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")
        _, res = ledger.status([ledger_key(payee)])
        self.assertEqual(res[0]["state"], "spent")
        self.assertEqual(res[0]["claim_witness"], b64u_encode(x))
        self.assertEqual(res[0]["spent_at"], T0 + 5_000)
        self.assert_invariant(ledger)

    def test_expiry_boundary_refund_yes_claim_no(self):
        """B5: at now == expiry the claim path is dead (lock_expired) and the
        refund path succeeds; refund pre-expiry -> lock_not_expired."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        x, r = new_secret(), new_secret()
        expiry = T0 + 10_000
        payee = self.fund_locked(ledger, 50, self.make_lock(expiry, x, r))
        h = ledger_key(payee)
        spec, _ = self.out(50)

        # pre-expiry: refund is not yet available
        clock.set(expiry - 1)
        errors = self.reject(ledger, [self.refund(h, r)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "lock_not_expired"}]
        )

        # now == expiry: claim no
        clock.set(expiry)
        errors = self.reject(ledger, [self.claim(payee, 50, x)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "lock_expired"}]
        )

        # now == expiry: refund yes; discloses nothing
        result = ledger.exchange(key(), "d", [self.refund(h, r)], outputs=[spec])
        self.assertEqual(result["status"], "ok")
        _, res = ledger.status([h])
        self.assertEqual(res[0]["state"], "spent")
        self.assertIsNone(res[0]["claim_witness"])
        self.assert_invariant(ledger)

    def test_plain_spend_of_locked_entry_rejected(self):
        """B5 (edge): a plain input against a locked entry ->
        lock_preimage_invalid; wrong claim witness likewise."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        x, r = new_secret(), new_secret()
        payee = self.fund_locked(
            ledger, 50, self.make_lock(T0 + 10_000, x, r)
        )
        spec, _ = self.out(50)
        errors = self.reject(ledger, [self.plain(payee, 50)], [spec])
        self.assertEqual(
            errors,
            [{"index": 0, "kind": "input", "reason": "lock_preimage_invalid"}],
        )
        errors = self.reject(
            ledger, [self.claim(payee, 50, new_secret())], [spec]
        )
        self.assertEqual(
            errors,
            [{"index": 0, "kind": "input", "reason": "lock_preimage_invalid"}],
        )


class TestAsymmetricCredentials(LedgerTestCase):
    def test_claim_needs_the_entry_token(self):
        """B6: claim-form with the CORRECT witness but a token whose secret
        does not hash to the entry -> rejected (L5)."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        x, r = new_secret(), new_secret()
        self.fund_locked(ledger, 50, self.make_lock(T0 + 10_000, x, r))
        spec, _ = self.out(50)
        # random secret: resolves to no entry
        errors = self.reject(ledger, [self.claim(new_secret(), 50, x)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "unknown"}]
        )
        # secret of a DIFFERENT (unlocked) entry: witness on unlocked input
        other = self.fund(ledger, 50)
        errors = self.reject(ledger, [self.claim(other, 50, x)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "bad_format"}]
        )
        self.assert_invariant(ledger)

    def test_refund_needs_no_secret(self):
        """B6: refund-form carries only hash + refund witness -> succeeds
        at expiry without any token secret (L5)."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        x, r = new_secret(), new_secret()
        expiry = T0 + 10_000
        payee = self.fund_locked(ledger, 50, self.make_lock(expiry, x, r))
        clock.set(expiry)
        spec, _ = self.out(50)
        result = ledger.exchange(
            key(), "d", [self.refund(ledger_key(payee), r)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")

    def test_token_amount_binding(self):
        """B6/B3 (requirement 3): a presented token whose amount disagrees
        with the ledger entry -> bad_format for that index."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 100)
        spec, _ = self.out(100)
        errors = self.reject(ledger, [self.plain(secret, 99)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "bad_format"}]
        )


class TestIssue(LedgerTestCase):
    def test_issue_increases_supply_and_is_spendable(self):
        """B7: issue() raises outstanding and cumulative_issued equally,
        invariant holds, and issued by-hash outputs are spendable later by
        their secret holders."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        self.assertEqual(
            ledger.supply(),
            {
                "outstanding_mc": 0,
                "cumulative_issued_mc": 0,
                "cumulative_burned_mc": 0,
            },
        )
        secrets = [new_secret() for _ in range(3)]
        amounts = [100, 50, 7]
        ledger.issue(
            [
                OutputSpec(amount_mc=a, secret_hash=ledger_key(s))
                for a, s in zip(amounts, secrets)
            ]
        )
        s = ledger.supply()
        self.assertEqual(s["outstanding_mc"], 157)
        self.assertEqual(s["cumulative_issued_mc"], 157)
        self.assertEqual(s["cumulative_burned_mc"], 0)
        self.assert_invariant(ledger)
        # the holder of a secret can spend its output
        spec, _ = self.out(100)
        result = ledger.exchange(
            key(), "d", [self.plain(secrets[0], 100)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")
        self.assert_invariant(ledger)

    def test_issue_rejects_existing_output(self):
        """B7 (edge): issuing onto an existing hash is refused atomically —
        neither entry lands, cumulative_issued unchanged."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 10)
        fresh = new_secret()
        with self.assertRaises(ExchangeRejected) as ctx:
            ledger.issue(
                [
                    OutputSpec(amount_mc=5, secret_hash=ledger_key(fresh)),
                    OutputSpec(amount_mc=5, secret_hash=ledger_key(secret)),
                ]
            )
        self.assertEqual(
            ctx.exception.errors,
            [{"index": 1, "kind": "output", "reason": "output_exists"}],
        )
        _, res = ledger.status([ledger_key(fresh)])
        self.assertEqual(res[0], {"state": "unknown"})
        self.assertEqual(ledger.supply()["cumulative_issued_mc"], 10)


class TestPrune(LedgerTestCase):
    def test_prune_semantics(self):
        """B8: spent-and-old records vanish (status -> unknown, claim_witness
        no longer served); unspent and locked-unspent survive regardless of
        age; recent spends survive; supply invariant unaffected."""
        window = 1_000
        ledger, clock, _ = self.make_ledger(rate_ppm=0, window=window)
        x, r = new_secret(), new_secret()
        # claim-spent locked entry (its record carries claim_witness)
        locked_spent = self.fund_locked(
            ledger, 50, self.make_lock(T0 + 500_000, x, r)
        )
        spec1, _ = self.out(50)
        ledger.exchange(
            key(), "d", [self.claim(locked_spent, 50, x)], outputs=[spec1]
        )
        # plain-spent entry
        plain_spent = self.fund(ledger, 20)
        spec2, _ = self.out(20)
        ledger.exchange(key(), "d", [self.plain(plain_spent, 20)], outputs=[spec2])
        # old unspent + old locked-unspent
        old_unspent = self.fund(ledger, 30)
        old_locked = self.fund(
            ledger, 40, lock=self.make_lock(T0 + 900_000, new_secret(), new_secret())
        )
        supply_before = ledger.supply()

        clock.set(T0 + window + 1)
        # a recent spend, inside the window
        recent_spent = self.fund(ledger, 15)
        spec3, _ = self.out(15)
        ledger.exchange(key(), "d", [self.plain(recent_spent, 15)], outputs=[spec3])

        deleted = ledger.prune()
        # three T0 spends: the locked entry, the plain entry, and the funder
        # entry consumed inside fund_locked()
        self.assertEqual(deleted, 3)

        _, res = ledger.status(
            [
                ledger_key(locked_spent),
                ledger_key(plain_spent),
                ledger_key(old_unspent),
                ledger_key(old_locked),
                ledger_key(recent_spent),
            ]
        )
        self.assertEqual(res[0], {"state": "unknown"})  # witness gone with it
        self.assertEqual(res[1], {"state": "unknown"})
        self.assertEqual(res[2]["state"], "unspent")
        self.assertEqual(res[3]["state"], "unspent")
        self.assertIsNotNone(res[3]["lock"])
        self.assertEqual(res[4]["state"], "spent")  # still in retention
        # supply invariant unaffected by pruning (spent rows carry no value)
        s = ledger.supply()
        self.assertEqual(
            s["cumulative_issued_mc"], supply_before["cumulative_issued_mc"] + 15
        )
        self.assert_invariant(ledger)

    def test_prune_expires_idempotency_records(self):
        """B8/§8(b): idempotency records prune on the same schedule — after
        pruning, the old key no longer conflicts with a new digest."""
        window = 1_000
        ledger, clock, _ = self.make_ledger(rate_ppm=0, window=window)
        k = key()
        secret = self.fund(ledger, 10)
        spec, _ = self.out(10)
        ledger.exchange(k, "digest-old", [self.plain(secret, 10)], outputs=[spec])
        # within the window a different digest conflicts
        errors = self.reject(
            ledger, [self.plain(new_secret(), 10)], [spec], k=k, digest="digest-new"
        )
        self.assertEqual(errors[0]["reason"], "idempotency_conflict")

        clock.set(T0 + window + 1)
        ledger.prune()
        # record gone: the same key now proceeds to normal validation
        errors = self.reject(
            ledger,
            [self.plain(new_secret(), 10)],
            [self.out(10)[0]],
            k=k,
            digest="digest-new",
        )
        self.assertEqual(
            errors, [{"index": 0, "kind": "input", "reason": "unknown"}]
        )


class TestMaxLockExpiry(LedgerTestCase):
    def test_max_lock_expiry_enforced_and_full_lock_served(self):
        """B9: lock with expiry > now + max_lock_expiry_ms -> bad_format;
        expiry exactly at the horizon is accepted; status returns the full
        lock object of a locked entry."""
        max_lock = 10_000
        ledger, _, _ = self.make_ledger(rate_ppm=0, max_lock=max_lock)
        x, r = new_secret(), new_secret()
        secret = self.fund(ledger, 50)
        payee = new_secret()

        too_far = self.make_lock(T0 + max_lock + 1, x, r)
        spec = OutputSpec(
            amount_mc=50, secret_hash=ledger_key(payee), lock=too_far
        )
        errors = self.reject(ledger, [self.plain(secret, 50)], [spec])
        self.assertEqual(
            errors, [{"index": 0, "kind": "output", "reason": "bad_format"}]
        )

        ok_lock = self.make_lock(T0 + max_lock, x, r)
        spec = OutputSpec(
            amount_mc=50, secret_hash=ledger_key(payee), lock=ok_lock
        )
        result = ledger.exchange(
            key(), "d2", [self.plain(secret, 50)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")
        _, res = ledger.status([ledger_key(payee)])
        self.assertEqual(res[0]["state"], "unspent")
        self.assertEqual(res[0]["lock"], ok_lock)  # full object, all 3 fields
        self.assertIsNone(res[0]["claim_witness"])


class TestNoRawSecretAtRest(LedgerTestCase):
    def test_by_secret_output_never_persisted(self):
        """B10: after by-secret output creation, the sqlite file contains
        neither the raw secret bytes nor their b64u form; idempotency rows
        store digests only."""
        ledger, _, path = self.make_ledger(rate_ppm=0)
        in_secret = self.fund(ledger, 100)
        out_secret = new_secret()
        digest = "digest-" + uuid.uuid4().hex
        ledger.exchange(
            key(),
            digest,
            [self.plain(in_secret, 100)],
            outputs=[OutputSpec(amount_mc=100, secret=out_secret)],
        )
        # by-secret issuance too
        issue_secret = new_secret()
        ledger.issue([OutputSpec(amount_mc=5, secret=issue_secret)])

        with open(path, "rb") as f:
            blob = f.read()
        for s in (out_secret, in_secret, issue_secret):
            self.assertNotIn(s, blob, "raw secret bytes found at rest")
            self.assertNotIn(
                b64u_encode(s).encode("ascii"), blob, "b64u secret found at rest"
            )
        # the hashes ARE there (that's the ledger), so the file was scanned
        self.assertIn(ledger_key(out_secret).encode("ascii"), blob)

        # idempotency table: key/digest/result only, and the result is clean
        conn = sqlite3.connect(path)
        try:
            rows = conn.execute(
                "SELECT body_digest, result_json FROM idempotency"
            ).fetchall()
        finally:
            conn.close()
        self.assertTrue(rows)
        for d, result_json in rows:
            self.assertEqual(d, digest)
            self.assertNotIn(b64u_encode(out_secret), result_json)
            self.assertNotIn(b64u_encode(in_secret), result_json)
        # and the by-secret output is spendable by its holder
        spec, _ = self.out(100)
        result = ledger.exchange(
            key(), "d2", [self.plain(out_secret, 100)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")


class TestStatusBatch(LedgerTestCase):
    def test_order_aligned_batch_with_unknowns(self):
        """B11: batch results order-aligned with the request, unknown (and
        malformed) hashes -> {"state":"unknown"} only, mint_time from the
        injected clock."""
        ledger, clock, _ = self.make_ledger(rate_ppm=0)
        unspent = self.fund(ledger, 10)
        spent = self.fund(ledger, 20)
        spec, _ = self.out(20)
        ledger.exchange(key(), "d", [self.plain(spent, 20)], outputs=[spec])
        clock.set(T0 + 777)

        hashes = [
            ledger_key(spent),
            "not-a-hash!!",
            ledger_key(new_secret()),  # valid form, unknown
            ledger_key(unspent),
        ]
        mint_time, res = ledger.status(hashes)
        self.assertEqual(mint_time, T0 + 777)
        self.assertEqual(len(res), 4)
        self.assertEqual(res[0]["state"], "spent")
        self.assertEqual(res[0]["amount_mc"], 20)
        self.assertEqual(res[0]["spent_at"], T0)
        self.assertIsNone(res[0]["lock"])
        self.assertIsNone(res[0]["claim_witness"])  # plain spend: no witness
        self.assertEqual(res[1], {"state": "unknown"})
        self.assertEqual(res[2], {"state": "unknown"})
        self.assertEqual(res[3]["state"], "unspent")
        self.assertEqual(res[3]["amount_mc"], 10)
        self.assertIsNone(res[3]["spent_at"])

    def test_status_never_spends(self):
        """B11 (edge): status is read-only — repeated queries leave state
        and supply untouched."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        secret = self.fund(ledger, 10)
        before = ledger.supply()
        for _ in range(3):
            _, res = ledger.status([ledger_key(secret)])
            self.assertEqual(res[0]["state"], "unspent")
        self.assertEqual(ledger.supply(), before)


class TestIssueWireForms(LedgerTestCase):
    """issue() accepts §3.3 wire-form output dicts via the same parser the
    HTTP layer uses (usability: paste the wire example straight into the
    Python API when funding a mint)."""

    def test_issue_accepts_wire_dicts_by_hash_and_by_secret(self):
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        s_hash, s_secret, s_locked = new_secret(), new_secret(), new_secret()
        x, r = new_secret(), new_secret()
        lock = self.make_lock(T0 + 60_000, x, r)
        ledger.issue(
            [
                {"amount_mc": 100, "secret_hash": ledger_key(s_hash)},
                {"amount_mc": 50, "secret": b64u_encode(s_secret),
                 "lock": None},
                {"amount_mc": 7, "secret_hash": ledger_key(s_locked),
                 "lock": lock},
            ]
        )
        s = ledger.supply()
        self.assertEqual(s["cumulative_issued_mc"], 157)
        self.assertEqual(s["outstanding_mc"], 157)
        self.assert_invariant(ledger)
        # All three land exactly as their OutputSpec equivalents would.
        _, res = ledger.status(
            [ledger_key(s_hash), ledger_key(s_secret), ledger_key(s_locked)]
        )
        self.assertEqual(res[0]["state"], "unspent")
        self.assertEqual(res[0]["amount_mc"], 100)
        self.assertEqual(res[1]["state"], "unspent")
        self.assertEqual(res[1]["amount_mc"], 50)
        self.assertEqual(res[2]["lock"], lock)
        # ... and are spendable by their secret holders.
        spec, _ = self.out(100)
        result = ledger.exchange(
            key(), "d", [self.plain(s_hash, 100)], outputs=[spec]
        )
        self.assertEqual(result["status"], "ok")

    def test_issue_mixes_wire_dicts_with_output_specs(self):
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        s1, s2 = new_secret(), new_secret()
        ledger.issue(
            [
                OutputSpec(amount_mc=10, secret_hash=ledger_key(s1)),
                {"amount_mc": 20, "secret_hash": ledger_key(s2)},
            ]
        )
        self.assertEqual(ledger.supply()["cumulative_issued_mc"], 30)
        self.assert_invariant(ledger)

    def test_issue_bad_shape_names_expected_forms(self):
        """A dict of unrecognized shape is bad_format at its index (§3.8
        shape unchanged) and the exception message names both accepted
        wire forms."""
        ledger, _, _ = self.make_ledger(rate_ppm=0)
        good = new_secret()
        with self.assertRaises(ExchangeRejected) as ctx:
            ledger.issue(
                [
                    {"amount_mc": 10, "secret_hash": ledger_key(good)},
                    {"amount_mc": 10, "wrong_key": "zzz"},
                ]
            )
        self.assertEqual(
            ctx.exception.errors,
            [{"index": 1, "kind": "output", "reason": "bad_format"}],
        )
        message = str(ctx.exception)
        self.assertIn("secret_hash", message)
        self.assertIn("secret", message)
        self.assertIn("lock", message)
        self.assertIn("[1]", message)
        # Atomic: the good output did not land either.
        self.assertEqual(ledger.supply()["cumulative_issued_mc"], 0)
        _, res = ledger.status([ledger_key(good)])
        self.assertEqual(res[0], {"state": "unknown"})

    def test_issue_wire_dict_shares_http_parser(self):
        """The parser really is shared: parse_output_wire is what C06
        imports, and issue() consumes its output."""
        from aicash.ledgerstore import parse_output_wire
        from aicash import mintapi

        self.assertIs(parse_output_wire, mintapi.parse_output_wire)
        s = new_secret()
        spec = parse_output_wire(
            {"amount_mc": 5, "secret_hash": ledger_key(s)}
        )
        self.assertEqual(
            spec, OutputSpec(amount_mc=5, secret_hash=ledger_key(s), lock=None)
        )
        # Unrecognized shapes pass through unchanged (bad_format at index).
        bad = {"amount_mc": 5}
        self.assertIs(parse_output_wire(bad), bad)


class TestLedgerConstruction(LedgerTestCase):
    def test_memory_db_path_rejected(self):
        """':memory:' cannot work — each thread's connection would be its
        own empty database — so the constructor refuses it with a message
        pointing at file paths."""
        from aicash.burncalc import BurnPolicy as BP

        with self.assertRaises(ValueError) as ctx:
            Ledger(
                ":memory:",
                FakeClock(T0),
                BP(rate_ppm=0, cap_mc=10**9, exempt_below_mc=10),
                WEEK_MS,
                None,
            )
        message = str(ctx.exception)
        self.assertIn(":memory:", message)
        self.assertIn("file path", message)
        self.assertIn("connection", message)

    def test_shared_parameters_readable(self):
        """The shared configuration parameters are exposed read-only so
        C06 can assert config/ledger consistency at boot."""
        ledger, _, _ = self.make_ledger(rate_ppm=1000, max_lock=WEEK_MS)
        self.assertEqual(ledger.burn_policy.rate_ppm, 1000)
        self.assertEqual(ledger.recovery_window_ms, WEEK_MS)
        self.assertEqual(ledger.max_lock_expiry_ms, WEEK_MS)
        with self.assertRaises(AttributeError):
            ledger.recovery_window_ms = 0


class NumbersThisLedgerCannotStoreAreRejectedNotBoundTest(LedgerTestCase):
    """B-class: a caller-supplied number that will not fit a column.

    ``Ledger.issue`` bound ``amount_mc`` into sqlite with a TYPE check and
    no RANGE check. Python's int is unbounded and SQLite's INTEGER is a
    signed 64-bit value, so nineteen nines — 9999999999999999999, one more
    digit than the column holds — is valid JSON, the correct type and
    positive, passed every guard, reached ``conn.execute`` and raised
    ``OverflowError``: not ``ExchangeRejected``, not a ``sqlite3.Error``,
    so ``except ExchangeRejected`` walked past it and C06's issuance route
    answered a bare 500 with no ``errors`` list. §3.8 promises an
    enumerated reason for every value the mint refuses.

    WHY IT SURVIVED. The identical value through ``/v3/exchange`` was
    refused correctly — conservation cannot balance an amount no entry can
    hold — so the case looked covered. It was covered by a DIFFERENT
    check that happens to also catch it, and ``issue`` has no inputs and
    therefore no conservation. A check that covers a case by accident
    stops covering it the moment the accident changes, which is why the
    bound below is at the one place an output amount enters the ledger
    rather than on the route that was reported.

    So these tests sweep the SHAPE — every caller-supplied number this
    module binds into a column — and not the one field.
    """

    # 9999999999999999999: nineteen nines, the reported value.
    NINETEEN_NINES = int("9" * 19)

    def unstorable_amounts(self):
        return {
            "nineteen nines": self.NINETEEN_NINES,
            "2**63": 1 << 63,
            "max + 1": _SQLITE_INT_MAX + 1,
            "10**25": 10 ** 25,
            "10**600": 10 ** 600,
        }

    # -- the reported instance, at the ledger ---------------------------

    def test_issue_refuses_an_amount_no_column_can_hold(self):
        """Enumerated, per output index, and NOT an OverflowError."""
        for name, amount in self.unstorable_amounts().items():
            with self.subTest(name):
                ledger, _, _ = self.make_ledger()
                with self.assertRaises(ExchangeRejected) as caught:
                    ledger.issue(
                        [OutputSpec(amount_mc=amount,
                                    secret_hash=ledger_key(new_secret()))]
                    )
                self.assertEqual(
                    caught.exception.errors,
                    [{"index": 0, "kind": "output", "reason": "bad_format"}],
                )

    def test_nothing_is_written_when_the_amount_is_refused(self):
        """The refusal rolls back: no entry, no supply movement."""
        ledger, _, path = self.make_ledger()
        with self.assertRaises(ExchangeRejected):
            ledger.issue(
                [OutputSpec(amount_mc=self.NINETEEN_NINES,
                            secret_hash=ledger_key(new_secret()))]
            )
        conn = sqlite3.connect(path)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0
            )
        finally:
            conn.close()
        self.assertEqual(ledger.supply()["cumulative_issued_mc"], 0)

    def test_the_index_named_is_the_offending_one(self):
        """§3.8 enumerates indices, so the index has to be right in a
        batch where the bad entry is not first."""
        ledger, _, _ = self.make_ledger()
        with self.assertRaises(ExchangeRejected) as caught:
            ledger.issue([
                OutputSpec(amount_mc=5, secret_hash=ledger_key(new_secret())),
                OutputSpec(amount_mc=7, secret_hash=ledger_key(new_secret())),
                OutputSpec(amount_mc=self.NINETEEN_NINES,
                           secret_hash=ledger_key(new_secret())),
            ])
        self.assertEqual(
            caught.exception.errors,
            [{"index": 2, "kind": "output", "reason": "bad_format"}],
        )

    def test_the_largest_storable_amount_is_still_ordinary_money(self):
        """The bound is the COLUMN's, so the value at the bound works. A
        fix that refused 2**63-1 would be a fix that broke the ledger."""
        ledger, _, _ = self.make_ledger()
        secret = new_secret()
        ledger.issue([OutputSpec(amount_mc=_SQLITE_INT_MAX,
                                 secret_hash=ledger_key(secret))])
        self.assertEqual(
            ledger.supply()["cumulative_issued_mc"], _SQLITE_INT_MAX
        )
        _, results = ledger.status([ledger_key(secret)])
        self.assertEqual(results[0]["amount_mc"], _SQLITE_INT_MAX)

    # -- every caller BENEFITS, not just the reported route -------------

    def test_exchange_refuses_the_same_amount_the_same_way(self):
        """The bound is at ``_resolve_output``, which both routes share,
        so the answer is the same on both. It used to be
        `amount_mismatch` here and OverflowError there — two answers to
        one question, which is how this survived."""
        ledger, _, _ = self.make_ledger()
        with self.assertRaises(ExchangeRejected) as caught:
            ledger.exchange(
                "idem-huge", "digest",
                [],
                outputs=[OutputSpec(amount_mc=self.NINETEEN_NINES,
                                    secret_hash=ledger_key(new_secret()))],
            )
        self.assertEqual(
            caught.exception.errors,
            [{"index": 0, "kind": "output", "reason": "bad_format"}],
        )

    # -- the OTHER numbers this module binds ----------------------------

    def test_a_lock_expiry_no_column_can_hold_is_refused(self):
        """The second caller-supplied number on an entries row. C02's
        validate_lock pins expiry's FORM (a positive int of ms) and says
        nothing about its SIZE, so `{"expiry": 10**19}` is a valid §3.4
        lock that raised the identical OverflowError out of
        ``_insert_entry``.

        Driven with ``max_lock=None`` on purpose: a ledger configured with
        a finite lock horizon refuses that expiry for a different reason
        (§8(b)), which is the same kind of accidental cover that hid the
        amount defect. ``max_lock_expiry_ms=None`` is a supported
        configuration, and it is the one where nothing else is watching.
        """
        for expiry in (10 ** 19, 1 << 63, _SQLITE_INT_MAX + 1, 10 ** 600):
            with self.subTest(expiry=expiry):
                ledger, _, _ = self.make_ledger(max_lock=None)
                lock = {
                    "preimage_hash": sha_b64u(b"p"),
                    "expiry": expiry,
                    "refund_hash": sha_b64u(b"r"),
                }
                with self.assertRaises(ExchangeRejected) as caught:
                    ledger.issue([
                        OutputSpec(amount_mc=5,
                                   secret_hash=ledger_key(new_secret()),
                                   lock=lock)
                    ])
                self.assertEqual(
                    caught.exception.errors,
                    [{"index": 0, "kind": "output", "reason": "bad_format"}],
                )

    def test_a_storable_lock_expiry_still_works(self):
        ledger, _, _ = self.make_ledger(max_lock=None)
        secret = new_secret()
        ledger.issue([
            OutputSpec(amount_mc=5, secret_hash=ledger_key(secret),
                       lock={"preimage_hash": sha_b64u(b"p"),
                             "expiry": _SQLITE_INT_MAX,
                             "refund_hash": sha_b64u(b"r")})
        ])
        _, results = ledger.status([ledger_key(secret)])
        self.assertEqual(results[0]["lock"]["expiry"], _SQLITE_INT_MAX)

    def test_a_batch_whose_SUM_overflows_the_supply_counter(self):
        """The number no per-value bound can reach.

        Every amount below is individually storable and their total is
        not: the supply UPDATE binds `total`, so two outputs of
        `_SQLITE_INT_MAX` raised the identical OverflowError from the
        identical route with every per-amount check passing. Found by
        sweeping this module for "what else does it bind", not by a second
        report.
        """
        ledger, _, _ = self.make_ledger()
        with self.assertRaises(ExchangeRejected) as caught:
            ledger.issue([
                OutputSpec(amount_mc=_SQLITE_INT_MAX,
                           secret_hash=ledger_key(new_secret())),
                OutputSpec(amount_mc=_SQLITE_INT_MAX,
                           secret_hash=ledger_key(new_secret())),
            ])
        # Index 1: the first entry fits, the second is where the ledger
        # runs out of column.
        self.assertEqual(
            caught.exception.errors,
            [{"index": 1, "kind": "output", "reason": "bad_format"}],
        )
        self.assertEqual(ledger.supply()["cumulative_issued_mc"], 0)

    def test_the_headroom_is_read_from_what_is_already_issued(self):
        """Not a per-call bound: a second call that would push the
        cumulative counter over the column is refused too, and the
        counter is exact right up to the edge."""
        ledger, _, _ = self.make_ledger()
        ledger.issue([OutputSpec(amount_mc=_SQLITE_INT_MAX - 1,
                                 secret_hash=ledger_key(new_secret()))])
        ledger.issue([OutputSpec(amount_mc=1,
                                 secret_hash=ledger_key(new_secret()))])
        self.assertEqual(
            ledger.supply()["cumulative_issued_mc"], _SQLITE_INT_MAX
        )
        with self.assertRaises(ExchangeRejected) as caught:
            ledger.issue([OutputSpec(amount_mc=1,
                                     secret_hash=ledger_key(new_secret()))])
        self.assertEqual(
            caught.exception.errors,
            [{"index": 0, "kind": "output", "reason": "bad_format"}],
        )

    # -- the bound itself, stated once ----------------------------------

    def test_the_bound_is_the_column_and_is_named_once(self):
        """One number with one cause. C01 already answers "how big can an
        amount be" with the same value for the same reason (the column),
        and a repository with two spellings of it is one where a retune
        moves only one of them."""
        self.assertEqual(_SQLITE_INT_MAX, (1 << 63) - 1)
        self.assertEqual(_SQLITE_INT_MIN, -(2 ** 63))
        self.assertIs(_SQLITE_INT_MAX, MAX_AMOUNT_MC)

    def test_the_predicate_is_about_the_value_not_the_field(self):
        """`_storable_int` is the chokepoint, so anything routed through it
        is covered — including a field added later."""
        for good in (0, 1, -1, _SQLITE_INT_MIN, _SQLITE_INT_MAX):
            self.assertTrue(_storable_int(good), good)
        for bad in (_SQLITE_INT_MAX + 1, _SQLITE_INT_MIN - 1, 1 << 63,
                    10 ** 600, True, False, 1.0, "5", None, 5 + 0j):
            self.assertFalse(_storable_int(bad), bad)

    def test_an_unstorable_number_never_reaches_sqlite(self):
        """The property, stated as the absence of the exception class the
        defect was made of: no path out of `issue` or `exchange` raises
        OverflowError for any of these, on any field."""
        candidates = list(self.unstorable_amounts().values())
        for amount in candidates:
            with self.subTest(amount=str(amount)[:12]):
                ledger, _, _ = self.make_ledger(max_lock=None)
                for call in (
                    lambda: ledger.issue([
                        OutputSpec(amount_mc=amount,
                                   secret_hash=ledger_key(new_secret()))]),
                    lambda: ledger.issue([
                        OutputSpec(amount_mc=5,
                                   secret_hash=ledger_key(new_secret()),
                                   lock={"preimage_hash": sha_b64u(b"p"),
                                         "expiry": amount,
                                         "refund_hash": sha_b64u(b"r")})]),
                    lambda: ledger.exchange(
                        "i-%s" % str(amount)[:8], "d", [],
                        outputs=[OutputSpec(
                            amount_mc=amount,
                            secret_hash=ledger_key(new_secret()))]),
                ):
                    try:
                        call()
                    except ExchangeRejected:
                        pass
                    except OverflowError as exc:  # pragma: no cover
                        self.fail("OverflowError reached sqlite: %r" % exc)


if __name__ == "__main__":
    unittest.main()
