"""Tests for C03 — burncalc (spec §7.3, §3.6; locked decision L12).

Benchmark items B1–B6 from components/C03-burncalc.md are named in each
test's docstring.
"""

import random
import unittest

from aicash.burncalc import (
    SEVEN_DAYS_MS,
    BurnPolicy,
    PolicyError,
    compute_burn,
    effective_policy,
    validate_notice,
    validate_policy,
)

DAY_MS = 24 * 60 * 60 * 1000


def policy(rate_ppm=1000, cap_mc=1_000_000, exempt_below_mc=10):
    return BurnPolicy(
        rate_ppm=rate_ppm, cap_mc=cap_mc, exempt_below_mc=exempt_below_mc
    )


class TestComputeBurnEdgeTable(unittest.TestCase):
    def test_sum_equal_exempt_is_zero(self):
        """B1: sum=10 with exempt_below_mc=10 -> 0 (boundary is exempt)."""
        self.assertEqual(compute_burn(10, policy(rate_ppm=10_000)), 0)

    def test_sum_11_max_rate_floors_to_zero(self):
        """B1: sum=11, rate=10_000 -> floor(11*10_000/1e6) = 0."""
        self.assertEqual(compute_burn(11, policy(rate_ppm=10_000)), 0)

    def test_spec_worked_example(self):
        """B1: the §7.3 worked example — sum=1000, rate=1000 (0.1%) -> 1."""
        self.assertEqual(compute_burn(1000, policy(rate_ppm=1000)), 1)

    def test_cap_binds(self):
        """B1: sum=10^9, rate=10_000, cap=100 -> 100 (cap binds)."""
        self.assertEqual(
            compute_burn(10**9, policy(rate_ppm=10_000, cap_mc=100)), 100
        )

    def test_sum_exempt_plus_one_exact(self):
        """B1: sum=exempt+1 at rate=10_000 — assert the exact formula value.

        exempt=10: floor(11*10_000/1e6) = 0.
        exempt=100: floor(101*10_000/1e6) = 1.
        """
        self.assertEqual(
            compute_burn(11, policy(rate_ppm=10_000, exempt_below_mc=10)), 0
        )
        self.assertEqual(
            compute_burn(101, policy(rate_ppm=10_000, exempt_below_mc=100)), 1
        )

    def test_zero_rate_is_zero_burn(self):
        """B1 (supporting): rate_ppm=0 burns nothing above the exemption."""
        self.assertEqual(compute_burn(10**9, policy(rate_ppm=0)), 0)

    def test_floor_division_never_rounds_up(self):
        """B1 (supporting): floor semantics — 1_999_999 mc at 1 ppm -> 1."""
        self.assertEqual(compute_burn(1_999_999, policy(rate_ppm=1)), 1)

    def test_negative_sum_rejected(self):
        """B1 (supporting): a negative input sum is invalid."""
        with self.assertRaises(ValueError):
            compute_burn(-1, policy())


class TestComputeBurnProperties(unittest.TestCase):
    def test_burn_bounded_and_monotone(self):
        """B2: over >=1,000 random valid (sum, policy): 0 <= burn < sum,
        burn <= cap_mc, and burn is monotone non-decreasing in sum for a
        fixed policy (req 2: burn strictly less than sum)."""
        rng = random.Random(0xA1CA54)
        for _ in range(1500):
            p = policy(
                rate_ppm=rng.randint(0, 10_000),
                cap_mc=rng.randint(0, 10**9),
                exempt_below_mc=rng.randint(10, 10**6),
            )
            validate_policy(p)  # every generated policy is valid
            s = rng.randint(1, 10**12)
            burn = compute_burn(s, p)
            self.assertIsInstance(burn, int)
            self.assertGreaterEqual(burn, 0)
            self.assertLess(burn, s)
            self.assertLessEqual(burn, p.cap_mc)
            # monotone non-decreasing in sum for fixed policy
            s2 = s + rng.randint(0, 10**6)
            self.assertGreaterEqual(compute_burn(s2, p), burn)

    def test_monotone_across_exemption_boundary(self):
        """B2 (supporting): monotone across the exempt boundary itself."""
        p = policy(rate_ppm=10_000, exempt_below_mc=10)
        prev = 0
        for s in range(1, 500):
            b = compute_burn(s, p)
            self.assertGreaterEqual(b, prev)
            prev = b


class TestValidatePolicy(unittest.TestCase):
    def test_rejects_rate_over_10000(self):
        """B3: rate_ppm=10_001 rejected."""
        with self.assertRaises(PolicyError):
            validate_policy(policy(rate_ppm=10_001))

    def test_rejects_negative_fields(self):
        """B3: negative rate_ppm, cap_mc, exempt_below_mc all rejected."""
        with self.assertRaises(PolicyError):
            validate_policy(policy(rate_ppm=-1))
        with self.assertRaises(PolicyError):
            validate_policy(policy(cap_mc=-1))
        with self.assertRaises(PolicyError):
            validate_policy(policy(exempt_below_mc=-1))

    def test_rejects_exempt_below_9(self):
        """B3: exempt_below_mc=9 rejected (minimum is 10)."""
        with self.assertRaises(PolicyError):
            validate_policy(policy(exempt_below_mc=9))

    def test_accepts_boundary_values(self):
        """B3: boundary values rate_ppm=10_000 and exempt_below_mc=10
        (and rate_ppm=0, cap_mc=0) are accepted."""
        validate_policy(policy(rate_ppm=10_000, exempt_below_mc=10))
        validate_policy(policy(rate_ppm=0, cap_mc=0))

    def test_compute_burn_validates_policy(self):
        """B3 (supporting): compute_burn refuses an invalid policy."""
        with self.assertRaises(PolicyError):
            compute_burn(1000, policy(rate_ppm=10_001))


class TestValidateNotice(unittest.TestCase):
    def test_rate_increase_6_day_gap_rejected(self):
        """B4: rate 500->1000 with a 6-day gap is rejected."""
        with self.assertRaises(PolicyError):
            validate_notice(
                policy(rate_ppm=500), policy(rate_ppm=1000),
                announced_at=0, effective_at=6 * DAY_MS,
                max_lock_expiry_ms=None,
            )

    def test_rate_increase_7_day_gap_accepted(self):
        """B4: rate 500->1000 with exactly a 7-day gap is accepted."""
        validate_notice(
            policy(rate_ppm=500), policy(rate_ppm=1000),
            announced_at=0, effective_at=7 * DAY_MS,
            max_lock_expiry_ms=None,
        )

    def test_rate_decrease_immediate_accepted(self):
        """B4: rate 500->400 immediate (zero gap) is accepted."""
        validate_notice(
            policy(rate_ppm=500), policy(rate_ppm=400),
            announced_at=1_000_000, effective_at=1_000_000,
            max_lock_expiry_ms=None,
        )

    def test_exempt_decrease_needs_notice(self):
        """B4: exempt_below_mc 20->10 is an increase (can raise the burn
        for sums in (10, 20]) and needs notice; 7 days satisfies it."""
        cur = policy(exempt_below_mc=20)
        nxt = policy(exempt_below_mc=10)
        with self.assertRaises(PolicyError):
            validate_notice(cur, nxt, 0, 6 * DAY_MS, None)
        validate_notice(cur, nxt, 0, 7 * DAY_MS, None)

    def test_cap_increase_needs_notice(self):
        """B4: cap_mc 5->10 is an increase and needs notice."""
        cur = policy(cap_mc=5)
        nxt = policy(cap_mc=10)
        with self.assertRaises(PolicyError):
            validate_notice(cur, nxt, 0, 6 * DAY_MS, None)
        validate_notice(cur, nxt, 0, 7 * DAY_MS, None)

    def test_max_lock_expiry_extends_notice(self):
        """B4: with max_lock_expiry_ms = 30 days, a 7-day gap on an
        increase is rejected and a 30-day gap is accepted."""
        cur = policy(rate_ppm=500)
        nxt = policy(rate_ppm=1000)
        thirty = 30 * DAY_MS
        with self.assertRaises(PolicyError):
            validate_notice(cur, nxt, 0, 7 * DAY_MS, thirty)
        validate_notice(cur, nxt, 0, thirty, thirty)

    def test_exempt_increase_is_a_decrease(self):
        """B4 (supporting, req 3): exempt 10->20 cannot raise any burn ->
        decrease -> immediate is fine."""
        validate_notice(
            policy(exempt_below_mc=10), policy(exempt_below_mc=20),
            0, 0, None,
        )

    def test_mixed_change_with_any_raising_axis_is_increase(self):
        """B4 (supporting, req 3): rate up + cap down can still raise the
        burn for some sum -> increase -> notice required."""
        cur = policy(rate_ppm=500, cap_mc=1000)
        nxt = policy(rate_ppm=1000, cap_mc=500)
        with self.assertRaises(PolicyError):
            validate_notice(cur, nxt, 0, 0, None)

    def test_unchanged_policy_is_not_an_increase(self):
        """B4 (supporting): an identical policy needs no notice."""
        validate_notice(policy(), policy(), 0, 0, None)

    def test_seven_days_constant(self):
        """B4 (supporting): the module's 7-day constant is 604_800_000 ms."""
        self.assertEqual(SEVEN_DAYS_MS, 7 * DAY_MS)
        self.assertEqual(SEVEN_DAYS_MS, 604_800_000)


class TestEffectivePolicy(unittest.TestCase):
    def test_flip_exactly_at_effective_at(self):
        """B5: returns current at t = effective_at - 1 and next at
        t = effective_at."""
        cur = policy(rate_ppm=500)
        nxt = policy(rate_ppm=1000)
        eff = 1_700_000_000_000
        self.assertEqual(effective_policy(cur, (nxt, eff), eff - 1), cur)
        self.assertEqual(effective_policy(cur, (nxt, eff), eff), nxt)
        self.assertEqual(effective_policy(cur, (nxt, eff), eff + 1), nxt)

    def test_none_next_returns_current(self):
        """B5 (supporting): with next_=None the current policy is in force
        at any time."""
        cur = policy()
        self.assertEqual(effective_policy(cur, None, 0), cur)
        self.assertEqual(effective_policy(cur, None, 10**15), cur)


class TestNoFloats(unittest.TestCase):
    def test_float_sum_raises(self):
        """B6: a float sum_inputs_mc raises TypeError."""
        with self.assertRaises(TypeError):
            compute_burn(1000.0, policy())

    def test_float_policy_field_raises(self):
        """B6: a float in any policy field raises TypeError — via
        validate_policy and via compute_burn."""
        with self.assertRaises(TypeError):
            validate_policy(policy(rate_ppm=1000.0))
        with self.assertRaises(TypeError):
            validate_policy(policy(cap_mc=100.0))
        with self.assertRaises(TypeError):
            validate_policy(policy(exempt_below_mc=10.0))
        with self.assertRaises(TypeError):
            compute_burn(1000, policy(rate_ppm=1000.0))

    def test_bool_rejected(self):
        """B6 (supporting): bool is not a legitimate int here."""
        with self.assertRaises(TypeError):
            compute_burn(True, policy())

    def test_float_timestamps_raise(self):
        """B6 (supporting): float now_ms / announced_at / effective_at /
        max_lock_expiry_ms all raise TypeError."""
        with self.assertRaises(TypeError):
            effective_policy(policy(), None, 1.5)
        with self.assertRaises(TypeError):
            effective_policy(policy(), (policy(), 1.0), 5)
        with self.assertRaises(TypeError):
            validate_notice(policy(), policy(rate_ppm=2000), 0.0,
                            7 * DAY_MS, None)
        with self.assertRaises(TypeError):
            validate_notice(policy(), policy(rate_ppm=2000), 0,
                            float(7 * DAY_MS), None)
        with self.assertRaises(TypeError):
            validate_notice(policy(), policy(rate_ppm=2000), 0,
                            30 * DAY_MS, 30.0 * DAY_MS)

    def test_result_is_int_never_float(self):
        """B6 (supporting) / req 1: compute_burn returns a plain int."""
        b = compute_burn(123_456_789, policy(rate_ppm=3333))
        self.assertIs(type(b), int)
        self.assertEqual(b, 123_456_789 * 3333 // 1_000_000)


if __name__ == "__main__":
    unittest.main()
