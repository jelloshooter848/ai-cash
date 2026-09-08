# C03 — burncalc

**Module:** `aicash/burncalc.py` · **Tests:** `tests/test_c03_burncalc.py` · **Spec:** §7.3, §3.6 (`burn_policy`, `burn_policy_next`)

## Purpose
Pure burn arithmetic and policy validation.

## Public API
```python
@dataclass(frozen=True)
class BurnPolicy: rate_ppm: int; cap_mc: int; exempt_below_mc: int

validate_policy(p: BurnPolicy) -> None
# raises PolicyError unless: 0 <= rate_ppm <= 10_000, cap_mc >= 0, exempt_below_mc >= 10

compute_burn(sum_inputs_mc: int, p: BurnPolicy) -> int
# 0 if sum_inputs_mc <= exempt_below_mc else min(cap_mc, sum_inputs_mc * rate_ppm // 1_000_000)

effective_policy(current: BurnPolicy, next_: tuple[BurnPolicy, int] | None, now_ms: int) -> BurnPolicy
# returns next policy iff next_ given and now_ms >= effective_at

validate_notice(current: BurnPolicy, next_: BurnPolicy, announced_at: int, effective_at: int,
                max_lock_expiry_ms: int | None) -> None
# an INCREASE (higher rate_ppm or lower exempt_below_mc or... see req 3) requires
# effective_at - announced_at >= max(7 days, max_lock_expiry_ms or 0); decreases exempt
```

## Requirements
1. Integer arithmetic only; `//` floor division; no floats anywhere.
2. Burn is strictly less than `sum_inputs_mc` for all valid inputs (follows from rate ≤ 1%; test it anyway).
3. "Increase" for notice purposes = any change that can raise the burn for some sum: `rate_ppm` up, `cap_mc` up, or `exempt_below_mc` down. Anything else is a decrease.
4. `compute_burn` is assessed once per call by the caller (C04); C03 exposes only the pure function — document that per-output assessment is forbidden (L12).

## Benchmark (critic checklist)
- [ ] B1 Edge table: sum=10 & exempt=10 → 0; sum=11, rate=10_000 → 0 (floor); sum=1000, rate=1000 → 1 (the §7.3 worked example); sum=10^9, rate=10_000, cap=100 → 100; sum=exempt+1, rate=10_000 → 0 or 1 per formula (assert exact).
- [ ] B2 Property test over ≥1,000 random valid (sum, policy): `0 <= burn < sum`, and burn is monotone non-decreasing in sum for fixed policy.
- [ ] B3 `validate_policy` rejects rate 10_001, negative anything, exempt_below 9; accepts boundary values 10_000 / 10.
- [ ] B4 Notice: rate 500→1000 with 6-day gap rejected; 7-day gap accepted; 500→400 immediate accepted; exempt 20→10 needs notice; cap 5→10 needs notice; with max_lock_expiry_ms = 30 days, a 7-day gap on an increase is rejected and 30-day accepted.
- [ ] B5 `effective_policy` flips exactly at `effective_at` (t = effective_at − 1 vs t = effective_at).
- [ ] B6 No floats: passing a float sum or float policy field raises (TypeError or explicit check).
