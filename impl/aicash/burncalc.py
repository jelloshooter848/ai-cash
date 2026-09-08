"""C03 — burncalc: pure burn arithmetic and burn-policy validation.

Spec: aicash-spec-v0.4.md §7.3 (anti-spam burn), §3.6 (`burn_policy`,
`burn_policy_next` descriptor fields). Locked decision L12.

Everything here is pure integer arithmetic — no floats anywhere, floor
division only, no clock reads (callers pass `now_ms`).

IMPORTANT (L12 / §7.3): the burn is assessed ONCE PER `/v3/exchange` CALL,
never per output and never per input. The caller (C04 exchange engine)
must invoke `compute_burn` exactly once per call with the sum of all input
amounts for that call. Per-output assessment is forbidden by design.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "BurnPolicy",
    "PolicyError",
    "SEVEN_DAYS_MS",
    "compute_burn",
    "effective_policy",
    "validate_notice",
    "validate_policy",
]

#: Minimum §7.3 change-notice interval for a burn increase: 7 days in ms.
SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000  # 604_800_000

#: §7.3: rate_ppm MUST NOT exceed 10_000 (1%).
MAX_RATE_PPM = 10_000

#: §7.3: exempt_below_mc MUST be at least 10 (1–10 mc drips never taxed).
MIN_EXEMPT_BELOW_MC = 10


class PolicyError(ValueError):
    """A burn policy or a burn-policy change notice violates §7.3."""


def _require_int(name: str, value: object) -> int:
    """Reject anything that is not a plain int (floats, bools, strings...).

    §7.3 arithmetic is integer-only (component requirement 1); a float
    sneaking in would silently change floor-division semantics, so it is
    an error, not a coercion. bool is a subclass of int in Python but is
    never a legitimate amount or parameter, so it is rejected too.
    """
    if type(value) is not int:
        raise TypeError(
            f"{name} must be a plain int, got {type(value).__name__}: {value!r}"
        )
    return value


@dataclass(frozen=True)
class BurnPolicy:
    """§3.6 descriptor `burn_policy`: { rate_ppm, cap_mc, exempt_below_mc }."""

    rate_ppm: int
    cap_mc: int
    exempt_below_mc: int


def validate_policy(p: BurnPolicy) -> None:
    """Raise PolicyError unless `p` is a valid §7.3 burn policy.

    Valid iff: 0 <= rate_ppm <= 10_000, cap_mc >= 0, exempt_below_mc >= 10.
    All three fields must be plain ints (TypeError otherwise).
    """
    if not isinstance(p, BurnPolicy):
        raise TypeError(f"expected BurnPolicy, got {type(p).__name__}")
    _require_int("rate_ppm", p.rate_ppm)
    _require_int("cap_mc", p.cap_mc)
    _require_int("exempt_below_mc", p.exempt_below_mc)
    if not (0 <= p.rate_ppm <= MAX_RATE_PPM):
        raise PolicyError(
            f"rate_ppm must be in [0, {MAX_RATE_PPM}], got {p.rate_ppm}"
        )
    if p.cap_mc < 0:
        raise PolicyError(f"cap_mc must be >= 0, got {p.cap_mc}")
    if p.exempt_below_mc < MIN_EXEMPT_BELOW_MC:
        raise PolicyError(
            f"exempt_below_mc must be >= {MIN_EXEMPT_BELOW_MC},"
            f" got {p.exempt_below_mc}"
        )


def compute_burn(sum_inputs_mc: int, p: BurnPolicy) -> int:
    """§7.3 burn for ONE `/v3/exchange` call (never per output — L12).

        burn = 0                                    if sum <= exempt_below_mc
             = min(cap_mc, sum * rate_ppm // 1_000_000)   otherwise

    Integer arithmetic only; `//` is floor division. Raises TypeError on a
    non-int sum or policy field, PolicyError on an invalid policy, and
    ValueError on a negative sum.
    """
    _require_int("sum_inputs_mc", sum_inputs_mc)
    validate_policy(p)
    if sum_inputs_mc < 0:
        raise ValueError(f"sum_inputs_mc must be >= 0, got {sum_inputs_mc}")
    if sum_inputs_mc <= p.exempt_below_mc:
        return 0
    return min(p.cap_mc, sum_inputs_mc * p.rate_ppm // 1_000_000)


def effective_policy(
    current: BurnPolicy,
    next_: tuple[BurnPolicy, int] | None,
    now_ms: int,
) -> BurnPolicy:
    """The policy in force at `now_ms` given `burn_policy_next` (§3.6).

    `next_` is `(policy, effective_at)` or None. Returns the next policy
    iff `next_` is given and `now_ms >= effective_at`; otherwise returns
    `current`. The flip happens exactly at `effective_at`.
    """
    validate_policy(current)
    _require_int("now_ms", now_ms)
    if next_ is None:
        return current
    next_policy, effective_at = next_
    validate_policy(next_policy)
    _require_int("effective_at", effective_at)
    if now_ms >= effective_at:
        return next_policy
    return current


def _is_increase(current: BurnPolicy, next_: BurnPolicy) -> bool:
    """§7.3 / component req 3: an "increase" is any change that can raise
    the burn for some sum — rate_ppm up, cap_mc up, or exempt_below_mc
    down. Anything else is a decrease."""
    return (
        next_.rate_ppm > current.rate_ppm
        or next_.cap_mc > current.cap_mc
        or next_.exempt_below_mc < current.exempt_below_mc
    )


def validate_notice(
    current: BurnPolicy,
    next_: BurnPolicy,
    announced_at: int,
    effective_at: int,
    max_lock_expiry_ms: int | None,
) -> None:
    """Validate a §7.3 `burn_policy_next` change notice.

    An INCREASE (rate_ppm up, cap_mc up, or exempt_below_mc down — any
    change that can raise the burn for some sum) requires

        effective_at - announced_at >= max(7 days, max_lock_expiry_ms or 0)

    so funds locked mid-flight are never repriced by surprise. Decreases
    are exempt and may be immediate. Raises PolicyError on violation.
    """
    validate_policy(current)
    validate_policy(next_)
    _require_int("announced_at", announced_at)
    _require_int("effective_at", effective_at)
    if max_lock_expiry_ms is not None:
        _require_int("max_lock_expiry_ms", max_lock_expiry_ms)
        if max_lock_expiry_ms < 0:
            raise PolicyError(
                f"max_lock_expiry_ms must be >= 0, got {max_lock_expiry_ms}"
            )
    if not _is_increase(current, next_):
        return  # decreases are exempt: immediate effect is allowed
    required_ms = max(SEVEN_DAYS_MS, max_lock_expiry_ms or 0)
    notice_ms = effective_at - announced_at
    if notice_ms < required_ms:
        raise PolicyError(
            "burn increase requires at least "
            f"{required_ms} ms notice (7 days or max_lock_expiry_ms,"
            f" whichever is longer); got {notice_ms} ms"
        )
