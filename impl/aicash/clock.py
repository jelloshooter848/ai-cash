"""Injectable clocks (LOCKED-DESIGN-DECISIONS L17).

The clock protocol (public contract): a clock is any ZERO-ARGUMENT callable
that returns the current time as an integer number of milliseconds since the
Unix epoch, UTC. That is the entire interface — every time-dependent component
takes such a ``clock`` and calls ``clock()`` to read the time; nothing may read
wall time (ledger/lock/caps logic included) except through an injected clock.

Both implementations here satisfy that callable protocol: ``system_clock`` (a
plain function, used by production code) and ``FakeClock`` (a settable,
advanceable instance whose ``__call__`` returns the current value, used by
tests). Anything else honoring the same zero-arg-returns-epoch-ms contract is
an equally valid clock.
"""

import time


def system_clock() -> int:
    return time.time_ns() // 1_000_000


class FakeClock:
    """A settable, advanceable test clock."""

    def __init__(self, now_ms: int = 1_756_000_000_000):
        self._now = int(now_ms)

    def __call__(self) -> int:
        return self._now

    @property
    def now_ms(self) -> int:
        """The current value (epoch ms) — a non-underscore accessor for
        integrators; equivalent to calling the clock."""
        return self._now

    def advance(self, delta_ms: int) -> int:
        self._now += int(delta_ms)
        return self._now

    def set(self, now_ms: int) -> int:
        self._now = int(now_ms)
        return self._now
