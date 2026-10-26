"""In-process clock readings and deadlines use integer monotonic nanoseconds.

These readings never cross a process boundary or become persisted timestamps.
Wall-clock timestamps remain timezone-aware datetimes. Convert durations to
seconds only at APIs such as asyncio timeouts that require seconds.
"""

from collections.abc import Callable

NANOSECONDS_PER_SECOND = 1_000_000_000
NANOSECONDS_PER_MICROSECOND = 1_000
type MonotonicClock = Callable[[], int]


def seconds_to_ns(seconds: int) -> int:
    return seconds * NANOSECONDS_PER_SECOND
