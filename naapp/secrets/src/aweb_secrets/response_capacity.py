"""Non-blocking byte reservations for the production broker's response lifetime."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import Lock

DEFAULT_RESPONSE_BUDGET_BYTES = 256 * 1024 * 1024


class ResponseCapacityUnavailable(Exception):
    """No upstream request may follow a failed reservation."""


class ResponseBudget:
    def __init__(self, maximum: int) -> None:
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("the broker response budget must be positive whole bytes")
        self._available = maximum
        self._lock = Lock()

    @contextmanager
    def reservation(self) -> Iterator[Callable[[int], None]]:
        """Charge once, without waiting for capacity; release on every exit.

        The bookkeeping lock protects only a counter, with no I/O or awaits.
        Charging never waits even for that lock, since the caller can hold DB
        authority locks. Release is synchronous, including during cancellation.
        """
        charged = 0

        def reserve(maximum: int) -> None:
            nonlocal charged
            if charged or type(maximum) is not int or maximum <= 0:
                raise ValueError("reserve a positive response bound exactly once")
            if not self._lock.acquire(blocking=False):
                raise ResponseCapacityUnavailable()
            try:
                if maximum > self._available:
                    raise ResponseCapacityUnavailable()
                self._available -= maximum
                charged = maximum
            finally:
                self._lock.release()

        try:
            yield reserve
        finally:
            if charged:
                with self._lock:
                    self._available += charged
