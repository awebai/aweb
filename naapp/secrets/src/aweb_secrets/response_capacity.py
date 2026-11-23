"""Non-blocking byte reservations for the production broker's response lifetime."""

from __future__ import annotations

from asyncio import Future
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Lock
from typing import Any

DEFAULT_RESPONSE_BUDGET_BYTES = 256 * 1024 * 1024


class ResponseCapacityUnavailable(Exception):
    """No upstream request may follow a failed reservation."""


class ResponseReservation:
    """Charge until both the dispatch scope and its response worker release."""

    def __init__(self, budget: ResponseBudget) -> None:
        self._budget = budget
        self._charged = 0
        self._worker: Future[Any] | None = None

    def charge(self, maximum: int) -> None:
        if self._charged or type(maximum) is not int or maximum <= 0:
            raise ValueError("reserve a positive response bound exactly once")
        self._budget._charge(maximum)
        self._charged = maximum

    def retain_until(self, worker: Future[Any]) -> None:
        assert self._charged and self._worker is None
        self._worker = worker

    def _release(self) -> None:
        worker, self._worker = self._worker, None
        if worker is not None and not worker.done():
            worker.add_done_callback(self._refund)
        else:
            self._refund()

    def _refund(self, _worker: Future[Any] | None = None) -> None:
        if self._charged:
            self._budget._refund(self._charged)
            self._charged = 0


class ResponseBudget:
    def __init__(self, maximum: int) -> None:
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("the broker response budget must be positive whole bytes")
        self._available = maximum
        self._lock = Lock()

    def _charge(self, maximum: int) -> None:
        # Never wait for capacity or the counter lock under DB authority locks.
        if not self._lock.acquire(blocking=False):
            raise ResponseCapacityUnavailable()
        try:
            if maximum > self._available:
                raise ResponseCapacityUnavailable()
            self._available -= maximum
        finally:
            self._lock.release()

    def _refund(self, maximum: int) -> None:
        with self._lock:
            self._available += maximum

    @contextmanager
    def reservation(self) -> Iterator[ResponseReservation]:
        reservation = ResponseReservation(self)
        try:
            yield reservation
        finally:
            reservation._release()
