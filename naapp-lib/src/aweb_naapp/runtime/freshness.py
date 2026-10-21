"""A bounded freshness cache for answers read from a remote authority.

Grant status and hook resolution share one rule (app-team-server-api §3, §4):
an answer is reused for at most ``min(max_age_seconds, 60)`` counted from when
the client asked for it (the authority answers after that, so a slow answer
gains no time), an expired answer is never served, not even while
its refresh runs, a refresh that outlasts its timeout fails closed for every
caller waiting on it, and concurrent misses for one key share one refresh.

Answers are cached whatever they say, so a definitive "not granted" is reused
for its window like a positive one. Failures are never cached. The cache
belongs to one event loop.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass

FRESHNESS_CEILING_SECONDS = 60
DEFAULT_REFRESH_TIMEOUT_SECONDS = 5.0

# What the authority answered, with the answer's own max_age_seconds.
type Fetch[V] = Callable[[], Awaitable[tuple[V, int]]]


class RefreshTimedOut(Exception):
    """The authority did not answer within the refresh timeout."""


@dataclass(frozen=True)
class Fresh[V]:
    """An answer and the :func:`time.monotonic` deadline after which it must not be used."""

    value: V
    fresh_until: float


class FreshnessCache[K: Hashable, V]:
    def __init__(
        self,
        *,
        refresh_timeout: float = DEFAULT_REFRESH_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            isinstance(refresh_timeout, bool)
            or not isinstance(refresh_timeout, int | float)
            or not math.isfinite(refresh_timeout)
            or refresh_timeout <= 0
        ):
            raise ValueError("refresh_timeout must be a positive finite number of seconds")
        self._refresh_timeout = refresh_timeout
        self._monotonic = monotonic
        self._entries: dict[K, Fresh[V]] = {}
        self._refreshes: dict[K, asyncio.Task[Fresh[V]]] = {}

    async def get(self, key: K, fetch: Fetch[V]) -> Fresh[V]:
        """The answer for ``key``, from the cache while fresh, otherwise from ``fetch``.

        Raises :class:`RefreshTimedOut` when the shared refresh times out, and
        whatever ``fetch`` raised when it failed; neither leaves an entry.
        """
        entry = self._entries.get(key)
        if entry is not None and self._monotonic() < entry.fresh_until:
            return entry
        refresh = self._refreshes.get(key)
        if refresh is None:
            # The window starts once, when the shared refresh starts: a caller
            # joining it later gets the same deadline.
            refresh = asyncio.ensure_future(self._refresh(key, fetch, self._monotonic()))
            # A refresh whose every waiter was cancelled still completes; its
            # outcome is observed here so a failure is not reported as unretrieved.
            refresh.add_done_callback(lambda task: task.cancelled() or task.exception())
            self._refreshes[key] = refresh
        # Shielded so that one cancelled caller does not cancel the refresh
        # that other callers are waiting on.
        return await asyncio.shield(refresh)

    async def _refresh(self, key: K, fetch: Fetch[V], asked_at: float) -> Fresh[V]:
        try:
            try:
                value, max_age = await asyncio.wait_for(fetch(), self._refresh_timeout)
            except TimeoutError as exc:
                raise RefreshTimedOut(f"no answer within {self._refresh_timeout} s") from exc
            if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 1:
                raise ValueError("an answer's max_age_seconds must be a positive whole number")
            fresh = Fresh(
                value=value, fresh_until=asked_at + min(max_age, FRESHNESS_CEILING_SECONDS)
            )
            self._entries[key] = fresh
            return fresh
        finally:
            self._refreshes.pop(key, None)
