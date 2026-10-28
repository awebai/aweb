"""Witness times for identity-tree authority events (docs/id-certificates.md §3).

AWID assigns registered_at, revoked_at, default effective_from and namespace
epoch times from the clock read after a transaction's last lock wait, never
from PostgreSQL's transaction-start now(). Conflicting authority events get
strictly increasing times in serialization order even if the clock steps back.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import FastAPI

Clock = Callable[[], datetime]

MICROSECOND = timedelta(microseconds=1)


def system_clock() -> datetime:
    return datetime.now(timezone.utc)


def app_clock(app: FastAPI) -> Clock:
    return getattr(app.state, "id_tree_clock", system_clock)


def serialization_time(clock: Clock, *after: datetime | None) -> datetime:
    """Read the clock now, but never at or before an event already serialized.

    Call it after the last lock wait; ``after`` holds the times of the
    conflicting events the caller's locks ordered before this one.
    """
    floors = [moment + MICROSECOND for moment in after if moment is not None]
    return max([clock(), *floors])
