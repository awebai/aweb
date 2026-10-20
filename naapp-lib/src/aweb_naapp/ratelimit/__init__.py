"""Token-bucket rate limits shared by naapps.

A bucket holds up to ``capacity`` tokens and refills continuously at
``capacity`` tokens per ``window_s`` seconds. A request takes one token from
each bucket it charges, or from none: if any bucket is empty, nothing is
charged and the decision names the empty buckets. Capacity and window come
with every call, so a policy that changes takes effect at once, and a shrunk
capacity caps a bucket immediately.

:func:`take` runs in the caller's transaction and locks its buckets in one
order, sorted by ``(bucket, key)``, until that transaction ends: a rolled-back
request charges nothing, concurrent requests never take more tokens than
there are, and overlapping bucket sets never deadlock. It never deletes. A
bucket that has refilled equals an absent one, which reads as full, and
:func:`sweep` deletes those in its own short transaction, never waiting on a
bucket another transaction holds. Callers run it after their request commits,
or from a periodic job, so attacker-chosen keys stay bounded.

Time is the caller's ``now`` on every call; the limiter never reads a clock.
A bucket's refill time never moves backwards: a worker whose clock lags sees
the bucket as of its last refill, so skew between workers never grants the
same refill twice. Deleting a full bucket loses nothing at the capacity it
was written with; if a later call raises the capacity, the bucket reaches the
new one sooner, an over-grant of at most the increase, once, after it went
idle.

A refusal is a :class:`Decision`, not an exception, and the limiter meters
nothing: each caller maps it to its own refusal. The table lives in the
calling app's own schema, through its own migration module, so two apps never
share buckets.

Imports only the standard library and pgdbm, so it needs no naapp runtime.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_ratelimit"
MAX_KEY_BYTES = 512

_BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


@dataclass(frozen=True)
class Charge:
    """One token from ``key``'s bucket in ``bucket``, which holds at most ``capacity``
    and refills ``capacity`` tokens per ``window_s`` seconds."""

    bucket: str
    key: str
    capacity: int
    window_s: int

    def __post_init__(self) -> None:
        if not isinstance(self.bucket, str) or not _BUCKET.fullmatch(self.bucket):
            raise ValueError("a bucket is 1-64 of a-z 0-9 . _ - and starts with a letter or digit")
        if not isinstance(self.key, str) or not 1 <= len(self.key.encode("utf-8")) <= MAX_KEY_BYTES:
            raise ValueError(f"a key is 1-{MAX_KEY_BYTES} bytes")
        if not (_positive_int(self.capacity) and _positive_int(self.window_s)):
            raise ValueError("capacity and window_s are positive integers")


@dataclass(frozen=True)
class Decision:
    """``allowed`` when every charge had a token and all were taken. Otherwise
    ``refused`` names the empty buckets and ``retry_after_s`` is the whole
    seconds, at least 1, until each of them holds a token again."""

    allowed: bool
    retry_after_s: int
    refused: tuple[Charge, ...]

    @property
    def throttled(self) -> bool:
        return not self.allowed


async def apply_ratelimit_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def _ordered(charges: Sequence[Charge], now: datetime) -> list[Charge]:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not charges:
        raise ValueError("a call charges at least one bucket")
    ordered = sorted(charges, key=lambda c: (c.bucket, c.key))
    pairs = [(c.bucket, c.key) for c in ordered]
    if len(set(pairs)) != len(pairs):
        raise ValueError("each (bucket, key) is charged at most once per call")
    return ordered


def _level(
    charge: Charge, tokens: float, refilled_at: datetime, now: datetime
) -> tuple[float, datetime]:
    """The bucket's tokens and the time they are counted at, never before ``refilled_at``."""
    at = max(now, refilled_at)
    elapsed = (at - refilled_at).total_seconds()
    # Rounded to a nanotoken, so float noise never withholds a refilled token.
    level = min(float(charge.capacity), tokens + elapsed * charge.capacity / charge.window_s)
    return round(level, 9), at


def _decide(levels: list[tuple[Charge, float]]) -> Decision:
    empty = [(c, tokens) for c, tokens in levels if tokens < 1]
    if not empty:
        return Decision(allowed=True, retry_after_s=0, refused=())
    wait = max((1 - tokens) * c.window_s / c.capacity for c, tokens in empty)
    return Decision(
        allowed=False,
        retry_after_s=max(1, math.ceil(round(wait, 6))),
        refused=tuple(c for c, _ in empty),
    )


async def take(tx: TransactionManager, charges: Sequence[Charge], *, now: datetime) -> Decision:
    """Take one token from each bucket in ``charges``, or from none.

    Runs in the caller's transaction, which holds the buckets' row locks until
    it ends. Never deletes rows; see :func:`sweep`.
    """
    levels: list[tuple[Charge, float]] = []
    counted_at: list[datetime] = []
    for c in _ordered(charges, now):
        # The upsert creates a missing bucket full and locks it in one statement.
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.rate_buckets}} AS b (bucket, key, tokens, refilled_at, full_at)
            VALUES ($1, $2, $3, $4, $4)
            ON CONFLICT (bucket, key) DO UPDATE SET bucket = b.bucket
            RETURNING tokens, refilled_at
            """,
            c.bucket,
            c.key,
            float(c.capacity),
            now,
        )
        if row is None:
            raise RuntimeError("a rate bucket was upserted but returned no row")
        tokens, at = _level(c, row["tokens"], row["refilled_at"], now)
        levels.append((c, tokens))
        counted_at.append(at)
    decision = _decide(levels)
    if decision.allowed:
        for (c, tokens), at in zip(levels, counted_at, strict=True):
            left = tokens - 1
            full_at = at + timedelta(seconds=(c.capacity - left) * c.window_s / c.capacity)
            await tx.execute(
                """
                UPDATE {{tables.rate_buckets}}
                SET tokens = $3, refilled_at = $4, full_at = $5
                WHERE bucket = $1 AND key = $2
                """,
                c.bucket,
                c.key,
                left,
                at,
                full_at,
            )
    return decision


async def peek(tx: TransactionManager, charges: Sequence[Charge], *, now: datetime) -> Decision:
    """What :func:`take` would decide now, without writing or locking anything.

    Advisory: a later take may still refuse.
    """
    levels: list[tuple[Charge, float]] = []
    for c in _ordered(charges, now):
        row = await tx.fetch_one(
            "SELECT tokens, refilled_at FROM {{tables.rate_buckets}} WHERE bucket = $1 AND key = $2",
            c.bucket,
            c.key,
        )
        if row is None:
            levels.append((c, float(c.capacity)))
        else:
            levels.append((c, _level(c, row["tokens"], row["refilled_at"], now)[0]))
    return _decide(levels)


async def sweep(db: AsyncDatabaseManager, *, now: datetime, limit: int = 1000) -> int:
    """Delete up to ``limit`` buckets that are full by ``now``, in their own transaction.

    Skips buckets another transaction holds, so it never waits on one. Returns
    how many were deleted.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not _positive_int(limit):
        raise ValueError("limit is a positive integer")
    async with db.transaction() as tx:
        deleted = await tx.fetch_value(
            """
            WITH stale AS (
                SELECT bucket, key FROM {{tables.rate_buckets}}
                WHERE full_at <= $1
                ORDER BY full_at
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            ), deleted AS (
                DELETE FROM {{tables.rate_buckets}} b
                USING stale
                WHERE b.bucket = stale.bucket AND b.key = stale.key
                RETURNING 1
            )
            SELECT count(*) FROM deleted
            """,
            now,
            limit,
        )
    return int(deleted)
