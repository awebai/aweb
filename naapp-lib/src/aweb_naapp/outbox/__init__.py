"""The shared durable outbox for naapps and the core server.

A producer enqueues an event in the same database transaction as the effect
it reports, so the two commit together or not at all. A drain then
materializes the event's deliveries, one per target its resolver names, and
delivers each through a pluggable transport, at least once, with bounded
exponential backoff per delivery. Nothing is dropped: an event whose targets
cannot be resolved yet stays pending, and a failing delivery is retried until
the transport reports a final outcome. :func:`outbox_status` exposes the
backlog, dead letters and faults.

Imports only the standard library and pgdbm, so the core server can use it
without the naapp runtime's dependencies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

logger = logging.getLogger(__name__)

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_outbox"
MAX_CALL_TIMEOUT_SECONDS = 30.0


class OutboxConflict(Exception):
    """An event id was enqueued again with different contents."""


class TargetChannelConflict(Exception):
    """A target id is already used by another channel."""


@dataclass(frozen=True)
class OutboxEvent:
    """One event to deliver. ``payload`` is delivered byte for byte; ``producer``
    holds the producer's own columns, which the outbox stores but never reads.
    ``channel`` names the kind of delivery: each channel drains on its own."""

    event_id: UUID
    team_id: str
    kind: str
    occurred_at: datetime
    payload: bytes
    signature: str | None = None
    critical: bool = False
    producer: Mapping[str, Any] = field(default_factory=dict)
    channel: str = "default"


@dataclass(frozen=True)
class StoredEvent:
    """An enqueued event as the resolver and the transport see it."""

    event_id: UUID
    team_id: str
    kind: str
    occurred_at: datetime
    payload: bytes
    signature: str | None
    critical: bool
    producer: Mapping[str, Any]
    channel: str


@dataclass(frozen=True)
class Target:
    """A delivery target. ``meta`` is stored with the delivery when it is
    materialized and handed to the transport unchanged."""

    id: str
    meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Acked:
    disposition: Literal["delivered", "duplicate"]
    receipt: bytes | None = None


@dataclass(frozen=True)
class Retryable:
    error_class: str


@dataclass(frozen=True)
class Permanent:
    error_class: str


@dataclass(frozen=True)
class Conflict:
    pass


@dataclass(frozen=True)
class Cancelled:
    reason: str


Outcome = Acked | Retryable | Permanent | Conflict | Cancelled

# The event's targets, or None when they cannot be resolved now. It runs inside
# the drain's transaction, so it must bound its own network calls; the drain
# also abandons it after RetryPolicy.call_timeout_seconds (at most 30 s).
Resolver = Callable[[StoredEvent], Awaitable[Sequence[Target] | None]]


class Transport(Protocol):
    async def deliver(self, event: StoredEvent, target: Target) -> Outcome:
        """Send one delivery and classify the result.

        It runs holding the delivery's row lock and a database connection, so
        it must bound its own network calls; the drain also abandons it after
        ``RetryPolicy.call_timeout_seconds`` (at most 30 s) and retries it.
        """
        ...


@dataclass(frozen=True)
class RetryPolicy:
    """How failed deliveries are retried.

    Retries back off exponentially from ``base_seconds``, capped at
    ``max_seconds``. A delivery still failing ``stalled_after`` its event was
    enqueued becomes ``stalled`` and keeps being retried. A ``Permanent``
    failure becomes ``rejected`` on its ``rejected_after_attempts``-th attempt.
    A resolver or transport call still running after ``call_timeout_seconds``
    is abandoned: the event stays unmaterialized, or the delivery is retried.
    """

    stalled_after: timedelta
    base_seconds: int = 5
    max_seconds: int = 300
    rejected_after_attempts: int = 8
    call_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 0 < self.call_timeout_seconds <= MAX_CALL_TIMEOUT_SECONDS:
            raise ValueError(f"call_timeout_seconds must be in (0, {MAX_CALL_TIMEOUT_SECONDS}]")


@dataclass(frozen=True)
class DrainResult:
    materialized: int = 0
    delivered: int = 0
    failed: int = 0
    finished: int = 0


@dataclass(frozen=True)
class TargetStatus:
    pending: int
    stalled: int
    dead_letter: int
    cancelled: int
    oldest_undelivered_age_seconds: float | None


@dataclass(frozen=True)
class UnmaterializedStatus:
    count: int
    oldest_age_seconds: float


@dataclass(frozen=True)
class OutboxStatus:
    targets: dict[str, TargetStatus]
    unmaterialized: dict[str, UnmaterializedStatus]
    faults: list[UUID]


async def apply_outbox_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def mint_event_id() -> UUID:
    """A new random event id. Mint it once, before building any bytes that carry it."""
    return uuid.uuid4()


async def enqueue(tx: TransactionManager, event: OutboxEvent) -> None:
    """Store the event in the caller's transaction.

    Enqueueing an event id again is a no-op when its contents are identical
    and raises :class:`OutboxConflict` otherwise.
    """
    payload_sha256 = hashlib.sha256(event.payload).hexdigest()
    inserted = await tx.fetch_value(
        """
        INSERT INTO {{tables.outbox_events}}
          (event_id, team_id, kind, occurred_at, payload, payload_sha256, signature, critical,
           producer, channel)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id
        """,
        event.event_id,
        event.team_id,
        event.kind,
        event.occurred_at,
        event.payload,
        payload_sha256,
        event.signature,
        event.critical,
        json.dumps(dict(event.producer), sort_keys=True),
        event.channel,
    )
    if inserted is not None:
        return
    stored = await tx.fetch_one(
        """
        SELECT team_id, kind, payload_sha256, signature, critical, channel
        FROM {{tables.outbox_events}} WHERE event_id = $1
        """,
        event.event_id,
    )
    if stored is None or (
        stored["team_id"],
        stored["kind"],
        stored["payload_sha256"],
        stored["signature"],
        stored["critical"],
        stored["channel"],
    ) != (
        event.team_id,
        event.kind,
        payload_sha256,
        event.signature,
        event.critical,
        event.channel,
    ):
        raise OutboxConflict(f"event {event.event_id} was already enqueued with other contents")


async def next_sequence(tx: TransactionManager, *, scope: str, team_id: str) -> int:
    """The next number in a per-(scope, team) sequence, assigned in the caller's
    transaction, so it rolls back with it."""
    value = await tx.fetch_value(
        """
        INSERT INTO {{tables.outbox_sequences}} AS s (scope, team_id, last_seq)
        VALUES ($1, $2, 1)
        ON CONFLICT (scope, team_id) DO UPDATE SET last_seq = s.last_seq + 1
        RETURNING last_seq
        """,
        scope,
        team_id,
    )
    return int(value)


def _stored(row: Mapping[str, Any]) -> StoredEvent:
    producer = row["producer"]
    return StoredEvent(
        event_id=row["event_id"],
        team_id=row["team_id"],
        kind=row["kind"],
        occurred_at=row["occurred_at"],
        payload=bytes(row["payload"]),
        signature=row["signature"],
        critical=row["critical"],
        producer=json.loads(producer) if isinstance(producer, str) else producer,
        channel=row["channel"],
    )


def _meta(value: Any) -> Mapping[str, Any]:
    return json.loads(value) if isinstance(value, str) else value


async def _claim_target(tx: TransactionManager, target_id: str, channel: str) -> None:
    await tx.execute(
        """
        INSERT INTO {{tables.outbox_targets}} (target_id, channel) VALUES ($1, $2)
        ON CONFLICT (target_id) DO NOTHING
        """,
        target_id,
        channel,
    )
    owner = await tx.fetch_value(
        "SELECT channel FROM {{tables.outbox_targets}} WHERE target_id = $1", target_id
    )
    if owner != channel:
        raise TargetChannelConflict(f"target {target_id} belongs to channel {owner}")


async def _materialize(
    db: AsyncDatabaseManager, channel: str, resolver: Resolver, policy: RetryPolicy, limit: int
) -> int:
    materialized = 0
    async with db.transaction() as tx:
        rows = await tx.fetch_all(
            """
            SELECT event_id, team_id, kind, occurred_at, payload, signature, critical, producer,
                   channel
            FROM {{tables.outbox_events}}
            WHERE materialized_at IS NULL AND channel = $2
            ORDER BY position
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            """,
            limit,
            channel,
        )
        for row in rows:
            event = _stored(row)
            try:
                targets = await asyncio.wait_for(resolver(event), policy.call_timeout_seconds)
            except Exception:
                logger.exception("Outbox resolver failed for event %s", event.event_id)
                continue
            if targets is None:
                continue
            try:
                async with tx.transaction() as event_tx:
                    for target in targets:
                        await _claim_target(event_tx, target.id, channel)
                        await event_tx.execute(
                            """
                            INSERT INTO {{tables.outbox_deliveries}}
                              (event_id, target_id, target_meta)
                            VALUES ($1, $2, $3::jsonb)
                            ON CONFLICT (event_id, target_id) DO NOTHING
                            """,
                            event.event_id,
                            target.id,
                            json.dumps(dict(target.meta), sort_keys=True),
                        )
                    await event_tx.execute(
                        "UPDATE {{tables.outbox_events}} SET materialized_at = NOW()"
                        " WHERE event_id = $1",
                        event.event_id,
                    )
            except TargetChannelConflict:
                logger.exception("Outbox event %s names another channel's target", event.event_id)
                continue
            materialized += 1
    return materialized


async def _deliver_one(
    db: AsyncDatabaseManager, channel: str, transport: Transport, policy: RetryPolicy
) -> Outcome | None:
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT d.event_id, d.target_id, d.target_meta, d.attempts,
                   e.team_id, e.kind, e.occurred_at, e.payload, e.signature, e.critical, e.producer,
                   e.channel, (NOW() - e.created_at) >= $1 AS past_horizon
            FROM {{tables.outbox_deliveries}} d
            JOIN {{tables.outbox_events}} e ON e.event_id = d.event_id
            WHERE d.state IN ('pending', 'stalled') AND d.next_attempt_at <= NOW()
              AND e.channel = $2
            ORDER BY e.position, d.target_id
            LIMIT 1
            FOR UPDATE OF d SKIP LOCKED
            """,
            policy.stalled_after,
            channel,
        )
        if row is None:
            return None
        event = _stored(row)
        target = Target(row["target_id"], _meta(row["target_meta"]))
        try:
            outcome = await asyncio.wait_for(
                transport.deliver(event, target), policy.call_timeout_seconds
            )
        except TimeoutError:
            logger.warning("Outbox delivery of %s to %s timed out", event.event_id, target.id)
            outcome = Retryable("timeout")
        except Exception as exc:
            logger.warning(
                "Outbox delivery of %s to %s raised %s",
                event.event_id,
                target.id,
                type(exc).__name__,
            )
            outcome = Retryable(type(exc).__name__)
        await _record(tx, row, outcome, policy)
        return outcome


async def _record(
    tx: TransactionManager, row: Mapping[str, Any], outcome: Outcome, policy: RetryPolicy
) -> None:
    key = (row["event_id"], row["target_id"])
    if isinstance(outcome, Acked):
        await tx.execute(
            """
            UPDATE {{tables.outbox_deliveries}}
            SET state = $3, receipt = $4, attempts = attempts + 1, last_error_class = NULL,
                acked_at = clock_timestamp(), updated_at = NOW()
            WHERE event_id = $1 AND target_id = $2
            """,
            *key,
            outcome.disposition,
            outcome.receipt,
        )
    elif isinstance(outcome, Conflict):
        await tx.execute(
            """
            UPDATE {{tables.outbox_deliveries}}
            SET state = 'conflict', attempts = attempts + 1, last_error_class = 'conflict',
                updated_at = NOW()
            WHERE event_id = $1 AND target_id = $2
            """,
            *key,
        )
    elif isinstance(outcome, Cancelled):
        await tx.execute(
            """
            UPDATE {{tables.outbox_deliveries}}
            SET state = 'cancelled', cancel_reason = $3, attempts = attempts + 1, updated_at = NOW()
            WHERE event_id = $1 AND target_id = $2
            """,
            *key,
            outcome.reason,
        )
    else:
        attempts = row["attempts"] + 1
        if isinstance(outcome, Permanent) and attempts >= policy.rejected_after_attempts:
            state = "rejected"
        elif row["past_horizon"]:
            state = "stalled"
        else:
            state = "pending"
        await tx.execute(
            """
            UPDATE {{tables.outbox_deliveries}}
            SET state = $3, attempts = $4, last_error_class = $5, updated_at = NOW(),
                next_attempt_at = NOW() + LEAST($6, $7 * POWER(2, LEAST($4 - 1, 20)))
                                  * INTERVAL '1 second'
            WHERE event_id = $1 AND target_id = $2
            """,
            *key,
            state,
            attempts,
            outcome.error_class,
            policy.max_seconds,
            policy.base_seconds,
        )


async def _finish_drained(db: AsyncDatabaseManager) -> int:
    rows = await db.fetch_all(
        """
        UPDATE {{tables.outbox_events}} AS e
        SET drained_at = NOW(), payload = NULL
        WHERE e.materialized_at IS NOT NULL AND e.drained_at IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM {{tables.outbox_deliveries}} d
            WHERE d.event_id = e.event_id
              AND (
                d.state IN ('pending', 'stalled')
                OR (d.state IN ('rejected', 'conflict') AND d.acknowledged_at IS NULL)
              )
          )
        RETURNING e.event_id
        """
    )
    return len(rows)


async def drain(
    db: AsyncDatabaseManager,
    *,
    channel: str,
    resolver: Resolver,
    transport: Transport,
    policy: RetryPolicy,
    limit: int = 100,
) -> DrainResult:
    """Materialize the channel's pending events, then deliver each of its due
    deliveries once. Other channels' events are left to their own drains.

    Materialization commits before any send, so a crash never re-resolves an
    event. Each delivery is sent and recorded in its own transaction, holding
    its row lock, so a crash mid-send leaves it pending for the next drain.
    """
    materialized = await _materialize(db, channel, resolver, policy, limit)
    delivered = failed = 0
    for _ in range(limit):
        outcome = await _deliver_one(db, channel, transport, policy)
        if outcome is None:
            break
        if isinstance(outcome, Acked):
            delivered += 1
        else:
            failed += 1
    finished = await _finish_drained(db)
    return DrainResult(
        materialized=materialized, delivered=delivered, failed=failed, finished=finished
    )


async def run_drain(
    db: AsyncDatabaseManager,
    *,
    channel: str,
    resolver: Resolver,
    transport: Transport,
    policy: RetryPolicy,
    stop: asyncio.Event,
    interval_seconds: float = 1.0,
) -> None:
    """Drain until ``stop`` is set, waiting ``interval_seconds`` whenever a pass
    found nothing to do. A failing pass is logged and retried."""
    while not stop.is_set():
        try:
            result = await drain(
                db, channel=channel, resolver=resolver, transport=transport, policy=policy
            )
            busy = result.materialized or result.delivered or result.failed
        except Exception:
            logger.exception("Outbox drain pass failed")
            busy = False
        if not busy:
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
            except TimeoutError:
                pass


async def cancel(
    db: AsyncDatabaseManager,
    target_id: str,
    *,
    except_event_ids: Sequence[UUID] = (),
    reason: str = "cancelled",
) -> list[UUID]:
    """Cancel the target's undelivered backlog, except the given events, and
    return the cancelled event ids in enqueue order."""
    rows = await db.fetch_all(
        """
        WITH cancelled AS (
            UPDATE {{tables.outbox_deliveries}}
            SET state = 'cancelled', cancel_reason = $3, updated_at = NOW()
            WHERE target_id = $1 AND state IN ('pending', 'stalled')
              AND NOT (event_id = ANY($2::uuid[]))
            RETURNING event_id
        )
        SELECT c.event_id FROM cancelled c
        JOIN {{tables.outbox_events}} e ON e.event_id = c.event_id
        ORDER BY e.position
        """,
        target_id,
        list(except_event_ids),
        reason,
    )
    return [row["event_id"] for row in rows]


async def redrive(
    db: AsyncDatabaseManager, target_id: str, event_ids: Sequence[UUID]
) -> list[UUID]:
    """Send the named rejected deliveries to the target again, from a fresh
    attempt count, and return the redriven event ids. A conflict is never
    redriven: the target holds other bytes under that event id."""
    rows = await db.fetch_all(
        """
        UPDATE {{tables.outbox_deliveries}}
        SET state = 'pending', attempts = 0, next_attempt_at = NOW(), last_error_class = NULL,
            updated_at = NOW()
        WHERE target_id = $1 AND state = 'rejected' AND acknowledged_at IS NULL
          AND event_id = ANY($2::uuid[])
        RETURNING event_id
        """,
        target_id,
        list(event_ids),
    )
    return [row["event_id"] for row in rows]


async def acknowledge_dead_letters(
    db: AsyncDatabaseManager, target_id: str, event_ids: Sequence[UUID]
) -> list[UUID]:
    """Accept the named rejected or conflicting deliveries as lost, and return
    their event ids. Until then a dead letter keeps its event's bytes, so it can
    be inspected and redriven; once acknowledged, the event can be tombstoned."""
    rows = await db.fetch_all(
        """
        UPDATE {{tables.outbox_deliveries}}
        SET acknowledged_at = NOW(), updated_at = NOW()
        WHERE target_id = $1 AND state IN ('rejected', 'conflict') AND acknowledged_at IS NULL
          AND event_id = ANY($2::uuid[])
        RETURNING event_id
        """,
        target_id,
        list(event_ids),
    )
    return [row["event_id"] for row in rows]


async def latest_receipt(db: AsyncDatabaseManager, target_id: str) -> bytes | None:
    """The receipt the target gave last, in arrival order.

    A target appends in the order deliveries arrive, not in enqueue order, so
    its newest receipt commits to its longest prefix. Receipts of first
    appends (``delivered``) are preferred; a ``duplicate`` ack's receipt is
    returned only when the target appended nothing. Delivery rows, with their
    receipts, are kept after their event drains.
    """
    value = await db.fetch_value(
        """
        SELECT receipt
        FROM {{tables.outbox_deliveries}}
        WHERE target_id = $1 AND state IN ('delivered', 'duplicate') AND receipt IS NOT NULL
        ORDER BY (state = 'delivered') DESC, acked_at DESC
        LIMIT 1
        """,
        target_id,
    )
    return bytes(value) if value is not None else None


async def outbox_status(db: AsyncDatabaseManager, channel: str | None = None) -> OutboxStatus:
    """Per target: undelivered, stalled, dead-letter (conflict or rejected, not
    yet acknowledged) and cancelled counts, and the age of the oldest
    undelivered event. Per team: the
    events not yet materialized, and the oldest one's age. Faults: critical
    events left with no delivery pending or acknowledged. ``channel`` limits
    every figure to that channel's events; None covers all channels."""
    target_rows = await db.fetch_all(
        """
        SELECT d.target_id,
               count(*) FILTER (WHERE d.state = 'pending') AS pending,
               count(*) FILTER (WHERE d.state = 'stalled') AS stalled,
               count(*) FILTER (
                   WHERE d.state IN ('conflict', 'rejected') AND d.acknowledged_at IS NULL
               ) AS dead_letter,
               count(*) FILTER (WHERE d.state = 'cancelled') AS cancelled,
               EXTRACT(EPOCH FROM NOW() - min(e.created_at)
                       FILTER (WHERE d.state IN ('pending', 'stalled'))) AS oldest
        FROM {{tables.outbox_deliveries}} d
        JOIN {{tables.outbox_events}} e ON e.event_id = d.event_id
        WHERE $1::text IS NULL OR e.channel = $1
        GROUP BY d.target_id
        """,
        channel,
    )
    unmaterialized_rows = await db.fetch_all(
        """
        SELECT team_id, count(*) AS count, EXTRACT(EPOCH FROM NOW() - min(created_at)) AS oldest
        FROM {{tables.outbox_events}}
        WHERE materialized_at IS NULL AND ($1::text IS NULL OR channel = $1)
        GROUP BY team_id
        """,
        channel,
    )
    fault_rows = await db.fetch_all(
        """
        SELECT e.event_id FROM {{tables.outbox_events}} e
        WHERE e.critical AND e.materialized_at IS NOT NULL
          AND ($1::text IS NULL OR e.channel = $1)
          AND NOT EXISTS (
            SELECT 1 FROM {{tables.outbox_deliveries}} d
            WHERE d.event_id = e.event_id
              AND d.state IN ('pending', 'stalled', 'delivered', 'duplicate')
          )
        ORDER BY e.position
        """,
        channel,
    )
    return OutboxStatus(
        targets={
            row["target_id"]: TargetStatus(
                pending=row["pending"],
                stalled=row["stalled"],
                dead_letter=row["dead_letter"],
                cancelled=row["cancelled"],
                oldest_undelivered_age_seconds=float(row["oldest"])
                if row["oldest"] is not None
                else None,
            )
            for row in target_rows
        },
        unmaterialized={
            row["team_id"]: UnmaterializedStatus(
                count=row["count"], oldest_age_seconds=float(row["oldest"])
            )
            for row in unmaterialized_rows
        },
        faults=[row["event_id"] for row in fault_rows],
    )
