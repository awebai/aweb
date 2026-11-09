"""Retention and purge (audit-substrate.md §B6).

A purge removes an event's content, its salt, signing bytes and signature, and
every projection of it, and keeps its skeleton, so the chain still verifies and
``verify`` reports the purged range with the act that purged it. Retention is
owner-set per event class: a hook's own setting, else the team's ``all``
setting, else the event is kept. :func:`apply_retention` purges what a team's
retention has expired, in bounded batches; :func:`run_retention` runs it while
logs runs.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from aweb_naapp.hooks.catalog import packaged_catalog
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs import read_store
from aweb_logs.chain import format_time

logger = logging.getLogger(__name__)

RETENTION_ACT = "logs.retention.set"
GOVERNANCE_HOOK = "post-governance-hook"
ALL_EVENTS = "all"
_BATCH = 500

# Whether an active legal hold keeps the event ``e`` from purging: a hold on
# everything, or a hold on an actor that the event's projection names, or any
# actor hold while the event has no projection yet to say whose it is.
HELD = (
    "EXISTS (SELECT 1 FROM {{tables.legal_holds}} h"
    " WHERE h.team_id = e.team_id AND h.released_at IS NULL AND ("
    "   h.hold_scope = 'all' OR NOT EXISTS (SELECT 1 FROM {{tables.read_events}} r"
    "     WHERE r.team_id = e.team_id AND r.chain_epoch = e.chain_epoch"
    "     AND r.team_seq = e.team_seq AND r.actor_did_aw IS DISTINCT FROM h.actor_ref"
    "     AND r.actor_did_key IS DISTINCT FROM h.actor_ref)))"
)

# One hook's events with content received before a cutoff, not held and not
# logs' own governance records ($5 is logs' origin), earliest first: a range of
# idx_chain_events_retained. Like an erasure, retention never purges the record
# of an owner act, so every purge's act stays resolvable to its signed act.
EXPIRED = (
    "SELECT e.chain_epoch, e.team_seq FROM {{tables.chain_events}} e"
    " WHERE e.team_id = $1 AND e.hook = $2 AND e.purge_act IS NULL AND e.received_at < $3"
    " AND NOT (e.hook = '" + GOVERNANCE_HOOK + "' AND e.producer_origin = $5)"
    " AND NOT " + HELD + " ORDER BY e.received_at LIMIT $4"
    " FOR UPDATE OF e SKIP LOCKED"
)


async def lock_holds(tx: TransactionManager, team_id: str, *, exclusive: bool = False) -> None:
    """Take the team's hold lock for the rest of ``tx``: shared to purge under
    the holds read in ``tx``, exclusive to set or release one, so no purge
    commits against a hold it did not see."""
    function = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    await tx.execute(f"SELECT {function}(hashtext($1))", f"logs.holds:{team_id}")


async def set_retention(
    db: AsyncDatabaseManager | TransactionManager,
    team_id: str,
    event_class: str,
    *,
    days: int | None,
    event_id: str,
) -> None:
    """Set how long a class of the team's events keeps its content: ``days``,
    or ``None`` to keep it. ``event_id`` is the governance event recording the
    owner act that set it; a purge it causes names that event in its act."""
    await db.execute(
        "INSERT INTO {{tables.retention_settings}} (team_id, event_class, retention_days, event_id)"
        " VALUES ($1, $2, $3, $4)"
        " ON CONFLICT (team_id, event_class) DO UPDATE"
        " SET retention_days = EXCLUDED.retention_days, event_id = EXCLUDED.event_id,"
        "     set_at = NOW()",
        team_id,
        event_class,
        days,
        event_id,
    )


async def purge(
    tx: TransactionManager, team_id: str, positions: Sequence[tuple[int, int]], *, act: str
) -> int:
    """Purge the content and projections of the team's events at these
    ``(chain_epoch, team_seq)`` positions, recording ``act`` as the act that
    purged them. An event already purged keeps its first act. Returns how many
    events this purged."""
    if not positions:
        return 0
    # Lock in position order, as catch-up does, so the two never deadlock.
    await tx.fetch_all(
        "SELECT 1 FROM {{tables.chain_events}}"
        " WHERE team_id = $1 AND purge_act IS NULL"
        " AND (chain_epoch, team_seq) IN (SELECT * FROM unnest($2::int[], $3::bigint[]))"
        " ORDER BY chain_epoch, team_seq FOR UPDATE",
        team_id,
        [epoch for epoch, _ in positions],
        [seq for _, seq in positions],
    )
    purged = await tx.fetch_all(
        "UPDATE {{tables.chain_events}}"
        " SET salt = NULL, signing_bytes = NULL, signature = NULL, purge_act = $4"
        " WHERE team_id = $1 AND purge_act IS NULL"
        " AND (chain_epoch, team_seq) IN (SELECT * FROM unnest($2::int[], $3::bigint[]))"
        " RETURNING chain_epoch, team_seq",
        team_id,
        [epoch for epoch, _ in positions],
        [seq for _, seq in positions],
        act,
    )
    await read_store.reproject(
        tx, team_id, [(row["chain_epoch"], row["team_seq"]) for row in purged]
    )
    return len(purged)


async def apply_retention(
    db: AsyncDatabaseManager,
    *,
    now: datetime,
    logs_origin: str,
    batch: int = _BATCH,
    stop: asyncio.Event | None = None,
) -> int:
    """Purge every event a team's retention has expired at ``now``, one batch
    per transaction, until ``stop`` is set. A team whose purge fails is logged
    and left for the next pass; the other teams go on. Returns how many events
    it purged."""
    teams = await db.fetch_all(
        "SELECT DISTINCT team_id FROM {{tables.retention_settings}}"
        " WHERE retention_days IS NOT NULL ORDER BY team_id"
    )
    total = 0
    for row in teams:
        if stop is not None and stop.is_set():
            break
        try:
            total += await _apply_team(
                db, row["team_id"], now=now, logs_origin=logs_origin, batch=batch, stop=stop
            )
        except Exception:
            logger.exception("Retention failed for team %s", row["team_id"])
    return total


async def _apply_team(
    db: AsyncDatabaseManager,
    team_id: str,
    *,
    now: datetime,
    logs_origin: str,
    batch: int,
    stop: asyncio.Event | None,
) -> int:
    purged = 0
    for hook, event_id, days in await _expiring_classes(db, team_id):
        cutoff = format_time(now - timedelta(days=days))
        while not (stop is not None and stop.is_set()):
            async with db.transaction() as tx:
                await lock_holds(tx, team_id)
                expired = await tx.fetch_all(EXPIRED, team_id, hook, cutoff, batch, logs_origin)
                purged += await purge(
                    tx,
                    team_id,
                    [(event["chain_epoch"], event["team_seq"]) for event in expired],
                    act=f"{RETENTION_ACT}:{event_id}",
                )
            if len(expired) < batch:
                break
    return purged


async def _expiring_classes(db: AsyncDatabaseManager, team_id: str) -> list[tuple[str, str, int]]:
    """Each hook whose events the team's retention expires, with the setting
    that expires them: the hook's own setting, else the team's "all" setting
    for every catalog hook without one of its own."""
    settings = {
        row["event_class"]: (str(row["event_id"]), row["retention_days"])
        for row in await db.fetch_all(
            "SELECT event_class, event_id, retention_days FROM {{tables.retention_settings}}"
            " WHERE team_id = $1",
            team_id,
        )
    }
    every = settings.pop(ALL_EVENTS, None)
    classes = dict(settings)
    if every is not None:
        for hook in packaged_catalog().hooks:
            classes.setdefault(hook, every)
    return [
        (hook, event_id, days)
        for hook, (event_id, days) in sorted(classes.items())
        if days is not None
    ]


async def run_retention(
    db: AsyncDatabaseManager,
    *,
    interval_seconds: float,
    logs_origin: str,
    stop: asyncio.Event,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Apply retention every ``interval_seconds`` until ``stop`` is set. A
    failing pass is logged and tried again at the next interval."""
    while not stop.is_set():
        try:
            await apply_retention(db, now=now(), logs_origin=logs_origin, stop=stop)
        except Exception:
            logger.exception("Retention pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
        except TimeoutError:
            pass
