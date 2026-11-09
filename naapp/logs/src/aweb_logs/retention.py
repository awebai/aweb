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
from datetime import UTC, datetime

from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs import read_store

logger = logging.getLogger(__name__)

RETENTION_ACT = "logs.retention.set"
ALL_EVENTS = "all"
_BATCH = 500

# A team's events with content whose class's retention has expired, earliest
# first, each with the setting that expires it. A hook's own setting comes
# before the team's "all" setting; an event no setting names is kept.
_EXPIRED = (
    "SELECT e.chain_epoch, e.team_seq, s.setting_id"
    " FROM {{tables.chain_events}} e"
    " CROSS JOIN LATERAL ("
    "   SELECT r.setting_id, r.retention_days FROM {{tables.retention_settings}} r"
    "   WHERE r.team_id = e.team_id AND r.event_class IN (e.hook, '" + ALL_EVENTS + "')"
    "   ORDER BY r.event_class = '" + ALL_EVENTS + "' LIMIT 1"
    " ) s"
    " WHERE e.team_id = $1 AND e.purge_act IS NULL AND s.retention_days IS NOT NULL"
    "   AND e.received_at < to_char("
    "     ($2::timestamptz - make_interval(days => s.retention_days)) AT TIME ZONE 'UTC',"
    '     \'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"\')'
    " ORDER BY e.chain_epoch, e.team_seq LIMIT $3"
    " FOR UPDATE OF e SKIP LOCKED"
)


async def set_retention(
    db: AsyncDatabaseManager | TransactionManager,
    team_id: str,
    event_class: str,
    *,
    days: int | None,
) -> str:
    """Set how long a class of the team's events keeps its content: ``days``,
    or ``None`` to keep it. Returns the setting's id, which a purge it causes
    names in its act."""
    setting_id = await db.fetch_value(
        "INSERT INTO {{tables.retention_settings}} (team_id, event_class, retention_days, setting_id)"
        " VALUES ($1, $2, $3, gen_random_uuid())"
        " ON CONFLICT (team_id, event_class) DO UPDATE"
        " SET retention_days = EXCLUDED.retention_days, setting_id = EXCLUDED.setting_id,"
        "     set_at = NOW()"
        " RETURNING setting_id",
        team_id,
        event_class,
        days,
    )
    return str(setting_id)


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


async def apply_retention(db: AsyncDatabaseManager, *, now: datetime, batch: int = _BATCH) -> int:
    """Purge every event a team's retention has expired at ``now``, one batch
    per transaction. Returns how many events it purged."""
    teams = await db.fetch_all(
        "SELECT DISTINCT team_id FROM {{tables.retention_settings}}"
        " WHERE retention_days IS NOT NULL ORDER BY team_id"
    )
    total = 0
    for row in teams:
        team_id = row["team_id"]
        while True:
            async with db.transaction() as tx:
                expired = await tx.fetch_all(_EXPIRED, team_id, now, batch)
                by_setting: dict[str, list[tuple[int, int]]] = {}
                for event in expired:
                    by_setting.setdefault(str(event["setting_id"]), []).append(
                        (event["chain_epoch"], event["team_seq"])
                    )
                for setting_id, positions in by_setting.items():
                    total += await purge(
                        tx, team_id, positions, act=f"{RETENTION_ACT}:{setting_id}"
                    )
            if len(expired) < batch:
                break
    return total


async def run_retention(
    db: AsyncDatabaseManager,
    *,
    interval_seconds: float,
    stop: asyncio.Event,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Apply retention every ``interval_seconds`` until ``stop`` is set. A
    failing pass is logged and tried again at the next interval."""
    while not stop.is_set():
        try:
            await apply_retention(db, now=now())
        except Exception:
            logger.exception("Retention pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
        except TimeoutError:
            pass
