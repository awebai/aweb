"""The purge ledger: Logs' erasure fence across a restore (audit-substrate.md
§B6; D1's backup-tombstone rule, agent-pages.md §11).

Every purge first records a tombstone here, keyed by event id, and commits it
before the content is purged. The ledger is a database of its own, never
restored from a content backup. Before Logs serves, it purges every event that
has a tombstone and still holds content (:func:`reapply_purges`), and ingest
appends a redelivered event that has one already purged. So a restored
content database never serves content purged after its backup, and a
producer's redelivery cannot bring it back.

A crash between the tombstone and the purge leaves the tombstone with its
content still present; the next start finishes the purge.

Each start also tombstones every event the content database already holds
purged (:func:`record_existing_purges`), so purges made before the ledger
existed, or committed before a crash lost their tombstone's commit order, are
fenced from then on. That baseline is taken from the database Logs starts on:
the first start of a Logs with this ledger must be on the live content
database, not on a restored one.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from aweb_naapp.runtime.db import require_separate_database
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "purge_ledger_migrations"
MIGRATIONS_MODULE = "aweb_logs_purge_ledger"


async def apply_purge_ledger_migrations(
    content: AsyncDatabaseManager, ledger: AsyncDatabaseManager
) -> None:
    """Migrate the purge ledger, refusing one that is not a database of its own."""
    await require_separate_database(content, ledger, ledger_name="purge ledger")
    await AsyncMigrationManager(
        ledger, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


class PurgeLedger:
    """The tombstones of every event Logs purged."""

    def __init__(self, db: AsyncDatabaseManager) -> None:
        self.db = db

    async def record(self, team_id: str, events: Sequence[tuple[UUID, str]], *, act: str) -> None:
        """Commit a tombstone for each ``(event_id, event_hash)`` of the team's
        events, naming ``act``. An event already tombstoned keeps its first act."""
        if not events:
            return
        await self.db.execute(
            "INSERT INTO {{tables.event_purges}} (team_id, event_id, event_hash, purge_act)"
            " SELECT $1, event_id, event_hash, $4"
            " FROM unnest($2::uuid[], $3::text[]) AS t(event_id, event_hash)"
            " ON CONFLICT (team_id, event_id) DO NOTHING",
            team_id,
            [event_id for event_id, _ in events],
            [event_hash for _, event_hash in events],
            act,
        )

    async def act(self, team_id: str, event_id: UUID) -> str | None:
        """The act that purged this event, or None when it was never purged."""
        return await self.db.fetch_value(
            "SELECT purge_act FROM {{tables.event_purges}} WHERE team_id = $1 AND event_id = $2",
            team_id,
            event_id,
        )

    async def tombstones(self) -> list[tuple[str, UUID, str]]:
        """Every tombstone, as ``(team_id, event_id, act)``."""
        rows = await self.db.fetch_all(
            "SELECT team_id, event_id, purge_act FROM {{tables.event_purges}}"
            " ORDER BY team_id, purged_at, event_id"
        )
        return [(row["team_id"], row["event_id"], row["purge_act"]) for row in rows]


async def record_existing_purges(content: AsyncDatabaseManager, ledger: PurgeLedger) -> None:
    """Tombstone every event ``content`` holds purged, naming its purge act.
    Events already tombstoned keep their first act."""
    acts: dict[tuple[str, str], list[tuple[UUID, str]]] = {}
    for row in await content.fetch_all(
        "SELECT team_id, event_id, event_hash, purge_act FROM {{tables.chain_events}}"
        " WHERE purge_act IS NOT NULL"
    ):
        acts.setdefault((row["team_id"], row["purge_act"]), []).append(
            (row["event_id"], row["event_hash"])
        )
    for (team_id, act), events in acts.items():
        await ledger.record(team_id, events, act=act)
