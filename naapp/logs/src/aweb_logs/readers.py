"""The readers of a team's log: humans an owner act designates, who read only
in a passkey session on logs' console origin (audit-substrate.md §B5).

Each reader has a B3 scope of its own, derived from the installation, the team
and the hash of the contact the owner act names. The owner signs that exact
scope, and logs designates only a scope it derived from the act's own
installation, team and contact. A session's scope therefore says which team it
reads, and nothing else does.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

READER_ROLE = "logs.reader"
_SCOPE = re.compile(r"logs\.reader\.[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def reader_scope(installation_id: str, team_id: str, contact_sha256: str) -> str:
    """The B3 scope of the reader of ``team_id``'s installation reached at the
    contact whose SHA-256 is ``contact_sha256``."""
    if not _SHA256.fullmatch(contact_sha256):
        raise ValueError("a reader's contact is named by its SHA-256")
    named = f"{installation_id}\n{team_id}\n{contact_sha256}".encode()
    return f"{READER_ROLE}.{hashlib.sha256(named).hexdigest()[:40]}"


def is_reader_scope(scope: str) -> bool:
    return _SCOPE.fullmatch(scope) is not None


@dataclass(frozen=True)
class Reader:
    scope: str
    installation_id: str
    team_id: str
    contact_sha256: str


class ReaderDirectory:
    """The readers designated on this deployment, by scope."""

    def __init__(self, db: AsyncDatabaseManager) -> None:
        self._db = db

    async def record(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, contact_sha256: str
    ) -> str:
        """Record, in the designating transaction, the reader an owner act names; return its scope."""
        scope = reader_scope(installation_id, team_id, contact_sha256)
        await tx.execute(
            "INSERT INTO {{tables.readers}} (scope, installation_id, team_id, contact_sha256)"
            " VALUES ($1, $2, $3, $4) ON CONFLICT (scope) DO NOTHING",
            scope,
            installation_id,
            team_id,
            contact_sha256,
        )
        return scope

    async def reader(self, scope: str) -> Reader | None:
        if not is_reader_scope(scope):
            return None
        row = await self._db.fetch_one(
            "SELECT scope, installation_id, team_id, contact_sha256 FROM {{tables.readers}}"
            " WHERE scope = $1",
            scope,
        )
        return Reader(**row) if row is not None else None

    async def readers(self, *, installation_id: str, team_id: str) -> list[Reader]:
        rows = await self._db.fetch_all(
            "SELECT scope, installation_id, team_id, contact_sha256 FROM {{tables.readers}}"
            " WHERE installation_id = $1 AND team_id = $2 ORDER BY scope",
            installation_id,
            team_id,
        )
        return [Reader(**row) for row in rows]
