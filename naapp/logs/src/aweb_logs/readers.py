"""The readers of a team's log: humans an owner act designates, who read only
in a passkey session on logs' console origin (audit-substrate.md §B5).

Each reader has a B3 scope of its own, a slot ``logs.reader.<32 hex>`` that
logs draws at random before the owner signs and binds to the installation,
the team and the hash of the contact the owner act must name. The scope is
public in the reader's governance events, so it is never derived from the
contact. The owner signs the exact slot; an act naming a slot for another
installation, team or contact, or an expired or already claimed one, claims
nothing. A pending slot grants nothing. A claimed slot is the reader's scope
for good, through enrolment, contact changes and recovery, and it says which
team its sessions read.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

READER_ROLE = "logs.reader"
SLOT_TTL = timedelta(hours=1)
_SCOPE = re.compile(r"logs\.reader\.[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def is_reader_scope(scope: str) -> bool:
    return _SCOPE.fullmatch(scope) is not None


class ReaderRefused(Exception):
    """No pending, unexpired slot issued for this installation, team and contact."""

    code = "owner_required"


@dataclass(frozen=True)
class Slot:
    scope: str
    expires_at: datetime


@dataclass(frozen=True)
class Reader:
    scope: str
    installation_id: str
    team_id: str


class ReaderDirectory:
    """The reader slots of this deployment, pending and claimed."""

    def __init__(self, db: AsyncDatabaseManager, *, slot_ttl: timedelta = SLOT_TTL) -> None:
        self._db = db
        self._slot_ttl = slot_ttl

    async def create_slot(self, *, installation_id: str, team_id: str, contact_sha256: str) -> Slot:
        """Issue a pending slot for the reader the owner will designate at this contact."""
        if not _SHA256.fullmatch(contact_sha256):
            raise ValueError("a reader's contact is named by its SHA-256")
        scope = f"{READER_ROLE}.{secrets.token_hex(16)}"
        expires_at = await self._db.fetch_value(
            "INSERT INTO {{tables.readers}}"
            " (scope, installation_id, team_id, contact_sha256, expires_at)"
            " VALUES ($1, $2, $3, $4, NOW() + $5) RETURNING expires_at",
            scope,
            installation_id,
            team_id,
            contact_sha256,
            self._slot_ttl,
        )
        return Slot(scope=scope, expires_at=expires_at)

    async def claim(
        self,
        tx: TransactionManager,
        *,
        scope: str,
        installation_id: str,
        team_id: str,
        contact_sha256: str,
    ) -> Reader:
        """Claim, in the designating transaction, the pending slot the owner act names."""
        claimed = await tx.fetch_value(
            "UPDATE {{tables.readers}} SET claimed_at = NOW()"
            " WHERE scope = $1 AND installation_id = $2 AND team_id = $3"
            " AND contact_sha256 = $4 AND claimed_at IS NULL AND expires_at > NOW()"
            " RETURNING scope",
            scope,
            installation_id,
            team_id,
            contact_sha256,
        )
        if claimed is None:
            raise ReaderRefused("no pending slot for this act")
        return Reader(scope=scope, installation_id=installation_id, team_id=team_id)

    async def reader(self, scope: str) -> Reader | None:
        if not is_reader_scope(scope):
            return None
        row = await self._db.fetch_one(
            "SELECT scope, installation_id, team_id FROM {{tables.readers}}"
            " WHERE scope = $1 AND claimed_at IS NOT NULL",
            scope,
        )
        return Reader(**row) if row is not None else None

    async def readers(self, *, installation_id: str, team_id: str) -> list[Reader]:
        rows = await self._db.fetch_all(
            "SELECT scope, installation_id, team_id FROM {{tables.readers}}"
            " WHERE installation_id = $1 AND team_id = $2 AND claimed_at IS NOT NULL"
            " ORDER BY scope",
            installation_id,
            team_id,
        )
        return [Reader(**row) for row in rows]
