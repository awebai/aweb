"""secrets' owners and approvers as B3 scopes (decisions 40 and 41).

B3 keeps one approver per scope, and a scope is unique across the database.
So each owner has its own scope, named from the installation and the owner's
stable principal (S5's principal_did), and each approver its own, named from
the installation and the approver's reference. Hashing keeps the name inside
the role token of an ``aweb.owner-act/1`` subject; the request that designates
an owner carries the principal, and the app recomputes the scope from it.

An owner scope's approver is designated only by a team owner act. Any other
scope's approver may be designated by an owner's approval of a change set.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from aweb_naapp.roles import PrincipalKey, has_role
from aweb_naapp.runtime.approvals import ActionPolicy, Approver
from aweb_naapp.runtime.passkeys import Passkeys
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "owner_migrations"
MIGRATIONS_MODULE = "aweb_secrets_owners"

OWNER_ROLE = "secrets.owner"
_OWNER_SCOPE = re.compile(r"secrets\.owner\.[0-9a-f]{40}")


def _segment(installation_id: str, name: str) -> str:
    return hashlib.sha256(f"{installation_id}\n{name}".encode()).hexdigest()[:40]


def owner_scope(installation_id: str, principal_did: str) -> str:
    """The B3 scope of ``principal_did`` as an owner of the installation."""
    return f"secrets.owner.{_segment(installation_id, principal_did)}"


def approver_scope(installation_id: str, approver_ref: str) -> str:
    """The B3 scope of the installation's approver ``approver_ref``."""
    return f"secrets.approver.{_segment(installation_id, approver_ref)}"


def is_owner_scope(scope: str) -> bool:
    return _OWNER_SCOPE.fullmatch(scope) is not None


async def apply_owner_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def record_owner(
    tx: TransactionManager, *, installation_id: str, principal: PrincipalKey
) -> str:
    """Record, in the designating transaction, which principal an owner scope stands for.

    Returns the scope."""
    scope = owner_scope(installation_id, principal.principal_did)
    await tx.execute(
        """
        INSERT INTO {{tables.owner_principals}} (scope, installation_id, team_id, principal_did)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (scope) DO NOTHING
        """,
        scope,
        installation_id,
        principal.team_id,
        principal.principal_did,
    )
    return scope


class OwnerDirectory:
    """The approver directory secrets gives B2 (decision 34).

    An owner scope's approver decides only while its B3 designation is current
    and its principal holds secrets.owner on its team, read again on every
    question, so revoking the role stops the owner at once. Any other scope's
    approver is B3's alone: approvers are not a DID role (design §4.2)."""

    def __init__(self, passkeys: Passkeys, db: AsyncDatabaseManager) -> None:
        self._passkeys = passkeys
        self._db = db

    async def designated_approver(self, policy: ActionPolicy) -> Approver | None:
        if not await self._owner_holds_role(policy.approver_scope):
            return None
        return await self._passkeys.designated_approver(policy)

    async def is_current(self, approver_subject: str, policy: ActionPolicy) -> bool:
        return await self._owner_holds_role(policy.approver_scope) and (
            await self._passkeys.is_current(approver_subject, policy)
        )

    async def _owner_holds_role(self, scope: str) -> bool:
        if not is_owner_scope(scope):
            return True
        row = await self._db.fetch_one(
            "SELECT team_id, principal_did FROM {{tables.owner_principals}} WHERE scope = $1",
            scope,
        )
        if row is None:
            return False
        principal = PrincipalKey(team_id=row["team_id"], principal_did=row["principal_did"])
        return await has_role(self._db, principal, OWNER_ROLE)
