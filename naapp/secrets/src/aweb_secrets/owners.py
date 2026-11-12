"""Secrets owner projections over the canonical shared human-role store.

The owner migration hands existing scope history to role_holdings without
changing assignments or B3 credentials. Reads of authority require that shared
holding; context-only reads can use its retained record after containment or
revocation. The old owner_principals map is migration history, never authority.
Owner bindings and credential replacement use the shared human-role writers;
the legacy contact-model entry refuses every scope.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from aweb_naapp import roles
from aweb_naapp.roles import PrincipalKey
from aweb_naapp.runtime.approvals import ActionPolicy, Approver
from aweb_naapp.runtime.passkeys import Passkeys
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.change import TYPE as CHANGE_TYPE

MIGRATIONS_PATH = Path(__file__).resolve().parent / "owner_migrations"
MIGRATIONS_MODULE = "aweb_secrets_owners"

OWNER_ROLE = "secrets.owner"
_OWNER_SCOPE = re.compile(r"secrets\.owner\.[0-9a-f]{40}")


def _segment(installation_id: str, team_id: str, name: str) -> str:
    named = f"{installation_id}\n{team_id}\n{name}"
    return hashlib.sha256(named.encode()).hexdigest()[:40]


def owner_scope(installation_id: str, team_id: str, principal_did: str) -> str:
    """The B3 scope of ``principal_did`` of ``team_id`` as an owner of the installation."""
    return f"secrets.owner.{_segment(installation_id, team_id, principal_did)}"


def approver_scope(installation_id: str, team_id: str, approver_ref: str) -> str:
    """The B3 scope of the installation's approver ``approver_ref``."""
    return f"secrets.approver.{_segment(installation_id, team_id, approver_ref)}"


def is_owner_scope(scope: str) -> bool:
    return _OWNER_SCOPE.fullmatch(scope) is not None


class OwnerRequired(Exception):
    """The act is not the team owner's act naming this principal, contact and installation."""

    code = "owner_required"


async def apply_owner_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def record_owner(
    tx: TransactionManager, *, installation_id: str, principal: PrincipalKey
) -> str:
    """The legacy owner writer is retired for every scope."""
    raise OwnerRequired("owner_required")


async def owner_record(
    db: AsyncDatabaseManager | TransactionManager, scope: str
) -> roles.HoldingRecord | None:
    """Resolve scope history for context only; a record grants no authority."""
    if not is_owner_scope(scope):
        return None
    record = await roles.holding_record_of_scope(db, scope)
    if record is None or record.role != OWNER_ROLE:
        return None
    if scope != roles.holding_scope(
        record.installation_id, record.team_id, OWNER_ROLE, record.principal
    ):
        return None
    return record


async def owner_binding(
    db: AsyncDatabaseManager | TransactionManager,
    scope: str,
    *,
    installation_id: str | None = None,
    team_id: str | None = None,
) -> dict[str, str] | None:
    """App context projection of shared history, never a current holding."""
    record = await owner_record(db, scope)
    if (
        record is None
        or (installation_id is not None and record.installation_id != installation_id)
        or (team_id is not None and record.team_id != team_id)
    ):
        return None
    return dict(
        scope=record.b3_scope,
        installation_id=record.installation_id,
        team_id=record.team_id,
        principal_did=record.principal,
    )


async def owner_holding(
    db: AsyncDatabaseManager | TransactionManager, scope: str
) -> roles.Holding | None:
    """The canonical live assignment and installation record, never old history."""
    if not is_owner_scope(scope):
        return None
    held = await roles.read_holding_of_scope(db, scope)
    return held if held is not None and held.role == OWNER_ROLE else None


async def has_owner(
    db: AsyncDatabaseManager | TransactionManager, principal: PrincipalKey, *, installation_id: str
) -> bool:
    return (
        await roles.read_holding(
            db,
            installation_id=installation_id,
            team_id=principal.team_id,
            role=OWNER_ROLE,
            principal=principal.principal_did,
        )
        is not None
    )


async def hold_owner(
    tx: TransactionManager, principal: PrincipalKey, *, installation_id: str
) -> bool:
    """Hold the complete canonical holding in the caller's original transaction."""
    return (
        await roles.hold_holding(
            tx,
            installation_id=installation_id,
            team_id=principal.team_id,
            role=OWNER_ROLE,
            principal=principal.principal_did,
        )
        is not None
    )


@dataclass(frozen=True)
class Drafter:
    """Who drafted a change set, as far as the directory can tell."""

    principal_did: str | None = None
    scope: str | None = None


class OwnerDirectory:
    """The approver directory secrets gives B2 (decisions 34 and 54).

    An owner scope's approver is a candidate only while its B3 designation is
    current and enrolled and the shared store retains its current holding in
    the installation. Both are read again on every question, so revoking the role stops
    that owner at once. Any other scope's approver is B3's alone: approvers
    are not a DID role (design §4.2).

    B2 leaves the requester out by comparing ``requested_by`` with each
    candidate's subject, which for a passkey designation is never a principal.
    So when a policy does not allow the requester to approve, this directory
    leaves out whoever drafted the change set itself: the drafting principal,
    and for a console draft, the scope that drafted it, owner or approver."""

    def __init__(self, passkeys: Passkeys, db: AsyncDatabaseManager) -> None:
        self._passkeys = passkeys
        self._db = db

    async def candidates(
        self,
        policy: ActionPolicy,
        request: Mapping[str, Any],
        *,
        tx: TransactionManager | None = None,
    ) -> list[Approver]:
        drafter = (
            Drafter() if policy.allow_requester_approval else await self._drafter(request, tx=tx)
        )
        found: list[Approver] = []
        for scope in policy.approver_scopes:
            if scope == drafter.scope:
                continue
            principal = await self._owner(scope, tx=tx)
            if is_owner_scope(scope) and principal is None:
                continue
            approver = await self._passkeys.designated_approver(scope, tx=tx)
            if approver is None:
                continue
            if principal is not None:
                if principal.principal_did == drafter.principal_did:
                    continue
                approver = replace(approver, principal_did=principal.principal_did)
            found.append(approver)
        return found

    async def is_current(
        self, scope: str, subject: str, *, tx: TransactionManager | None = None
    ) -> bool:
        if is_owner_scope(scope) and await self._owner(scope, tx=tx) is None:
            return False
        return await self._passkeys.is_current(scope, subject, tx=tx)

    async def enrolled_owners(
        self, db: AsyncDatabaseManager | TransactionManager, *, installation_id: str, team_id: str
    ) -> list[PrincipalKey]:
        """The installation's owners that hold secrets.owner and have an enrolled,
        in-effect passkey. Roles are read through ``db``, so a caller's own
        uncommitted role change counts."""
        if isinstance(db, AsyncDatabaseManager):
            async with db.transaction() as tx:
                return await self.enrolled_owners(
                    tx, installation_id=installation_id, team_id=team_id
                )
        rows = await db.fetch_all(
            "SELECT b3_scope, principal_did FROM {{tables.role_holdings}}"
            " WHERE installation_id=$1 AND team_id=$2 AND role=$3 ORDER BY principal_did",
            installation_id,
            team_id,
            OWNER_ROLE,
        )
        owners: list[PrincipalKey] = []
        for row in rows:
            if await owner_holding(db, row["b3_scope"]) is None:
                continue
            if await self._passkeys.current_subject_in(db, row["b3_scope"]) is None:
                continue
            owners.append(PrincipalKey(team_id, row["principal_did"]))
        return owners

    async def owner_of(
        self, db: AsyncDatabaseManager | TransactionManager, scope: str
    ) -> PrincipalKey | None:
        """The owner an owner scope stands for, while it holds secrets.owner,
        read through ``db``; None for any other scope."""
        held = await owner_holding(db, scope)
        return None if held is None else PrincipalKey(held.team_id, held.principal)

    async def _owner(
        self, scope: str, *, tx: TransactionManager | None = None
    ) -> PrincipalKey | None:
        """The owner a scope stands for, while it holds secrets.owner; None
        for a scope that is not an owner scope or whose owner lost the role."""
        return await self.owner_of(tx or self._db, scope)

    async def _drafter(
        self, request: Mapping[str, Any], *, tx: TransactionManager | None = None
    ) -> Drafter:
        """Who drafted a change set: a member's principal, or the console scope
        that drafted it with the owner it stands for, if it is an owner scope."""
        if request.get("type") != CHANGE_TYPE:
            return Drafter()
        drafter = request.get("drafter") or {}
        if drafter.get("via") == "team_auth":
            return Drafter(principal_did=drafter.get("principal"))
        if drafter.get("via") == "console":
            scope = drafter.get("scope")
            record = (
                None if not isinstance(scope, str) else await owner_record(tx or self._db, scope)
            )
            return Drafter(principal_did=None if record is None else record.principal, scope=scope)
        return Drafter()
