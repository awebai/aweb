"""secrets' owners and approvers as B3 scopes (decisions 40 and 41).

B3 keeps one approver per scope, and a scope is unique across the database.
So each owner has its own scope, named from the installation, its team and
the owner's stable principal (S5's principal_did), and each approver its own,
named from the installation, its team and the approver's reference. Hashing keeps the name inside
the role token of an ``aweb.owner-act/1`` subject; the request that designates
an owner carries the principal, and the app recomputes the scope from it.

An owner scope's approver is designated only by a team owner act. Any other
scope's approver may be designated by an owner's approval of a change set.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.roles import PrincipalKey, assign, has_role
from aweb_naapp.runtime.approvals import ActionPolicy, Approver
from aweb_naapp.runtime.passkeys import (
    Designation,
    DesignationRefused,
    Passkeys,
    contact_sha256,
)
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
    """Record, in the designating transaction, which principal an owner scope stands for.

    Returns the scope. A scope already recorded for another installation, team
    or principal is refused as ``owner_required``, never silently kept."""
    scope = owner_scope(installation_id, principal.team_id, principal.principal_did)
    recorded = await tx.fetch_one(
        """
        INSERT INTO {{tables.owner_principals}} (scope, installation_id, team_id, principal_did)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (scope) DO UPDATE SET scope = EXCLUDED.scope
        RETURNING installation_id, team_id, principal_did
        """,
        scope,
        installation_id,
        principal.team_id,
        principal.principal_did,
    )
    assert recorded is not None
    if (recorded["installation_id"], recorded["team_id"], recorded["principal_did"]) != (
        installation_id,
        principal.team_id,
        principal.principal_did,
    ):
        raise OwnerRequired("the owner scope is recorded for another owner")
    return scope


@dataclass(frozen=True)
class Drafter:
    """Who drafted a change set, as far as the directory can tell."""

    principal_did: str | None = None
    scope: str | None = None


class OwnerDirectory:
    """The approver directory secrets gives B2 (decisions 34 and 54).

    An owner scope's approver is a candidate only while its B3 designation is
    current and enrolled and its recorded principal holds secrets.owner on its
    team. Both are read again on every question, so revoking the role stops
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

    async def candidates(self, policy: ActionPolicy, request: Mapping[str, Any]) -> list[Approver]:
        drafter = Drafter() if policy.allow_requester_approval else await self._drafter(request)
        found: list[Approver] = []
        for scope in policy.approver_scopes:
            if scope == drafter.scope:
                continue
            principal = await self._owner(scope)
            if is_owner_scope(scope) and principal is None:
                continue
            approver = await self._passkeys.designated_approver(scope)
            if approver is None:
                continue
            if principal is not None:
                if principal.principal_did == drafter.principal_did:
                    continue
                approver = replace(approver, principal_did=principal.principal_did)
            found.append(approver)
        return found

    async def is_current(self, scope: str, subject: str) -> bool:
        if is_owner_scope(scope) and await self._owner(scope) is None:
            return False
        return await self._passkeys.is_current(scope, subject)

    async def _owner(self, scope: str) -> PrincipalKey | None:
        """The owner a scope stands for, while it holds secrets.owner; None
        for a scope that is not an owner scope or whose owner lost the role."""
        if not is_owner_scope(scope):
            return None
        row = await self._db.fetch_one(
            "SELECT team_id, principal_did FROM {{tables.owner_principals}} WHERE scope = $1",
            scope,
        )
        if row is None:
            return None
        principal = PrincipalKey(team_id=row["team_id"], principal_did=row["principal_did"])
        return principal if await has_role(self._db, principal, OWNER_ROLE) else None

    async def _drafter(self, request: Mapping[str, Any]) -> Drafter:
        """Who drafted a change set: a member's principal, or the console scope
        that drafted it with the owner it stands for, if it is an owner scope."""
        if request.get("type") != CHANGE_TYPE:
            return Drafter()
        drafter = request.get("drafter") or {}
        if drafter.get("via") == "team_auth":
            return Drafter(principal_did=drafter.get("principal"))
        if drafter.get("via") == "console":
            scope = drafter.get("scope")
            principal_did = await self._db.fetch_value(
                "SELECT principal_did FROM {{tables.owner_principals}} WHERE scope = $1", scope
            )
            return Drafter(principal_did=principal_did, scope=scope)
        return Drafter()
        drafter = request.get("drafter") or {}
        if drafter.get("via") == "team_auth":
            return drafter.get("principal")
        if drafter.get("via") == "console":
            return await self._db.fetch_value(
                "SELECT principal_did FROM {{tables.owner_principals}} WHERE scope = $1",
                drafter.get("scope"),
            )
        return None


async def apply_owner_act(
    db: AsyncDatabaseManager,
    passkeys: Passkeys,
    verifier: OwnerActVerifier,
    *,
    signing: bytes,
    signature: str,
    app_id: str,
    installation_id: str,
    installation_team_id: str,
    principal: PrincipalKey,
    contact: str,
) -> Designation:
    """Make ``principal`` an owner on the strength of the team owner act (design §10.2).

    ``principal`` comes from the request body; the controller's act is the
    only authority for it. The principal must be on the team the installation
    belongs to: ``installation_team_id`` comes from the app's installation
    record, never from the request. The act must be signed by the current
    controller key of that team and name exactly this installation, this
    principal's owner scope and this contact. ``app-role.designate`` makes the scope's first owner;
    ``app-credential.recover`` replaces it after the cooling-off. In one
    transaction the act's nonce is consumed, the principal is given
    secrets.owner and recorded as the scope's owner, and the scope is
    designated. Anything less is ``owner_required``, and nothing changes.
    Deliver the returned designation after this returns.
    """
    if principal.team_id != installation_team_id:
        raise OwnerRequired("the principal is not on the installation's team")
    scope = owner_scope(installation_id, principal.team_id, principal.principal_did)
    expected_subject = {
        "app_id": app_id,
        "installation_id": installation_id,
        "role": scope,
        "contact_sha256": contact_sha256(contact),
    }
    try:
        prepared = await verifier.prepare(signing, signature, team_id=principal.team_id)
        async with db.transaction() as tx:
            act = await verifier.consume_in(tx, prepared, expected_subject=expected_subject)
            await record_owner(tx, installation_id=installation_id, principal=principal)
            await assign(tx, principal, OWNER_ROLE)
            return await passkeys.designate(tx, scope=scope, contact=contact, evidence=act)
    except (Refused, DesignationRefused, OwnerRequired) as exc:
        raise OwnerRequired(str(exc)) from None
