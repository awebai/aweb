"""The shared role assignments of a naapp, keyed by stable principal.

A principal is ``(team_id, principal_did)``. ``principal_did`` is the
``member_did_aw`` of the member's team certificate when it carries one, else
its ``member_did_key``. The team controller's signature over the certificate
asserts that binding, which is sound for roles inside that team. It does not
prove that the did:key is the did:aw's current registry key, and nothing here
reads or claims that check. A did:aw is never a principal across teams.

An assignment belongs to the derived ``principal_did``. A member with a did:aw
keeps its roles through a reissued certificate under that did:aw. A member
without one is its key: after a key rotation, or once its certificate carries a
did:aw, it is a new principal holding none of the old roles. The two forms are
never matched against each other.

Role names are app-named: dot-separated segments of ``[a-z0-9][a-z0-9_-]*``,
at least two, the first naming the app (``secrets.owner``, ``logs.reader``),
and at most 128 characters.

Imports only the standard library and pgdbm, so it needs no naapp runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_roles"

MAX_ROLE_NAME_LENGTH = 128
_ROLE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+")

type Executor = AsyncDatabaseManager | TransactionManager


class TargetUnresolved(Exception):
    """The role is held by no principal of the team, or by more than one."""

    code = "target_unresolved"
    status = 422


class CertifiedMember(Protocol):
    """The certificate facts a principal is derived from, as team-auth verifies them."""

    @property
    def team_id(self) -> str: ...

    @property
    def did_key(self) -> str: ...

    @property
    def did_aw(self) -> str | None: ...


@dataclass(frozen=True)
class PrincipalKey:
    team_id: str
    principal_did: str


def is_role_name(role: str) -> bool:
    return len(role) <= MAX_ROLE_NAME_LENGTH and _ROLE_NAME.fullmatch(role) is not None


def principal_key(member: CertifiedMember) -> PrincipalKey:
    """The principal a verified team certificate's member acts as."""
    if not member.team_id:
        raise ValueError("a principal needs a team")
    if member.did_aw is not None:
        if not member.did_aw.startswith("did:aw:"):
            raise ValueError("a certificate's member_did_aw must be a did:aw")
        return PrincipalKey(team_id=member.team_id, principal_did=member.did_aw)
    if not member.did_key.startswith("did:key:"):
        raise ValueError("a certificate's member_did_key must be a did:key")
    return PrincipalKey(team_id=member.team_id, principal_did=member.did_key)


def _require_role_name(role: str) -> None:
    if not is_role_name(role):
        raise ValueError("a role name is app-named: dot-separated lowercase segments")


async def apply_roles_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def assign(tx: TransactionManager, principal: PrincipalKey, role: str) -> None:
    """Give ``principal`` the role in the caller's transaction; assigning twice is one assignment."""
    _require_role_name(role)
    await tx.execute(
        """
        INSERT INTO {{tables.role_assignments}} (team_id, principal_did, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (team_id, principal_did, role) DO NOTHING
        """,
        principal.team_id,
        principal.principal_did,
        role,
    )


async def unassign(tx: TransactionManager, principal: PrincipalKey, role: str) -> None:
    """Take the role from ``principal`` in the caller's transaction."""
    _require_role_name(role)
    await tx.execute(
        """
        DELETE FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND principal_did = $2 AND role = $3
        """,
        principal.team_id,
        principal.principal_did,
        role,
    )


async def purge_team(tx: TransactionManager, team_id: str) -> None:
    """Remove every role assignment of the team in the caller's transaction.

    Assignments are authority: an app purges them when its installation for the
    team is uninstalled or replaced by a new one, so a reinstall starts with no
    roles. A role resolved in a transaction still open is purged once it ends.
    """
    await tx.execute("DELETE FROM {{tables.role_assignments}} WHERE team_id = $1", team_id)


async def has_role(db: Executor, principal: PrincipalKey, role: str) -> bool:
    """Whether ``principal`` holds the role now, without locking the assignment.

    For read-only checks, such as listing what a member may see. When a
    transaction acts on the role's authority and commits evidence of it, use
    :func:`hold_role` instead, so the role cannot be withdrawn under it.
    """
    _require_role_name(role)
    return bool(
        await db.fetch_value(
            """
            SELECT EXISTS (
                SELECT 1 FROM {{tables.role_assignments}}
                WHERE team_id = $1 AND principal_did = $2 AND role = $3
            )
            """,
            principal.team_id,
            principal.principal_did,
            role,
        )
    )


async def hold_role(tx: TransactionManager, principal: PrincipalKey, role: str) -> bool:
    """Whether ``principal`` holds the role, holding the assignment until the transaction ends.

    True locks the assignment row: an unassign or a purge of the team waits
    until the caller's transaction commits or rolls back, so evidence written
    on the role's authority commits while the role is still held. False means
    there is no assignment now; a withdrawal committed first is seen.

    Lock order for a transaction that acts on a role: the installation fence
    first, then this hold, then approval and candidate locks, then the
    transaction's own writes. A withdrawal of the role (an unassign, a team
    purge, an owner revocation, an installation retirement) takes the same
    order: the installation fence first when it needs it, then the role's row
    through :func:`unassign` or :func:`purge_team`, then any approval locks,
    so the two orders never cycle.
    """
    _require_role_name(role)
    held = await tx.fetch_value(
        """
        SELECT 1 FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND principal_did = $2 AND role = $3
        FOR SHARE
        """,
        principal.team_id,
        principal.principal_did,
        role,
    )
    return held is not None


async def roles_of(db: Executor, principal: PrincipalKey) -> list[str]:
    """The roles ``principal`` holds, in name order."""
    rows = await db.fetch_all(
        """
        SELECT role FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND principal_did = $2
        ORDER BY role
        """,
        principal.team_id,
        principal.principal_did,
    )
    return [row["role"] for row in rows]


async def members_of(db: Executor, team_id: str, role: str) -> list[PrincipalKey]:
    """The team's principals holding the role, in ``principal_did`` order."""
    _require_role_name(role)
    rows = await db.fetch_all(
        """
        SELECT principal_did FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND role = $2
        ORDER BY principal_did
        """,
        team_id,
        role,
    )
    return [PrincipalKey(team_id=team_id, principal_did=row["principal_did"]) for row in rows]


async def resolve_one(tx: TransactionManager, team_id: str, role: str) -> PrincipalKey:
    """The one principal of the team holding the role, read in the caller's transaction.

    The assignment it resolves is locked until that transaction ends, so the
    caller can freeze the result before the role can be taken away. Raises
    :class:`TargetUnresolved`, naming no member, when nobody or more than one
    principal holds the role. It never falls back to another principal.
    """
    _require_role_name(role)
    rows = await tx.fetch_all(
        """
        SELECT principal_did FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND role = $2
        ORDER BY principal_did
        LIMIT 2
        FOR SHARE
        """,
        team_id,
        role,
    )
    if len(rows) != 1:
        raise TargetUnresolved("the role does not resolve to exactly one principal")
    return PrincipalKey(team_id=team_id, principal_did=rows[0]["principal_did"])
