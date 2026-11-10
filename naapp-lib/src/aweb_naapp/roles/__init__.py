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

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

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


def holding_scope(installation_id: str, team_id: str, role: str, principal: str) -> str:
    """The B3 scope of ``principal``'s holding of ``role`` in the installation.

    It is named by the installation, the team and the principal; the role is
    its prefix only, so the scope of ``secrets.owner`` is the one secrets has
    always given its owners. A holding is never named from a contact.
    """
    _require_role_name(role)
    if not principal.startswith("did:aw:") or principal == "did:aw:":
        raise ValueError("a human role is held by a did:aw principal")
    named = f"{installation_id}\n{team_id}\n{principal}"
    return f"{role}.{hashlib.sha256(named.encode()).hexdigest()[:40]}"


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


@dataclass(frozen=True)
class Holding:
    """A principal's holding of a human role in one installation.

    ``held_since`` is its assignment's time: kept while the holding lasts, new
    when the role is held again after it ended. ``certificate`` is the exact
    certificate retained for it, or None for one retained before certificates.
    """

    installation_id: str
    team_id: str
    role: str
    principal: str
    b3_scope: str
    certificate: bytes | None
    held_since: datetime


@dataclass(frozen=True)
class HoldingRecord:
    """The installation's record of a holding, kept as history after the
    holding ends. It grants nothing: it names whose scope ``b3_scope`` is."""

    installation_id: str
    team_id: str
    role: str
    principal: str
    b3_scope: str


# A holding: the live assignment joined to the installation's record of it.
_HOLDINGS = """
    SELECT h.b3_scope, h.certificate, a.assigned_at,
        h.installation_id, h.team_id, h.role, h.principal_did
    FROM {{tables.role_assignments}} a
    JOIN {{tables.role_holdings}} h
        ON h.team_id = a.team_id AND h.role = a.role AND h.principal_did = a.principal_did
"""
_HOLDING = (
    _HOLDINGS
    + "WHERE h.installation_id = $1 AND a.team_id = $2 AND a.role = $3 AND a.principal_did = $4"
)
_HOLDING_OF_SCOPE = _HOLDINGS + "WHERE h.b3_scope = $1"
_ASSIGNMENT = """
    SELECT assigned_at FROM {{tables.role_assignments}}
    WHERE team_id = $1 AND role = $2 AND principal_did = $3
"""
_RECORD = "SELECT 1 FROM {{tables.role_holdings}} WHERE b3_scope = $1"
_RECORD_OF_SCOPE = """
    SELECT installation_id, team_id, role, principal_did, b3_scope
    FROM {{tables.role_holdings}} WHERE b3_scope = $1
"""


def _holding(row: Any) -> Holding | None:
    if row is None:
        return None
    return Holding(
        installation_id=row["installation_id"],
        team_id=row["team_id"],
        role=row["role"],
        principal=row["principal_did"],
        b3_scope=row["b3_scope"],
        certificate=None if row["certificate"] is None else bytes(row["certificate"]),
        held_since=row["assigned_at"],
    )


async def read_holding(
    db: Executor, *, installation_id: str, team_id: str, role: str, principal: str
) -> Holding | None:
    """The current holding, by SQL reads only: no lock and no refresh. None for
    no holding, and for a bare role assignment the installation has no record of."""
    holding_scope(installation_id, team_id, role, principal)
    row = await db.fetch_one(_HOLDING, installation_id, team_id, role, principal)
    return _holding(row)


async def read_holding_of_scope(db: Executor, b3_scope: str) -> Holding | None:
    """The current holding whose record is ``b3_scope``, by SQL reads only: no
    lock and no refresh. None for a scope the installation never recorded, and
    for one whose holding has ended. The caller checks the holding is its own
    installation's."""
    return _holding(await db.fetch_one(_HOLDING_OF_SCOPE, b3_scope))


async def holding_record_of_scope(db: Executor, b3_scope: str) -> HoldingRecord | None:
    """The installation's record for ``b3_scope``, current or ended, by SQL
    reads only. It grants nothing: it names the installation, team, role and
    principal whose scope this is, such as for a credential event after the
    holding ended. None for a scope never recorded."""
    row = await db.fetch_one(_RECORD_OF_SCOPE, b3_scope)
    if row is None:
        return None
    return HoldingRecord(
        installation_id=row["installation_id"],
        team_id=row["team_id"],
        role=row["role"],
        principal=row["principal_did"],
        b3_scope=row["b3_scope"],
    )


async def is_holding_scope(db: Executor, b3_scope: str) -> bool:
    """Whether the installation ever recorded a holding for this B3 scope,
    current or ended. It grants nothing: it only tells a B3 scope that belongs
    to human-role holdings from one that does not."""
    return bool(await db.fetch_value(_RECORD, b3_scope))


async def _lock(
    tx: TransactionManager,
    mode: str,
    installation_id: str,
    team_id: str,
    role: str,
    principal: str,
) -> Holding | None:
    # The assignment first, then the record: every holder and writer locks in
    # this order, in separate statements, so the two orders never cycle.
    scope = holding_scope(installation_id, team_id, role, principal)
    if await tx.fetch_one(f"{_ASSIGNMENT} FOR {mode}", team_id, role, principal) is None:
        return None
    if await tx.fetch_one(f"{_RECORD} FOR {mode}", scope) is None:
        return None
    row = await tx.fetch_one(_HOLDING, installation_id, team_id, role, principal)
    return _holding(row)


async def hold_holding(
    tx: TransactionManager, *, installation_id: str, team_id: str, role: str, principal: str
) -> Holding | None:
    """The current holding, held FOR SHARE until the transaction ends, so no
    holding writer commits under it. Takes no B3 row: the caller prepares B3
    once, for every pair it needs, after all its holds."""
    return await _lock(tx, "SHARE", installation_id, team_id, role, principal)


async def lock_holding(
    tx: TransactionManager, *, installation_id: str, team_id: str, role: str, principal: str
) -> Holding | None:
    """The current holding, locked FOR UPDATE for a writer, after the
    installation fence and before any B3 row. None when nothing is held."""
    return await _lock(tx, "UPDATE", installation_id, team_id, role, principal)


async def begin_holding(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    role: str,
    principal: str,
    certificate: bytes | None,
) -> Holding | None:
    """Make ``principal`` hold the role in the installation, retaining
    ``certificate``. None, writing nothing, when the role is already held."""
    scope = holding_scope(installation_id, team_id, role, principal)
    assigned_at = await tx.fetch_value(
        """
        INSERT INTO {{tables.role_assignments}} (team_id, principal_did, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (team_id, principal_did, role) DO NOTHING
        RETURNING assigned_at
        """,
        team_id,
        principal,
        role,
    )
    if assigned_at is None:
        return None
    recorded = await tx.fetch_value(
        """
        INSERT INTO {{tables.role_holdings}} AS h
            (b3_scope, installation_id, team_id, role, principal_did, certificate)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (b3_scope) DO UPDATE SET certificate = EXCLUDED.certificate
        WHERE (h.installation_id, h.team_id, h.role, h.principal_did)
            = (EXCLUDED.installation_id, EXCLUDED.team_id, EXCLUDED.role,
               EXCLUDED.principal_did)
        RETURNING 1
        """,
        scope,
        installation_id,
        team_id,
        role,
        principal,
        certificate,
    )
    if recorded is None:
        raise ValueError("this holding's scope is recorded for another holding")
    return Holding(installation_id, team_id, role, principal, scope, certificate, assigned_at)


async def end_holding(
    tx: TransactionManager, *, installation_id: str, team_id: str, role: str, principal: str
) -> bool:
    """End the holding, keeping its record as history. False, writing
    nothing, when nothing is held."""
    if (
        await lock_holding(
            tx, installation_id=installation_id, team_id=team_id, role=role, principal=principal
        )
        is None
    ):
        return False
    ended = await tx.fetch_value(
        """
        DELETE FROM {{tables.role_assignments}}
        WHERE team_id = $1 AND principal_did = $2 AND role = $3
        RETURNING 1
        """,
        team_id,
        principal,
        role,
    )
    return ended is not None


async def refresh_holding_certificate(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    role: str,
    principal: str,
    held_since: datetime,
    certificate: bytes,
) -> bool:
    """Retain ``certificate`` for the holding that has held since
    ``held_since``. False, writing nothing, when that holding has ended, even
    if the role is held again."""
    held = await lock_holding(
        tx, installation_id=installation_id, team_id=team_id, role=role, principal=principal
    )
    if held is None or held.held_since != held_since:
        return False
    await tx.execute(
        "UPDATE {{tables.role_holdings}} SET certificate = $2 WHERE b3_scope = $1",
        held.b3_scope,
        certificate,
    )
    return True


async def purge_team(tx: TransactionManager, team_id: str) -> None:
    """Remove every role assignment of the team in the caller's transaction.

    Assignments are authority: an app purges them when its installation for the
    team is uninstalled or replaced by a new one, so a reinstall starts with no
    roles. A role resolved in a transaction still open is purged once it ends.
    """
    await tx.execute("DELETE FROM {{tables.role_assignments}} WHERE team_id = $1", team_id)
    await tx.execute("DELETE FROM {{tables.role_holdings}} WHERE team_id = $1", team_id)


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
