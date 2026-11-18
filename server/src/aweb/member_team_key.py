"""A member is a member under its team's current key.

The server records, on each member's agents row, the team key under which it
last accepted that member (accepted_team_did_key): the key a certificate was
verified under, or, for a row written without one, the team's key at that
moment. The team's current key is the key the server holds for the team
(teams.team_did_key, aweb.team_key_pins). A row is a member only while the two
are equal, wherever it is looked up, so changing a team's key removes every
member until each is accepted under the new key.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from uuid import UUID

from awid.team_ids import parse_team_id

from aweb.service_errors import AuthenticationError, NotFoundError


class MemberStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    ARCHIVED = "archived"
    DELETED = "deleted"


RECIPIENT_RECONNECT_DETAIL = (
    "Check the name; if the agent exists, ask it to reconnect with a current team certificate."
)


CURRENT_MEMBERSHIP_REQUIRED_DETAIL = (
    "Team membership is no longer current. "
    "Reconnect with a certificate issued under the team's current key."
)


def recipient_not_found(*, label: str | None = None) -> NotFoundError:
    """Tell the sender how to restore a missing current-member recipient."""
    detail = "Recipient name does not identify a current member of the team"
    if label:
        detail += f": {label}"
    return NotFoundError(detail + ". " + RECIPIENT_RECONNECT_DETAIL)


def member_team_scope(team_id: str) -> tuple[str, str]:
    """Require the team:domain scope in docs/identity.md:93-95.

    A malformed authority scope never means an empty revocation list.
    """
    try:
        return parse_team_id(team_id)
    except ValueError as exc:
        raise AuthenticationError(
            "Team identity is invalid. Reconnect using a certificate for a canonical team ID."
        ) from exc


_MEMBER_COLUMNS = (
    "agent_id",
    "team_id",
    "alias",
    "did_key",
    "did_aw",
    "address",
    "did_aw_verified_key",
    "identity_scope",
    "certificate_id",
    "accepted_team_did_key",
    "status",
    "deleted_at",
    "agent_type",
    "human_verified_key",
    "inbound_mode",
)


def member_projection_columns_sql(agent: str) -> str:
    """Canonical native member columns for a SELECT, including a host's JOIN.

    The alias is a source-code SQL identifier, never request input. Hosts keep
    account/custody overlay columns separate from this projection.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", agent):
        raise ValueError("Invalid member projection SQL alias")
    columns = ", ".join(f"{agent}.{column}" for column in _MEMBER_COLUMNS)
    return f"{columns}, {current_team_key_sql(agent)} AS current_team_did_key"


@dataclass(frozen=True)
class MemberProjection(Mapping[str, Any]):
    """An immutable, complete native row, not proof that it is a member.

    Raw claims remain available for policy classification. Consumers obtain
    attributed identity through ``verified_identity``; eligibility remains the
    member owner's decision. Missing columns are not replaced with NULL.
    docs/identity.md:569-585 separates verified projection from policy claims.
    """

    _row: Mapping[str, Any]

    def __post_init__(self) -> None:
        source = dict(self._row)
        columns = (*_MEMBER_COLUMNS, "current_team_did_key")
        missing = [column for column in columns if column not in source]
        if missing:
            raise ValueError("Incomplete native member projection: " + ", ".join(missing))
        values = {column: source[column] for column in columns}
        for column in columns:
            if column in ("agent_id", "deleted_at"):
                continue
            if values[column] is not None and not isinstance(values[column], str):
                raise ValueError(f"Native member projection column {column} must be text or NULL")
        # PostgreSQL row_to_json/to_jsonb encodes UUIDs/timestamps as strings.
        # A host's joined snapshot and the native SELECT have one public shape.
        values["agent_id"] = UUID(str(values["agent_id"]))
        if isinstance(values["deleted_at"], str):
            values["deleted_at"] = datetime.fromisoformat(
                values["deleted_at"].replace("Z", "+00:00")
            )
        if values["deleted_at"] is not None and not isinstance(values["deleted_at"], datetime):
            raise ValueError("Native member projection deleted_at must be a timestamp or NULL")
        object.__setattr__(self, "_row", MappingProxyType(values))

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> MemberProjection:
        return cls(row)

    def __getitem__(self, key: str) -> Any:
        return self._row[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._row)

    def __len__(self) -> int:
        return len(self._row)

    def verified_identity(self) -> dict[str, Any]:
        from aweb.identity_binding import verified_projection

        return verified_projection(self)


async def read_member_projection(
    db,
    *,
    team_id: str | None = None,
    did_key: str | None = None,
    agent_id: str | UUID | None = None,
) -> MemberProjection | None:
    """Read the same native row an embedding host can include in its snapshot.

    This is a projection lookup, not an eligibility decision: a presented,
    verified new certificate may reaccept a row under a new team key. It also
    returns deleted/inactive rows so actor resolvers can distinguish an absent
    actor from a refused one. Key selection requires its explicit team; agent
    IDs are globally unique and can optionally be constrained by team.
    """
    if (did_key is None) == (agent_id is None) or (did_key is not None and not team_id):
        raise ValueError("Select a native member by team and did_key, or by agent_id")
    selector = "a.agent_id=$1::uuid" if agent_id is not None else "a.did_key=$1"
    selected = UUID(str(agent_id)) if agent_id is not None else did_key
    row = await db.fetch_one(
        "SELECT "
        + member_projection_columns_sql("a")
        + """
        FROM {{tables.agents}} a
        WHERE """
        + selector
        + " AND ($2::text IS NULL OR a.team_id=$2)",
        selected,
        team_id,
    )
    return MemberProjection.from_row(row) if row is not None else None


def current_team_key_sql(agent: str) -> str:
    """SQL for the current key of the team of the agents row aliased ``agent``."""
    return f"(SELECT team_did_key FROM {{{{tables.teams}}}} WHERE team_id = {agent}.team_id)"


def member_key_columns_sql(agent: str) -> str:
    """The columns member_key_current reads, from the agents row aliased ``agent``."""
    return f"{agent}.accepted_team_did_key, {current_team_key_sql(agent)} AS current_team_did_key"


def member_key_current_sql(agent: str) -> str:
    """SQL predicate: the agents row aliased ``agent`` is a member under its
    team's current key."""
    return f"({agent}.accepted_team_did_key = {current_team_key_sql(agent)})"


def member_key_current(row) -> bool:
    """Whether the member ``row`` (an agents row read with
    member_key_columns_sql) was accepted under its team's current key. A row
    read without those columns is not."""
    accepted = str(row.get("accepted_team_did_key") or "").strip()
    return bool(accepted) and accepted == str(row.get("current_team_did_key") or "").strip()


def current_member(row: Mapping[str, Any] | None) -> bool:
    """An active live member admitted under the team's current key.

    Migration 052:1-4 and docs/design/team-room-v1.md:16-21 require current
    membership; the identity's independent residence is not this question.
    """
    return bool(
        row
        and row.get("status") == MemberStatus.ACTIVE.value
        and row.get("deleted_at") is None
        and member_key_current(row)
    )


def current_member_sql(agent: str) -> str:
    """The current_member predicate for a query that grants membership."""
    return (
        f"({agent}.status = '{MemberStatus.ACTIVE.value}' AND {agent}.deleted_at IS NULL "
        f"AND {member_key_current_sql(agent)})"
    )


async def current_member_projections(
    db,
    *,
    agent_id: UUID | None = None,
    team_id: str | None = None,
    aliases: list[str] | None = None,
    dids: list[str] | None = None,
    namespace: str | None = None,
) -> list[MemberProjection]:
    """Select members by identity or membership without a newest-row winner.

    docs/identity.md:93-107 scopes a member name to a team. Verified global
    claims are selected through identity_binding, never raw metadata.
    """
    from aweb.identity_binding import verified_key_sql

    if all(value is None for value in (agent_id, team_id, aliases, dids, namespace)):
        raise ValueError("Select a current member by identity, team, name or namespace")
    manager = db.get_manager("aweb") if hasattr(db, "get_manager") else db
    rows = await manager.fetch_all(
        "SELECT "
        + member_projection_columns_sql("a")
        + f"""
        FROM {{{{tables.agents}}}} a
        WHERE {current_member_sql("a")}
          AND ($1::uuid IS NULL OR a.agent_id=$1)
          AND ($2::text IS NULL OR a.team_id=$2)
          AND ($3::text[] IS NULL OR a.alias=ANY($3))
          AND ($4::text[] IS NULL OR a.did_key=ANY($4)
               OR ({verified_key_sql("a")} AND a.did_aw=ANY($4)))
          AND ($5::text IS NULL OR EXISTS (
              SELECT 1 FROM {{{{tables.teams}}}} t
              WHERE t.team_id=a.team_id AND t.namespace=$5))
        ORDER BY a.agent_id
        """,
        agent_id,
        team_id,
        aliases,
        dids,
        namespace,
    )
    return [MemberProjection.from_row(row) for row in rows]


def messaging_identity_projection(row: MemberProjection) -> dict[str, Any]:
    """Attributed messaging identity and raw claims kept only for policy."""
    from aweb.human_kind import effective_agent_type

    recipient = row.verified_identity()
    recipient["has_global_claim"] = bool(row["did_aw"])
    recipient["policy_did_aw"] = row["did_aw"]
    recipient["agent_type"] = effective_agent_type(row)
    return recipient


async def read_participant_identity_projection(
    db, *, participant_did: str
) -> dict[str, Any] | None:
    """Read identity for an already-authorized participant, never a team actor.

    docs/identity-messaging-contract.md:96-116 keeps participation independent
    of current membership. A new first-contact lookup must use the member
    selectors or independently verify its address route instead.
    """
    from aweb.identity_binding import verified_key_sql
    from aweb.service_errors import ConflictError

    manager = db.get_manager("aweb") if hasattr(db, "get_manager") else db
    rows = await manager.fetch_all(
        "SELECT "
        + member_projection_columns_sql("a")
        + f"""
        FROM {{{{tables.agents}}}} a
        WHERE a.deleted_at IS NULL
          AND (a.did_key=$1 OR ({verified_key_sql("a")} AND a.did_aw=$1))
        ORDER BY a.agent_id
        """,
        participant_did,
    )
    projections = [MemberProjection.from_row(row) for row in rows]
    if not projections:
        return None
    identities = {(row.verified_identity().get("did_aw"), row["did_key"]) for row in projections}
    if len(identities) != 1:
        raise ConflictError(
            "Participant identity is ambiguous. Reconnect with current identity credentials."
        )
    recipient = messaging_identity_projection(projections[0])
    recipient.update(agent_id=None, team_id=None)
    if len({row.verified_identity().get("address") for row in projections}) != 1:
        recipient["address"] = None
    return recipient


async def current_member_team_ids_for_identity(db, dids: list[str]) -> set[str]:
    """All current memberships of the exact verified identity, for R5 policy."""
    selected = [did.strip() for did in dids if did and did.strip()]
    if not selected:
        return set()
    return {row["team_id"] for row in await current_member_projections(db, dids=selected)}


def grant_issuer_current(row) -> bool:
    """Whether the grant ``row``, joined to its subject's agents row
    (certificate_id and member_key_columns_sql), still has its issuing
    certificate: the subject is a member under the current key and that
    member's certificate is the one the grant was issued from. A credential
    issued from a superseded certificate does not return."""
    if not member_key_current(row):
        return False
    issuer = str(row.get("issued_by_certificate_id") or "").strip()
    current = str(row.get("certificate_id") or "").strip()
    return not issuer or not current or issuer == current
