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

import logging
import re
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum, auto
from types import MappingProxyType
from typing import Any
from uuid import UUID

from awid.team_certificate import (
    TeamCertificateError,
    TeamCertificateStanding,
    evaluate_team_certificate_standing,
)
from fastapi import HTTPException, Request

from aweb.certificate_evidence import EvidenceMode
from aweb.certificate_registration import (
    CertificateRegistrationObservation,
    RegistrationDecision,
    RegistrationMode,
    RegistrationState,
    configured_registration_mode,
    observe_certificate_registrations,
    record_certificate_registration,
)
from aweb.identity_scope import IdentityScope
from aweb.member_status import MemberStatus as MemberStatus
from aweb.service_errors import NotFoundError
from aweb.team_registry import refresh_certificate_standing, revoked_certificates
from aweb.team_scope import member_team_scope as member_team_scope

logger = logging.getLogger(__name__)

class MemberReadLock(Enum):
    """Row protection requested inside the caller's existing transaction."""

    NONE = auto()
    SHARE = auto()
    UPDATE = auto()


RECIPIENT_RECONNECT_DETAIL = (
    "Check the name; if the agent exists, ask it to reconnect with a current team certificate."
)


CURRENT_MEMBERSHIP_REQUIRED_DETAIL = (
    "Team membership is no longer current. "
    "Reconnect with a certificate issued under the team's current key."
)


class CurrentMembershipRequired(ValueError):
    """The native certificate could not establish a current team member."""

    def __init__(self, detail: str = CURRENT_MEMBERSHIP_REQUIRED_DETAIL) -> None:
        super().__init__(detail)


GRANT_ISSUER_RECOVERY_DETAIL = (
    "This grant was issued from a certificate that is no longer current. "
    "Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
)


def recipient_not_found(*, label: str | None = None) -> NotFoundError:
    """Tell the sender how to restore a missing current-member recipient."""
    detail = "Recipient name does not identify a current member of the team"
    if label:
        detail += f": {label}"
    return NotFoundError(detail + ". " + RECIPIENT_RECONNECT_DETAIL)


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


def member_projection_columns_sql(agent: str, *, team: str | None = None) -> str:
    """Canonical native member columns for a SELECT, including a host's JOIN.

    The alias is a source-code SQL identifier, never request input. Hosts keep
    account/custody overlay columns separate from this projection.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", agent):
        raise ValueError("Invalid member projection SQL alias")
    if team is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", team):
        raise ValueError("Invalid team projection SQL alias")
    columns = ", ".join(f"{agent}.{column}" for column in _MEMBER_COLUMNS)
    current_key = f"{team}.team_did_key" if team else current_team_key_sql(agent)
    return f"{columns}, {current_key} AS current_team_did_key"


@dataclass(frozen=True)
class MemberProjection(Mapping[str, Any]):
    """An immutable, complete native row, not proof that it is a member.

    Raw claims remain available for policy classification. Consumers obtain
    attributed identity through ``verified_identity``; eligibility remains the
    member owner's decision. Missing columns are not replaced with NULL.
    docs/identity.md:598-609 separates verified projection from policy claims.
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
        # These are NOT NULL constrained native columns, not optional host overlays.
        values["status"] = MemberStatus(values["status"])
        values["identity_scope"] = IdentityScope(values["identity_scope"])
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
    read_lock: MemberReadLock = MemberReadLock.NONE,
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
    if not isinstance(read_lock, MemberReadLock):
        raise TypeError("Member reads require a named MemberReadLock")
    locked = read_lock is not MemberReadLock.NONE
    join_sql = " JOIN {{tables.teams}} t ON t.team_id=a.team_id" if locked else ""
    lock_sql = ""
    if locked:
        lock_sql = (
            " FOR SHARE OF t FOR UPDATE OF a"
            if read_lock is MemberReadLock.UPDATE
            else " FOR SHARE OF t, a"
        )
    selector = "a.agent_id=$1::uuid" if agent_id is not None else "a.did_key=$1"
    selected = UUID(str(agent_id)) if agent_id is not None else did_key
    row = await db.fetch_one(
        "SELECT "
        + member_projection_columns_sql("a", team="t" if locked else None)
        + """
        FROM {{tables.agents}} a
        """
        + join_sql
        + " WHERE "
        + selector
        + " AND ($2::text IS NULL OR a.team_id=$2)"
        + lock_sql,
        selected,
        team_id,
    )
    return MemberProjection.from_row(row) if row is not None else None


async def lock_member_projections(tx, *, agent_ids: list[UUID]) -> list[MemberProjection]:
    """Read complete native actor facts under caller-owned row locks.

    Actor-ID ordering preserves the public embedding transaction contract.
    Callers apply current_member and compare their retained identity facts;
    these row locks do not grant a team or participant identity.
    """
    if not agent_ids:
        return []
    rows = await tx.fetch_all(
        "SELECT "
        + member_projection_columns_sql("a")
        + """
        FROM {{tables.agents}} a WHERE a.agent_id=ANY($1::uuid[])
        ORDER BY a.agent_id FOR UPDATE OF a
        """,
        sorted(set(agent_ids)),
    )
    return [MemberProjection.from_row(row) for row in rows]


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


def member_key_current(row, *, checked_key: str | None = None) -> bool:
    """Whether the member ``row`` (an agents row read with
    member_key_columns_sql) was accepted under its team's current key. A row
    read without those columns is not."""
    accepted = checked_key if checked_key is not None else str(row.get("accepted_team_did_key") or "").strip()
    return bool(accepted) and accepted == str(row.get("current_team_did_key") or "").strip()


def member_row_active(row: Mapping[str, Any] | None) -> bool:
    """Read native status/deletion only, never identity or current-key authority.

    migrations/aweb/001_initial.sql:42-45 defines native row state separately
    from any certificate proof.
    """
    return bool(row and row.get("status") == MemberStatus.ACTIVE and row.get("deleted_at") is None)


def current_member(row: Mapping[str, Any] | None, *, checked_key: str | None = None) -> bool:
    """An active live member admitted under the team's current key.

    Migration 052:1-4 and docs/design/team-room-v1.md:16-21 require current
    membership; the identity's independent residence is not this question.
    """
    return member_row_active(row) and member_key_current(row, checked_key=checked_key)


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
    read_lock: MemberReadLock = MemberReadLock.NONE,
) -> list[MemberProjection]:
    """Select members by identity or membership without a newest-row winner.

    docs/identity.md:93-102 scopes a member name to a team. Verified global
    claims are selected through identity_binding, never raw metadata.
    SHARE holds eligible rows through the caller's transaction, preserving
    delivery policy through commit under Global And Local Identities
    (docs/identity-messaging-contract.md:94-99).
    It creates no transaction and adds no lock to the ordinary default read.
    """
    from aweb.identity_binding import verified_key_sql

    if not isinstance(read_lock, MemberReadLock):
        raise TypeError("Member reads require a named MemberReadLock")
    lock_sql = {
        MemberReadLock.NONE: "",
        MemberReadLock.SHARE: " FOR SHARE OF a",
        MemberReadLock.UPDATE: " FOR UPDATE OF a",
    }[read_lock]
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
        """
        + lock_sql,
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

    Global And Local Identities (docs/identity-messaging-contract.md:124-144)
    keeps participation independent
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


class CertificateStandingState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    UNREGISTERED = "unregistered"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CertificateStanding:
    state: CertificateStandingState
    unavailable_cause: Exception | None = None
    registration: RegistrationDecision | None = None
    refreshed_after_miss: bool = False

    def require_active(self) -> None:
        if self.state is CertificateStandingState.UNAVAILABLE:
            if self.unavailable_cause is None:
                raise RuntimeError("Unavailable certificate standing requires an acquisition error")
            raise self.unavailable_cause
        if self.state is not CertificateStandingState.ACTIVE:
            raise TeamCertificateError(self.state.value)


async def read_certificate_standings(
    registry_client,
    team_id: str,
    certificate_ids: Collection[str],
    *,
    request: Request | None = None,
    mode: RegistrationMode | None = None,
    revocation_evidence: EvidenceMode = EvidenceMode.CACHED,
    registrations: CertificateRegistrationObservation | None = None,
) -> dict[str, CertificateStanding]:
    """Read standing for checked artifacts or previously admitted certificates.

    Global And Local Identities (docs/identity-messaging-contract.md:81-86)
    gives the same standing rule to request, stream, and delivery membership.
    An authorized caller can supply a fresh registration snapshot it already
    needs; otherwise strict misses use the SDK's bounded refresh owner.
    """
    if registrations is not None and registrations.team_id != team_id:
        raise ValueError("Certificate registrations must come from the selected team")
    selected = set(certificate_ids)
    if not selected:
        return {}
    try:
        revoked = await revoked_certificates(
            registry_client, team_id, certificate_ids=sorted(selected), evidence=revocation_evidence,
        )
    except HTTPException as exc:
        if exc.status_code < 500:
            raise
        return {cid: CertificateStanding(CertificateStandingState.UNAVAILABLE, exc) for cid in selected}
    result = {
        cid: CertificateStanding(CertificateStandingState.REVOKED)
        for cid in selected
        if evaluate_team_certificate_standing(
            revoked=cid in revoked, registered=None,
        ) is TeamCertificateStanding.REVOKED
    }
    remaining = selected - result.keys()
    if not remaining:
        return result
    mode = mode if mode is not None else configured_registration_mode()
    snapshot = registrations if registrations is not None else await observe_certificate_registrations(
        registry_client=registry_client, team_id=team_id, mode=mode,
    )
    for certificate_id in sorted(remaining):
        observation = snapshot
        refreshed = False
        if (
            registrations is None
            and mode is RegistrationMode.REQUIRED
            and snapshot.registered_certificate_ids is not None
            and certificate_id not in snapshot.registered_certificate_ids
        ):
            try:
                standing = await refresh_certificate_standing(
                    registry_client, team_id, certificate_id=certificate_id,
                )
            except HTTPException as exc:
                if exc.status_code < 500:
                    raise
                result[certificate_id] = CertificateStanding(CertificateStandingState.UNAVAILABLE, exc)
                continue
            if standing is TeamCertificateStanding.REVOKED:
                result[certificate_id] = CertificateStanding(CertificateStandingState.REVOKED)
                continue
            if standing is TeamCertificateStanding.ACTIVE:
                observation = CertificateRegistrationObservation(
                    team_id=team_id, registered_certificate_ids={certificate_id},
                )
                refreshed = True
        registration = record_certificate_registration(
            request, observation=observation, certificate_id=certificate_id, mode=mode,
        )
        if registration.allows_registration:
            result[certificate_id] = CertificateStanding(
                CertificateStandingState.ACTIVE, registration=registration, refreshed_after_miss=refreshed,
            )
        elif registration.state is RegistrationState.UNAVAILABLE:
            result[certificate_id] = CertificateStanding(
                CertificateStandingState.UNAVAILABLE, registration.unavailable_cause, registration,
            )
        else:
            result[certificate_id] = CertificateStanding(
                CertificateStandingState.UNREGISTERED, registration=registration,
            )
    return result


async def current_membership(
    registry_client, row: Mapping[str, Any] | None, *, request: Request | None = None
) -> Mapping[str, Any] | None:
    """Keep exact identity facts and strip team context from an ineligible member."""
    if not row or not (team_id := str(row.get("team_id") or "").strip()):
        return row
    if not current_member(row):
        reason = "the member is inactive or was accepted under a superseded key"
    else:
        certificate_id = str(row.get("certificate_id") or "").strip()
        if not certificate_id:
            return row
        standings = await read_certificate_standings(
            registry_client, team_id, [certificate_id], request=request
        )
        standing = standings[certificate_id]
        if standing.state is CertificateStandingState.ACTIVE:
            return row
        if standing.state is CertificateStandingState.UNAVAILABLE:
            if standing.registration is None:
                standing.require_active()
            raise HTTPException(
                status_code=503,
                detail="Certificate registration is unavailable. Retry in a moment.",
            ) from standing.unavailable_cause
        reason = f"certificate {certificate_id} is {standing.state}"
    logger.warning("Team context stripped for alias %r in %s: %s", row.get("alias"), team_id, reason)
    return {**row, "team_id": None, "alias": None, "agent_id": None}


async def current_member_team_ids_for_identity(
    db, dids: list[str], *, registry_client, read_lock: MemberReadLock = MemberReadLock.NONE
) -> set[str]:
    """Current memberships with the admitting certificate's live standing.

    Apply SDK revocation and staged registration policy after selecting each
    admitted membership under the current key.
    """
    selected = [did.strip() for did in dids if did and did.strip()]
    if not selected:
        return set()
    teams = set()
    for row in await current_member_projections(db, dids=selected, read_lock=read_lock):
        standing = await current_membership(registry_client, dict(row))
        if standing is not None and standing.get("team_id"):
            teams.add(standing["team_id"])
    return teams


def grant_issuer_current(row) -> bool:
    """Whether the grant ``row``, joined to its subject's agents row
    (certificate_id and member_key_columns_sql), still has its issuing
    certificate: the subject is a member under the current key and that
    member's certificate is the one the grant was issued from. A credential
    issued from a superseded certificate does not return: reaccepting the
    member does not renew an earlier delegation (Session grants, docs/identity.md:807-811).
    """
    if not member_key_current(row):
        return False
    issuer = str(row.get("issued_by_certificate_id") or "").strip()
    current = str(row.get("certificate_id") or "").strip()
    return not issuer or issuer == current


def grant_issuer_current_sql(*, agent: str, grant: str) -> str:
    """The SQL form of grant_issuer_current for joined presence readers.

    Session grants (docs/identity.md:807-811) retains exact issuing-certificate equality after
    reacceptance. Legacy issuer-ID-less grants keep their existing lifetime.
    Both aliases are source-code identifiers, never request values.
    """
    for alias in (agent, grant):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", alias):
            raise ValueError("Invalid grant eligibility SQL alias")
    current_key = member_key_current_sql(agent)
    issuer = f"NULLIF(BTRIM({grant}.issued_by_certificate_id), '')"
    current = f"NULLIF(BTRIM({agent}.certificate_id), '')"
    return f"({current_key} AND ({issuer} IS NULL OR {issuer}={current}))"
