"""Read-time delivery-team membership, independent of message claims."""

from aweb.identity_binding import IdentityProjectionField, verified_identity_field_sql
import logging
from enum import StrEnum
from uuid import UUID

from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pydantic import BaseModel

from aweb.member_team_key import member_key_columns_sql, current_member
from aweb.certificate_registration import (
    configured_registration_mode,
    read_certificate_registration,
)
from aweb.application_state import application_registry_client
from aweb.team_registry import request_revoked_certificates


logger = logging.getLogger(__name__)


class SenderMembershipState(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class SenderMembership(BaseModel):
    team_id: str
    member_did_aw: str | None = None
    state: SenderMembershipState = SenderMembershipState.UNKNOWN


async def sender_memberships(
    request: Request | None,
    db,
    rows,
    *,
    member_rows: list[dict] | None = None,
) -> dict[tuple[str, str], SenderMembership]:
    """Project only stored sender IDs in their stored delivery teams.

    Call only after participant authorization. Missing provenance or unavailable
    revocation state cannot establish active membership. No roster discovery.
    ``member_rows`` are the senders' agent rows when the caller read them with
    its messages; otherwise they are read here.
    """
    keys = {(str(r.get("team_id") or ""), str(r.get("from_agent_id") or "")) for r in rows}
    result = {key: SenderMembership(team_id=key[0]) for key in keys}
    if request is None:
        return result
    ids = [UUID(agent) for team, agent in keys if team and agent]
    if not ids:
        return result
    members = (
        member_rows
        if member_rows is not None
        else await db.get_manager("aweb").fetch_all(
            f"""SELECT a.agent_id, a.team_id, {verified_identity_field_sql(IdentityProjectionField.STABLE_DID, agent="a")} AS did_aw, a.status, a.deleted_at, a.certificate_id, """
            + member_key_columns_sql("a")
            + " "
            "FROM {{tables.agents}} AS a WHERE a.agent_id = ANY($1::uuid[])",
            ids,
        )
    )
    team_certificates: dict[str, list[str]] = {}
    for member in members:
        team = str(member["team_id"])
        if (team, str(member["agent_id"])) in result:
            certificate_id = str(member.get("certificate_id") or "").strip()
            if certificate_id:
                team_certificates.setdefault(team, []).append(certificate_id)
    revocations: dict[str, set[str] | None] = {}
    for member in members:
        key = (str(member["team_id"]), str(member["agent_id"]))
        if key not in result:
            continue
        projection = result[key]
        projection.member_did_aw = str(member.get("did_aw") or "").strip() or None
        if not current_member(member):
            projection.state = SenderMembershipState.INACTIVE
            continue
        certificate_id = str(member.get("certificate_id") or "").strip()
        if not certificate_id:
            continue
        team = key[0]
        if team not in revocations:
            try:
                parse_team_id(team)
            except ValueError:
                logger.warning("Sender membership has invalid team scope", exc_info=True)
                continue
            try:
                revocations[team] = await request_revoked_certificates(
                    request, team, certificate_ids=team_certificates[team]
                )
            except HTTPException:
                logger.warning("Sender certificate revocations unavailable", exc_info=True)
                revocations[team] = None
        revoked = revocations[team]
        if revoked is None:
            continue
        if certificate_id in revoked:
            projection.state = SenderMembershipState.INACTIVE
            continue
        registration = await read_certificate_registration(
            registry_client=application_registry_client(request.app.state),
            team_id=team,
            certificate_id=certificate_id,
            mode=configured_registration_mode(),
            request=request,
        )
        if registration.allows_registration:
            projection.state = SenderMembershipState.ACTIVE
        elif registration.unavailable_cause is None:
            projection.state = SenderMembershipState.INACTIVE
    return result
