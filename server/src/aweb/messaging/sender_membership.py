"""Read-time delivery-team membership, independent of message claims."""

import logging
from enum import StrEnum
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import BaseModel

from aweb.application_state import (
    RegistryClientUnavailable,
    application_registry_client,
)
from aweb.identity_binding import IdentityProjectionField, verified_identity_field_sql
from aweb.member_team_key import (
    CertificateStandingState,
    current_member,
    member_key_columns_sql,
    read_certificate_standings,
)
from aweb.service_errors import AuthenticationError


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
    keys = {
        (str(r.get("team_id") or ""), str(r.get("from_agent_id") or "")) for r in rows
    }
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
    pending: dict[str, list[tuple[str, SenderMembership]]] = {}
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
        if certificate_id:
            pending.setdefault(key[0], []).append((certificate_id, projection))
    for team, projections in pending.items():
        try:
            standing = await read_certificate_standings(
                application_registry_client(request.app.state),
                team,
                {certificate_id for certificate_id, _ in projections},
                request=request,
            )
        except AuthenticationError:
            logger.warning("Sender membership has invalid team scope", exc_info=True)
            continue
        except (HTTPException, RegistryClientUnavailable):
            logger.warning("Sender certificate standing unavailable", exc_info=True)
            continue
        for certificate_id, projection in projections:
            state = standing[certificate_id].state
            if state is CertificateStandingState.ACTIVE:
                projection.state = SenderMembershipState.ACTIVE
            elif state is not CertificateStandingState.UNAVAILABLE:
                projection.state = SenderMembershipState.INACTIVE
    return result
