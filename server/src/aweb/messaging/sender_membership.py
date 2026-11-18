"""Read-time delivery-team membership, independent of message claims."""
from typing import Literal
from uuid import UUID

from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pydantic import BaseModel

from aweb.member_team_key import member_key_columns_sql, member_key_current
from aweb.team_auth_deps import _get_revoked_certificates


class SenderMembership(BaseModel):
    team_id: str
    member_did_aw: str | None = None
    state: Literal["active", "inactive", "unknown"] = "unknown"


async def sender_memberships(
    request: Request | None, db, rows, *, member_rows: list[dict] | None = None,
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
            "SELECT a.agent_id, a.team_id, CASE WHEN a.did_aw_verified_key = a.did_key THEN a.did_aw END AS did_aw, "
            "a.status, a.deleted_at, a.certificate_id, " + member_key_columns_sql("a") + " "
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
    revocations = {}
    for member in members:
        key = (str(member["team_id"]), str(member["agent_id"]))
        if key not in result:
            continue
        projection = result[key]
        projection.member_did_aw = str(member.get("did_aw") or "").strip() or None
        if member["status"] != "active" or member.get("deleted_at") is not None or not member_key_current(member):
            projection.state = "inactive"
            continue
        certificate_id = str(member.get("certificate_id") or "").strip()
        if not certificate_id:
            continue
        team = key[0]
        if team not in revocations:
            try:
                parse_team_id(team)
            except ValueError:
                continue
            try:
                revocations[team] = await _get_revoked_certificates(request, team, certificate_ids=team_certificates[team])
            except HTTPException:
                # The existing revocation helper logs dependency failures.
                revocations[team] = None
        revoked = revocations[team]
        if revoked is not None:
            projection.state = "inactive" if certificate_id in revoked else "active"
    return result
