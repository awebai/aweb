"""Read-time membership from local enrollment or a verified stored team route."""
from typing import Literal
from uuid import UUID

from awid.federation_errors import FederationAuthorityError
from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pydantic import BaseModel

from aweb.federation.team_routes import verify_team_route
from aweb.team_auth_deps import _get_revoked_certificates


class SenderMembership(BaseModel):
    team_id: str
    member_did_aw: str | None = None
    state: Literal["active", "inactive", "unknown"] = "unknown"


async def sender_memberships(request: Request | None, db, rows) -> dict[str, SenderMembership]:
    """Participant-authorized reads only. Missing or unavailable proof is unknown.

    Key by message: two foreign authors have NULL actor IDs, and even one key
    can have distinct team routes in different conversations.
    """
    result = {str(row["message_id"]): SenderMembership(team_id=str(row.get("team_id") or "")) for row in rows}
    if request is None:
        return result
    manager = db.get_manager("aweb")
    ids = {UUID(str(row["from_agent_id"])) for row in rows if row.get("from_agent_id")}
    members = await manager.fetch_all(
        "SELECT agent_id, team_id, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, status, deleted_at, certificate_id "
        "FROM {{tables.agents}} WHERE agent_id = ANY($1::uuid[])", list(ids),
    ) if ids else []
    by_id = {str(member["agent_id"]): member for member in members}
    revocations = {}
    for row in rows:
        projection = result[str(row["message_id"])]
        member = by_id.get(str(row.get("from_agent_id") or ""))
        if member is not None and member["team_id"] == projection.team_id:
            projection.member_did_aw = str(member.get("did_aw") or "").strip() or None
            if member["status"] != "active" or member.get("deleted_at") is not None:
                projection.state = "inactive"
                continue
            certificate_id = str(member.get("certificate_id") or "").strip()
            if not certificate_id:
                continue
            team = member["team_id"]
            if team not in revocations:
                try:
                    parse_team_id(team)
                    revocations[team] = await _get_revoked_certificates(request, team)
                except (ValueError, HTTPException):
                    revocations[team] = None
            revoked = revocations[team]
            if revoked is not None:
                projection.state = "inactive" if certificate_id in revoked else "active"
            continue
        did = str(row.get("from_did") or "")
        if row.get("from_agent_id") or not did.startswith("did:key:"):
            continue
        conversation_id = row.get("conversation_id") or row.get("session_id")
        if not conversation_id:
            conversation_id = await manager.fetch_value(
                "SELECT session_id FROM {{tables.chat_messages}} WHERE message_id=$1", row["message_id"],
            )
        if not conversation_id:
            continue
        route = await manager.fetch_one(
            "SELECT route_team_id, route_certificate_id, route_certificate "
            "FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
            UUID(str(conversation_id)), did,
        )
        if not route or not route["route_team_id"]:
            continue
        projection.team_id = route["route_team_id"]
        try:
            membership = await verify_team_route(request, route["route_certificate"], membership_only=True)
            if (membership.team_id != route["route_team_id"] or membership.member_did_key != did
                    or membership.certificate_id != route["route_certificate_id"]):
                projection.state = "inactive"
            else:
                projection.state = "active"
        except FederationAuthorityError as exc:
            if exc.reason in {"local_sender_certificate_revoked", "local_sender_team_key_stale", "local_sender_certificate_invalid"}:
                projection.state = "inactive"
    return result
