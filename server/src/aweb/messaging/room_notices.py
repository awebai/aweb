"""Per-recipient room notices, independent of mail/chat delivery state."""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import HTTPException, Request
from aweb.config import require_registered_certificates
from aweb.grant_streams import grant_has_scope, grant_terminal_reason
from aweb.identity_binding import verify_identity_binding
from aweb.id_chain_auth import authenticate_id_chain
from aweb.messaging.room import _active_member, _post_dict, _uuid
from aweb.service_errors import ServiceError
from aweb.team_auth import parse_and_verify_certificate
from aweb.team_auth_deps import (
    TeamIdentity,
    _aweb_db,
    _get_registered_certificates,
    _get_revoked_certificates,
    _resolve_team_key,
)

logger = logging.getLogger(__name__)


async def _refresh_room_authority(request, db, identity):
    # A snapshot is not a new HTTP request. Its opening signature/timestamp
    # already admitted this actor; only current authority must be refreshed.
    # Reset request-local binding observations so they cannot outlive the
    # production registry cache bounds during the stream.
    authority_request = Request({**request.scope, "state": {}})
    if identity.grant is not None:
        reason = await grant_terminal_reason(authority_request, db, identity)
        if reason:
            raise HTTPException(status_code=403, detail=reason)
        row = await db.get_manager("aweb").fetch_one(
            """SELECT team_id, scopes FROM {{tables.identity_session_grants}}
            WHERE grant_id=$1 AND subject_agent_id=$2""",
            UUID(identity.grant.grant_id),
            UUID(identity.agent_id),
        )
        if (
            not row
            or row["team_id"] != identity.team_id
            or "chat.read" not in (row["scopes"] or ())
        ):
            raise HTTPException(status_code=403, detail="Room grant out of scope")
    else:
        team_key = await _resolve_team_key(authority_request, identity.team_id)
        revoked = await _get_revoked_certificates(authority_request, identity.team_id)
        try:
            cert = parse_and_verify_certificate(
                request.headers.get("X-AWID-Team-Certificate", ""),
                request_did_key=identity.did_key,
                team_public_key_resolver=lambda team: (
                    team_key if team == identity.team_id else ""
                ),
                revocation_checker=lambda team, certificate: certificate in revoked,
            )
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if (
            cert["team_id"] != identity.team_id
            or cert["certificate_id"] != identity.certificate_id
        ):
            raise HTTPException(status_code=403, detail="Room membership changed")
        if require_registered_certificates():
            registered = await _get_registered_certificates(
                authority_request, identity.team_id
            )
            if identity.certificate_id not in registered:
                raise HTTPException(
                    status_code=403, detail="Room certificate not registered"
                )
    binding = await verify_identity_binding(
        authority_request,
        did_key=identity.did_key,
        did_aw=identity.did_aw,
        address=identity.address,
    )
    await authenticate_id_chain(authority_request, binding)


async def count_room_notices(db, actor: TeamIdentity) -> int:
    """Count for an already room-admitted actor; no content, locks or receipts.

    Callers establish current room membership through ordinary admission.
    This SELECT also binds the live member/key/team and any admitted grant,
    so a stale actor or narrowed grant cannot disclose another count.
    """
    if not grant_has_scope(actor, "chat.read"):
        return 0
    grant = actor.grant
    return int(
        await _aweb_db(db).fetch_val(
            """
        SELECT count(*)
        FROM {{tables.room_post_notices}} n
        JOIN {{tables.room_messages}} m ON m.message_id=n.message_id
        JOIN {{tables.team_rooms}} r ON r.room_id=m.room_id
        JOIN {{tables.agents}} a ON a.agent_id=n.recipient_agent_id
          AND a.team_id=r.team_id
        WHERE a.agent_id=$1 AND a.team_id=$2 AND a.did_key=$3
          AND a.status='active' AND a.deleted_at IS NULL
          AND ($4::uuid IS NULL OR EXISTS (
              SELECT 1 FROM {{tables.identity_session_grants}} g
              WHERE g.grant_id=$4 AND g.subject_agent_id=a.agent_id
                AND g.team_id=a.team_id AND g.grant_did_key=$5
                AND g.revoked_at IS NULL AND 'chat.read'=ANY(g.scopes)
                AND (g.expires_at>now() OR g.expires_at>=g.issued_at+interval '99 years')
          ))
        """,
            UUID(actor.agent_id),
            actor.team_id,
            actor.did_key,
            UUID(grant.grant_id) if grant else None,
            grant.session_did_key if grant else None,
        )
    )


async def pending_room_notices(db, actor, *, limit=50):
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        rows = await tx.fetch_all(
            """
            SELECT m.*
            FROM {{tables.room_post_notices}} n
            JOIN {{tables.room_messages}} m ON m.message_id=n.message_id
            JOIN {{tables.team_rooms}} r ON r.room_id=m.room_id
            WHERE n.recipient_agent_id=$1 AND r.team_id=$2
            ORDER BY m.sequence LIMIT $3
        """,
            UUID(actor.agent_id),
            actor.team_id,
            limit,
        )
        notices = []
        for row in rows:
            post = _post_dict(row, actor.team_id)
            notices.append(
                {
                    "type": "actionable_room_post",
                    "team_id": actor.team_id,
                    "agent_id": str(actor.agent_id),
                    "room_id": post["room_id"],
                    "message_id": post["message_id"],
                    "from_alias": post["from_alias"],
                    "from_did": post["from_did"],
                    "from_stable_id": post["from_stable_id"],
                    "subject": post["subject"],
                }
            )
        count = await count_room_notices(tx, actor)
        return {
            "pending_count": count,
            "notices": notices,
            "has_more": count > len(notices),
        }


async def ack_room_notice(db, actor, message_id):
    message_id = _uuid(message_id)
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        await tx.execute(
            """DELETE FROM {{tables.room_post_notices}} n
            USING {{tables.room_messages}} m, {{tables.team_rooms}} r
            WHERE n.message_id=$1 AND n.recipient_agent_id=$2
              AND m.message_id=n.message_id AND r.room_id=m.room_id AND r.team_id=$3
        """,
            message_id,
            UUID(actor.agent_id),
            actor.team_id,
        )
    return {"message_id": str(message_id), "status": "acknowledged"}


async def current_room_events(request, db, identity):
    if not grant_has_scope(identity, "chat.read"):
        return []
    # No room activity adds no authority call to an existing mail/chat stream.
    exists = await db.get_manager("aweb").fetch_val(
        """
        SELECT EXISTS (SELECT 1 FROM {{tables.room_post_notices}}
        WHERE recipient_agent_id=$1)
    """,
        UUID(identity.agent_id),
    )
    if not exists:
        return []
    try:
        await _refresh_room_authority(request, db, identity)
        return (await pending_room_notices(db, identity))["notices"]
    except (HTTPException, ServiceError):
        logger.warning(
            "Room notice snapshot refused by current membership authority",
            exc_info=True,
        )
        return []
