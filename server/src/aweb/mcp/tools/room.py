"""Additive room tools; hosted custody signs as the authenticated actor."""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException

from aweb.agent_wake import agent_wake_scope
from aweb.id_chain_auth import authenticate_id_chain
from aweb.member_team_key import current_membership
from aweb.application_state import application_registry_client
from aweb.identity_binding import verify_identity_binding
from aweb.mcp.auth import current_agent_wake_publisher, get_auth
from aweb.mcp.signing import sign_hosted_message
from aweb.mcp.mutations import current_mutation_callback
from aweb.mcp.tools._common import team_identity
from aweb.member_team_key import (
    CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
    current_member,
    read_member_projection,
)
from aweb.messaging.room import (
    RoomPost,
    post_room_message,
    present_room,
    read_room,
    room_metadata,
)
from aweb.messaging.room_notices import count_room_notices, pending_room_notices

logger = logging.getLogger(__name__)


async def _room_actor(db):
    auth = get_auth()
    if (
        not auth.team_id
        or not auth.agent_id
        or not auth.request
        or not (auth.certificate_id or auth.trusted_proxy)
    ):
        raise HTTPException(403, "Room requires authenticated team context")
    projection = await read_member_projection(
        db.get_manager("aweb"),
        agent_id=auth.agent_id,
        team_id=auth.team_id,
    )
    if (
        not projection
        or not projection["certificate_id"]
        or projection["did_key"] != auth.did_key
        or not current_member(projection)
    ):
        raise HTTPException(403, CURRENT_MEMBERSHIP_REQUIRED_DETAIL)
    row = await current_membership(
        application_registry_client(auth.request.app.state),
        dict(projection),
        request=auth.request,
    )
    if not row or row["team_id"] != auth.team_id:
        raise HTTPException(403, CURRENT_MEMBERSHIP_REQUIRED_DETAIL)
    if auth.trusted_proxy:
        # Original proxy actor authentication is already complete. Admit the
        # existing adjacent carrier against that exact actor, not a room key.
        binding = await verify_identity_binding(
            auth.request,
            did_key=auth.did_key,
            did_aw=auth.did_aw or "",
            address=auth.address or "",
        )
        await authenticate_id_chain(auth.request, binding)
    return auth, replace(team_identity(auth), certificate_id=row["certificate_id"])


async def room_read(db, *, after=None, limit=50):
    auth, actor = await _room_actor(db)
    return json.dumps(
        await present_room(
            db, auth.request, await read_room(db, actor, after=after, limit=limit)
        )
    )


async def room_notice_count(db) -> int | None:
    """Optional hosted-nudge count for the current admitted MCP actor only."""
    try:
        _, actor = await _room_actor(db)
        return await count_room_notices(db, actor)
    except Exception:
        # A count failure must not fail the already-successful tool or turn
        # unknown authority into a zero. The nudge omits this component.
        logger.warning("Room notice count unavailable", exc_info=True)
        return None


async def room_pending(db):
    _, actor = await _room_actor(db)
    return json.dumps(await pending_room_notices(db, actor))


async def room_post(
    db, *, hosted_signer=None, subject="", body="", e2ee=False, signed_post=None
):
    if e2ee:
        raise HTTPException(422, "room_e2ee_unsupported")
    auth, actor = await _room_actor(db)
    if signed_post is not None:
        # A noncustodial MCP caller supplies its own ordinary signed envelope.
        payload = RoomPost.model_validate(signed_post)
    else:
        if not auth.trusted_proxy:
            raise HTTPException(
                403, "Provide an identity-signed post, or use aw room post"
            )
        room = await room_metadata(db, actor)
        signed = {
            "type": "chat",
            "from": actor.address or actor.alias or actor.did_key,
            "from_did": actor.did_key,
            "to": "team-room:" + actor.team_id,
            "to_did": "",
            "conversation_id": room["room_id"],
            "message_id": str(uuid4()),
            "subject": subject,
            "body": body,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if actor.did_aw:
            signed["from_stable_id"] = actor.did_aw
        result = await sign_hosted_message(
            auth=auth, signer=hosted_signer, message_type="chat", payload=signed
        )
        payload = RoomPost(
            room_id=room["room_id"],
            signed_payload=result.signed_payload,
            signature=result.signature,
            signing_key_id=result.signing_key_id or result.from_did,
        )
    with agent_wake_scope(current_agent_wake_publisher()):
        output = await post_room_message(
            db,
            actor,
            payload,
            id_chain=getattr(auth.request.state, "id_chain", None),
            on_mutation=current_mutation_callback(),
        )
    return json.dumps(await present_room(db, auth.request, output))
