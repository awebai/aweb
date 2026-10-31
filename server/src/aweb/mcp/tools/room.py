"""Additive room tools; hosted custody signs as the authenticated actor."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException
from aweb.id_chain_auth import authenticate_id_chain
from aweb.identity_binding import verify_identity_binding
from aweb.identity_auth_deps import _enforce_current_membership
from aweb.mcp.auth import get_auth
from aweb.mcp.signing import sign_hosted_message
from aweb.messaging.room import (
    RoomPost,
    room_metadata,
    read_room,
    post_room_message,
    present_room,
)
from aweb.team_auth_deps import TeamIdentity
from aweb.messaging.room_notices import pending_room_notices


async def _room_actor(db):
    auth = get_auth()
    if (
        not auth.team_id
        or not auth.agent_id
        or not auth.request
        or not (auth.certificate_id or auth.trusted_proxy)
    ):
        raise HTTPException(403, "Room requires authenticated team context")
    row = await db.get_manager("aweb").fetch_one(
        """
        SELECT agent_id,team_id,did_key,certificate_id,status,deleted_at FROM {{tables.agents}}
        WHERE agent_id=$1 AND team_id=$2 AND did_key=$3
    """,
        UUID(auth.agent_id),
        auth.team_id,
        auth.did_key,
    )
    if (
        not row
        or not row["certificate_id"]
        or row["status"] != "active"
        or row["deleted_at"] is not None
    ):
        raise HTTPException(403, "Room requires current team membership")
    row = await _enforce_current_membership(auth.request, dict(row))
    if not row or row["team_id"] != auth.team_id:
        raise HTTPException(403, "Room requires current team membership")
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
    actor = TeamIdentity(
        team_id=auth.team_id,
        alias=auth.alias or "",
        did_key=auth.did_key,
        did_aw=auth.did_aw or "",
        address=auth.address or "",
        agent_id=auth.agent_id,
        identity_scope=auth.identity_scope or "",
        certificate_id=row["certificate_id"],
    )
    return auth, actor


async def room_read(db, *, after=None, limit=50):
    auth, actor = await _room_actor(db)
    return json.dumps(
        await present_room(
            db, auth.request, await read_room(db, actor, after=after, limit=limit)
        )
    )


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
    output = await post_room_message(
        db, actor, payload, id_chain=getattr(auth.request.state, "id_chain", None)
    )
    return json.dumps(await present_room(db, auth.request, output))
