"""MCP tools for real-time chat messaging."""

from __future__ import annotations

import asyncio
import json
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from uuid import UUID

from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agent_by_alias,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    resolve_agent_by_did,
    send_in_session,
)
from aweb.messaging.messages import evaluate_messaging_policy
from aweb.messaging.waiting import register_waiting, unregister_waiting
from aweb.mcp.auth import get_auth
from aweb.service_errors import ServiceError

MAX_TOTAL_WAIT_SECONDS = 600


def _actor_did() -> str:
    auth = get_auth()
    return (auth.did_aw or auth.did_key or "").strip()


def _actor_alias(actor_agent: dict | None) -> str:
    auth = get_auth()
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or ((actor_agent or {}).get("alias") or "").strip()
        or ((actor_agent or {}).get("address") or "").strip()
        or _actor_did()
    )


async def _wait_for_replies(
    aweb_db,
    redis,
    *,
    session_id: UUID,
    participant_did: str,
    after: datetime,
    wait_seconds: int,
) -> tuple[list[dict], bool]:
    session_id_str = str(session_id)
    start = time.monotonic()
    absolute_deadline = start + MAX_TOTAL_WAIT_SECONDS
    deadline = start + wait_seconds

    await register_waiting(redis, session_id_str, participant_did)
    last_refresh = time.monotonic()
    last_seen_at = after

    try:
        while time.monotonic() < deadline:
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, participant_did)
                last_refresh = now_mono

            new_msgs = await aweb_db.fetch_all(
                """
                SELECT message_id, from_did, from_alias, body, created_at,
                       sender_leaving, hang_on
                FROM {{tables.chat_messages}}
                WHERE session_id = $1
                  AND from_did <> $2
                  AND created_at > $3
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                participant_did,
                last_seen_at,
            )

            if new_msgs:
                replies = []
                for row in new_msgs:
                    last_seen_at = max(last_seen_at, row["created_at"])
                    is_hang_on = bool(row["hang_on"])
                    if is_hang_on:
                        extended = time.monotonic() + HANG_ON_EXTENSION_SECONDS
                        deadline = min(max(deadline, extended), absolute_deadline)
                    replies.append(
                        {
                            "message_id": str(row["message_id"]),
                            "from_alias": row["from_alias"],
                            "from_did": row["from_did"],
                            "body": row["body"],
                            "hang_on": is_hang_on,
                            "sender_leaving": bool(row["sender_leaving"]),
                            "timestamp": row["created_at"].isoformat(),
                        }
                    )
                if any(not reply["hang_on"] for reply in replies):
                    return replies, False

            await asyncio.sleep(0.5)

        return [], True
    finally:
        await unregister_waiting(redis, session_id_str, participant_did)


async def chat_send(
    db_infra,
    redis,
    *,
    registry_client,
    message: str,
    to_alias: str = "",
    to_did: str = "",
    to_address: str = "",
    session_id: str = "",
    wait: bool = False,
    wait_seconds: int = 120,
    leaving: bool = False,
    hang_on: bool = False,
) -> str:
    auth = get_auth()
    actor_did = _actor_did()
    actor_agent = await resolve_agent_by_did(db_infra, actor_did) if actor_did else None
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(actor_agent)
    aweb_db = db_infra.get_manager("aweb")

    recipient_modes = int(bool(to_alias.strip())) + int(bool(to_did.strip())) + int(bool(to_address.strip()))
    if not session_id and recipient_modes != 1:
        return json.dumps({"error": "Provide exactly one of to_alias, to_did, or to_address"})
    if session_id and recipient_modes != 0:
        return json.dumps({"error": "Provide session_id or a recipient, not both"})

    if not actor_did:
        return json.dumps({"error": "Authenticated identity is missing a routing DID"})

    if not session_id:
        if to_alias:
            if auth.team_id is None:
                return json.dumps({"error": "to_alias requires team context"})
            target = await get_agent_by_alias(db_infra, team_id=auth.team_id, alias=to_alias.strip())
            if not target:
                return json.dumps({"error": f"Agent '{to_alias}' not found in team"})
        elif to_did:
            target = await resolve_agent_by_did(db_infra, to_did.strip())
            if not target:
                return json.dumps({"error": f"Recipient '{to_did}' not found"})
        else:
            if registry_client is None:
                return json.dumps({"error": "AWID registry unavailable"})
            if "/" not in to_address:
                return json.dumps({"error": "to_address must be domain/name"})
            domain, name = to_address.split("/", 1)
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is None or not resolved.did_aw:
                return json.dumps({"error": f"Recipient address '{to_address}' not found"})
            target = await resolve_agent_by_did(db_infra, resolved.did_aw)
            if not target:
                return json.dumps({"error": f"Recipient '{to_address}' not connected"})

        target_did = (target.get("did_aw") or target.get("did_key") or "").strip()
        if target_did == actor_did:
            return json.dumps({"error": "Cannot chat with yourself"})
        try:
            await evaluate_messaging_policy(
                db_infra,
                registry_client=registry_client,
                recipient_agent=target,
                sender_did=actor_did,
                sender_address=auth.address,
            )
        except ServiceError as exc:
            return json.dumps({"error": exc.detail})

        try:
            sid = await ensure_session(
                db_infra,
                team_id=auth.team_id,
                participant_rows=[
                    {"did": actor_did, "agent_id": actor_agent_id, "alias": actor_alias},
                    {
                        "did": target_did,
                        "agent_id": str(target["agent_id"]) if target.get("agent_id") else None,
                        "alias": (target.get("alias") or target.get("address") or target_did).strip(),
                    },
                ],
                created_by=actor_alias,
            )
        except ServiceError:
            return json.dumps({"error": "Failed to create chat session"})

        msg_created_at = datetime.now(timezone.utc)
        pre_message_id = uuid_mod.uuid4()
        msg = await send_in_session(
            db_infra,
            session_id=sid,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
        if msg is None:
            return json.dumps({"error": "Failed to send message"})
    else:
        try:
            sid = UUID(session_id.strip())
        except Exception:
            return json.dumps({"error": "Invalid session_id format"})

        sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", sid)
        if not sess:
            return json.dumps({"error": "Session not found"})

        msg = await send_in_session(
            db_infra,
            session_id=sid,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            created_at=datetime.now(timezone.utc),
            message_id=uuid_mod.uuid4(),
        )
        if msg is None:
            return json.dumps({"error": "Not a participant in this session"})

    result: dict = {
        "session_id": str(sid),
        "message_id": str(msg["message_id"]),
        "delivered": True,
    }
    if wait:
        replies, timed_out = await _wait_for_replies(
            aweb_db,
            redis,
            session_id=sid,
            participant_did=actor_did,
            after=msg["created_at"],
            wait_seconds=wait_seconds,
        )
        result["replies"] = replies
        result["timed_out"] = timed_out
    return json.dumps(result)


async def chat_pending(db_infra, redis) -> str:
    auth = get_auth()
    actor_did = _actor_did()
    actor_agent = await resolve_agent_by_did(db_infra, actor_did) if actor_did else None
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    conversations = await get_pending_conversations(
        db_infra,
        participant_did=actor_did,
        participant_agent_id=actor_agent_id,
    )
    pending = [
        {
            "session_id": row["session_id"],
            "participants": row["participants"],
            "last_message": row["last_message"],
            "last_from": row["last_from"],
            "unread_count": row["unread_count"],
            "last_activity": row["last_activity"].isoformat() if row["last_activity"] else "",
        }
        for row in conversations
    ]
    return json.dumps({"pending": pending})


async def chat_history(
    db_infra,
    *,
    session_id: str,
    unread_only: bool = False,
    limit: int = 50,
) -> str:
    actor_did = _actor_did()
    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    aweb_db = db_infra.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        return json.dumps({"error": "Session not found"})

    try:
        messages = await get_message_history(
            db_infra,
            session_id=session_uuid,
            participant_did=actor_did,
            unread_only=unread_only,
            limit=min(limit, 200),
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "messages": [
                {
                    "message_id": msg["message_id"],
                    "from_alias": msg["from_alias"],
                    "from_did": msg.get("from_did"),
                    "body": msg["body"],
                    "sender_leaving": msg["sender_leaving"],
                    "timestamp": msg["created_at"].isoformat(),
                }
                for msg in messages
            ],
        }
    )


async def chat_read(db_infra, *, session_id: str, up_to_message_id: str) -> str:
    auth = get_auth()
    actor_did = _actor_did()
    actor_agent = await resolve_agent_by_did(db_infra, actor_did) if actor_did else None
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})
    try:
        UUID(up_to_message_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid message_id format"})

    try:
        result = await mark_messages_read(
            db_infra,
            session_id=session_uuid,
            participant_did=actor_did,
            participant_agent_id=actor_agent_id,
            up_to_message_id=up_to_message_id.strip(),
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": result["session_id"],
            "messages_marked": result["messages_marked"],
            "status": "read",
        }
    )
