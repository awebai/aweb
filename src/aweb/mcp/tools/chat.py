"""MCP tools for real-time chat messaging."""

from __future__ import annotations

import asyncio
import json
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from uuid import UUID

from aweb.chat_service import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agent_by_alias,
    get_agent_by_id,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    send_in_session,
)
from aweb.chat_waiting import (
    register_waiting,
    unregister_waiting,
)
from aweb.custody import sign_on_behalf
from aweb.mcp.auth import get_auth

from fastapi import HTTPException

MAX_TOTAL_WAIT_SECONDS = 600  # Absolute cap even with hang_on extensions


async def _wait_for_replies(
    aweb_db,
    redis,
    *,
    session_id: UUID,
    agent_id: str,
    after: datetime,
    wait_seconds: int,
) -> tuple[list[dict], bool]:
    """Poll for replies from other agents. Returns (messages, timed_out)."""
    session_id_str = str(session_id)
    agent_uuid = UUID(agent_id)
    start = time.monotonic()
    absolute_deadline = start + MAX_TOTAL_WAIT_SECONDS
    deadline = start + wait_seconds

    await register_waiting(redis, session_id_str, agent_id)
    last_refresh = time.monotonic()
    last_seen_at = after

    try:
        while time.monotonic() < deadline:
            # Refresh Redis registration every 30s.
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, agent_id)
                last_refresh = now_mono

            new_msgs = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on
                FROM {{tables.chat_messages}}
                WHERE session_id = $1
                  AND from_agent_id <> $2
                  AND created_at > $3
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                agent_uuid,
                last_seen_at,
            )

            if new_msgs:
                replies = []
                for r in new_msgs:
                    last_seen_at = max(last_seen_at, r["created_at"])
                    is_hang_on = bool(r["hang_on"])
                    if is_hang_on:
                        extended = time.monotonic() + HANG_ON_EXTENSION_SECONDS
                        deadline = min(max(deadline, extended), absolute_deadline)
                    replies.append(
                        {
                            "message_id": str(r["message_id"]),
                            "from_alias": r["from_alias"],
                            "body": r["body"],
                            "hang_on": is_hang_on,
                            "sender_leaving": bool(r["sender_leaving"]),
                            "timestamp": r["created_at"].isoformat(),
                        }
                    )

                # Return non-hang_on replies immediately. If all messages are
                # hang_on only, keep waiting for the real reply.
                has_real_reply = any(not m["hang_on"] for m in replies)
                if has_real_reply:
                    return replies, False

            await asyncio.sleep(0.5)

        return [], True
    finally:
        await unregister_waiting(redis, session_id_str, agent_id)


async def chat_send(
    db_infra,
    redis,
    *,
    message: str,
    to_alias: str = "",
    session_id: str = "",
    wait: bool = False,
    wait_seconds: int = 120,
    leaving: bool = False,
    hang_on: bool = False,
) -> str:
    """Send a chat message. Creates a session if to_alias is provided."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if not to_alias and not session_id:
        return json.dumps({"error": "Provide to_alias or session_id"})
    if to_alias and session_id:
        return json.dumps({"error": "Provide to_alias or session_id, not both"})

    if to_alias:
        # Create or find session and send.
        sender = await get_agent_by_id(db_infra, project_id=auth.project_id, agent_id=auth.agent_id)
        if not sender:
            return json.dumps({"error": "Sender agent not found"})

        if sender["alias"] == to_alias:
            return json.dumps({"error": "Cannot chat with yourself"})

        target = await get_agent_by_alias(db_infra, project_id=auth.project_id, alias=to_alias)
        if not target:
            return json.dumps({"error": f"Agent '{to_alias}' not found in project"})

        try:
            sid = await ensure_session(
                db_infra,
                project_id=auth.project_id,
                agent_rows=[dict(sender), dict(target)],
            )
        except HTTPException:
            return json.dumps({"error": "Failed to create chat session"})

        # Server-side custodial signing.
        msg_from_did = None
        msg_signature = None
        msg_signing_key_id = None
        msg_created_at = datetime.now(timezone.utc)
        pre_message_id = uuid_mod.uuid4()

        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
            UUID(auth.project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        sign_result = await sign_on_behalf(
            auth.agent_id,
            {
                "from": f"{project_slug}/{sender['alias']}",
                "from_did": "",
                "message_id": str(pre_message_id),
                "to": f"{project_slug}/{to_alias}",
                "to_did": "",
                "type": "chat",
                "subject": "",
                "body": message,
                "timestamp": msg_created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            db_infra,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

        msg = await send_in_session(
            db_infra,
            session_id=sid,
            agent_id=auth.agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            from_did=msg_from_did,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
        if msg is None:
            return json.dumps({"error": "Failed to send message"})
    else:
        # Send in existing session.
        try:
            sid = UUID(session_id.strip())
        except Exception:
            return json.dumps({"error": "Invalid session_id format"})

        # Verify session belongs to project.
        sess = await aweb_db.fetch_one(
            "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
            sid,
            UUID(auth.project_id),
        )
        if not sess:
            return json.dumps({"error": "Session not found"})

        # Server-side custodial signing.
        sender_row = await aweb_db.fetch_one(
            "SELECT alias FROM {{tables.chat_session_participants}} WHERE session_id = $1 AND agent_id = $2",
            sid,
            UUID(auth.agent_id),
        )
        sender_alias = sender_row["alias"] if sender_row else ""
        msg_from_did = None
        msg_signature = None
        msg_signing_key_id = None
        msg_created_at = datetime.now(timezone.utc)
        pre_message_id = uuid_mod.uuid4()

        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
            UUID(auth.project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        sign_result = await sign_on_behalf(
            auth.agent_id,
            {
                "from": f"{project_slug}/{sender_alias}",
                "from_did": "",
                "message_id": str(pre_message_id),
                "to": "",
                "to_did": "",
                "type": "chat",
                "subject": "",
                "body": message,
                "timestamp": msg_created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            db_infra,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

        msg = await send_in_session(
            db_infra,
            session_id=sid,
            agent_id=auth.agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            from_did=msg_from_did,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            created_at=msg_created_at,
            message_id=pre_message_id,
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
            agent_id=auth.agent_id,
            after=msg["created_at"],
            wait_seconds=wait_seconds,
        )
        result["replies"] = replies
        result["timed_out"] = timed_out

    return json.dumps(result)


async def chat_pending(db_infra, redis) -> str:
    """List conversations with unread messages."""
    auth = get_auth()

    conversations = await get_pending_conversations(
        db_infra, project_id=auth.project_id, agent_id=auth.agent_id
    )

    pending = []
    for r in conversations:
        pending.append(
            {
                "session_id": r["session_id"],
                "participants": r["participants"],
                "last_message": r["last_message"],
                "last_from": r["last_from"],
                "unread_count": r["unread_count"],
                "last_activity": r["last_activity"].isoformat() if r["last_activity"] else "",
            }
        )

    return json.dumps({"pending": pending})


async def chat_history(
    db_infra,
    *,
    session_id: str,
    unread_only: bool = False,
    limit: int = 50,
) -> str:
    """Get messages for a chat session."""
    auth = get_auth()

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    aweb_db = db_infra.get_manager("aweb")

    # Verify session exists in project.
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(auth.project_id),
    )
    if not sess:
        return json.dumps({"error": "Session not found"})

    try:
        messages = await get_message_history(
            db_infra,
            session_id=session_uuid,
            agent_id=auth.agent_id,
            unread_only=unread_only,
            limit=min(limit, 200),
        )
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "messages": [
                {
                    "message_id": m["message_id"],
                    "from_alias": m["from_alias"],
                    "body": m["body"],
                    "sender_leaving": m["sender_leaving"],
                    "timestamp": m["created_at"].isoformat(),
                }
                for m in messages
            ],
        }
    )


async def chat_read(db_infra, *, session_id: str, up_to_message_id: str) -> str:
    """Mark messages as read up to a given message."""
    auth = get_auth()

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
            agent_id=auth.agent_id,
            up_to_message_id=up_to_message_id.strip(),
        )
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": result["session_id"],
            "messages_marked": result["messages_marked"],
            "status": "read",
        }
    )
