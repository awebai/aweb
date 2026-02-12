"""MCP tools for real-time chat messaging."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from uuid import UUID

from aweb.chat_waiting import (
    register_waiting,
    unregister_waiting,
)
from aweb.mcp.auth import get_auth

HANG_ON_EXTENSION_SECONDS = 300
MAX_TOTAL_WAIT_SECONDS = 600  # Absolute cap even with hang_on extensions


def _participant_hash(agent_ids: list[str]) -> str:
    normalized = sorted({str(UUID(a)) for a in agent_ids})
    return hashlib.sha256((",".join(normalized)).encode("utf-8")).hexdigest()


async def _ensure_session(aweb_db, *, project_id: str, agent_rows: list[dict]) -> UUID:
    """Create or find a chat session for a set of participants."""
    p_hash = _participant_hash([str(r["agent_id"]) for r in agent_rows])

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_sessions}} (project_id, participant_hash)
        VALUES ($1, $2)
        ON CONFLICT (project_id, participant_hash) DO NOTHING
        RETURNING session_id
        """,
        UUID(project_id),
        p_hash,
    )
    if row and row.get("session_id"):
        session_id = row["session_id"]
    else:
        existing = await aweb_db.fetch_one(
            """
            SELECT session_id
            FROM {{tables.chat_sessions}}
            WHERE project_id = $1 AND participant_hash = $2
            """,
            UUID(project_id),
            p_hash,
        )
        if existing is None:
            return None  # type: ignore[return-value]
        session_id = existing["session_id"]

    for agent in agent_rows:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.chat_session_participants}} (session_id, agent_id, alias)
            VALUES ($1, $2, $3)
            ON CONFLICT (session_id, agent_id) DO UPDATE SET alias = EXCLUDED.alias
            """,
            session_id,
            UUID(str(agent["agent_id"])),
            agent["alias"],
        )

    return UUID(str(session_id))


async def _send_in_session(
    aweb_db,
    *,
    session_id: UUID,
    agent_id: str,
    body: str,
    leaving: bool = False,
    hang_on: bool = False,
) -> dict | None:
    """Send a message in an existing session. Returns message row or None."""
    agent_uuid = UUID(agent_id)

    participant = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    if not participant:
        return None

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_agent_id, from_alias, body, sender_leaving, hang_on)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING message_id, created_at
        """,
        session_id,
        agent_uuid,
        participant["alias"],
        body,
        bool(leaving),
        bool(hang_on),
    )

    # Advance sender's read receipt.
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        session_id,
        agent_uuid,
        msg_row["message_id"],
        msg_row["created_at"],
    )

    return dict(msg_row)


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
        sender = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            UUID(auth.agent_id),
            UUID(auth.project_id),
        )
        if not sender:
            return json.dumps({"error": "Sender agent not found"})

        if sender["alias"] == to_alias:
            return json.dumps({"error": "Cannot chat with yourself"})

        target = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias
            FROM {{tables.agents}}
            WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            UUID(auth.project_id),
            to_alias,
        )
        if not target:
            return json.dumps({"error": f"Agent '{to_alias}' not found in project"})

        sid = await _ensure_session(
            aweb_db,
            project_id=auth.project_id,
            agent_rows=[dict(sender), dict(target)],
        )
        if sid is None:
            return json.dumps({"error": "Failed to create chat session"})

        msg = await _send_in_session(
            aweb_db,
            session_id=sid,
            agent_id=auth.agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
        )
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

        msg = await _send_in_session(
            aweb_db,
            session_id=sid,
            agent_id=auth.agent_id,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
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
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            lm.body AS last_message,
            lm.from_alias AS last_from,
            lm.created_at AS last_activity,
            COALESCE(unread.cnt, 0) AS unread_count
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_session_participants}} p
          ON p.session_id = s.session_id AND p.agent_id = $2
        JOIN {{tables.chat_session_participants}} p2
          ON p2.session_id = s.session_id
        LEFT JOIN LATERAL (
            SELECT body, from_alias, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = s.session_id
            ORDER BY created_at DESC
            LIMIT 1
        ) lm ON TRUE
        LEFT JOIN {{tables.chat_read_receipts}} rr
          ON rr.session_id = s.session_id AND rr.agent_id = $2
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::int AS cnt
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_agent_id <> $2
              AND m.created_at > COALESCE(rr.last_read_at, 'epoch'::timestamptz)
        ) unread ON TRUE
        WHERE s.project_id = $1
        GROUP BY s.session_id, lm.body, lm.from_alias, lm.created_at, unread.cnt
        HAVING COALESCE(unread.cnt, 0) > 0
        ORDER BY lm.created_at DESC
        """,
        UUID(auth.project_id),
        UUID(auth.agent_id),
    )

    pending = []
    for r in rows:
        pending.append(
            {
                "session_id": str(r["session_id"]),
                "participants": list(r["participants"] or []),
                "last_message": r["last_message"] or "",
                "last_from": r["last_from"] or "",
                "unread_count": int(r["unread_count"] or 0),
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
    aweb_db = db_infra.get_manager("aweb")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    agent_uuid = UUID(auth.agent_id)

    # Verify session exists and agent is participant.
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(auth.project_id),
    )
    if not sess:
        return json.dumps({"error": "Session not found"})

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    if not is_participant:
        return json.dumps({"error": "Not a participant in this session"})

    rr = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    last_read_at = rr["last_read_at"] if rr else None

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, body, created_at, sender_leaving
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND ($2::bool IS FALSE OR (created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz) AND from_agent_id <> $4))
        ORDER BY created_at DESC
        LIMIT $5
        """,
        session_uuid,
        bool(unread_only),
        last_read_at,
        agent_uuid,
        int(min(limit, 200)),
    )
    rows = list(reversed(rows))

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "messages": [
                {
                    "message_id": str(r["message_id"]),
                    "from_alias": r["from_alias"],
                    "body": r["body"],
                    "sender_leaving": bool(r["sender_leaving"]),
                    "timestamp": r["created_at"].isoformat(),
                }
                for r in rows
            ],
        }
    )


async def chat_read(db_infra, *, session_id: str, up_to_message_id: str) -> str:
    """Mark messages as read up to a given message."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    try:
        up_to_uuid = UUID(up_to_message_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid message_id format"})

    agent_uuid = UUID(auth.agent_id)

    # Verify participation.
    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    if not is_participant:
        return json.dumps({"error": "Not a participant in this session"})

    msg = await aweb_db.fetch_one(
        """
        SELECT created_at
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = $2
        """,
        session_uuid,
        up_to_uuid,
    )
    if not msg:
        return json.dumps({"error": "Message not found"})

    up_to_time = msg["created_at"]
    read_time = datetime.now(timezone.utc)

    old = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    old_last = old["last_read_at"] if old else None

    marked = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND from_agent_id <> $2
          AND created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz)
          AND created_at <= $4
        """,
        session_uuid,
        agent_uuid,
        old_last,
        up_to_time,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        session_uuid,
        agent_uuid,
        up_to_uuid,
        read_time,
    )

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "messages_marked": int(marked or 0),
            "status": "read",
        }
    )
