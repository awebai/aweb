from __future__ import annotations

import hashlib
import logging
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException

logger = logging.getLogger(__name__)

HANG_ON_EXTENSION_SECONDS = 300


def participant_hash(agent_ids: list[str]) -> str:
    normalized = sorted({str(UUID(a)) for a in agent_ids})
    return hashlib.sha256((",".join(normalized)).encode("utf-8")).hexdigest()


async def get_agent_by_id(db, *, project_id: str, agent_id: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if not row:
        return None
    return dict(row)


async def get_agent_by_alias(db, *, project_id: str, alias: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        UUID(project_id),
        alias,
    )
    if not row:
        return None
    return dict(row)


async def ensure_session(
    db,
    *,
    project_id: str,
    agent_rows: list[dict[str, Any]],
) -> UUID:
    """Create or find a chat session for a set of participants.

    Raises HTTPException(500) on failure (matching messages_service pattern).
    """
    aweb_db = db.get_manager("aweb")
    p_hash = participant_hash([str(r["agent_id"]) for r in agent_rows])

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
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
            existing = await tx.fetch_one(
                """
                SELECT session_id
                FROM {{tables.chat_sessions}}
                WHERE project_id = $1 AND participant_hash = $2
                """,
                UUID(project_id),
                p_hash,
            )
            if existing is None:
                logger.error(
                    "Chat session not found after INSERT ON CONFLICT DO NOTHING. "
                    "project_id=%s participant_hash=%s",
                    project_id,
                    p_hash,
                )
                raise HTTPException(
                    status_code=500,
                    detail="Failed to create or retrieve chat session",
                )
            session_id = existing["session_id"]

        for agent in agent_rows:
            await tx.execute(
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


async def send_in_session(
    db,
    *,
    session_id: UUID,
    agent_id: str,
    body: str,
    leaving: bool = False,
    hang_on: bool = False,
    from_did: str | None = None,
    to_did: str | None = None,
    signature: str | None = None,
    signing_key_id: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
) -> dict | None:
    """Send a message in an existing session. Returns message row dict or None.

    Returns None if the agent is not a participant in the session.
    """
    aweb_db = db.get_manager("aweb")
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

    effective_created_at = created_at if created_at is not None else datetime.now(timezone.utc)
    effective_message_id = message_id if message_id is not None else uuid_mod.uuid4()

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_agent_id, from_alias, body, sender_leaving, hang_on,
             from_did, to_did, signature, signing_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING message_id, created_at
        """,
        effective_message_id,
        session_id,
        agent_uuid,
        participant["alias"],
        body,
        bool(leaving),
        bool(hang_on),
        from_did,
        to_did,
        signature,
        signing_key_id,
        effective_created_at,
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
        WHERE {{tables.chat_read_receipts}}.last_read_at IS NULL
           OR EXCLUDED.last_read_at > {{tables.chat_read_receipts}}.last_read_at
        """,
        session_id,
        agent_uuid,
        msg_row["message_id"],
        msg_row["created_at"],
    )

    return dict(msg_row)


async def get_pending_conversations(
    db,
    *,
    project_id: str,
    agent_id: str,
) -> list[dict[str, Any]]:
    """Get conversations with unread messages for an agent."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids,
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
        UUID(project_id),
        UUID(agent_id),
    )

    return [
        {
            "session_id": str(r["session_id"]),
            "participants": list(r["participants"] or []),
            "participant_ids": list(r["participant_ids"] or []),
            "last_message": r["last_message"] or "",
            "last_from": r["last_from"] or "",
            "unread_count": int(r["unread_count"] or 0),
            "last_activity": r["last_activity"],
        }
        for r in rows
    ]


async def get_message_history(
    db,
    *,
    session_id: UUID,
    agent_id: str,
    unread_only: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Get messages for a chat session.

    Raises HTTPException(404) if the session is not found.
    Raises HTTPException(403) if the agent is not a participant.
    """
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    if not is_participant:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    rr = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    last_read_at = rr["last_read_at"] if rr else None

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, body, created_at, sender_leaving,
               from_did, to_did, signature, signing_key_id
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND ($2::bool IS FALSE OR (created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz) AND from_agent_id <> $4))
        ORDER BY created_at DESC
        LIMIT $5
        """,
        session_id,
        bool(unread_only),
        last_read_at,
        agent_uuid,
        int(limit),
    )
    rows = list(reversed(rows))

    return [
        {
            "message_id": str(r["message_id"]),
            "from_alias": r["from_alias"],
            "body": r["body"],
            "created_at": r["created_at"],
            "sender_leaving": bool(r["sender_leaving"]),
            "from_did": r.get("from_did"),
            "to_did": r.get("to_did"),
            "signature": r.get("signature"),
            "signing_key_id": r.get("signing_key_id"),
        }
        for r in rows
    ]


async def mark_messages_read(
    db,
    *,
    session_id: UUID,
    agent_id: str,
    up_to_message_id: str,
) -> dict[str, Any]:
    """Mark messages as read up to a given message.

    Raises HTTPException(403) if the agent is not a participant.
    Raises HTTPException(404) if the message is not found.
    """
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)
    up_to_uuid = UUID(up_to_message_id)

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    if not is_participant:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    msg = await aweb_db.fetch_one(
        """
        SELECT created_at
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = $2
        """,
        session_id,
        up_to_uuid,
    )
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    up_to_time = msg["created_at"]
    read_time = datetime.now(timezone.utc)

    old = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
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
        session_id,
        agent_uuid,
        old_last,
        up_to_time,
    )

    # Guard: only advance cursor if the target message is newer than the
    # currently stored one.  Uses a subquery on message timestamps rather than
    # last_read_at (which is wall-clock time) so that the comparison is always
    # between message creation times.
    upserted = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_read_receipts}} (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        WHERE $5 > COALESCE(
            (SELECT created_at FROM {{tables.chat_messages}}
             WHERE message_id = {{tables.chat_read_receipts}}.last_read_message_id),
            'epoch'::timestamptz
        )
        RETURNING 1
        """,
        session_id,
        agent_uuid,
        up_to_uuid,
        read_time,
        up_to_time,
    )

    return {
        "session_id": str(session_id),
        "messages_marked": int(marked or 0) if upserted else 0,
    }
