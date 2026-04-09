from __future__ import annotations

import logging
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError

logger = logging.getLogger(__name__)

HANG_ON_EXTENSION_SECONDS = 300


async def get_agent_by_id(db, *, team_id: str, agent_id: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        team_id,
    )
    if not row:
        return None
    return dict(row)


async def get_agent_by_alias(db, *, team_id: str, alias: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_id,
        alias,
    )
    if not row:
        return None
    return dict(row)


async def get_agents_by_aliases(db, *, team_id: str, aliases: list[str]) -> list[dict[str, Any]]:
    """Resolve multiple aliases to agents in a single query."""
    if not aliases:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, team_id, alias
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = ANY($2::text[]) AND deleted_at IS NULL
        """,
        team_id,
        aliases,
    )
    return [dict(r) for r in rows]


async def find_session_between(
    db,
    *,
    agent_id_a: UUID,
    agent_id_b: UUID,
) -> UUID | None:
    """Find an existing chat session between two agents."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT cp1.session_id
        FROM {{tables.chat_participants}} cp1
        JOIN {{tables.chat_participants}} cp2
          ON cp2.session_id = cp1.session_id
        WHERE cp1.agent_id = $1 AND cp2.agent_id = $2
        LIMIT 1
        """,
        agent_id_a,
        agent_id_b,
    )
    if not row:
        return None
    return row["session_id"]


async def ensure_session(
    db,
    *,
    team_id: str,
    agent_rows: list[dict[str, Any]],
    created_by_alias: str,
) -> UUID:
    """Create or find a chat session for a set of participants.

    For 2-party sessions, finds an existing session between the agents.
    For multi-party, always creates a new session.
    """
    aweb_db = db.get_manager("aweb")

    # For 2-party sessions, try to find an existing one
    if len(agent_rows) == 2:
        existing = await find_session_between(
            db,
            agent_id_a=UUID(str(agent_rows[0]["agent_id"])),
            agent_id_b=UUID(str(agent_rows[1]["agent_id"])),
        )
        if existing is not None:
            return existing

    # Create session
    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.chat_sessions}} (team_id, created_by)
            VALUES ($1, $2)
            RETURNING session_id
            """,
            team_id,
            created_by_alias,
        )
        if not row:
            raise ServiceError("Failed to create chat session")
        session_id = row["session_id"]

        for agent in agent_rows:
            await tx.execute(
                """
                INSERT INTO {{tables.chat_participants}} (session_id, agent_id, alias)
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
    reply_to: UUID | None = None,
    leaving: bool = False,
    hang_on: bool = False,
    from_did: str | None = None,
    signature: str | None = None,
    signed_payload: str | None = None,
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
        FROM {{tables.chat_participants}}
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
            (message_id, session_id, from_agent_id, from_alias, body,
             sender_leaving, hang_on, reply_to,
             from_did, signature, signed_payload, created_at)
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
        reply_to,
        from_did,
        signature,
        signed_payload,
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
    agent_id: str,
) -> list[dict[str, Any]]:
    """Get conversations with unread messages or active waits for an agent."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids,
            lm.body AS last_message,
            lm.from_alias AS last_from,
            lm.from_agent_id AS last_from_agent_id,
            lm.hang_on AS last_message_hang_on,
            lm.created_at AS last_activity,
            COALESCE(unread.cnt, 0) AS unread_count,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            COALESCE(wait_ext.total_seconds, 0) AS extended_wait_seconds
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_participants}} p
          ON p.session_id = s.session_id AND p.agent_id = $1
        JOIN {{tables.chat_participants}} p2
          ON p2.session_id = s.session_id
        LEFT JOIN LATERAL (
            SELECT body, from_alias, from_agent_id, hang_on, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = s.session_id
            ORDER BY created_at DESC
            LIMIT 1
        ) lm ON TRUE
        LEFT JOIN {{tables.chat_read_receipts}} rr
          ON rr.session_id = s.session_id AND rr.agent_id = $1
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = rr.last_read_message_id
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::int AS cnt
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_agent_id <> $1
              AND m.created_at > COALESCE(last_read_msg.created_at, 'epoch'::timestamptz)
        ) unread ON TRUE
        LEFT JOIN LATERAL (
            SELECT COALESCE(SUM($2::int), 0)::int AS total_seconds
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.hang_on = TRUE
              AND (s.wait_started_at IS NULL OR m.created_at >= s.wait_started_at)
        ) wait_ext ON TRUE
        WHERE p.agent_id = $1
        GROUP BY
            s.session_id,
            lm.body,
            lm.from_alias,
            lm.from_agent_id,
            lm.hang_on,
            lm.created_at,
            unread.cnt,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            wait_ext.total_seconds
        HAVING COALESCE(unread.cnt, 0) > 0
            OR (
                s.wait_started_at IS NOT NULL
                AND s.wait_seconds IS NOT NULL
                AND s.wait_started_by IS NOT NULL
                AND s.wait_started_by <> $1
                AND (
                    lm.from_agent_id IS NULL
                    OR lm.from_agent_id <> $1
                    OR COALESCE(lm.hang_on, FALSE) = TRUE
                )
                AND s.wait_started_at
                    + ((s.wait_seconds + COALESCE(wait_ext.total_seconds, 0)) * INTERVAL '1 second')
                    > NOW()
            )
        ORDER BY lm.created_at DESC
        """,
        UUID(agent_id),
        HANG_ON_EXTENSION_SECONDS,
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
            "wait_seconds": int(r["wait_seconds"]) if r.get("wait_seconds") is not None else None,
            "wait_started_at": r.get("wait_started_at"),
            "wait_started_by": (
                str(r["wait_started_by"])
                if r.get("wait_started_by") is not None
                else None
            ),
            "extended_wait_seconds": int(r["extended_wait_seconds"] or 0),
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

    Raises ForbiddenError if the agent is not a participant.
    """
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    if not is_participant:
        raise ForbiddenError("Not a participant in this session")

    rr = await aweb_db.fetch_one(
        """
        SELECT last_read_msg.created_at AS last_read_message_at
        FROM {{tables.chat_read_receipts}}
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = {{tables.chat_read_receipts}}.last_read_message_id
        WHERE {{tables.chat_read_receipts}}.session_id = $1
          AND {{tables.chat_read_receipts}}.agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    last_read_message_at = rr["last_read_message_at"] if rr else None

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, body, created_at, sender_leaving,
               from_agent_id, reply_to,
               from_did, signature, signed_payload
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND ($2::bool IS FALSE OR (created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz) AND from_agent_id <> $4))
        ORDER BY created_at DESC
        LIMIT $5
        """,
        session_id,
        bool(unread_only),
        last_read_message_at,
        agent_uuid,
        int(limit),
    )
    rows = list(reversed(rows))

    return [
        {
            "message_id": str(r["message_id"]),
            "from_agent_id": str(r["from_agent_id"]),
            "from_alias": r["from_alias"],
            "body": r["body"],
            "created_at": r["created_at"],
            "sender_leaving": bool(r["sender_leaving"]),
            "reply_to": (
                str(r["reply_to"])
                if r.get("reply_to") is not None
                else None
            ),
            "from_did": r.get("from_did"),
            "signature": r.get("signature"),
            "signed_payload": r.get("signed_payload"),
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

    Raises ForbiddenError if the agent is not a participant.
    Raises NotFoundError if the message is not found.
    """
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)
    up_to_uuid = UUID(up_to_message_id)

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    if not is_participant:
        raise ForbiddenError("Not a participant in this session")

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
        raise NotFoundError("Message not found")

    up_to_time = msg["created_at"]
    read_time = datetime.now(timezone.utc)

    old = await aweb_db.fetch_one(
        """
        SELECT last_read_msg.created_at AS last_read_message_at
        FROM {{tables.chat_read_receipts}}
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = {{tables.chat_read_receipts}}.last_read_message_id
        WHERE {{tables.chat_read_receipts}}.session_id = $1
          AND {{tables.chat_read_receipts}}.agent_id = $2
        """,
        session_id,
        agent_uuid,
    )
    old_last_message_at = old["last_read_message_at"] if old else None

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
        old_last_message_at,
        up_to_time,
    )

    # Only advance cursor if the target message is newer than the stored one.
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
