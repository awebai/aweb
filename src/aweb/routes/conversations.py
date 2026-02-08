from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/conversations", tags=["aweb-conversations"])


class ConversationItem(BaseModel):
    conversation_type: str  # "mail" or "chat"
    conversation_id: str
    participants: list[str]
    subject: str
    last_message_at: str
    last_message_from: str
    last_message_preview: str
    unread_count: int


class ConversationsResponse(BaseModel):
    conversations: list[ConversationItem]
    next_cursor: str | None


@router.get("", response_model=ConversationsResponse)
async def list_conversations(
    request: Request,
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db=Depends(get_db),
) -> ConversationsResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    aweb_db = db.get_manager("aweb")

    project_uuid = UUID(project_id)
    actor_uuid = UUID(actor_id)

    cursor_dt: datetime | None = None
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(cursor.replace("Z", "+00:00"))
        except Exception:
            cursor_dt = None

    # --- Mail conversations ---
    # Group by COALESCE(thread_id, message_id) to treat standalone mails as their own thread.
    # Only include conversations where this agent is sender or receiver.
    mail_rows = await aweb_db.fetch_all(
        """
        SELECT
            COALESCE(m.thread_id, m.message_id)::text AS conversation_id,
            MAX(m.created_at) AS last_message_at,
            (array_agg(m.body ORDER BY m.created_at DESC))[1] AS last_body,
            (array_agg(m.from_alias ORDER BY m.created_at DESC))[1] AS last_from,
            (array_agg(m.subject ORDER BY m.created_at DESC))[1] AS subject,
            COUNT(*) FILTER (WHERE m.to_agent_id = $2 AND m.read_at IS NULL)::int AS unread_count
        FROM {{tables.messages}} m
        WHERE m.project_id = $1
          AND (m.from_agent_id = $2 OR m.to_agent_id = $2)
        GROUP BY COALESCE(m.thread_id, m.message_id)
        ORDER BY MAX(m.created_at) DESC
        """,
        project_uuid,
        actor_uuid,
    )

    # Batch-resolve participants for all mail conversations in one query.
    conv_ids = [row["conversation_id"] for row in mail_rows]
    participants_map: dict[str, list[str]] = {cid: [] for cid in conv_ids}
    if conv_ids:
        part_rows = await aweb_db.fetch_all(
            """
            SELECT COALESCE(m.thread_id, m.message_id)::text AS conv_id, a.alias
            FROM {{tables.messages}} m
            JOIN {{tables.agents}} a ON a.agent_id IN (m.from_agent_id, m.to_agent_id)
            WHERE m.project_id = $1
              AND COALESCE(m.thread_id, m.message_id)::text = ANY($2)
            GROUP BY COALESCE(m.thread_id, m.message_id), a.alias
            ORDER BY a.alias
            """,
            project_uuid,
            conv_ids,
        )
        for r in part_rows:
            participants_map[r["conv_id"]].append(r["alias"])

    mail_items: list[dict] = []
    for row in mail_rows:
        conv_id = row["conversation_id"]
        preview = (row["last_body"] or "")[:100]

        mail_items.append(
            {
                "conversation_type": "mail",
                "conversation_id": conv_id,
                "participants": participants_map.get(conv_id, []),
                "subject": row["subject"] or "",
                "last_message_at": row["last_message_at"],
                "last_message_from": row["last_from"] or "",
                "last_message_preview": preview,
                "unread_count": row["unread_count"],
            }
        )

    # --- Chat conversations ---
    chat_rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id::text AS conversation_id,
            array_agg(DISTINCT p2.alias ORDER BY p2.alias) AS participants,
            lm.body AS last_body,
            lm.from_alias AS last_from,
            lm.created_at AS last_message_at,
            COALESCE(unread.cnt, 0)::int AS unread_count
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
            FROM {{tables.chat_messages}} cm
            WHERE cm.session_id = s.session_id
              AND cm.from_agent_id <> $2
              AND cm.created_at > COALESCE(rr.last_read_at, 'epoch'::timestamptz)
        ) unread ON TRUE
        WHERE s.project_id = $1
          AND lm.created_at IS NOT NULL
        GROUP BY s.session_id, lm.body, lm.from_alias, lm.created_at, unread.cnt
        ORDER BY lm.created_at DESC
        """,
        project_uuid,
        actor_uuid,
    )

    chat_items: list[dict] = []
    for row in chat_rows:
        preview = (row["last_body"] or "")[:100]
        chat_items.append(
            {
                "conversation_type": "chat",
                "conversation_id": row["conversation_id"],
                "participants": list(row["participants"] or []),
                "subject": "",
                "last_message_at": row["last_message_at"],
                "last_message_from": row["last_from"] or "",
                "last_message_preview": preview,
                "unread_count": row["unread_count"],
            }
        )

    # --- Merge and sort ---
    combined = mail_items + chat_items
    combined.sort(key=lambda x: x["last_message_at"], reverse=True)

    # Apply cursor filter
    if cursor_dt:
        combined = [c for c in combined if c["last_message_at"] < cursor_dt]

    # Apply limit
    page = combined[:limit]
    next_cursor: str | None = None
    if len(page) == limit and len(combined) > limit:
        last = page[-1]["last_message_at"]
        next_cursor = last.isoformat() if hasattr(last, "isoformat") else str(last)

    # Serialize datetimes
    result = []
    for item in page:
        ts = item["last_message_at"]
        result.append(
            ConversationItem(
                conversation_type=item["conversation_type"],
                conversation_id=item["conversation_id"],
                participants=item["participants"],
                subject=item["subject"],
                last_message_at=ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                last_message_from=item["last_message_from"],
                last_message_preview=item["last_message_preview"],
                unread_count=item["unread_count"],
            )
        )

    return ConversationsResponse(conversations=result, next_cursor=next_cursor)
