from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth

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


def _conversation_label(alias: str | None, did: str | None) -> str:
    alias_value = (alias or "").strip()
    if alias_value:
        return alias_value
    return (did or "").strip()


def _dedupe_labels(values: list[str]) -> list[str]:
    labels: list[str] = []
    for value in values:
        value = (value or "").strip()
        if value and value not in labels:
            labels.append(value)
    return labels


@router.get("", response_model=ConversationsResponse)
async def list_conversations(
    request: Request,
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> ConversationsResponse:
    del request
    aweb_db = db.get_manager("aweb")
    actor_dids = auth_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    cursor_dt: datetime | None = None
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(cursor.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid cursor format")

    # --- Mail conversations ---
    # Mail is one conversation per stored message. message_id is unique per row.
    mail_rows = await aweb_db.fetch_all(
        """
        SELECT
            m.message_id::text AS conversation_id,
            m.created_at AS last_message_at,
            m.body AS last_body,
            m.from_alias AS last_from,
            m.from_did AS last_from_did,
            m.subject AS subject,
            m.to_alias AS to_alias,
            m.to_did AS to_did,
            CASE
                WHEN m.to_did = ANY($1::text[]) AND m.read_at IS NULL THEN 1
                ELSE 0
            END::int AS unread_count
        FROM {{tables.messages}} m
        WHERE m.from_did = ANY($1::text[])
           OR m.to_did = ANY($1::text[])
        ORDER BY m.created_at DESC
        """,
        actor_dids,
    )

    mail_items: list[dict] = []
    for row in mail_rows:
        preview = (row["last_body"] or "")[:100]
        mail_items.append(
            {
                "conversation_type": "mail",
                "conversation_id": row["conversation_id"],
                "participants": _dedupe_labels(
                    [
                        _conversation_label(row["last_from"], row["last_from_did"]),
                        _conversation_label(row["to_alias"], row["to_did"]),
                    ]
                ),
                "subject": row["subject"] or "",
                "last_message_at": row["last_message_at"],
                "last_message_from": _conversation_label(row["last_from"], row["last_from_did"]),
                "last_message_preview": preview,
                "unread_count": row["unread_count"],
            }
        )

    # --- Chat conversations ---
    rows_by_session: dict[str, dict] = {}
    for actor_did in actor_dids:
        rows = await aweb_db.fetch_all(
            """
            SELECT
                s.session_id::text AS conversation_id,
                array_agg(p2.alias ORDER BY p2.alias) AS participants,
                array_agg(p2.did ORDER BY p2.alias) AS participant_dids,
                lm.body AS last_body,
                lm.from_alias AS last_from,
                lm.from_did AS last_from_did,
                lm.created_at AS last_message_at,
                COALESCE(unread.cnt, 0)::int AS unread_count
            FROM {{tables.chat_sessions}} s
            JOIN {{tables.chat_participants}} p
              ON p.session_id = s.session_id AND p.did = $1
            JOIN {{tables.chat_participants}} p2
              ON p2.session_id = s.session_id
            LEFT JOIN LATERAL (
                SELECT body, from_alias, from_did, created_at
                FROM {{tables.chat_messages}}
                WHERE session_id = s.session_id
                ORDER BY created_at DESC
                LIMIT 1
            ) lm ON TRUE
            LEFT JOIN {{tables.chat_read_receipts}} rr
              ON rr.session_id = s.session_id AND rr.did = $1
            LEFT JOIN {{tables.chat_messages}} last_read_msg
              ON last_read_msg.message_id = rr.last_read_message_id
            LEFT JOIN LATERAL (
                SELECT COUNT(*)::int AS cnt
                FROM {{tables.chat_messages}} cm
                WHERE cm.session_id = s.session_id
                  AND cm.from_did <> $1
                  AND cm.created_at > COALESCE(last_read_msg.created_at, 'epoch'::timestamptz)
            ) unread ON TRUE
            WHERE lm.created_at IS NOT NULL
            GROUP BY s.session_id, lm.body, lm.from_alias, lm.from_did, lm.created_at, unread.cnt
            ORDER BY lm.created_at DESC
            """,
            actor_did,
        )
        for row in rows:
            rows_by_session.setdefault(row["conversation_id"], dict(row))
    chat_rows = list(rows_by_session.values())
    chat_rows.sort(key=lambda row: row["last_message_at"], reverse=True)

    chat_items: list[dict] = []
    for row in chat_rows:
        preview = (row["last_body"] or "")[:100]
        participants = _dedupe_labels(
            [
                _conversation_label(alias, did)
                for alias, did in zip(list(row["participants"] or []), list(row["participant_dids"] or []))
            ]
        )
        chat_items.append(
            {
                "conversation_type": "chat",
                "conversation_id": row["conversation_id"],
                "participants": participants,
                "subject": "",
                "last_message_at": row["last_message_at"],
                "last_message_from": _conversation_label(row["last_from"], row["last_from_did"]),
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
