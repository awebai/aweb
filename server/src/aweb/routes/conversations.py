from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth

router = APIRouter(prefix="/v1/conversations", tags=["aweb-conversations"])


class ConversationItem(BaseModel):
    conversation_type: str  # "mail" or "chat"
    conversation_id: str | None = None
    legacy_message_id: str | None = None
    status: str = "active"
    participants: list[str]
    participant_dids: list[str] = Field(default_factory=list)
    participant_addresses: list[str] = Field(default_factory=list)
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
    actor_agent_id = str(auth.agent_id).strip() if auth.agent_id else None
    actor_address = str(auth.address).strip() if auth.address else None
    if not actor_dids and not actor_agent_id and not actor_address:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    cursor_dt: datetime | None = None
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(cursor.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid cursor format")

    # --- Mail conversations ---
    # New mail rows share conversation_id across a thread. Legacy rows without
    # conversation_id are listed by legacy_message_id so clients do not mistake
    # a historical message id for a continuation-capable conversation id.
    mail_rows = await aweb_db.fetch_all(
        """
        SELECT
            m.message_id,
            m.conversation_id,
            m.created_at,
            m.body,
            m.from_alias,
            m.from_did,
            m.subject,
            m.to_alias AS to_alias,
            m.to_did AS to_did,
            m.read_at,
            c.status
        FROM {{tables.messages}} m
        LEFT JOIN {{tables.conversations}} c
          ON c.conversation_id = m.conversation_id
        WHERE m.from_did = ANY($1::text[])
           OR m.to_did = ANY($1::text[])
           OR (
                m.conversation_id IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM {{tables.conversation_participants}} cp
                    WHERE cp.conversation_id = m.conversation_id
                      AND (
                           cp.did = ANY($1::text[])
                        OR ($2::uuid IS NOT NULL AND cp.agent_id = $2::uuid)
                        OR ($3::text IS NOT NULL AND cp.address = $3::text)
                      )
                )
           )
        ORDER BY m.created_at DESC, m.message_id DESC
        """,
        actor_dids,
        actor_agent_id,
        actor_address,
    )

    actor_did_set = set(actor_dids)
    mail_by_conversation: dict[str, dict] = {}
    for row in mail_rows:
        real_conversation_id = str(row["conversation_id"]) if row["conversation_id"] else None
        legacy_message_id = None if real_conversation_id else str(row["message_id"])
        group_key = real_conversation_id or f"legacy:{legacy_message_id}"
        item = mail_by_conversation.get(group_key)
        if item is None:
            preview = (row["body"] or "")[:100]
            item = {
                "conversation_type": "mail",
                "conversation_id": real_conversation_id,
                "legacy_message_id": legacy_message_id,
                "status": row["status"] or "legacy",
                "participants": [],
                "subject": row["subject"] or "",
                "last_message_at": row["created_at"],
                "last_message_from": _conversation_label(row["from_alias"], row["from_did"]),
                "last_message_preview": preview,
                "unread_count": 0,
            }
            mail_by_conversation[group_key] = item
        item["participants"] = _dedupe_labels(
            item["participants"]
            + [
                _conversation_label(row["from_alias"], row["from_did"]),
                _conversation_label(row["to_alias"], row["to_did"]),
            ]
        )
        if (row["to_did"] or "").strip() in actor_did_set and row["read_at"] is None:
            item["unread_count"] += 1

    mail_items = list(mail_by_conversation.values())
    mail_conversation_ids = [
        UUID(str(item["conversation_id"]))
        for item in mail_items
        if item.get("conversation_id")
    ]
    mail_participant_rows = []
    if mail_conversation_ids:
        mail_participant_rows = await aweb_db.fetch_all(
            """
            SELECT conversation_id, did, alias, address
            FROM {{tables.conversation_participants}}
            WHERE conversation_id = ANY($1::uuid[])
            ORDER BY conversation_id, alias
            """,
            mail_conversation_ids,
        )
    mail_participants_by_conversation: dict[str, list[dict]] = {}
    for row in mail_participant_rows:
        mail_participants_by_conversation.setdefault(str(row["conversation_id"]), []).append(dict(row))
    for item in mail_items:
        conversation_id = item.get("conversation_id")
        if not conversation_id:
            item["participant_dids"] = []
            item["participant_addresses"] = []
            continue
        participant_rows = mail_participants_by_conversation.get(str(conversation_id), [])
        item["participant_dids"] = _dedupe_labels(
            [(row.get("did") or "").strip() for row in participant_rows]
        )
        item["participant_addresses"] = _dedupe_labels(
            [(row.get("address") or "").strip() for row in participant_rows]
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
                "status": "active",
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
                legacy_message_id=item.get("legacy_message_id"),
                status=item.get("status", "active"),
                participants=item["participants"],
                participant_dids=item.get("participant_dids", []),
                participant_addresses=item.get("participant_addresses", []),
                subject=item["subject"],
                last_message_at=ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                last_message_from=item["last_message_from"],
                last_message_preview=item["last_message_preview"],
                unread_count=item["unread_count"],
            )
        )

    return ConversationsResponse(conversations=result, next_cursor=next_cursor)
