from __future__ import annotations
from aweb.messaging.mail_attribution import incoming_mail_sql

import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from awid.pagination import decode_cursor, encode_cursor
from aweb.identity_auth_deps import participant_dids
from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.identity_metadata import native_participant_reference

router = APIRouter(prefix="/v1/conversations", tags=["aweb-conversations"])


class ParticipantDetail(BaseModel):
    participant_ref: dict[str, str] | None = None
    alias: str
    address: str | None = None


class ConversationItem(BaseModel):
    conversation_type: str  # "mail" or "chat"
    conversation_id: str | None = None
    legacy_message_id: str | None = None
    status: str = "active"
    participants: list[str]
    participant_dids: list[str] = Field(default_factory=list)
    participant_addresses: list[str] = Field(default_factory=list)
    participant_details: list[ParticipantDetail] = Field(default_factory=list)
    subject: str
    title: str = ""
    first_message_id: str | None = None
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


def _grant_conversation_scope_allowed(auth: MessagingAuth, requested_type: str | None) -> None:
    if auth.grant is None:
        return
    scopes = {scope.strip() for scope in auth.grant.scopes if scope.strip()}
    if requested_type == "mail":
        required = {"mail.read"}
    elif requested_type == "chat":
        required = {"chat.read"}
    else:
        required = {"mail.read", "chat.read"}
    if not required.issubset(scopes):
        raise HTTPException(status_code=403, detail="outside grant scope")


def _participant_detail(did: str | None, alias: str | None, address: str | None = None) -> dict:
    return {
        "participant_ref": native_participant_reference(str(did or "")),
        "alias": str(alias or ""), "address": str(address or "").strip() or None,
    }


def _index_boundary(cursor: str | None, scope: dict) -> tuple[datetime | None, str | None]:
    if not cursor:
        return None, None
    try:
        data = decode_cursor(cursor)
        if not data or data.get("kind") != "conversation_index" or data.get("scope") != scope:
            raise ValueError("Cursor scope mismatch")
        at = datetime.fromisoformat(data["last_message_at"])
        if at.tzinfo is None:
            raise ValueError("Cursor timestamp must have a timezone")
        key = data["key"]
        parts = key.split(":")
        if not ((len(parts) == 2 and parts[0] in {"mail", "chat"})
                or (len(parts) == 3 and parts[:2] == ["mail", "legacy"])):
            raise ValueError("Invalid row key")
        if str(UUID(parts[-1])) != parts[-1]:
            raise ValueError("Invalid row ID")
        return at.astimezone(timezone.utc), key
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise HTTPException(400, "Invalid conversation cursor; start from the first page") from exc


class PeerUnreadCount(BaseModel):
    participant_did: str
    unread_count: int


class UnreadCountsResponse(BaseModel):
    counts: list[PeerUnreadCount]


@router.get("/unread-counts", response_model=UnreadCountsResponse)
async def unread_counts(
    participant_did: list[str] = Query(..., min_length=1, max_length=100),
    conversation_type: str = Query("mail"),
    db=Depends(get_db), auth: MessagingAuth = Depends(get_messaging_auth),
) -> UnreadCountsResponse:
    if conversation_type != "mail":
        raise HTTPException(422, "conversation_type must be mail")
    if any(native_participant_reference(did) is None for did in participant_did):
        raise HTTPException(422, "participant_did must be a native DID")
    _grant_conversation_scope_allowed(auth, "mail")
    actor_dids = participant_dids(auth)
    if not actor_dids:
        raise HTTPException(401, "Authenticated identity is missing a routing DID")
    peers = list(dict.fromkeys(participant_did))
    rows = await db.get_manager("aweb").fetch_all(
        f"""
        WITH incoming AS MATERIALIZED (
            SELECT conversation_id, from_did, COUNT(*) AS n
            FROM {{{{tables.messages}}}} m
            WHERE {incoming_mail_sql('$1')} AND read_at IS NULL
            GROUP BY conversation_id, from_did
        )
        SELECT peer.did AS participant_did, COALESCE(SUM(i.n), 0)::bigint AS unread_count
        FROM unnest($2::text[]) AS peer(did)
        LEFT JOIN incoming i ON (
            (i.conversation_id IS NULL AND i.from_did = peer.did)
            OR EXISTS (
                SELECT 1 FROM {{{{tables.conversation_participants}}}} cp
                WHERE cp.conversation_id = i.conversation_id AND cp.did = peer.did
            )
        )
        GROUP BY peer.did
        """, actor_dids, peers,
    )
    counts = {row["participant_did"]: row["unread_count"] for row in rows}
    return UnreadCountsResponse(counts=[
        PeerUnreadCount(participant_did=did, unread_count=counts[did]) for did in peers
    ])


@router.get("", response_model=ConversationsResponse)
async def list_conversations(
    request: Request,
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    conversation_type: str | None = Query(None),
    participant_did: str | None = Query(None),
    participant_address: str | None = Query(None),
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> ConversationsResponse:
    return await list_conversations_for_auth(
        db, auth, cursor=cursor, limit=limit, conversation_type=conversation_type,
        participant_did=participant_did, participant_address=participant_address,
    )


async def list_conversations_for_auth(
    db, auth: MessagingAuth, *, cursor: str | None = None, limit: int = 50,
    conversation_type: str | None = None, participant_did: str | None = None,
    participant_address: str | None = None,
) -> ConversationsResponse:
    """The participant-scoped index shared by HTTP and MCP; never marks mail read."""
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
    aweb_db = db.get_manager("aweb")
    actor_dids = participant_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    requested_type = (conversation_type or "").strip().lower() or None
    if requested_type is not None and requested_type not in {"mail", "chat"}:
        raise HTTPException(status_code=422, detail="conversation_type must be mail or chat")
    _grant_conversation_scope_allowed(auth, requested_type)
    target_did = (participant_did or "").strip() or None
    target_address = (participant_address or "").strip() or None
    cursor_scope = {"actor_dids": sorted(actor_dids), "conversation_type": requested_type,
                    "participant_did": target_did, "participant_address": target_address}
    cursor_dt, cursor_key = _index_boundary(cursor, cursor_scope)

    # --- Mail conversations ---
    # New mail rows share conversation_id across a thread. Legacy rows without
    # conversation_id are listed by legacy_message_id so clients do not mistake
    # a historical message id for a continuation-capable conversation id.
    mail_rows = []
    if requested_type in (None, "mail"):
        mail_rows = await aweb_db.fetch_all(
            f"""
            WITH visible AS (
                SELECT
                    m.message_id,
                    m.conversation_id,
                    m.created_at,
                    m.body,
                    m.from_alias,
                    m.from_address,
                    m.from_did,
                    m.subject,
                    m.content_mode,
                    m.to_alias AS to_alias,
                    m.to_did AS to_did,
                    m.read_at,
                    {incoming_mail_sql('$1')} AS incoming,
                    COALESCE(m.conversation_id::text, 'legacy:' || m.message_id::text) AS group_key
                FROM {{{{tables.messages}}}} m
                WHERE (
                        m.from_did = ANY($1::text[])
                     OR m.to_did = ANY($1::text[])
                     OR (
                            m.conversation_id IS NOT NULL
                            AND EXISTS (
                                SELECT 1
                                FROM {{{{tables.conversation_participants}}}} cp
                                WHERE cp.conversation_id = m.conversation_id
                                  AND cp.did = ANY($1::text[])
                            )
                       )
                    )
                  AND (
                        ($2::text IS NULL AND $3::text IS NULL)
                     OR (
                            m.conversation_id IS NOT NULL
                            AND EXISTS (
                                SELECT 1
                                FROM {{{{tables.conversation_participants}}}} target_cp
                                WHERE target_cp.conversation_id = m.conversation_id
                                  AND (
                                       ($2::text IS NOT NULL AND target_cp.did = $2::text)
                                    OR ($3::text IS NOT NULL AND target_cp.address = $3::text)
                                  )
                            )
                        )
                  )
            ),
            grouped AS (
                SELECT
                    group_key,
                    MAX(created_at) AS last_message_at,
                    COUNT(*) FILTER (
                        WHERE incoming AND read_at IS NULL
                    )::int AS unread_count
                FROM visible
                GROUP BY group_key
            ),
            page AS (
                -- group_key breaks ties so the page has the same members on
                -- every call: which conversations fall inside the limit is
                -- decided here, not by the caller-visible sort further down.
                SELECT group_key, last_message_at, unread_count
                FROM grouped
                WHERE ($4::timestamptz IS NULL OR last_message_at < $4::timestamptz
                    OR (last_message_at = $4::timestamptz AND $6::text IS NOT NULL
                        AND 'mail:' || group_key < $6::text))
                ORDER BY last_message_at DESC, group_key DESC
                LIMIT $5::int
            )
            SELECT
                newest.message_id,
                newest.conversation_id,
                p.last_message_at AS created_at,
                LEFT(COALESCE(newest.body, ''), 100) AS body,
                newest.from_alias,
                newest.from_did,
                newest.from_address, newest.to_did, newest.to_alias,
                newest.subject,
                first.message_id AS first_message_id,
                CASE WHEN first.content_mode = 'encrypted_v2' THEN '' ELSE first.subject END AS title,
                p.unread_count,
                CASE WHEN c.status = 'active' AND c.expires_at <= CURRENT_TIMESTAMP
                     THEN 'expired' ELSE c.status END AS status,
                labels.participants
            FROM page p
            JOIN LATERAL (
                SELECT v.message_id, v.conversation_id, v.body, v.subject,
                       v.from_alias, v.from_did, v.from_address, v.to_did, v.to_alias
                FROM visible v
                WHERE v.group_key = p.group_key
                ORDER BY v.created_at DESC, v.message_id DESC
                LIMIT 1
            ) newest ON TRUE
            JOIN LATERAL (
                SELECT v.message_id, v.subject, v.content_mode
                FROM visible v
                WHERE v.group_key = p.group_key
                ORDER BY v.created_at ASC, v.message_id ASC
                LIMIT 1
            ) first ON TRUE
            LEFT JOIN {{{{tables.conversations}}}} c
              ON c.conversation_id = newest.conversation_id
            LEFT JOIN LATERAL (
                SELECT array_agg(ranked.label ORDER BY ranked.first_ord) AS participants
                FROM (
                    SELECT labelled.label, MIN(labelled.ord) AS first_ord
                    FROM (
                        SELECT
                            COALESCE(
                                NULLIF(BTRIM(COALESCE(pair.alias, '')), ''),
                                BTRIM(COALESCE(pair.did, ''))
                            ) AS label,
                            ROW_NUMBER() OVER (
                                ORDER BY v2.created_at DESC, v2.message_id DESC
                            ) * 2 + pair.pos AS ord
                        FROM visible v2
                        CROSS JOIN LATERAL (
                            VALUES
                                (v2.from_alias, v2.from_did, 0),
                                (v2.to_alias, v2.to_did, 1)
                        ) AS pair(alias, did, pos)
                        WHERE v2.group_key = p.group_key
                    ) labelled
                    WHERE labelled.label <> ''
                    GROUP BY labelled.label
                ) ranked
            ) labels ON TRUE
            ORDER BY p.last_message_at DESC, p.group_key DESC
            """,
            actor_dids,
            target_did,
            target_address,
            cursor_dt,
            limit + 1,
            cursor_key,
        )

    mail_items: list[dict] = []
    for row in mail_rows:
        real_conversation_id = str(row["conversation_id"]) if row["conversation_id"] else None
        legacy_message_id = None if real_conversation_id else str(row["message_id"])
        mail_items.append(
            {
                "conversation_type": "mail",
                "cursor_key": "mail:" + (real_conversation_id or "legacy:" + legacy_message_id),
                "participant_details": [_participant_detail(row["from_did"], row["from_alias"], row["from_address"]),
                                        _participant_detail(row["to_did"], row["to_alias"])],
                "conversation_id": real_conversation_id,
                "legacy_message_id": legacy_message_id,
                "status": row["status"] or "legacy",
                "participants": _dedupe_labels(list(row["participants"] or [])),
                "subject": row["subject"] or "",
                "title": row["title"] or "",
                "first_message_id": str(row["first_message_id"]),
                "last_message_at": row["created_at"],
                "last_message_from": _conversation_label(row["from_alias"], row["from_did"]),
                "last_message_preview": row["body"] or "",
                "unread_count": row["unread_count"],
            }
        )
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
            ORDER BY conversation_id, alias, did
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
        item["participant_details"] = [_participant_detail(row["did"], row["alias"], row["address"]) for row in participant_rows]
        item["participant_dids"] = _dedupe_labels(
            [(row.get("did") or "").strip() for row in participant_rows]
        )
        item["participant_addresses"] = _dedupe_labels(
            [(row.get("address") or "").strip() for row in participant_rows]
        )

    # --- Chat conversations ---
    rows_by_session: dict[str, dict] = {}
    if requested_type in (None, "chat"):
        for actor_did in actor_dids:
            rows = await aweb_db.fetch_all(
                """
                SELECT
                    s.session_id::text AS conversation_id,
                    jsonb_agg(jsonb_build_object('did', p2.did, 'alias', p2.alias, 'address', p2.address)
                              ORDER BY p2.alias, p2.did) AS participant_details,
                    array_agg(p2.alias ORDER BY p2.alias) AS participants,
                    array_agg(p2.did ORDER BY p2.alias) AS participant_dids,
                    array_agg(p2.address ORDER BY p2.alias) AS participant_addresses,
                    LEFT(COALESCE(lm.body, ''), 100) AS last_body,
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
                    ORDER BY created_at DESC, message_id DESC
                    LIMIT 1
                ) lm ON TRUE
                LEFT JOIN LATERAL (
                    SELECT COUNT(*)::int AS cnt
                    FROM {{tables.chat_messages}} cm
                    WHERE cm.session_id = s.session_id
                      AND cm.from_did <> p.did
                      AND cm.from_did IS DISTINCT FROM p.current_did_key
                      AND NOT EXISTS (
                          SELECT 1
                          FROM {{tables.chat_message_reads}} mr
                          WHERE mr.session_id = cm.session_id
                            AND mr.did = $1
                            AND mr.message_id = cm.message_id
                      )
                ) unread ON TRUE
                WHERE lm.created_at IS NOT NULL
                  AND ($4::timestamptz IS NULL OR lm.created_at < $4::timestamptz
                    OR (lm.created_at = $4::timestamptz AND $5::text IS NOT NULL
                        AND 'chat:' || s.session_id::text < $5::text))
                  AND (
                        ($2::text IS NULL AND $3::text IS NULL)
                     OR EXISTS (
                            SELECT 1
                            FROM {{tables.chat_participants}} target_cp
                            WHERE target_cp.session_id = s.session_id
                              AND (
                                   ($2::text IS NOT NULL AND target_cp.did = $2::text)
                                OR ($3::text IS NOT NULL AND target_cp.address = $3::text)
                              )
                        )
                  )
                GROUP BY s.session_id, lm.body, lm.from_alias, lm.from_did, lm.created_at, unread.cnt
                ORDER BY lm.created_at DESC, s.session_id DESC
                LIMIT $6::int
                """,
                actor_did,
                target_did,
                target_address,
                cursor_dt,
                cursor_key,
                limit + 1,
            )
            for row in rows:
                rows_by_session.setdefault(row["conversation_id"], dict(row))
    chat_rows = list(rows_by_session.values())
    chat_rows.sort(key=lambda row: row["last_message_at"], reverse=True)

    chat_items: list[dict] = []
    for row in chat_rows:
        details = row["participant_details"]
        if isinstance(details, str):
            details = json.loads(details)
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
                "cursor_key": "chat:" + row["conversation_id"],
                "participant_details": [_participant_detail(p["did"], p["alias"], p["address"])
                                        for p in details],
                "conversation_id": row["conversation_id"],
                "status": "active",
                "participants": participants,
                "participant_dids": _dedupe_labels(
                    [(did or "").strip() for did in list(row["participant_dids"] or [])]
                ),
                "participant_addresses": _dedupe_labels(
                    [(address or "").strip() for address in list(row.get("participant_addresses") or [])]
                ),
                "subject": "",
                "last_message_at": row["last_message_at"],
                "last_message_from": _conversation_label(row["last_from"], row["last_from_did"]),
                "last_message_preview": preview,
                "unread_count": row["unread_count"],
            }
        )

    # --- Merge and sort ---
    combined = mail_items + chat_items
    combined.sort(key=lambda x: (x["last_message_at"], x["cursor_key"]), reverse=True)

    # Apply limit
    page = combined[:limit]
    next_cursor: str | None = None
    if len(page) == limit and len(combined) > limit:
        last = page[-1]
        next_cursor = encode_cursor({"kind": "conversation_index", "scope": cursor_scope,
                                     "last_message_at": last["last_message_at"].isoformat(),
                                     "key": last["cursor_key"]})

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
                participant_details=item.get("participant_details", []),
                subject=item["subject"],
                title=item.get("title", ""),
                first_message_id=item.get("first_message_id"),
                last_message_at=ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                last_message_from=item["last_message_from"],
                last_message_preview=item["last_message_preview"],
                unread_count=item["unread_count"],
            )
        )

    return ConversationsResponse(conversations=result, next_cursor=next_cursor)
