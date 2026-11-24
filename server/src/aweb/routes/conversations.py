from __future__ import annotations
from aweb.messaging.conversation_index import CONVERSATION_PAGE_SQL
from aweb.messaging.mail_attribution import incoming_mail_sql

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
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


async def require_mail_thread_peer_for_auth(
    db, auth: MessagingAuth, *, conversation_id: str | UUID, peer_did: str,
) -> None:
    """Require canonical caller and exact native peer in this mail thread.

    The embedder authenticates the caller. This read-only check does not select
    recipients or establish peer kind, and remains valid for historical threads.
    """
    _grant_conversation_scope_allowed(auth, "mail")
    actor_dids = participant_dids(auth)
    if not actor_dids:
        raise HTTPException(401, "Authenticated identity is missing a routing DID")
    try:
        conversation_uuid = UUID(str(conversation_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "Invalid conversation_id format") from exc
    if native_participant_reference(peer_did) is None:
        raise HTTPException(422, "peer_did must be a native DID")
    exists = await db.get_manager("aweb").fetch_val(
        """
        SELECT EXISTS (
            SELECT 1 FROM {{tables.conversations}} c
            JOIN {{tables.conversation_participants}} own
              ON own.conversation_id = c.conversation_id
            JOIN {{tables.conversation_participants}} peer
              ON peer.conversation_id = c.conversation_id
            WHERE c.conversation_id = $1 AND c.conversation_type = 'mail'
              AND own.did = ANY($2::text[]) AND peer.did = $3
        )
        """, conversation_uuid, actor_dids, peer_did,
    )
    if not exists:
        raise HTTPException(404, "Mail thread not found")


def _participant_detail(did: str | None, alias: str | None, address: str | None = None) -> ParticipantDetail:
    return ParticipantDetail(
        participant_ref=native_participant_reference(str(did or "")),
        alias=str(alias or ""),
        address=str(address or "").strip() or None,
    )


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

    rows = await aweb_db.fetch_all(
        CONVERSATION_PAGE_SQL, actor_dids, target_did, target_address,
        cursor_dt, cursor_key, limit, requested_type,
    )
    mail_ids = [row["row_id"] for row in rows if row["kind"] == "mail"]
    mail_participants: dict[UUID, list[Mapping[str, Any]]] = {}
    if mail_ids:
        participants = await aweb_db.fetch_all(
            """
            SELECT conversation_id, did, alias, address
            FROM {{tables.conversation_participants}}
            WHERE conversation_id = ANY($1::uuid[])
            ORDER BY conversation_id, alias, did
            """,
            mail_ids,
        )
        for participant in participants:
            mail_participants.setdefault(participant["conversation_id"], []).append(participant)

    result = []
    for row in rows:
        kind = row["kind"]
        if kind == "chat":
            details = row["participant_details"]
            if isinstance(details, str):
                details = json.loads(details)
            participants = [
                _conversation_label(alias, did)
                for alias, did in zip(row["participants"], row["participant_dids"], strict=True)
            ]
            participant_dids_list = row["participant_dids"]
            participant_addresses = row["participant_addresses"]
        elif kind == "mail":
            details = mail_participants.get(row["row_id"], [])
            participants = row["participants"]
            participant_dids_list = [p["did"] for p in details]
            participant_addresses = [p["address"] for p in details]
        else:
            details = [
                {"did": row["from_did"], "alias": row["from_alias"], "address": row["from_address"]},
                {"did": row["to_did"], "alias": row["to_alias"], "address": None},
            ]
            participants = row["participants"]
            participant_dids_list = []
            participant_addresses = []

        result.append(ConversationItem(
            conversation_type="chat" if kind == "chat" else "mail",
            conversation_id=None if kind == "legacy" else str(row["row_id"]),
            legacy_message_id=str(row["row_id"]) if kind == "legacy" else None,
            status="active" if kind == "chat" else (row["status"] or "legacy"),
            participants=_dedupe_labels(participants or []),
            participant_dids=_dedupe_labels(participant_dids_list or []),
            participant_addresses=_dedupe_labels(participant_addresses or []),
            participant_details=[_participant_detail(p["did"], p["alias"], p["address"]) for p in details],
            subject=row["subject"] or "",
            title=row["title"] or "",
            first_message_id=str(row["first_message_id"]) if kind != "chat" else None,
            last_message_at=row["created_at"].isoformat(),
            last_message_from=_conversation_label(row["from_alias"], row["from_did"]),
            last_message_preview=row["preview"] or "",
            unread_count=row["unread_count"],
        ))

    next_cursor = None
    if rows and rows[-1]["has_more"]:
        last = rows[-1]
        next_cursor = encode_cursor({
            "kind": "conversation_index", "scope": cursor_scope,
            "last_message_at": last["created_at"].isoformat(), "key": last["cursor_key"],
        })
    return ConversationsResponse(conversations=result, next_cursor=next_cursor)
