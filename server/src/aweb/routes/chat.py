from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid as uuid_mod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator
from uuid import UUID

import asyncpg.exceptions
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.deps import get_db, get_redis
from aweb.events import chat_session_channel_name, publish_chat_session_signal
from aweb.hooks import fire_mutation_hook
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agent_by_alias,
    get_agents_by_aliases,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    resolve_agent_by_did,
    send_in_session,
)
from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts
from aweb.messaging.messages import evaluate_messaging_policy, utc_iso as _utc_iso
from aweb.messaging.waiting import (
    get_waiting_agents,
    get_waiting_agents_by_session,
    register_waiting,
    unregister_waiting,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/chat", tags=["aweb-chat"])

MAX_CHAT_STREAM_DURATION = 300
CHAT_STREAM_FALLBACK_POLL_SECONDS = 2.0
CHAT_STREAM_KEEPALIVE_SECONDS = 30.0


def _parse_uuid(value: str, *, field: str) -> str:
    try:
        return str(UUID(str(value).strip()))
    except Exception:
        raise ValueError(f"Invalid {field} format")


def _parse_timestamp(value: str, label: str = "timestamp") -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid {label} format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail=f"{label} must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _parse_deadline(value: str) -> datetime:
    return _parse_timestamp(value, "deadline")


def _parse_signed_timestamp(value: str) -> datetime:
    dt = _parse_timestamp(value, "timestamp")
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    return dt


def _actor_did(auth: MessagingAuth) -> str:
    return (auth.did_aw or auth.did_key or "").strip()


def _actor_dids(auth: MessagingAuth) -> list[str]:
    dids: list[str] = []
    for value in ((auth.did_aw or "").strip(), (auth.did_key or "").strip()):
        if value and value not in dids:
            dids.append(value)
    return dids


def _actor_alias(auth: MessagingAuth, actor_agent: dict[str, Any] | None) -> str:
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or ((actor_agent or {}).get("alias") or "").strip()
        or ((actor_agent or {}).get("address") or "").strip()
        or _actor_did(auth)
    )


async def _resolve_actor_agent(db, actor_dids: list[str]) -> dict[str, Any] | None:
    for did in actor_dids:
        if not did:
            continue
        actor_agent = await resolve_agent_by_did(db, did)
        if actor_agent is not None:
            return actor_agent
    return None


async def _resolve_session_actor_did(db, *, session_id: UUID, actor_dids: list[str]) -> str:
    if not actor_dids:
        return ""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT did
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
          AND did = ANY($2::text[])
        ORDER BY CASE WHEN did = $3 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        session_id,
        actor_dids,
        actor_dids[0],
    )
    return (row.get("did") or "").strip() if row else ""


def _chat_to_address(participant_rows: list[dict[str, Any]], *, from_did: str) -> str:
    refs = [row["alias"] for row in participant_rows if (row.get("did") or "").strip() != from_did]
    refs.sort()
    return ",".join(refs)


def _group_participants_by_session(
    participant_rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in participant_rows:
        grouped[str(row["session_id"])].append(dict(row))
    return grouped


async def _lookup_addresses_by_did(db, dids: list[str]) -> dict[str, str]:
    if not dids:
        return {}
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT did_aw, did_key, address
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND address IS NOT NULL
          AND (did_aw = ANY($1::text[]) OR did_key = ANY($1::text[]))
        """,
        list(set(dids)),
    )
    result: dict[str, str] = {}
    for row in rows:
        address = (row.get("address") or "").strip()
        if not address:
            continue
        if row.get("did_aw"):
            result[str(row["did_aw"]).strip()] = address
        if row.get("did_key"):
            result[str(row["did_key"]).strip()] = address
    return result


async def _targets_left(db, *, session_id: UUID, target_dids: list[str]) -> list[str]:
    if not target_dids:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT ON (from_did) from_did, sender_leaving
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND from_did = ANY($2::text[])
        ORDER BY from_did, created_at DESC
        """,
        session_id,
        target_dids,
    )
    left_dids = {str(row["from_did"]) for row in rows if row.get("sender_leaving")}
    if not left_dids:
        return []
    part_rows = await aweb_db.fetch_all(
        """
        SELECT did, alias
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = ANY($2::text[])
        """,
        session_id,
        list(left_dids),
    )
    return [row["alias"] for row in part_rows]


async def _resolve_chat_targets(
    db,
    *,
    registry_client,
    auth: MessagingAuth,
    to_aliases: list[str],
    to_dids: list[str],
    to_addresses: list[str],
) -> list[dict[str, Any]]:
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    actor_did_set = set(actor_dids)
    sender_address = (auth.address or "").strip() or None
    resolved: dict[str, dict[str, Any]] = {}

    if to_aliases:
        if auth.team_id is None:
            raise HTTPException(status_code=422, detail="to_aliases requires team context")
        target_rows = await get_agents_by_aliases(db, team_id=auth.team_id, aliases=to_aliases)
        resolved_aliases = {row["alias"] for row in target_rows}
        missing = [alias for alias in to_aliases if alias not in resolved_aliases]
        if missing:
            raise HTTPException(status_code=404, detail=f"Unknown aliases: {', '.join(missing)}")
        for row in target_rows:
            target_did = (row.get("did_aw") or row.get("did_key") or "").strip()
            if target_did:
                resolved[target_did] = row

    for did in to_dids:
        row = await resolve_agent_by_did(db, did)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Recipient agent not found: {did}")
        resolved[did] = row

    for address in to_addresses:
        if registry_client is None:
            raise HTTPException(status_code=503, detail="AWID registry unavailable")
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_addresses entries must be domain/name")
        domain, name = address.split("/", 1)
        resolution = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolution is None or not resolution.did_aw:
            raise HTTPException(status_code=404, detail=f"Recipient address not found: {address}")
        row = await resolve_agent_by_did(db, resolution.did_aw)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Recipient agent not found: {address}")
        resolved[resolution.did_aw] = row

    if not resolved:
        raise HTTPException(status_code=422, detail="Must provide to_aliases, to_dids, or to_addresses")

    if any(did in resolved for did in actor_did_set):
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

    for row in resolved.values():
        try:
            await evaluate_messaging_policy(
                db,
                registry_client=registry_client,
                recipient_agent=row,
                sender_did=actor_did,
                sender_address=sender_address,
            )
        except (ValidationError, NotFoundError, ForbiddenError) as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return list(resolved.values())


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_aliases: list[str] = Field(default_factory=list)
    to_dids: list[str] = Field(default_factory=list)
    to_addresses: list[str] = Field(default_factory=list)
    message: str
    leaving: bool = False
    wait_seconds: int | None = None
    message_id: str | None = None
    reply_to: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None

    @field_validator("to_aliases", "to_dids", "to_addresses")
    @classmethod
    def _clean_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if value:
                cleaned.append(value)
        return cleaned

    @model_validator(mode="after")
    def _validate_targets(self) -> "CreateSessionRequest":
        if not self.to_aliases and not self.to_dids and not self.to_addresses:
            raise ValueError("Must provide to_aliases, to_dids, or to_addresses")
        if len(self.to_aliases) != len(set(self.to_aliases)):
            raise ValueError("to_aliases contains duplicates")
        if len(self.to_dids) != len(set(self.to_dids)):
            raise ValueError("to_dids contains duplicates")
        if len(self.to_addresses) != len(set(self.to_addresses)):
            raise ValueError("to_addresses contains duplicates")
        return self

    @field_validator("message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None, info: ValidationInfo) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field=str(info.field_name or "message_id"))


class CreateSessionResponse(BaseModel):
    session_id: str
    message_id: str
    participants: list[dict[str, str]]
    sse_url: str
    targets_connected: list[str]
    targets_left: list[str]


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_or_send(
    request: Request,
    payload: CreateSessionRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(auth, actor_agent)
    registry_client = getattr(request.app.state, "awid_registry_client", None)

    target_rows = await _resolve_chat_targets(
        db,
        registry_client=registry_client,
        auth=auth,
        to_aliases=payload.to_aliases,
        to_dids=payload.to_dids,
        to_addresses=payload.to_addresses,
    )
    target_dids = sorted({(row.get("did_aw") or row.get("did_key") or "").strip() for row in target_rows})

    participant_rows = [
        {
            "did": actor_did,
            "did_key": auth.did_key,
            "agent_id": actor_agent_id,
            "alias": actor_alias,
        }
    ] + [
        {
            "did": (row.get("did_aw") or row.get("did_key") or "").strip(),
            "did_key": (row.get("did_key") or "").strip() or None,
            "agent_id": str(row["agent_id"]) if row.get("agent_id") else None,
            "alias": (row.get("alias") or row.get("address") or "").strip()
            or (row.get("did_aw") or row.get("did_key") or "").strip(),
        }
        for row in target_rows
    ]

    session_id = await ensure_session(
        db,
        team_id=auth.team_id,
        participant_rows=participant_rows,
        created_by=actor_alias,
    )

    aweb_db = db.get_manager("aweb")
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        if payload.from_did.strip() not in set(_actor_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    if payload.reply_to is not None:
        reply_target = await aweb_db.fetch_one(
            """
            SELECT 1 FROM {{tables.chat_messages}}
            WHERE session_id = $1 AND message_id = $2
            """,
            session_id,
            uuid_mod.UUID(payload.reply_to),
        )
        if reply_target is None:
            raise HTTPException(status_code=404, detail="Replied-to message not found")

    try:
        msg_row = await send_in_session(
            db,
            session_id=session_id,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            body=payload.message,
            reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
            leaving=payload.leaving,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail="Failed to send message")

    if payload.wait_seconds is not None:
        await aweb_db.execute(
            """
            UPDATE {{tables.chat_sessions}}
            SET wait_seconds = $2,
                wait_started_at = $3,
                wait_started_by = $4
            WHERE session_id = $1
            """,
            session_id,
            int(payload.wait_seconds),
            msg_row["created_at"],
            UUID(actor_agent_id) if actor_agent_id else None,
        )

    participants_rows = await aweb_db.fetch_all(
        """
        SELECT did, alias
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        ORDER BY alias ASC
        """,
        session_id,
    )

    targets_left = await _targets_left(db, session_id=session_id, target_dids=target_dids)
    waiting_dids = await get_waiting_agents(redis, str(session_id), target_dids)
    waiting_set = set(waiting_dids)
    targets_connected = [
        row["alias"]
        for row in participants_rows
        if (row.get("did") or "").strip() in waiting_set and (row.get("did") or "").strip() in set(target_dids)
    ]

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "session_id": str(session_id),
            "message_id": str(msg_row["message_id"]),
            "from_did": actor_did,
        },
    )

    return CreateSessionResponse(
        session_id=str(session_id),
        message_id=str(msg_row["message_id"]),
        participants=[{"did": str(row["did"]), "alias": row["alias"]} for row in participants_rows],
        sse_url=f"/v1/chat/sessions/{session_id}/stream",
        targets_connected=targets_connected,
        targets_left=targets_left,
    )


class PendingResponse(BaseModel):
    pending: list[dict[str, Any]]
    messages_waiting: int = 0


@router.get("/pending", response_model=PendingResponse)
async def pending(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> PendingResponse:
    del request
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    conversations_by_session: dict[str, dict[str, Any]] = {}
    for participant_did in actor_dids:
        rows = await get_pending_conversations(
            db,
            participant_did=participant_did,
            participant_agent_id=actor_agent_id,
        )
        for row in rows:
            conversations_by_session.setdefault(row["session_id"], row)
    conversations = list(conversations_by_session.values())

    aweb_db = db.get_manager("aweb")
    mail_unread = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.messages}}
        WHERE to_did = ANY($1::text[]) AND read_at IS NULL
        """,
        actor_dids,
    )

    session_ids = [UUID(item["session_id"]) for item in conversations]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.did, p.alias
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    address_map = await _lookup_addresses_by_did(
        db,
        [
            (row.get("did") or "").strip()
            for row in participant_rows
            if (row.get("did") or "").strip()
        ]
        + [
            (item.get("last_from_did") or "").strip()
            for item in conversations
            if (item.get("last_from_did") or "").strip()
        ],
    )
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            item["session_id"]: [did for did in item.get("participant_dids", []) if did not in set(actor_dids)]
            for item in conversations
        },
    )

    pending_items = []
    for item in conversations:
        session_participants = participants_by_session.get(item["session_id"], [])
        waiting = waiting_by_session.get(item["session_id"], [])
        participants = [
            row["alias"]
            for row in session_participants
            if (row.get("did") or "").strip() not in set(actor_dids)
        ]
        participant_addresses = [
            address_map.get((row.get("did") or "").strip(), row["alias"])
            for row in session_participants
            if (row.get("did") or "").strip() not in set(actor_dids)
        ]
        time_remaining_seconds = (
            max(
                0,
                int(item["wait_seconds"] or 0)
                + int(item["extended_wait_seconds"] or 0)
                - int((datetime.now(timezone.utc) - item["wait_started_at"]).total_seconds()),
            )
            if item.get("wait_seconds") is not None and item.get("wait_started_at") is not None and waiting
            else 0
        )
        if int(item["unread_count"] or 0) <= 0 and time_remaining_seconds <= 0:
            continue
        pending_items.append(
            {
                "session_id": item["session_id"],
                "participants": participants,
                "participant_addresses": participant_addresses,
                "last_message": item["last_message"],
                "last_from": item["last_from"],
                "last_from_address": address_map.get(
                    (item.get("last_from_did") or "").strip(),
                    item["last_from"],
                ),
                "unread_count": item["unread_count"],
                "last_activity": _utc_iso(item["last_activity"]) if item["last_activity"] else "",
                "sender_waiting": len(waiting) > 0,
                "time_remaining_seconds": time_remaining_seconds,
            }
        )

    return PendingResponse(pending=pending_items, messages_waiting=int(mail_unread or 0))


class HistoryResponse(BaseModel):
    messages: list[dict[str, Any]]


@router.get("/sessions/{session_id}/messages", response_model=HistoryResponse)
async def history(
    request: Request,
    session_id: str = Path(..., min_length=1),
    unread_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> HistoryResponse:
    del request
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")

    participant_rows = await aweb_db.fetch_all(
        """
        SELECT p.did, p.alias
        FROM {{tables.chat_participants}} p
        WHERE session_id = $1
        ORDER BY p.alias ASC
        """,
        session_uuid,
    )

    messages = await get_message_history(
        db,
        session_id=session_uuid,
        participant_did=actor_did,
        unread_only=unread_only,
        limit=limit,
    )
    contact_addrs = await get_contact_addresses(db, owner_dids=owner_dids)
    address_map = await _lookup_addresses_by_did(
        db,
        [m["from_did"] for m in messages if m.get("from_did")],
    )

    history_items: list[dict[str, Any]] = []
    for msg in messages:
        from_address = address_map.get(msg.get("from_did") or "", msg["from_alias"])
        history_items.append(
            {
                "message_id": msg["message_id"],
                "from_agent": msg["from_alias"],
                "from_address": from_address,
                "body": msg["body"],
                "timestamp": _utc_iso(msg["created_at"]),
                "sender_leaving": msg["sender_leaving"],
                "reply_to": msg.get("reply_to"),
                "to_address": _chat_to_address(participant_rows, from_did=msg.get("from_did") or ""),
                "from_did": msg.get("from_did"),
                "signature": msg.get("signature"),
                "signed_payload": msg.get("signed_payload"),
                "is_contact": is_address_in_contacts(from_address, contact_addrs),
            }
        )

    return HistoryResponse(messages=history_items)


class MarkReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    up_to_message_id: str = Field(..., min_length=1)

    @field_validator("up_to_message_id")
    @classmethod
    def _validate_message_id(cls, v: str) -> str:
        return _parse_uuid(v, field="up_to_message_id")


@router.post("/sessions/{session_id}/read")
async def mark_read(
    request: Request,
    session_id: str,
    payload: MarkReadRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> dict[str, Any]:
    del request
    actor_dids = _actor_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    session_uuid = UUID(session_id.strip())

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")

    result = await mark_messages_read(
        db,
        session_id=session_uuid,
        participant_did=actor_did,
        participant_agent_id=actor_agent_id,
        up_to_message_id=payload.up_to_message_id,
    )
    if int(result["messages_marked"] or 0) > 0:
        await publish_chat_session_signal(
            redis,
            session_id=str(session_uuid),
            signal_type="read_receipt",
            agent_id=actor_did,
            message_id=payload.up_to_message_id,
        )

    return {"success": True, "messages_marked": result["messages_marked"]}


async def _close_session_pubsub(pubsub: PubSub | None, channel: str) -> None:
    if pubsub is None:
        return
    try:
        await pubsub.unsubscribe(channel)
    except Exception:
        pass
    try:
        await pubsub.aclose()
    except Exception:
        pass


async def _sse_events(
    *,
    db,
    redis,
    session_id: UUID,
    viewer_did: str,
    contact_owner_dids: list[str],
    deadline: datetime,
    after: datetime | None = None,
) -> AsyncIterator[str]:
    aweb_db = db.get_manager("aweb")
    session_id_str = str(session_id)

    await register_waiting(redis, session_id_str, viewer_did)
    last_refresh = time.monotonic()
    last_keepalive = last_refresh
    last_pubsub_ping = last_refresh
    last_db_poll = last_refresh
    channel = chat_session_channel_name(session_id_str)
    pubsub: PubSub | None = None
    reconnect_delay_seconds = 0.1
    max_reconnect_delay_seconds = 5.0
    next_reconnect_at: float | None = None

    try:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.did, p.alias
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = $1
            ORDER BY p.alias ASC
            """,
            session_id,
        )
        if not participant_rows:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        viewer_row = next((row for row in participant_rows if (row.get("did") or "").strip() == viewer_did), None)
        if viewer_row is None:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return

        contact_addrs = await get_contact_addresses(db, owner_dids=contact_owner_dids)

        async def _connect_pubsub() -> PubSub:
            ps: PubSub = redis.pubsub()
            await ps.subscribe(channel)
            return ps

        try:
            pubsub = await _connect_pubsub()
            last_pubsub_ping = time.monotonic()
        except RedisError:
            logger.info("Chat session pubsub subscribe failed; using DB fallback polling", exc_info=True)
            next_reconnect_at = time.monotonic() + reconnect_delay_seconds
            reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)

        yield ": keepalive\n\n"
        last_keepalive = time.monotonic()

        if after is not None:
            recent = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on, reply_to, from_did, signature, signed_payload
                FROM {{tables.chat_messages}}
                WHERE session_id = $1 AND created_at > $2
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                after,
            )
            last_message_at = recent[-1]["created_at"] if recent else after
            waiting = set(await get_waiting_agents(redis, session_id_str, list({str(r["from_did"]) for r in recent if r.get("from_did")})))
            address_map = await _lookup_addresses_by_did(db, [str(r["from_did"]) for r in recent if r.get("from_did")])
            for row in recent:
                is_hang_on = bool(row["hang_on"])
                from_did = (row.get("from_did") or "").strip()
                from_address = address_map.get(from_did, row["from_alias"])
                payload = {
                    "type": "message",
                    "session_id": session_id_str,
                    "message_id": str(row["message_id"]),
                    "from_agent": row["from_alias"],
                    "from_address": from_address,
                    "body": row["body"],
                    "sender_leaving": bool(row["sender_leaving"]),
                    "sender_waiting": from_did in waiting,
                    "hang_on": is_hang_on,
                    "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                    "reply_to": str(row["reply_to"]) if row.get("reply_to") is not None else None,
                    "timestamp": _utc_iso(row["created_at"]),
                    "to_address": _chat_to_address(participant_rows, from_did=from_did),
                    "from_did": row.get("from_did"),
                    "signature": row.get("signature"),
                    "signed_payload": row.get("signed_payload"),
                    "is_contact": is_address_in_contacts(from_address, contact_addrs),
                }
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
        else:
            last_message_at = datetime.now(timezone.utc)

        last_receipt_at = datetime.now(timezone.utc)
        last_db_poll = time.monotonic()

        while datetime.now(timezone.utc) < deadline:
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, viewer_did)
                last_refresh = now_mono

            if pubsub is None and (next_reconnect_at is None or now_mono >= next_reconnect_at):
                try:
                    pubsub = await _connect_pubsub()
                    reconnect_delay_seconds = 0.1
                    next_reconnect_at = None
                    last_pubsub_ping = time.monotonic()
                except RedisError:
                    logger.info("Chat session pubsub reconnect failed; using DB fallback polling", exc_info=True)
                    next_reconnect_at = now_mono + reconnect_delay_seconds
                    reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)

            should_poll = now_mono - last_db_poll >= CHAT_STREAM_FALLBACK_POLL_SECONDS
            if not should_poll:
                wait_timeout = min(1.0, max(0.0, CHAT_STREAM_FALLBACK_POLL_SECONDS - (now_mono - last_db_poll)))
                if pubsub is not None:
                    try:
                        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=wait_timeout)
                    except RedisConnectionError:
                        logger.info("Chat session pubsub connection dropped; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                        message = None
                    except RedisError:
                        logger.warning("Chat session pubsub error; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                        message = None
                    if message is not None and message["type"] == "message":
                        should_poll = True
                else:
                    await asyncio.sleep(wait_timeout)

            if should_poll:
                new_msgs = await aweb_db.fetch_all(
                    """
                    SELECT message_id, from_agent_id, from_alias, body, created_at,
                           sender_leaving, hang_on, reply_to, from_did, signature, signed_payload
                    FROM {{tables.chat_messages}}
                    WHERE session_id = $1 AND created_at > $2
                    ORDER BY created_at ASC
                    LIMIT 200
                    """,
                    session_id,
                    last_message_at,
                )
                sender_dids = list({str(row["from_did"]) for row in new_msgs if row.get("from_did")})
                sender_waiting = set(await get_waiting_agents(redis, session_id_str, sender_dids)) if sender_dids else set()
                address_map = await _lookup_addresses_by_did(db, sender_dids)
                for row in new_msgs:
                    last_message_at = max(last_message_at, row["created_at"])
                    is_hang_on = bool(row["hang_on"])
                    from_did = (row.get("from_did") or "").strip()
                    from_address = address_map.get(from_did, row["from_alias"])
                    payload = {
                        "type": "message",
                        "session_id": session_id_str,
                        "message_id": str(row["message_id"]),
                        "from_agent": row["from_alias"],
                        "from_address": from_address,
                        "body": row["body"],
                        "sender_leaving": bool(row["sender_leaving"]),
                        "sender_waiting": from_did in sender_waiting,
                        "hang_on": is_hang_on,
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                        "reply_to": str(row["reply_to"]) if row.get("reply_to") is not None else None,
                        "timestamp": _utc_iso(row["created_at"]),
                        "to_address": _chat_to_address(participant_rows, from_did=from_did),
                        "from_did": row.get("from_did"),
                        "signature": row.get("signature"),
                        "signed_payload": row.get("signed_payload"),
                        "is_contact": is_address_in_contacts(from_address, contact_addrs),
                    }
                    yield f"event: message\ndata: {json.dumps(payload)}\n\n"

                receipts = await aweb_db.fetch_all(
                    """
                    SELECT rr.did, rr.last_read_message_id, rr.last_read_at, p.alias
                    FROM {{tables.chat_read_receipts}} rr
                    JOIN {{tables.chat_participants}} p
                      ON p.session_id = rr.session_id AND p.did = rr.did
                    WHERE rr.session_id = $1
                      AND rr.did <> $2
                      AND rr.last_read_at IS NOT NULL
                      AND rr.last_read_at > $3
                    ORDER BY rr.last_read_at ASC
                    """,
                    session_id,
                    viewer_did,
                    last_receipt_at,
                )
                for row in receipts:
                    last_receipt_at = max(last_receipt_at, row["last_read_at"])
                    payload = {
                        "type": "read_receipt",
                        "session_id": session_id_str,
                        "reader_alias": row["alias"],
                        "up_to_message_id": str(row["last_read_message_id"]) if row["last_read_message_id"] else "",
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS,
                        "timestamp": _utc_iso(row["last_read_at"]),
                    }
                    yield f"event: read_receipt\ndata: {json.dumps(payload)}\n\n"

                last_db_poll = time.monotonic()

            current_time = time.monotonic()
            if current_time - last_keepalive >= CHAT_STREAM_KEEPALIVE_SECONDS:
                if pubsub is not None and current_time - last_pubsub_ping >= CHAT_STREAM_KEEPALIVE_SECONDS:
                    try:
                        await pubsub.ping()
                        last_pubsub_ping = current_time
                    except RedisError:
                        logger.info("Chat session pubsub ping failed; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = current_time + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                yield ": keepalive\n\n"
                last_keepalive = current_time
    finally:
        await _close_session_pubsub(pubsub, channel)
        await unregister_waiting(redis, session_id_str, viewer_did)


@router.get("/sessions/{session_id}/stream")
async def stream(
    request: Request,
    session_id: str,
    deadline: str = Query(..., min_length=1),
    after: str | None = Query(None),
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    del request
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    deadline_dt = _parse_deadline(deadline)
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_CHAT_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline

    after_dt = _parse_timestamp(after, "after") if after is not None else None
    await register_waiting(redis, str(session_uuid), actor_did)

    return StreamingResponse(
        _sse_events(
            db=db,
            redis=redis,
            session_id=session_uuid,
            viewer_did=actor_did,
            contact_owner_dids=owner_dids,
            deadline=deadline_dt,
            after=after_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1)
    hang_on: bool = False
    reply_to: str | None = None
    message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None

    @field_validator("message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="message_id")


class SendMessageResponse(BaseModel):
    message_id: str
    delivered: bool
    extends_wait_seconds: int = 0


@router.post("/sessions/{session_id}/messages", response_model=SendMessageResponse)
async def send_message(
    request: Request,
    session_id: str = Path(..., min_length=1),
    payload: SendMessageRequest = ...,
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")

    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()
    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        if payload.from_did.strip() not in set(_actor_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    try:
        msg_row = await send_in_session(
            db,
            session_id=session_uuid,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            body=payload.body,
            reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
            hang_on=payload.hang_on,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail="Failed to send message")

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "session_id": str(session_uuid),
            "message_id": str(msg_row["message_id"]),
            "from_did": actor_did,
        },
    )

    return SendMessageResponse(
        message_id=str(msg_row["message_id"]),
        delivered=True,
        extends_wait_seconds=HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0,
    )


class SessionListItem(BaseModel):
    session_id: str
    participants: list[str]
    created_at: str
    sender_waiting: bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionListItem]


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SessionListResponse:
    del request
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    aweb_db = db.get_manager("aweb")
    rows_by_session: dict[str, Any] = {}
    for participant_did in actor_dids:
        rows = await aweb_db.fetch_all(
            """
            SELECT s.session_id, s.created_at,
                   array_agg(p2.alias ORDER BY p2.alias) AS participants,
                   array_agg(p2.did ORDER BY p2.alias) AS participant_dids
            FROM {{tables.chat_sessions}} s
            JOIN {{tables.chat_participants}} p
              ON p.session_id = s.session_id AND p.did = $1
            JOIN {{tables.chat_participants}} p2
              ON p2.session_id = s.session_id
            GROUP BY s.session_id, s.created_at
            ORDER BY s.created_at DESC
            """,
            participant_did,
        )
        for row in rows:
            rows_by_session.setdefault(str(row["session_id"]), row)
    rows = list(rows_by_session.values())
    rows.sort(key=lambda row: row["created_at"], reverse=True)

    session_ids = [row["session_id"] for row in rows]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.did, p.alias
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            str(row["session_id"]): [did for did in (row["participant_dids"] or []) if did not in set(actor_dids)]
            for row in rows
        },
    )

    sessions = []
    for row in rows:
        session_participants = participants_by_session.get(str(row["session_id"]), [])
        waiting = waiting_by_session.get(str(row["session_id"]), [])
        sessions.append(
            SessionListItem(
                session_id=str(row["session_id"]),
                participants=[
                    participant["alias"]
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in set(actor_dids)
                ],
                created_at=_utc_iso(row["created_at"]),
                sender_waiting=len(waiting) > 0,
            )
        )

    return SessionListResponse(sessions=sessions)
