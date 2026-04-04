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
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.address_scope import (
    format_local_address,
    get_project_scope,
    parse_recipient_ref,
    resolve_local_recipient,
)
from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agent_by_id,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    send_in_session,
)
from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts
from aweb.awid.custody import sign_on_behalf
from aweb.awid.did import validate_stable_id
from aweb.awid.replacement import get_sender_delivery_metadata
from aweb.awid.stable_id import ensure_agent_stable_ids
from aweb.deps import get_db, get_redis
from aweb.events import chat_session_channel_name, publish_chat_session_signal
from aweb.hooks import fire_mutation_hook
from aweb.messaging.messages import utc_iso as _utc_iso
from aweb.messaging.waiting import (
    get_waiting_agents,
    get_waiting_agents_by_session,
    is_agent_waiting,
    register_waiting,
    unregister_waiting,
)

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


def _chat_to_address(participant_rows: list[dict[str, Any]], *, from_agent_id: str) -> str:
    sender = next((r for r in participant_rows if str(r["agent_id"]) == str(from_agent_id)), None)
    if sender is None:
        return ""
    sender_project_slug = sender["project_slug"]
    refs = [
        format_local_address(
            base_project_slug=sender_project_slug,
            target_project_slug=r["project_slug"],
            alias=r["alias"],
        )
        for r in participant_rows
        if str(r["agent_id"]) != str(from_agent_id)
    ]
    refs.sort()
    return ",".join(refs)


def _chat_signature_fields(
    *,
    from_address: str,
    message_id: UUID,
    to_address: str,
    to_did: str | None,
    body: str,
    created_at: datetime,
    from_stable_id: str | None,
    to_stable_id: str | None,
) -> dict[str, str]:
    fields: dict[str, str] = {
        "from": from_address,
        "from_did": "",
        "message_id": str(message_id),
        "to": to_address,
        "to_did": to_did or "",
        "type": "chat",
        "subject": "",
        "body": body,
        "timestamp": _utc_iso(created_at),
    }
    if from_stable_id:
        fields["from_stable_id"] = from_stable_id
    if to_stable_id:
        fields["to_stable_id"] = to_stable_id
    return fields


def _group_participants_by_session(
    participant_rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in participant_rows:
        grouped[str(row["session_id"])].append(dict(row))
    return grouped


async def _targets_left(db, *, session_id: UUID, target_agent_ids: list[str]) -> list[str]:
    if not target_agent_ids:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT ON (from_agent_id) from_agent_id, sender_leaving
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND from_agent_id = ANY($2::uuid[])
        ORDER BY from_agent_id, created_at DESC
        """,
        session_id,
        [UUID(a) for a in target_agent_ids],
    )
    left_ids = {str(r["from_agent_id"]) for r in rows if r.get("sender_leaving")}
    if not left_ids:
        return []
    part_rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = ANY($2::uuid[])
        """,
        session_id,
        [UUID(a) for a in left_ids],
    )
    return [r["alias"] for r in part_rows]


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_aliases: list[str] = Field(..., min_length=1)
    message: str
    leaving: bool = False
    wait_seconds: int | None = None
    message_id: str | None = None
    reply_to_message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    from_stable_id: str | None = Field(default=None, max_length=256)
    to_did: str | None = Field(default=None, max_length=256)
    to_stable_id: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signing_key_id: str | None = Field(default=None, max_length=256)
    signed_payload: str | None = None

    @field_validator("to_aliases")
    @classmethod
    def _validate_to_aliases(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if not value:
                continue
            parse_recipient_ref(value)
            cleaned.append(value)
        if not cleaned:
            raise ValueError("to_aliases must not be empty")
        return cleaned

    @field_validator("message_id", "reply_to_message_id")
    @classmethod
    def _validate_message_id(cls, v: str | None, info: ValidationInfo) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field=str(info.field_name or "message_id"))

    @field_validator("from_stable_id", "to_stable_id")
    @classmethod
    def _validate_stable_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        return validate_stable_id(v)


class CreateSessionResponse(BaseModel):
    session_id: str
    message_id: str
    participants: list[dict[str, str]]
    sse_url: str
    targets_connected: list[str]
    targets_left: list[str]


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_or_send(
    request: Request, payload: CreateSessionRequest, db=Depends(get_db), redis=Depends(get_redis)
):
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    viewer_scope = await get_project_scope(db, project_id=project_id)
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    sender = await get_agent_by_id(db, project_id=project_id, agent_id=actor_id)
    if sender is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    sender_scope = await get_project_scope(db, project_id=project_id)
    to_aliases = [a for a in payload.to_aliases if a]
    if not to_aliases:
        raise HTTPException(status_code=422, detail="to_aliases must not be empty")
    if len(to_aliases) != len(set(to_aliases)):
        raise HTTPException(status_code=422, detail="to_aliases contains duplicates")
    if sender["alias"] in to_aliases:
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

    resolved_targets = [
        await resolve_local_recipient(
            db,
            sender_project_id=project_id,
            sender_agent_id=actor_id,
            ref=ref,
        )
        for ref in to_aliases
    ]
    targets = [
        {"agent_id": r.agent_id, "alias": r.agent_alias, "project_id": r.project_id}
        for r in resolved_targets
    ]

    # Enforce access_mode: contacts_only agents reject non-contacts.
    from aweb.messaging.contacts import check_access

    for target in targets:
        sender_from_address = format_local_address(
            base_project_slug=(
                await get_project_scope(db, project_id=target["project_id"])
            ).project_slug,
            target_project_slug=sender_scope.project_slug,
            alias=sender["alias"],
        )
        allowed = await check_access(
            db,
            target_project_id=target["project_id"],
            target_agent_id=target["agent_id"],
            sender_project_id=project_id,
            sender_address=sender_from_address,
            sender_owner_type=sender_scope.owner_type,
            sender_owner_ref=sender_scope.owner_ref,
        )
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail="Recipient only accepts messages from contacts",
            )

    # Ensure no duplicate aliases.
    target_ids = sorted({str(t["agent_id"]) for t in targets})
    agent_rows = [sender] + [t for t in targets if str(t["agent_id"]) not in {sender["agent_id"]}]

    session_id = await ensure_session(db, project_id=project_id, agent_rows=agent_rows)

    aweb_db = db.get_manager("aweb")

    stable_ids = await ensure_agent_stable_ids(aweb_db, agent_ids=[actor_id, *target_ids])
    sender_stable_id = stable_ids.get(actor_id)
    expected_to_stable_id: str | None = None
    if to_aliases:
        stable_targets: list[str] = []
        for ref, target in sorted(zip(to_aliases, resolved_targets), key=lambda item: item[0]):
            stable = stable_ids.get(target.agent_id)
            if not stable:
                stable_targets = []
                break
            stable_targets.append(stable)
        if stable_targets:
            expected_to_stable_id = ",".join(stable_targets)

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_from_stable_id = payload.from_stable_id
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    msg_to_stable_id = payload.to_stable_id
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()
    msg_signed_payload = payload.signed_payload

    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(
                status_code=422, detail="from_did is required when signature is provided"
            )
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    if payload.from_stable_id is not None and payload.from_stable_id != sender_stable_id:
        raise HTTPException(
            status_code=403, detail="from_stable_id does not match sender stable_id"
        )
    if payload.to_stable_id is not None and payload.to_stable_id != expected_to_stable_id:
        raise HTTPException(
            status_code=403, detail="to_stable_id does not match recipient stable_id(s)"
        )
    if payload.reply_to_message_id is not None:
        reply_target = await aweb_db.fetch_one(
            """
            SELECT 1
            FROM {{tables.chat_messages}}
            WHERE session_id = $1 AND message_id = $2
            """,
            session_uuid,
            uuid_mod.UUID(payload.reply_to_message_id),
        )
        if reply_target is None:
            raise HTTPException(status_code=404, detail="Replied-to message not found")

    cross_project = any(r.project_slug != sender_scope.project_slug for r in resolved_targets)
    msg_from_stable_id = sender_stable_id
    msg_to_stable_id = expected_to_stable_id
    to_address = ",".join(sorted(payload.to_aliases))
    message_fields = _chat_signature_fields(
        from_address=(
            f"{sender_scope.project_slug}~{sender['alias']}" if cross_project else sender["alias"]
        ),
        message_id=pre_message_id,
        to_address=to_address,
        to_did=payload.to_did,
        body=payload.message,
        created_at=msg_created_at,
        from_stable_id=msg_from_stable_id,
        to_stable_id=msg_to_stable_id,
    )

    if payload.signature is None:
        sign_result = await sign_on_behalf(
            actor_id,
            message_fields,
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id, msg_signed_payload = sign_result

    try:
        msg_row = await send_in_session(
            db,
            session_id=session_id,
            agent_id=actor_id,
            body=payload.message,
            leaving=payload.leaving,
            from_did=msg_from_did,
            from_stable_id=msg_from_stable_id,
            to_did=payload.to_did,
            to_stable_id=msg_to_stable_id,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            signed_payload=msg_signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as e:
        if isinstance(e, asyncpg.exceptions.UniqueViolationError):
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
                wait_started_by_agent_id = $4
            WHERE session_id = $1
            """,
            session_id,
            int(payload.wait_seconds),
            msg_row["created_at"],
            UUID(actor_id),
        )

    participants_rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1
        ORDER BY alias ASC
        """,
        session_id,
    )

    targets_left = await _targets_left(db, session_id=session_id, target_agent_ids=target_ids)

    waiting_ids = await get_waiting_agents(redis, str(session_id), target_ids)
    waiting_set = set(waiting_ids)
    targets_connected = [
        r["alias"]
        for r in participants_rows
        if str(r["agent_id"]) in waiting_set and str(r["agent_id"]) in set(target_ids)
    ]

    hook_context = {
        "session_id": str(session_id),
        "message_id": str(msg_row["message_id"]),
        "from_agent_id": actor_id,
    }
    await fire_mutation_hook(request, "chat.message_sent", hook_context)

    return CreateSessionResponse(
        session_id=str(session_id),
        message_id=str(msg_row["message_id"]),
        participants=[
            {"agent_id": str(r["agent_id"]), "alias": r["alias"]} for r in participants_rows
        ],
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
) -> PendingResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    owner = await get_agent_by_id(db, project_id=project_id, agent_id=actor_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    owner_scope = await get_project_scope(db, project_id=project_id)
    conversations = await get_pending_conversations(db, agent_id=actor_id)

    # Unread mail count (best-effort; used only as informational field).
    aweb_db = db.get_manager("aweb")
    mail_unread = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.messages}}
        WHERE recipient_project_id = $1 AND to_agent_id = $2 AND read_at IS NULL
        """,
        UUID(project_id),
        UUID(actor_id),
    )

    pending_items = []
    session_ids = [UUID(r["session_id"]) for r in conversations]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.agent_id, p.alias, pr.slug AS project_slug
            FROM {{tables.chat_session_participants}} p
            JOIN {{tables.projects}} pr ON pr.project_id = p.project_id
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, pr.slug, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            r["session_id"]: [pid for pid in r["participant_ids"] if pid != actor_id]
            for r in conversations
        },
    )

    for r in conversations:
        participant_rows = participants_by_session.get(r["session_id"], [])
        waiting = waiting_by_session.get(r["session_id"], [])
        participants = [
            format_local_address(
                base_project_slug=owner_scope.project_slug,
                target_project_slug=row["project_slug"],
                alias=row["alias"],
            )
            for row in participant_rows
            if str(row["agent_id"]) != actor_id
        ]
        last_from = next(
            (
                format_local_address(
                    base_project_slug=owner_scope.project_slug,
                    target_project_slug=row["project_slug"],
                    alias=row["alias"],
                )
                for row in participant_rows
                if row["alias"] == r["last_from"]
            ),
            r["last_from"],
        )
        time_remaining_seconds = (
            max(
                0,
                int(r["wait_seconds"] or 0)
                + int(r["extended_wait_seconds"] or 0)
                - int((datetime.now(timezone.utc) - r["wait_started_at"]).total_seconds()),
            )
            if (
                len(waiting) > 0
                and r.get("wait_seconds") is not None
                and r.get("wait_started_at") is not None
            )
            else 0
        )
        if int(r["unread_count"] or 0) <= 0 and time_remaining_seconds <= 0:
            continue
        pending_items.append(
            {
                "session_id": r["session_id"],
                "participants": participants,
                "last_message": r["last_message"],
                "last_from": last_from,
                "unread_count": r["unread_count"],
                "last_activity": _utc_iso(r["last_activity"]) if r["last_activity"] else "",
                "sender_waiting": len(waiting) > 0,
                "time_remaining_seconds": time_remaining_seconds,
            }
        )

    return PendingResponse(
        pending=pending_items,
        messages_waiting=int(mail_unread or 0),
    )


class HistoryResponse(BaseModel):
    messages: list[dict[str, Any]]


@router.get("/sessions/{session_id}/messages", response_model=HistoryResponse)
async def history(
    request: Request,
    session_id: str = Path(..., min_length=1),
    unread_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
    db=Depends(get_db),
) -> HistoryResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    viewer_scope = await get_project_scope(db, project_id=project_id)

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    participant_rows = await aweb_db.fetch_all(
        """
        SELECT p.agent_id, p.alias, pr.slug AS project_slug
        FROM {{tables.chat_session_participants}} p
        JOIN {{tables.projects}} pr ON pr.project_id = p.project_id
        WHERE session_id = $1
        ORDER BY pr.slug ASC, p.alias ASC
        """,
        session_uuid,
    )
    if actor_id not in {str(r["agent_id"]) for r in participant_rows}:
        raise HTTPException(status_code=404, detail="Session not found")

    messages = await get_message_history(
        db,
        session_id=session_uuid,
        agent_id=actor_id,
        unread_only=unread_only,
        limit=limit,
    )

    contact_addrs = await get_contact_addresses(db, project_id=project_id)
    sender_delivery = await get_sender_delivery_metadata(
        aweb_db,
        sender_ids=[UUID(str(m["from_agent_id"])) for m in messages],
    )

    history_items: list[dict[str, Any]] = []
    for m in messages:
        sender_row = next(r for r in participant_rows if str(r["agent_id"]) == str(m["from_agent_id"]))
        local_from_address = format_local_address(
            base_project_slug=viewer_scope.project_slug,
            target_project_slug=sender_row["project_slug"],
            alias=m["from_alias"],
        )
        sender_meta = sender_delivery.get(str(m["from_agent_id"]), {})
        from_address = sender_meta.get("from_address") or local_from_address
        history_items.append(
            {
                "message_id": m["message_id"],
                "from_agent": m["from_alias"],
                "from_address": from_address,
                "body": m["body"],
                "timestamp": _utc_iso(m["created_at"]),
                "sender_leaving": m["sender_leaving"],
                "reply_to_message_id": m.get("reply_to_message_id"),
                "to_address": _chat_to_address(
                    participant_rows, from_agent_id=m["from_agent_id"]
                ),
                "from_did": m["from_did"],
                "from_stable_id": m.get("from_stable_id"),
                "to_did": m["to_did"],
                "to_stable_id": m.get("to_stable_id"),
                "signature": m["signature"],
                "signing_key_id": m["signing_key_id"],
                "signed_payload": m.get("signed_payload"),
                "replacement_announcement": sender_meta.get("replacement_announcement"),
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
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    session_uuid = UUID(session_id.strip())

    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    result = await mark_messages_read(
        db,
        session_id=session_uuid,
        agent_id=actor_id,
        up_to_message_id=payload.up_to_message_id,
    )
    if int(result["messages_marked"] or 0) > 0:
        await publish_chat_session_signal(
            redis,
            session_id=str(session_uuid),
            signal_type="read_receipt",
            agent_id=actor_id,
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
    agent_id: UUID,
    deadline: datetime,
    after: datetime | None = None,
) -> AsyncIterator[str]:
    aweb_db = db.get_manager("aweb")
    agent_id_str = str(agent_id)
    session_id_str = str(session_id)

    await register_waiting(redis, session_id_str, agent_id_str)
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
            SELECT p.agent_id, p.alias, pr.project_id, pr.slug AS project_slug
            FROM {{tables.chat_session_participants}} p
            JOIN {{tables.projects}} pr ON pr.project_id = p.project_id
            WHERE p.session_id = $1
            ORDER BY pr.slug ASC, p.alias ASC
            """,
            session_id,
        )
        if not participant_rows:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        viewer_row = next(
            (row for row in participant_rows if str(row["agent_id"]) == agent_id_str),
            None,
        )
        if viewer_row is None:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        sse_project_id = str(viewer_row["project_id"])
        viewer_project_slug = viewer_row["project_slug"]
        # Fetched once per SSE session — contact changes during the stream
        # won't be reflected until the next connection.
        contact_addrs = await get_contact_addresses(db, project_id=sse_project_id)
        sender_delivery = await get_sender_delivery_metadata(
            aweb_db,
            sender_ids=[UUID(str(row["agent_id"])) for row in participant_rows],
        )

        async def _connect_pubsub() -> PubSub:
            ps: PubSub = redis.pubsub()
            await ps.subscribe(channel)
            return ps

        try:
            pubsub = await _connect_pubsub()
            last_pubsub_ping = time.monotonic()
        except RedisError:
            logger.info(
                "Chat session pubsub subscribe failed; using DB fallback polling",
                exc_info=True,
            )
            next_reconnect_at = time.monotonic() + reconnect_delay_seconds
            reconnect_delay_seconds = min(
                max_reconnect_delay_seconds,
                reconnect_delay_seconds * 2,
            )

        # Emit an immediate keepalive after the session wake subscription is in place
        # so early follow-up messages do not slip into the fallback poll window.
        yield ": keepalive\n\n"
        last_keepalive = time.monotonic()

        if after is not None:
            # Replay only messages newer than the given timestamp (catches the
            # send→SSE connect race window without replaying full history).
            recent = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on, reply_to_message_id,
                       from_did, from_stable_id, to_did, to_stable_id, signature, signing_key_id, signed_payload
                FROM {{tables.chat_messages}}
                WHERE session_id = $1 AND created_at > $2
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                after,
            )
            last_message_at = recent[-1]["created_at"] if recent else after

            replay_sender_ids = list({str(r["from_agent_id"]) for r in recent})
            replay_waiting = set(await get_waiting_agents(redis, session_id_str, replay_sender_ids))

            for r in recent:
                is_hang_on = bool(r["hang_on"])
                sender_row = next(
                    row for row in participant_rows if str(row["agent_id"]) == str(r["from_agent_id"])
                )
                local_from_address = format_local_address(
                    base_project_slug=viewer_project_slug,
                    target_project_slug=sender_row["project_slug"],
                    alias=r["from_alias"],
                )
                sender_meta = sender_delivery.get(str(r["from_agent_id"]), {})
                from_address = sender_meta.get("from_address") or local_from_address
                payload = {
                    "type": "message",
                    "session_id": session_id_str,
                    "message_id": str(r["message_id"]),
                    "from_agent": r["from_alias"],
                    "from_address": from_address,
                    "body": r["body"],
                    "sender_leaving": bool(r["sender_leaving"]),
                        "sender_waiting": str(r["from_agent_id"]) in replay_waiting,
                        "hang_on": is_hang_on,
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                        "reply_to_message_id": (
                            str(r["reply_to_message_id"])
                            if r.get("reply_to_message_id") is not None
                            else None
                        ),
                        "timestamp": _utc_iso(r["created_at"]),
                    "to_address": _chat_to_address(participant_rows, from_agent_id=str(r["from_agent_id"])),
                    "from_did": r["from_did"],
                    "from_stable_id": r.get("from_stable_id"),
                    "to_did": r["to_did"],
                    "to_stable_id": r.get("to_stable_id"),
                    "signature": r["signature"],
                    "signing_key_id": r["signing_key_id"],
                    "signed_payload": r.get("signed_payload"),
                    "replacement_announcement": sender_meta.get("replacement_announcement"),
                    "is_contact": is_address_in_contacts(from_address, contact_addrs),
                }
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
        else:
            # No replay — poll only for messages arriving after now.
            last_message_at = datetime.now(timezone.utc)

        last_receipt_at = datetime.now(timezone.utc)
        last_db_poll = time.monotonic()

        while datetime.now(timezone.utc) < deadline:
            # Refresh registration every 30s.
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, agent_id_str)
                last_refresh = now_mono

            if pubsub is None and (next_reconnect_at is None or now_mono >= next_reconnect_at):
                try:
                    pubsub = await _connect_pubsub()
                    reconnect_delay_seconds = 0.1
                    next_reconnect_at = None
                    last_pubsub_ping = time.monotonic()
                except RedisError:
                    logger.info(
                        "Chat session pubsub reconnect failed; using DB fallback polling",
                        exc_info=True,
                    )
                    next_reconnect_at = now_mono + reconnect_delay_seconds
                    reconnect_delay_seconds = min(
                        max_reconnect_delay_seconds,
                        reconnect_delay_seconds * 2,
                    )

            should_poll = now_mono - last_db_poll >= CHAT_STREAM_FALLBACK_POLL_SECONDS
            if not should_poll:
                wait_timeout = min(
                    1.0,
                    max(0.0, CHAT_STREAM_FALLBACK_POLL_SECONDS - (now_mono - last_db_poll)),
                )
                if pubsub is not None:
                    try:
                        message = await pubsub.get_message(
                            ignore_subscribe_messages=True,
                            timeout=wait_timeout,
                        )
                    except RedisConnectionError:
                        logger.info(
                            "Chat session pubsub connection dropped; using DB fallback polling",
                            exc_info=True,
                        )
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(
                            max_reconnect_delay_seconds,
                            reconnect_delay_seconds * 2,
                        )
                        message = None
                    except RedisError:
                        logger.warning(
                            "Chat session pubsub error; using DB fallback polling",
                            exc_info=True,
                        )
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(
                            max_reconnect_delay_seconds,
                            reconnect_delay_seconds * 2,
                        )
                        message = None
                    if message is not None and message["type"] == "message":
                        should_poll = True
                else:
                    await asyncio.sleep(wait_timeout)

            if should_poll:
                # New messages.
                new_msgs = await aweb_db.fetch_all(
                    """
                    SELECT message_id, from_agent_id, from_alias, body, created_at,
                           sender_leaving, hang_on, reply_to_message_id,
                           from_did, from_stable_id, to_did, to_stable_id, signature, signing_key_id, signed_payload
                    FROM {{tables.chat_messages}}
                    WHERE session_id = $1 AND created_at > $2
                    ORDER BY created_at ASC
                    LIMIT 200
                    """,
                    session_id,
                    last_message_at,
                )
                sender_waiting_ids = (
                    set(
                        await get_waiting_agents(
                            redis,
                            session_id_str,
                            list({str(r["from_agent_id"]) for r in new_msgs}),
                        )
                    )
                    if new_msgs
                    else set()
                )
                for r in new_msgs:
                    last_message_at = max(last_message_at, r["created_at"])
                    is_hang_on = bool(r["hang_on"])
                    sender_row = next(
                        row for row in participant_rows if str(row["agent_id"]) == str(r["from_agent_id"])
                    )
                    local_from_address = format_local_address(
                        base_project_slug=viewer_project_slug,
                        target_project_slug=sender_row["project_slug"],
                        alias=r["from_alias"],
                    )
                    sender_meta = sender_delivery.get(str(r["from_agent_id"]), {})
                    from_address = sender_meta.get("from_address") or local_from_address
                    payload = {
                        "type": "message",
                        "session_id": session_id_str,
                        "message_id": str(r["message_id"]),
                        "from_agent": r["from_alias"],
                        "from_address": from_address,
                        "body": r["body"],
                        "sender_leaving": bool(r["sender_leaving"]),
                        "sender_waiting": str(r["from_agent_id"]) in sender_waiting_ids,
                        "hang_on": is_hang_on,
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                        "reply_to_message_id": (
                            str(r["reply_to_message_id"])
                            if r.get("reply_to_message_id") is not None
                            else None
                        ),
                        "timestamp": _utc_iso(r["created_at"]),
                        "to_address": _chat_to_address(participant_rows, from_agent_id=str(r["from_agent_id"])),
                        "from_did": r["from_did"],
                        "from_stable_id": r.get("from_stable_id"),
                        "to_did": r["to_did"],
                        "to_stable_id": r.get("to_stable_id"),
                        "signature": r["signature"],
                        "signing_key_id": r["signing_key_id"],
                        "signed_payload": r.get("signed_payload"),
                        "replacement_announcement": sender_meta.get("replacement_announcement"),
                        "is_contact": is_address_in_contacts(from_address, contact_addrs),
                    }
                    yield f"event: message\ndata: {json.dumps(payload)}\n\n"

                # Read receipts from others.
                receipts = await aweb_db.fetch_all(
                    """
                    SELECT rr.agent_id, rr.last_read_message_id, rr.last_read_at, p.alias
                    FROM {{tables.chat_read_receipts}} rr
                    JOIN {{tables.chat_session_participants}} p
                      ON p.session_id = rr.session_id AND p.agent_id = rr.agent_id
                    WHERE rr.session_id = $1
                      AND rr.agent_id <> $2
                      AND rr.last_read_at IS NOT NULL
                      AND rr.last_read_at > $3
                    ORDER BY rr.last_read_at ASC
                    """,
                    session_id,
                    agent_id,
                    last_receipt_at,
                )
                for r in receipts:
                    last_receipt_at = max(last_receipt_at, r["last_read_at"])
                    payload = {
                        "type": "read_receipt",
                        "session_id": session_id_str,
                        "reader_alias": r["alias"],
                        "up_to_message_id": (
                            str(r["last_read_message_id"]) if r["last_read_message_id"] else ""
                        ),
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS,
                        "timestamp": _utc_iso(r["last_read_at"]),
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
                        logger.info(
                            "Chat session pubsub ping failed; using DB fallback polling",
                            exc_info=True,
                        )
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = current_time + reconnect_delay_seconds
                        reconnect_delay_seconds = min(
                            max_reconnect_delay_seconds,
                            reconnect_delay_seconds * 2,
                        )
                yield ": keepalive\n\n"
                last_keepalive = current_time
    finally:
        await _close_session_pubsub(pubsub, channel)
        await unregister_waiting(redis, session_id_str, agent_id_str)


@router.get("/sessions/{session_id}/stream")
async def stream(
    request: Request,
    session_id: str,
    deadline: str = Query(..., min_length=1),
    after: str | None = Query(None),
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent_uuid = UUID(actor_id)

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

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
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    deadline_dt = _parse_deadline(deadline)
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_CHAT_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline

    after_dt = _parse_timestamp(after, "after") if after is not None else None

    # Register immediately so presence is visible even if the stream isn't consumed yet.
    await register_waiting(redis, str(session_uuid), str(agent_uuid))

    return StreamingResponse(
        _sse_events(
            db=db,
            redis=redis,
            session_id=session_uuid,
            agent_id=agent_uuid,
            deadline=deadline_dt,
            after=after_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# Send message in existing session
# ---------------------------------------------------------------------------


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1)
    hang_on: bool = Field(default=False)
    reply_to_message_id: str | None = None
    message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    from_stable_id: str | None = Field(default=None, max_length=256)
    to_did: str | None = Field(default=None, max_length=256)
    to_stable_id: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signing_key_id: str | None = Field(default=None, max_length=256)
    signed_payload: str | None = None

    @field_validator("message_id", "reply_to_message_id")
    @classmethod
    def _validate_message_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="message_id")

    @field_validator("from_stable_id", "to_stable_id")
    @classmethod
    def _validate_stable_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        return validate_stable_id(v)


class SendMessageResponse(BaseModel):
    message_id: str
    delivered: bool
    extends_wait_seconds: int = 0


@router.post("/sessions/{session_id}/messages", response_model=SendMessageResponse)
async def send_message(
    request: Request,
    session_id: str = Path(..., min_length=1),
    payload: SendMessageRequest = ...,  # type: ignore[assignment]
    db=Depends(get_db),
) -> SendMessageResponse:
    """Send a message in an existing chat session.

    Sessions are persistent (no lifecycle states to check).
    Uses canonical alias from participants table to prevent spoofing.
    Supports hang_on flag for requesting more time to reply.
    """
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")

    # Verify session exists.
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get canonical alias from participants table (prevents alias spoofing)
    agent_uuid = UUID(actor_id)
    participant = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.chat_session_participants}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    if not participant:
        raise HTTPException(status_code=404, detail="Session not found")
    canonical_alias = participant["alias"]

    participant_rows = await aweb_db.fetch_all(
        """
        SELECT p.agent_id, p.alias, pr.slug AS project_slug
        FROM {{tables.chat_session_participants}} p
        JOIN {{tables.projects}} pr ON pr.project_id = p.project_id
        WHERE session_id = $1
        ORDER BY pr.slug ASC, p.alias ASC
        """,
        session_uuid,
    )
    participant_ids = [str(r["agent_id"]) for r in participant_rows]
    stable_ids = await ensure_agent_stable_ids(aweb_db, agent_ids=participant_ids)
    sender_stable_id = stable_ids.get(actor_id)
    sender_row = next(r for r in participant_rows if str(r["agent_id"]) == actor_id)
    stable_targets: list[str] = []
    for row in sorted(
        [r for r in participant_rows if str(r["agent_id"]) != actor_id],
        key=lambda r: format_local_address(
            base_project_slug=sender_row["project_slug"],
            target_project_slug=r["project_slug"],
            alias=r["alias"],
        ),
    ):
        stable = stable_ids.get(str(row["agent_id"]))
        if not stable:
            stable_targets = []
            break
        stable_targets.append(stable)
    expected_to_stable_id = ",".join(stable_targets) if stable_targets else None

    extends_wait_seconds = HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_from_stable_id = payload.from_stable_id
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    msg_to_stable_id = payload.to_stable_id
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()
    msg_signed_payload = payload.signed_payload

    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(
                status_code=422, detail="from_did is required when signature is provided"
            )
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    if payload.from_stable_id is not None and payload.from_stable_id != sender_stable_id:
        raise HTTPException(
            status_code=403, detail="from_stable_id does not match sender stable_id"
        )
    if payload.to_stable_id is not None and payload.to_stable_id != expected_to_stable_id:
        raise HTTPException(
            status_code=403, detail="to_stable_id does not match recipient stable_id(s)"
        )

    sender_row = next(r for r in participant_rows if str(r["agent_id"]) == actor_id)
    cross_project = any(
        r["project_slug"] != sender_row["project_slug"]
        for r in participant_rows
        if str(r["agent_id"]) != actor_id
    )
    msg_from_stable_id = sender_stable_id
    msg_to_stable_id = expected_to_stable_id
    to_address = _chat_to_address(participant_rows, from_agent_id=actor_id)
    message_fields = _chat_signature_fields(
        from_address=(
            f"{sender_row['project_slug']}~{canonical_alias}" if cross_project else canonical_alias
        ),
        message_id=pre_message_id,
        to_address=to_address,
        to_did=payload.to_did,
        body=payload.body,
        created_at=msg_created_at,
        from_stable_id=msg_from_stable_id,
        to_stable_id=msg_to_stable_id,
    )

    if payload.signature is None:
        sign_result = await sign_on_behalf(
            actor_id,
            message_fields,
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id, msg_signed_payload = sign_result

    try:
        msg_row = await send_in_session(
            db,
            session_id=session_uuid,
            agent_id=actor_id,
            body=payload.body,
            reply_to_message_id=(
                uuid_mod.UUID(payload.reply_to_message_id)
                if payload.reply_to_message_id is not None
                else None
            ),
            hang_on=payload.hang_on,
            from_did=msg_from_did,
            from_stable_id=msg_from_stable_id,
            to_did=payload.to_did,
            to_stable_id=msg_to_stable_id,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            signed_payload=msg_signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as e:
        if isinstance(e, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail="Failed to send message")

    hook_context = {
        "session_id": str(session_uuid),
        "message_id": str(msg_row["message_id"]),
        "from_agent_id": actor_id,
    }
    await fire_mutation_hook(request, "chat.message_sent", hook_context)

    return SendMessageResponse(
        message_id=str(msg_row["message_id"]),
        delivered=True,
        extends_wait_seconds=extends_wait_seconds,
    )


# ---------------------------------------------------------------------------
# List sessions for a workspace
# ---------------------------------------------------------------------------


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
) -> SessionListResponse:
    """List chat sessions for the authenticated agent.

    Sessions are persistent. Returns sessions where agent is a participant.
    """
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent_uuid = UUID(actor_id)
    viewer_scope = await get_project_scope(db, project_id=project_id)

    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT s.session_id, s.created_at,
               array_agg(p2.alias ORDER BY p2.alias) AS participants,
               array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_session_participants}} p
          ON p.session_id = s.session_id AND p.agent_id = $1
        JOIN {{tables.chat_session_participants}} p2
          ON p2.session_id = s.session_id
        WHERE p.agent_id = $1
        GROUP BY s.session_id, s.created_at
        ORDER BY s.created_at DESC
        """,
        agent_uuid,
    )

    sessions = []
    session_ids = [row["session_id"] for row in rows]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.agent_id, p.alias, pr.slug AS project_slug
            FROM {{tables.chat_session_participants}} p
            JOIN {{tables.projects}} pr ON pr.project_id = p.project_id
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, pr.slug, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            str(row["session_id"]): [pid for pid in (row["participant_ids"] or []) if pid != actor_id]
            for row in rows
        },
    )

    for row in rows:
        participant_rows = participants_by_session.get(str(row["session_id"]), [])
        waiting = waiting_by_session.get(str(row["session_id"]), [])
        sessions.append(
            SessionListItem(
                session_id=str(row["session_id"]),
                participants=[
                    format_local_address(
                        base_project_slug=viewer_scope.project_slug,
                        target_project_slug=p["project_slug"],
                        alias=p["alias"],
                    )
                    for p in participant_rows
                    if str(p["agent_id"]) != actor_id
                ],
                created_at=_utc_iso(row["created_at"]),
                sender_waiting=len(waiting) > 0,
            )
        )

    return SessionListResponse(sessions=sessions)
