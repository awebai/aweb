from __future__ import annotations

from aweb.agent_wake import agent_wake_publisher

from aweb.attachment_service import prepare_attachment_send, attachment_retry, attachment_references_by_message

from aweb.messaging.sender_membership import sender_memberships
from aweb.identity_metadata import native_participant_reference

import anyio
import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.deps import get_db, get_redis
from aweb.events import chat_session_channel_name
from aweb.redis_subscriptions import open_subscription, release_subscription
from aweb.identity_metadata import lookup_identity_metadata_by_did, routable_chat_address
from aweb.id_chain_auth import stored_id_chain
from aweb.messaging.chat_send import (
    _address_from_alias,
    _left_dids_by_session,
    _parse_timestamp,
    _target_did,
    resolve_actor_agent,
    resolve_chat_targets,
    send_chat,
)
from aweb.messaging.runtime import messaging_runtime
from aweb.identity_auth_deps import participant_dids
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.messaging.alias_targets import (
    validate_alias_selector,
)
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    MAX_CHAT_MARK_READ_IDS,
    get_message_history,
    get_pending_conversations,
    resolve_session_actor_did,
    wake_chat_session_participants,
)
from aweb.messaging.chat_read import mark_chat_read
from aweb.messaging.activity_stream import SessionActivity
from aweb.messaging.contacts import (
    get_contact_addresses,
    is_address_in_contacts,
)
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.messages import utc_iso as _utc_iso
from aweb.messaging.verification import verified_signed_recipient_fields
from aweb.messaging.waiting import (
    get_waiting_agents,
    get_waiting_agents_by_session,
    register_waiting,
    unregister_waiting,
)
from aweb.grant_streams import (
    GRANT_STREAM_RECHECK_SECONDS,
    clamp_deadline_to_grant,
    grant_expiry_reason,
    grant_terminal_reason,
    grant_terminal_sse,
    require_valid_stream_grant,
)
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/chat", tags=["aweb-chat"])

MAX_CHAT_STREAM_DURATION = 300
CHAT_STREAM_FALLBACK_POLL_SECONDS = 2.0
CHAT_STREAM_PAGE_SIZE = 200
CHAT_STREAM_KEEPALIVE_SECONDS = 30.0


def _parse_uuid(value: str, *, field: str) -> str:
    try:
        return str(UUID(str(value).strip()))
    except Exception:
        raise ValueError(f"Invalid {field} format")


def _parse_deadline(value: str) -> datetime:
    return _parse_timestamp(value, "deadline")


def _actor_dids(auth: MessagingAuth) -> list[str]:
    return participant_dids(auth)


def _chat_to_address(participant_rows: list[dict[str, Any]], *, from_did: str) -> str:
    refs = [
        (row.get("address") or row["alias"])
        for row in participant_rows
        if (row.get("did") or "").strip() != from_did
    ]
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
    metadata = await lookup_identity_metadata_by_did(db, dids)
    result: dict[str, str] = {}
    for did, meta in metadata.items():
        address = (meta.get("address") or "").strip()
        if address:
            result[did] = address
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


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None = None
    to_aliases: list[str] = Field(default_factory=list)
    to_dids: list[str] = Field(default_factory=list)
    to_addresses: list[str] = Field(default_factory=list)
    message: str
    content_mode: str = "legacy_plaintext_v1"
    message_version: int = 1
    encrypted_envelope: dict[str, Any] | None = None
    leaving: bool = False
    hang_on: bool = False
    wait_seconds: int | None = None
    message_id: str | None = None
    reply_to: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_hosted_handle_targets(cls, data):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        aliases: list[str] = []
        promoted_addresses: list[str] = []
        for value in normalized.get("to_aliases") or []:
            text = str(value or "").strip()
            address = normalize_hosted_handle_reference(text, require_agent=True)
            if text.startswith("@") and address != text and "/" in address:
                promoted_addresses.append(address)
            else:
                aliases.append(text)
        if promoted_addresses:
            normalized["to_aliases"] = aliases
            normalized["to_addresses"] = list(normalized.get("to_addresses") or []) + promoted_addresses
        if normalized.get("to_addresses"):
            normalized["to_addresses"] = [
                normalize_hosted_handle_reference(str(value), require_agent=True)
                for value in normalized.get("to_addresses") or []
            ]
        return normalized

    @field_validator("to_aliases", "to_dids", "to_addresses")
    @classmethod
    def _clean_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if value:
                cleaned.append(value)
        return cleaned

    @field_validator("to_aliases")
    @classmethod
    def _validate_aliases(cls, values: list[str]) -> list[str]:
        return [validate_alias_selector(value, field="to_aliases") for value in values]

    @field_validator("to_addresses")
    @classmethod
    def _validate_addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            if value.startswith("@"):
                raise ValueError("Invalid to_addresses format")
        return values

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

    @model_validator(mode="after")
    def _validate_content_mode(self) -> "CreateSessionRequest":
        encrypted = (
            self.content_mode == "encrypted_v2"
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if encrypted:
            if self.content_mode != "encrypted_v2":
                raise ValueError("content_mode must be encrypted_v2 for encrypted chat")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted chat")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted chat")
        elif self.content_mode != "legacy_plaintext_v1" or self.message_version != 1:
            raise ValueError("unsupported chat content mode")
        return self

    @field_validator("session_id", "message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None, info: ValidationInfo) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field=str(info.field_name or "message_id"))


class CreateSessionParticipant(BaseModel):
    participant_ref: dict[str, str] | None = None
    did: str
    alias: str
    agent_id: str | None = None
    address: str | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    conversation_id: str
    message_id: str
    participants: list[CreateSessionParticipant]
    sse_url: str
    targets_connected: list[str]
    targets_left: list[str]


async def _create_session_response(
    db, redis, *, session_id: UUID, message_id: str, target_dids: list[str],
    participants_rows: list[dict[str, Any]] | None = None,
) -> CreateSessionResponse:
    """Project the sent message and current session without repeating effects.

    ``participants_rows`` are the session's participants when the send already
    read them; without them they are read here.
    """
    if participants_rows is None:
        aweb_db = db.get_manager("aweb")
        participants_rows = await aweb_db.fetch_all(
            """
            SELECT did, alias, address
            FROM {{tables.chat_participants}}
            WHERE session_id = $1
            ORDER BY alias ASC
            """,
            session_id,
        )
    participant_address_map = await _lookup_addresses_by_did(
        db,
        [(row.get("did") or "").strip() for row in participants_rows],
    )

    targets_left = await _targets_left(db, session_id=session_id, target_dids=target_dids)
    waiting_dids = await get_waiting_agents(redis, str(session_id), target_dids)
    waiting_set = set(waiting_dids)
    targets_connected = [
        row["alias"]
        for row in participants_rows
        if (row.get("did") or "").strip() in waiting_set and (row.get("did") or "").strip() in set(target_dids)
    ]

    return CreateSessionResponse(
        session_id=str(session_id),
        conversation_id=str(session_id),
        message_id=message_id,
        participants=[
            {
                "participant_ref": native_participant_reference(row["did"]),
                "did": str(row["did"]),
                "alias": row["alias"],
                "address": participant_address_map.get((row.get("did") or "").strip())
                or (row.get("address") or "").strip()
                or _address_from_alias(row.get("alias"))
                or None,
            }
            for row in participants_rows
        ],
        sse_url=f"/v1/chat/sessions/{session_id}/stream",
        targets_connected=targets_connected,
        targets_left=targets_left,
    )


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_or_send(
    request: Request,
    payload: CreateSessionRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    attachment_context = prepare_attachment_send(
        getattr(request.app.state, "attachment_backend", None), payload, auth,
    )
    if attachment_context is not None:
        with attachment_context:
            return await create_or_send(request, payload, db=db, redis=redis, auth=auth)
    runtime = messaging_runtime(request.app.state)
    sender = replace(auth, id_chain=getattr(getattr(request, "state", None), "id_chain", None))
    target = await resolve_chat_targets(
        db, sender, payload, runtime,
        source=str(request.client.host if request.client else "unknown"),
    )
    target_dids = sorted({_target_did(row) for row in target.recipients if _target_did(row)})
    sent = await send_chat(db, sender, target, payload, runtime)
    if sent.federated:
        return CreateSessionResponse(
            session_id=str(sent.session_id),
            conversation_id=str(sent.session_id),
            message_id=str(sent.message["message_id"]),
            participants=[
                CreateSessionParticipant(
                    did=str(row["did"]),
                    alias=row["alias"],
                    agent_id=str(row["agent_id"]) if row.get("agent_id") else None,
                    address=row.get("address"),
                )
                for row in sent.participants
            ],
            sse_url=f"/v1/chat/sessions/{sent.session_id}/stream",
            targets_connected=[],
            targets_left=[],
        )
    return await _create_session_response(
        db, redis, session_id=sent.session_id, message_id=str(sent.message["message_id"]), target_dids=target_dids,
        participants_rows=sent.participants,
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
    actor_agent = await resolve_actor_agent(db, actor_dids)
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
            SELECT p.session_id, p.did, p.alias, p.address
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    left_dids_by_session = await _left_dids_by_session(db, session_ids)
    identity_map = await lookup_identity_metadata_by_did(
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
        left_dids = left_dids_by_session.get(item["session_id"], set())
        hidden_dids = set(actor_dids) | left_dids
        waiting = waiting_by_session.get(item["session_id"], [])
        participants = [
            row["alias"]
            for row in session_participants
            if (row.get("did") or "").strip() not in hidden_dids
        ]
        participant_addresses = [
            (row.get("address") or "").strip() or routable_chat_address(
                identity_map.get((row.get("did") or "").strip(), {}),
                auth.team_id,
                row["alias"],
            )
            for row in session_participants
            if (row.get("did") or "").strip() not in hidden_dids
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
                "conversation_id": item["session_id"],
                "team_id": item.get("team_id") or "",
                "participants": participants,
                "participant_dids": [
                    (row.get("did") or "").strip()
                    for row in session_participants
                    if (row.get("did") or "").strip() not in hidden_dids
                ],
                "participant_addresses": participant_addresses,
                "last_message": item["last_message"],
                "last_message_content_mode": item.get("last_message_content_mode") or "legacy_plaintext_v1",
                "last_message_version": item.get("last_message_version") or 1,
                "last_encrypted_envelope": item.get("last_encrypted_envelope"),
                "last_from": item["last_from"],
                "last_from_stable_id": identity_map.get(
                    (item.get("last_from_did") or "").strip(), {}
                ).get("stable_id", ""),
                "last_from_did": (item.get("last_from_did") or "").strip(),
                "last_from_address": item.get("last_from_address") or routable_chat_address(
                    identity_map.get((item.get("last_from_did") or "").strip(), {}),
                    auth.team_id,
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
    message_id: str | None = Query(default=None),
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> HistoryResponse:
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT team_id FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    actor_did = await resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    participant_rows = await aweb_db.fetch_all(
        """
        SELECT p.did, p.alias, p.address
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
        message_id=message_id,
    )
    contact_addrs = await get_contact_addresses(db, owner_dids=owner_dids)
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [m["from_did"] for m in messages if m.get("from_did")],
    )

    memberships = await sender_memberships(request, db, [dict(m, team_id=sess["team_id"]) for m in messages])
    attachment_refs = await attachment_references_by_message(db, "chat", [m["message_id"] for m in messages])
    history_items: list[dict[str, Any]] = []
    for msg in messages:
        from_did = (msg.get("from_did") or "").strip()
        from_address = msg.get("from_address") or routable_chat_address(
            identity_map.get(from_did, {}),
            auth.team_id,
            msg["from_alias"],
        )
        history_items.append(
            {
                "attachment_refs": attachment_refs[str(msg["message_id"])],
                "sender_membership": memberships[(str(sess["team_id"] or ""), str(msg.get("from_agent_id") or ""))],
                "conversation_id": str(session_uuid),
                "message_id": msg["message_id"],
                "seq": msg["seq"],
                "from_agent": msg["from_alias"],
                "from_address": from_address,
                "body": msg["body"],
                "content_mode": msg.get("content_mode") or "legacy_plaintext_v1",
                "message_version": msg.get("message_version") or 1,
                "encrypted_envelope": msg.get("encrypted_envelope"),
                "timestamp": _utc_iso(msg["created_at"]),
                "sender_leaving": msg["sender_leaving"],
                "reply_to": msg.get("reply_to"),
                "to_address": _chat_to_address(participant_rows, from_did=from_did),
                "from_did": from_did or None,
                "from_stable_id": identity_map.get(from_did, {}).get("stable_id") or None,
                "signature": msg.get("signature"),
                "signed_payload": msg.get("signed_payload"),
                "id_chain": stored_id_chain(msg.get("id_chain")),
                **verified_signed_recipient_fields({**msg, "conversation_id": str(session_uuid)}),
                "is_contact": is_address_in_contacts(from_address, contact_addrs),
            }
        )

    return HistoryResponse(messages=history_items)


class MarkReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    up_to_message_id: str | None = Field(default=None, min_length=1)
    message_ids: list[str] | None = Field(default=None, min_length=1, max_length=MAX_CHAT_MARK_READ_IDS)

    @field_validator("up_to_message_id")
    @classmethod
    def _validate_watermark_message_id(cls, value: str | None) -> str | None:
        return _parse_uuid(value, field="up_to_message_id") if value is not None else None

    @field_validator("message_ids")
    @classmethod
    def _validate_message_ids(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        return [_parse_uuid(value, field="message_ids") for value in values]

    @model_validator(mode="after")
    def _require_at_least_one_shape(self) -> "MarkReadRequest":
        if self.up_to_message_id is None and self.message_ids is None:
            raise ValueError("provide at least one of up_to_message_id or message_ids")
        return self


@router.post("/sessions/{session_id}/read")
async def mark_read(
    request: Request,
    session_id: str,
    payload: MarkReadRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> dict[str, Any]:
    actor_dids = _actor_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    session_uuid = UUID(session_id.strip())

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    result = await mark_chat_read(
        db,
        redis,
        auth,
        session_id=session_uuid,
        message_ids=payload.message_ids,
        up_to_message_id=payload.up_to_message_id,
        agent_wake_publisher=agent_wake_publisher(request.app.state),
    )
    if result is None:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    return {"success": True, "messages_marked": result["messages_marked"]}


async def _close_session_pubsub(pubsub: PubSub | None, channel: str) -> None:
    await release_subscription(pubsub, channel)


async def _sse_events(
    *,
    request: Request,
    db,
    redis,
    session_id: UUID,
    viewer_did: str,
    viewer_team_id: str | None,
    contact_owner_dids: list[str],
    deadline: datetime,
    auth: MessagingAuth,
    cursor: int,
    receipts_after: int,
    delivery_team_id: str | None = None,
    include_activity: bool = False,
) -> AsyncIterator[str]:
    aweb_db = db.get_manager("aweb")
    session_id_str = str(session_id)

    await register_waiting(redis, session_id_str, viewer_did)
    last_refresh = time.monotonic()
    last_keepalive = last_refresh
    last_pubsub_ping = last_refresh
    last_db_poll = last_refresh
    next_grant_check = time.monotonic() + GRANT_STREAM_RECHECK_SECONDS

    async def _stream_grant_reason():
        nonlocal next_grant_check
        reason = grant_expiry_reason(auth)
        if reason or auth.grant is None:
            return reason
        if time.monotonic() < next_grant_check:
            return None
        try:
            reason = await grant_terminal_reason(request, db, auth)
        except Exception:
            logger.exception("Chat stream grant verification failed for session %s", session_id_str)
            return "verification_unavailable"
        next_grant_check = time.monotonic() + GRANT_STREAM_RECHECK_SECONDS
        return reason

    channel = chat_session_channel_name(session_id_str)
    pubsub: PubSub | None = None
    reconnect_delay_seconds = 0.1
    max_reconnect_delay_seconds = 5.0
    next_reconnect_at: float | None = None

    try:
        # DID participation was already authorized. Activity channels are only
        # a display projection, resolved in the conversation's team when absent.
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.did, p.alias, p.address, p.agent_id,
                   activity_agent.agent_id AS activity_agent_id
            FROM {{tables.chat_participants}} p
            LEFT JOIN LATERAL (
                SELECT a.agent_id
                FROM {{tables.agents}} a
                WHERE $3::boolean AND a.deleted_at IS NULL AND a.status = 'active'
                  AND CASE WHEN a.did_aw_verified_key = a.did_key
                           THEN COALESCE(NULLIF(a.did_aw, ''), a.did_key)
                           ELSE a.did_key END = p.did
                  AND ((p.agent_id IS NOT NULL AND a.agent_id = p.agent_id)
                       OR (p.agent_id IS NULL AND a.team_id = $2))
                ORDER BY a.agent_id
                LIMIT 1
            ) activity_agent ON TRUE
            WHERE p.session_id = $1
            ORDER BY p.alias ASC
            """,
            session_id,
            delivery_team_id,
            include_activity and redis is not None,
        )
        if not participant_rows:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        viewer_row = next((row for row in participant_rows if (row.get("did") or "").strip() == viewer_did), None)
        if viewer_row is None:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        # The other participant agents' activity, for a stream that asked for it.
        activity = None
        if include_activity and redis is not None:
            activity = SessionActivity(
                session_id_str,
                {
                    str(row["activity_agent_id"]): row["alias"]
                    for row in participant_rows
                    if row.get("activity_agent_id") is not None and row is not viewer_row
                },
            )

        async def _open_activity(ps: PubSub) -> tuple[list[str], bool]:
            """Subscribe, confirm, snapshot, then drain what arrived meanwhile.

            Returns the frames to send and whether a session wake arrived.
            """
            pending = await activity.subscribe(ps)
            frames = await activity.snapshot(redis)
            woken = False
            for queued in pending:
                if activity.owns(queued["channel"]):
                    frame = activity.accept(queued["data"])
                    if frame is not None:
                        frames.append(frame)
                else:
                    woken = True
            return frames, woken

        contact_addrs = await get_contact_addresses(db, owner_dids=contact_owner_dids)

        async def _connect_pubsub() -> PubSub:
            return await open_subscription(redis, channel)

        if redis is not None:
            try:
                pubsub = await _connect_pubsub()
                last_pubsub_ping = time.monotonic()
            except RedisError:
                logger.info("Chat session pubsub subscribe failed; using DB fallback polling", exc_info=True)
                next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)

        yield ": keepalive\n\n"
        last_keepalive = time.monotonic()

        reason = await _stream_grant_reason()
        if reason:
            yield grant_terminal_sse(reason)
            return

        if activity is not None and pubsub is not None:
            try:
                frames, _ = await _open_activity(pubsub)
            except (RedisError, TimeoutError):
                logger.info("Chat session activity subscribe failed; retrying with the pubsub", exc_info=True)
                await _close_session_pubsub(pubsub, channel)
                pubsub = None
                next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
            else:
                for frame in frames:
                    yield frame

        # cursor is the session number this stream has delivered up to: every
        # message and read receipt with a greater number is delivered, in number
        # order; read receipts only above receipts_after as well. The first
        # poll is immediate: it replays what the cursor asks for and delivers
        # what was committed while the stream was being set up.
        last_db_poll = 0.0

        while datetime.now(timezone.utc) < deadline:
            reason = await _stream_grant_reason()
            if reason:
                yield grant_terminal_sse(reason)
                return

            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, viewer_did)
                last_refresh = now_mono

            if redis is not None and pubsub is None and (next_reconnect_at is None or now_mono >= next_reconnect_at):
                try:
                    pubsub = await _connect_pubsub()
                    if activity is not None:
                        frames, woken = await _open_activity(pubsub)
                        for frame in frames:
                            yield frame
                        if woken:
                            last_db_poll = 0.0
                    reconnect_delay_seconds = 0.1
                    next_reconnect_at = None
                    last_pubsub_ping = time.monotonic()
                except (RedisError, TimeoutError):
                    logger.info("Chat session pubsub reconnect failed; using DB fallback polling", exc_info=True)
                    await _close_session_pubsub(pubsub, channel)
                    pubsub = None
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
                        if activity is not None and activity.owns(message["channel"]):
                            frame = activity.accept(message["data"])
                            if frame is not None:
                                yield frame
                        else:
                            should_poll = True
                else:
                    await asyncio.sleep(wait_timeout)

            if datetime.now(timezone.utc) >= deadline:
                break

            if should_poll:
                reason = await _stream_grant_reason()
                if reason:
                    yield grant_terminal_sse(reason)
                    return
                # Numbers are given out under the session's row lock, held to
                # commit, so every number up to last_seq is committed when
                # last_seq is read. Both kinds are read up to that one bound,
                # and the cursor moves to it: a number committed while the two
                # queries run is above the bound and waits for the next poll.
                bound = await aweb_db.fetch_value(
                    "SELECT last_seq FROM {{tables.chat_sessions}} WHERE session_id = $1", session_id,
                )
                page_full = False
                if bound is not None and bound > cursor:
                    new_msgs = await aweb_db.fetch_all(
                        """
                        SELECT message_id, seq, from_agent_id, from_alias, from_address,
                               CASE WHEN content_mode = 'encrypted_v2' THEN '' ELSE body END AS body,
                               content_mode, message_version, encrypted_envelope, created_at,
                               sender_leaving, hang_on, reply_to, from_did, signature, signed_payload, id_chain
                        FROM {{tables.chat_messages}}
                        WHERE session_id = $1 AND seq > $2 AND seq <= $3
                        ORDER BY seq ASC
                        LIMIT $4
                        """,
                        session_id,
                        cursor,
                        bound,
                        CHAT_STREAM_PAGE_SIZE,
                    )
                    if len(new_msgs) == CHAT_STREAM_PAGE_SIZE:
                        page_full = True
                        bound = new_msgs[-1]["seq"]
                    receipts = await aweb_db.fetch_all(
                        """
                        SELECT rr.did, rr.seq, rr.last_read_message_id, rr.last_read_at, p.alias
                        FROM {{tables.chat_read_receipts}} rr
                        JOIN {{tables.chat_participants}} p
                          ON p.session_id = rr.session_id AND p.did = rr.did
                        WHERE rr.session_id = $1
                          AND rr.did <> $2
                          AND rr.last_read_at IS NOT NULL
                          AND rr.seq > $3 AND rr.seq <= $4
                        ORDER BY rr.seq ASC
                        """,
                        session_id,
                        viewer_did,
                        max(cursor, receipts_after),
                        bound,
                    )
                    sender_dids = list({str(row["from_did"]) for row in new_msgs if row.get("from_did")})
                    sender_waiting = set(await get_waiting_agents(redis, session_id_str, sender_dids)) if sender_dids else set()
                    identity_map = await lookup_identity_metadata_by_did(db, sender_dids)
                    reason = await _stream_grant_reason()
                    if reason:
                        yield grant_terminal_sse(reason)
                        return
                    memberships = await sender_memberships(request, db, [dict(r, team_id=delivery_team_id) for r in new_msgs])
                    numbered_frames: list[tuple[int, str]] = []
                    for row in new_msgs:
                        is_hang_on = bool(row["hang_on"])
                        from_did = (row.get("from_did") or "").strip()
                        from_address = row.get("from_address") or routable_chat_address(
                            identity_map.get(from_did, {}),
                            viewer_team_id,
                            row["from_alias"],
                        )
                        payload = {
                            "sender_membership": memberships[(str(delivery_team_id or ""), str(row.get("from_agent_id") or ""))].model_dump(),
                            "type": "message",
                            "session_id": session_id_str,
                            "conversation_id": session_id_str,
                            "message_id": str(row["message_id"]),
                            "seq": row["seq"],
                            "from_agent": row["from_alias"],
                            "from_address": from_address,
                            "from_stable_id": identity_map.get(from_did, {}).get("stable_id") or None,
                            "body": row["body"],
                            "content_mode": row.get("content_mode") or "legacy_plaintext_v1",
                            "message_version": row.get("message_version") or 1,
                            "encrypted_envelope": row.get("encrypted_envelope"),
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
                            "id_chain": stored_id_chain(row.get("id_chain")),
                            **verified_signed_recipient_fields({**row, "conversation_id": session_id_str}),
                            "is_contact": is_address_in_contacts(from_address, contact_addrs),
                        }
                        numbered_frames.append((row["seq"], f"event: message\ndata: {json.dumps(payload)}\n\n"))
                    for row in receipts:
                        payload = {
                            "type": "read_receipt",
                            "session_id": session_id_str,
                            "conversation_id": session_id_str,
                            "seq": row["seq"],
                            "reader_alias": row["alias"],
                            "up_to_message_id": str(row["last_read_message_id"]) if row["last_read_message_id"] else "",
                            "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS,
                            "timestamp": _utc_iso(row["last_read_at"]),
                        }
                        numbered_frames.append((row["seq"], f"event: read_receipt\ndata: {json.dumps(payload)}\n\n"))
                    for _, frame in sorted(numbered_frames):
                        yield frame
                    cursor = bound

                # A full page leaves more to deliver: poll again at once.
                last_db_poll = 0.0 if page_full else time.monotonic()

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
        reason = grant_expiry_reason(auth)
        if reason:
            yield grant_terminal_sse(reason)
    finally:
        # A client disconnect cancels the response's task group; shield the
        # cleanup so this viewer stops counting as waiting when it leaves.
        with anyio.CancelScope(shield=True):
            await _close_session_pubsub(pubsub, channel)
            await unregister_waiting(redis, session_id_str, viewer_did)
            await wake_chat_session_participants(
                aweb_db, agent_wake_publisher(request.app.state), session_id=session_id
            )


@router.get("/sessions/{session_id}/stream")
async def stream(
    request: Request,
    session_id: str,
    deadline: str = Query(..., min_length=1),
    after: str | None = Query(None),
    after_seq: int | None = Query(None, ge=0),
    include: str | None = Query(None),
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT team_id FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    actor_did = await resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    deadline_dt = _parse_deadline(deadline)
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_CHAT_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline
    deadline_dt = clamp_deadline_to_grant(deadline_dt, auth)

    if after is not None and after_seq is not None:
        raise HTTPException(status_code=422, detail="Provide after or after_seq, not both")
    after_dt = _parse_timestamp(after, "after") if after is not None else None
    await require_valid_stream_grant(request, db, auth)
    replay_cursor = after_seq
    if after_dt is not None:
        # A timestamp names the last message stamped at or before it; replay
        # starts after that message's number.
        replay_cursor = await aweb_db.fetch_value(
            "SELECT COALESCE(MAX(seq), 0) FROM {{tables.chat_messages}} WHERE session_id = $1 AND created_at <= $2",
            session_uuid,
            after_dt,
        )
    # The live cursor is taken before the stream announces itself: a peer that
    # answers the waiting registration or the wake commits after this read.
    live_cursor = await aweb_db.fetch_value(
        "SELECT last_seq FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid,
    )
    if live_cursor is None:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
    # A cursor past the session's counter would hide the numbers up to it.
    cursor = live_cursor if replay_cursor is None else min(replay_cursor, live_cursor)
    await register_waiting(redis, str(session_uuid), actor_did)
    await wake_chat_session_participants(
        aweb_db, agent_wake_publisher(request.app.state), session_id=session_uuid
    )

    return StreamingResponse(
        _sse_events(
            request=request,
            db=db,
            redis=redis,
            session_id=session_uuid,
            viewer_did=actor_did,
            viewer_team_id=auth.team_id,
            contact_owner_dids=owner_dids,
            deadline=deadline_dt,
            auth=auth,
            cursor=cursor,
            # A timestamp replays messages only; read receipts start live.
            receipts_after=live_cursor if after_dt is not None else cursor,
            delivery_team_id=sess.get("team_id"),
            include_activity="agent_activity" in {value.strip() for value in (include or "").split(",")},
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = ""
    content_mode: str = "legacy_plaintext_v1"
    message_version: int = 1
    encrypted_envelope: dict[str, Any] | None = None
    leaving: bool = False
    hang_on: bool = False
    wait_seconds: int | None = Field(default=None, ge=0, le=600)
    reply_to: str | None = None
    message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="after")
    def _validate_content_mode(self) -> "SendMessageRequest":
        encrypted = (
            self.content_mode == "encrypted_v2"
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if encrypted:
            if self.content_mode != "encrypted_v2":
                raise ValueError("content_mode must be encrypted_v2 for encrypted chat")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted chat")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted chat")
            return self
        if self.content_mode != "legacy_plaintext_v1" or self.message_version != 1:
            raise ValueError("unsupported chat content mode")
        if not self.body:
            raise ValueError("body is required")
        return self

    @field_validator("message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="message_id")


class SendMessageResponse(BaseModel):
    message_id: str
    conversation_id: str
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
    attachment_context = prepare_attachment_send(
        getattr(request.app.state, "attachment_backend", None), payload, auth,
    )
    if attachment_context is not None:
        with attachment_context:
            existing = await attachment_retry(db, payload, "chat")
            if existing:
                binding, row = existing
                if binding.conversation_id != session_id:
                    raise HTTPException(409, detail={"code": "attachment_conflict"})
                return SendMessageResponse(message_id=binding.message_id, conversation_id=binding.conversation_id, delivered=True)
            return await send_message(request, session_id, payload, db=db, auth=auth)
    runtime = messaging_runtime(request.app.state)
    sender = replace(auth, id_chain=getattr(getattr(request, "state", None), "id_chain", None))
    target = await resolve_chat_targets(
        db, sender, session_id, runtime,
        source=str(request.client.host if request.client else "unknown"),
    )
    sent = await send_chat(db, sender, target, payload, runtime)
    return SendMessageResponse(
        message_id=str(sent.message["message_id"]),
        conversation_id=str(sent.session_id),
        delivered=True,
        extends_wait_seconds=HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0,
    )


class SessionListItem(BaseModel):
    session_id: str
    conversation_id: str
    team_id: str = ""
    participants: list[str]
    participant_dids: list[str] = Field(default_factory=list)
    participant_addresses: list[str] = Field(default_factory=list)
    created_at: str
    last_activity: str
    sender_waiting: bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionListItem]
    # True when the limit left sessions out, so a short page is never mistaken
    # for the whole list. There is no cursor yet: this reports the omission, it
    # does not let a caller retrieve what was omitted.
    has_more: bool = False


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
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
                   s.team_id,
                   COALESCE(MAX(m.created_at), s.created_at) AS last_activity,
                   array_agg(DISTINCT p2.alias ORDER BY p2.alias) AS participants,
                   array_agg(DISTINCT p2.did ORDER BY p2.did) AS participant_dids
            FROM {{tables.chat_sessions}} s
            JOIN {{tables.chat_participants}} p
              ON p.session_id = s.session_id AND p.did = $1
            JOIN {{tables.chat_participants}} p2
              ON p2.session_id = s.session_id
            LEFT JOIN {{tables.chat_messages}} m
              ON m.session_id = s.session_id
            GROUP BY s.session_id, s.team_id, s.created_at
            ORDER BY last_activity DESC, s.created_at DESC, s.session_id DESC
            LIMIT $2::int
            """,
            participant_did,
            limit + 1,
        )
        for row in rows:
            rows_by_session.setdefault(str(row["session_id"]), row)
    rows = list(rows_by_session.values())
    rows.sort(key=lambda row: (row["last_activity"], row["created_at"]), reverse=True)
    # Count after the merge across the identity's dids: the same session reached
    # through two dids is one session, and counting per query would report an
    # omission that deduplication has already undone.
    has_more = len(rows) > limit
    rows = rows[:limit]

    session_ids = [row["session_id"] for row in rows]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.did, p.alias, p.address
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    left_dids_by_session = await _left_dids_by_session(db, session_ids)
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [(row.get("did") or "").strip() for row in participant_rows if (row.get("did") or "").strip()],
    )
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
        hidden_dids = set(actor_dids) | left_dids_by_session.get(str(row["session_id"]), set())
        waiting = waiting_by_session.get(str(row["session_id"]), [])
        sessions.append(
            SessionListItem(
                session_id=str(row["session_id"]),
                conversation_id=str(row["session_id"]),
                team_id=row["team_id"] or "",
                participants=[
                    participant["alias"]
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in hidden_dids
                ],
                participant_dids=[
                    (participant.get("did") or "").strip()
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in hidden_dids
                ],
                participant_addresses=[
                    (participant.get("address") or "").strip() or routable_chat_address(
                        identity_map.get((participant.get("did") or "").strip(), {}),
                        auth.team_id,
                        participant["alias"],
                    )
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in hidden_dids
                ],
                created_at=_utc_iso(row["created_at"]),
                last_activity=_utc_iso(row["last_activity"]),
                sender_waiting=len(waiting) > 0,
            )
        )

    return SessionListResponse(sessions=sessions, has_more=has_more)
