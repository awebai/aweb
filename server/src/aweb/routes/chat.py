"""Real-time chat routes for team coordination."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.deps import get_db, get_redis
from aweb.events import chat_session_channel_name, publish_chat_session_signal
from aweb.hooks import fire_mutation_hook
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agents_by_aliases,
    get_agent_by_id,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    send_in_session,
)
from aweb.messaging.messages import utc_iso as _utc_iso
from aweb.service_errors import ForbiddenError, NotFoundError
from aweb.messaging.waiting import (
    get_waiting_agents,
    is_agent_waiting,
    register_waiting,
    unregister_waiting,
)
from aweb.team_auth_deps import get_team_identity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/chat", tags=["aweb-chat"])

MAX_CHAT_STREAM_DURATION = 300
CHAT_STREAM_FALLBACK_POLL_SECONDS = 2.0
CHAT_STREAM_KEEPALIVE_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


async def _targets_left(db, *, session_id: UUID, target_agent_ids: list[str]) -> list[str]:
    """Return aliases of targets whose last message in the session was a leave."""
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
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND agent_id = ANY($2::uuid[])
        """,
        session_id,
        [UUID(a) for a in left_ids],
    )
    return [r["alias"] for r in part_rows]


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


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_aliases: list[str] = Field(..., min_length=1)
    message: str
    leaving: bool = False
    wait_seconds: int | None = None
    reply_to_message_id: str | None = None

    @field_validator("to_aliases")
    @classmethod
    def _validate_to_aliases(cls, values: list[str]) -> list[str]:
        cleaned = [(v or "").strip() for v in (values or [])]
        cleaned = [v for v in cleaned if v]
        if not cleaned:
            raise ValueError("to_aliases must not be empty")
        return cleaned

    @field_validator("reply_to_message_id")
    @classmethod
    def _validate_reply_to(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="reply_to_message_id")


class CreateSessionResponse(BaseModel):
    session_id: str
    message_id: str
    participants: list[dict[str, str]]
    sse_url: str
    targets_connected: list[str]
    targets_left: list[str]


class PendingResponse(BaseModel):
    pending: list[dict[str, Any]]
    messages_waiting: int = 0


class HistoryResponse(BaseModel):
    messages: list[dict[str, Any]]


class MarkReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    up_to_message_id: str

    @field_validator("up_to_message_id")
    @classmethod
    def _validate_message_id(cls, v: str) -> str:
        return _parse_uuid(v, field="up_to_message_id")


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1)
    hang_on: bool = False
    reply_to_message_id: str | None = None

    @field_validator("reply_to_message_id")
    @classmethod
    def _validate_reply_to(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="reply_to_message_id")


class SendMessageResponse(BaseModel):
    message_id: str
    delivered: bool
    extends_wait_seconds: int = 0


class SessionListItem(BaseModel):
    session_id: str
    participants: list[str]
    created_at: str
    sender_waiting: bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionListItem]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_or_send(
    request: Request, payload: CreateSessionRequest, db=Depends(get_db), redis=Depends(get_redis)
):
    identity = await get_team_identity(request, db)

    sender = await get_agent_by_id(db, team_address=identity.team_address, agent_id=identity.agent_id)
    if sender is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    to_aliases = [a for a in payload.to_aliases if a]
    if not to_aliases:
        raise HTTPException(status_code=422, detail="to_aliases must not be empty")
    if len(to_aliases) != len(set(to_aliases)):
        raise HTTPException(status_code=422, detail="to_aliases contains duplicates")
    if sender["alias"] in to_aliases:
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

    targets = await get_agents_by_aliases(db, team_address=identity.team_address, aliases=to_aliases)
    if len(targets) != len(to_aliases):
        found = {t["alias"] for t in targets}
        missing = [a for a in to_aliases if a not in found]
        raise HTTPException(status_code=404, detail=f"Agent(s) not found: {', '.join(missing)}")

    target_ids = sorted({str(t["agent_id"]) for t in targets})
    agent_rows = [sender] + [t for t in targets if str(t["agent_id"]) != str(sender["agent_id"])]

    session_id = await ensure_session(
        db, team_address=identity.team_address, agent_rows=agent_rows,
        created_by_alias=identity.alias,
    )

    aweb_db = db.get_manager("aweb")

    reply_to = UUID(payload.reply_to_message_id) if payload.reply_to_message_id else None
    if reply_to is not None:
        reply_exists = await aweb_db.fetch_one(
            "SELECT 1 FROM {{tables.chat_messages}} WHERE session_id = $1 AND message_id = $2",
            session_id, reply_to,
        )
        if reply_exists is None:
            raise HTTPException(status_code=404, detail="Replied-to message not found")

    msg_row = await send_in_session(
        db,
        session_id=session_id,
        agent_id=identity.agent_id,
        body=payload.message,
        leaving=payload.leaving,
        reply_to=reply_to,
    )
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
            UUID(identity.agent_id),
        )

    participants_rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        ORDER BY alias ASC
        """,
        session_id,
    )

    targets_left_list = await _targets_left(db, session_id=session_id, target_agent_ids=target_ids)

    waiting_ids = await get_waiting_agents(redis, str(session_id), target_ids)
    waiting_set = set(waiting_ids)
    targets_connected = [
        r["alias"]
        for r in participants_rows
        if str(r["agent_id"]) in waiting_set and str(r["agent_id"]) in set(target_ids)
    ]

    await fire_mutation_hook(request, "chat.message_sent", {
        "session_id": str(session_id),
        "message_id": str(msg_row["message_id"]),
        "from_alias": identity.alias,
        "team_address": identity.team_address,
    })

    return CreateSessionResponse(
        session_id=str(session_id),
        message_id=str(msg_row["message_id"]),
        participants=[
            {"agent_id": str(r["agent_id"]), "alias": r["alias"]} for r in participants_rows
        ],
        sse_url=f"/v1/chat/sessions/{session_id}/stream",
        targets_connected=targets_connected,
        targets_left=targets_left_list,
    )


@router.get("/pending", response_model=PendingResponse)
async def pending(
    request: Request, db=Depends(get_db), redis=Depends(get_redis)
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    conversations = await get_pending_conversations(db, agent_id=identity.agent_id)

    unread_mail = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int FROM {{tables.messages}}
        WHERE team_address = $1 AND to_agent_id = $2 AND read_at IS NULL
        """,
        identity.team_address,
        UUID(identity.agent_id),
    )

    pending_list = []
    for conv in conversations:
        session_id = conv["session_id"]
        participant_aliases = conv.get("participants", [])
        other_aliases = [a for a in participant_aliases if a != identity.alias]

        other_ids = conv.get("participant_ids", [])
        waiting_ids = await get_waiting_agents(redis, session_id, other_ids)
        waiting_set = set(waiting_ids)

        wait_seconds = conv.get("wait_seconds")
        wait_started_at = conv.get("wait_started_at")
        extended_wait = conv.get("extended_wait_seconds", 0)
        sender_waiting = False
        time_remaining = None

        if wait_started_at is not None and wait_seconds is not None:
            total_wait = int(wait_seconds) + int(extended_wait)
            deadline_dt = wait_started_at + timedelta(seconds=total_wait)
            remaining = (deadline_dt - datetime.now(timezone.utc)).total_seconds()
            if remaining > 0:
                sender_waiting = True
                time_remaining = int(remaining)

        last_from = conv.get("last_from", "")

        pending_list.append({
            "session_id": session_id,
            "participants": other_aliases,
            "last_message": conv.get("last_message", ""),
            "last_from": last_from,
            "unread_count": conv.get("unread_count", 0),
            "last_activity": _utc_iso(conv["last_activity"]) if conv.get("last_activity") else None,
            "sender_waiting": sender_waiting,
            "time_remaining": time_remaining,
            "targets_connected": [
                a for a, aid in zip(participant_aliases, conv.get("participant_ids", []))
                if aid in waiting_set and a != identity.alias
            ],
        })

    return PendingResponse(pending=pending_list, messages_waiting=int(unread_mail or 0))


@router.get("/sessions/{session_id}/messages", response_model=HistoryResponse)
async def history(
    request: Request,
    session_id: str,
    db=Depends(get_db),
    unread_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        sid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid session_id format")

    session = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND team_address = $2",
        sid, identity.team_address,
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    rows = await get_message_history(
        db, session_id=sid, agent_id=identity.agent_id,
        unread_only=unread_only, limit=limit,
    )

    messages = []
    for r in rows:
        msg: dict[str, Any] = {
            "message_id": r["message_id"],
            "from_agent_id": r["from_agent_id"],
            "from_alias": r["from_alias"],
            "body": r["body"],
            "timestamp": _utc_iso(r["created_at"]) if r.get("created_at") else None,
            "sender_leaving": r.get("sender_leaving", False),
            "reply_to": r.get("reply_to"),
        }
        if r.get("from_did"):
            msg["from_did"] = r["from_did"]
        if r.get("signature"):
            msg["signature"] = r["signature"]
        if r.get("signed_payload"):
            msg["signed_payload"] = r["signed_payload"]
        messages.append(msg)

    return HistoryResponse(messages=messages)


@router.post("/sessions/{session_id}/read")
async def mark_read(
    request: Request,
    session_id: str,
    payload: MarkReadRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        sid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid session_id format")

    session = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND team_address = $2",
        sid, identity.team_address,
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        result = await mark_messages_read(
            db, session_id=sid, agent_id=identity.agent_id,
            up_to_message_id=payload.up_to_message_id,
        )
    except ForbiddenError:
        raise HTTPException(status_code=403, detail="Not a participant in this session")
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Message not found")

    await publish_chat_session_signal(
        redis, session_id=str(sid), signal_type="read",
        agent_id=identity.agent_id,
        message_id=payload.up_to_message_id,
    )

    return result


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------


async def _sse_events(
    *,
    db,
    redis,
    session_id: UUID,
    agent_id: UUID,
    deadline: datetime,
    after: datetime | None = None,
) -> AsyncIterator[str]:
    """Yield SSE events for a chat session until the deadline."""
    aweb_db = db.get_manager("aweb")
    agent_id_str = str(agent_id)
    session_id_str = str(session_id)

    await register_waiting(redis, session_id_str, agent_id_str)

    last_message_at = after or datetime.now(timezone.utc)
    last_receipt_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    last_refresh = time.monotonic()
    last_keepalive = time.monotonic()
    last_poll = 0.0

    channel = chat_session_channel_name(session_id_str)
    pubsub: PubSub | None = None
    pubsub_backoff = 1.0

    async def _connect_pubsub() -> PubSub | None:
        try:
            ps = redis.pubsub()
            await ps.subscribe(channel)
            return ps
        except (RedisError, RedisConnectionError, OSError):
            logger.info("Redis pubsub unavailable for chat session %s, falling back to polling", session_id_str)
            return None

    try:
        pubsub = await _connect_pubsub()
        yield ": connected\n\n"

        # Replay messages after the cutoff
        if after is not None:
            replay_rows = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on, reply_to,
                       from_did, signature, signed_payload
                FROM {{tables.chat_messages}}
                WHERE session_id = $1 AND created_at > $2
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                after,
            )
            for r in replay_rows:
                sender_waiting = await is_agent_waiting(redis, session_id_str, str(r["from_agent_id"]))
                payload = _build_message_payload(r, session_id_str, sender_waiting)
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
                if r["created_at"] > last_message_at:
                    last_message_at = r["created_at"]

        # Main event loop
        while datetime.now(timezone.utc) < deadline:
            now_mono = time.monotonic()

            # Re-register waiting presence
            if now_mono - last_refresh > 30:
                await register_waiting(redis, session_id_str, agent_id_str)
                last_refresh = now_mono

            # Reconnect pubsub if lost
            if pubsub is None and now_mono - last_poll > pubsub_backoff:
                pubsub = await _connect_pubsub()
                if pubsub is None:
                    pubsub_backoff = min(pubsub_backoff * 2, 30.0)
                else:
                    pubsub_backoff = 1.0

            # Wait for pubsub signal or poll interval
            should_poll = False
            if now_mono - last_poll >= CHAT_STREAM_FALLBACK_POLL_SECONDS:
                should_poll = True
            elif pubsub is not None:
                try:
                    msg = await asyncio.wait_for(
                        pubsub.get_message(ignore_subscribe_messages=True),
                        timeout=min(CHAT_STREAM_FALLBACK_POLL_SECONDS, 1.0),
                    )
                    if msg is not None:
                        should_poll = True
                except asyncio.TimeoutError:
                    pass
                except (RedisError, RedisConnectionError, OSError):
                    await _close_session_pubsub(pubsub, channel)
                    pubsub = None
            else:
                await asyncio.sleep(CHAT_STREAM_FALLBACK_POLL_SECONDS)
                should_poll = True

            # Poll for new messages
            if should_poll:
                last_poll = time.monotonic()
                new_rows = await aweb_db.fetch_all(
                    """
                    SELECT message_id, from_agent_id, from_alias, body, created_at,
                           sender_leaving, hang_on, reply_to,
                           from_did, signature, signed_payload
                    FROM {{tables.chat_messages}}
                    WHERE session_id = $1 AND created_at > $2
                    ORDER BY created_at ASC
                    LIMIT 200
                    """,
                    session_id,
                    last_message_at,
                )
                for r in new_rows:
                    sender_waiting = await is_agent_waiting(redis, session_id_str, str(r["from_agent_id"]))
                    payload = _build_message_payload(r, session_id_str, sender_waiting)
                    yield f"event: message\ndata: {json.dumps(payload)}\n\n"
                    if r["created_at"] > last_message_at:
                        last_message_at = r["created_at"]

                # Poll for read receipts
                receipt_rows = await aweb_db.fetch_all(
                    """
                    SELECT rr.agent_id, rr.last_read_message_id, rr.last_read_at, p.alias
                    FROM {{tables.chat_read_receipts}} rr
                    JOIN {{tables.chat_participants}} p
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
                for rr in receipt_rows:
                    receipt_payload = {
                        "type": "read_receipt",
                        "session_id": session_id_str,
                        "reader_alias": rr["alias"],
                        "up_to_message_id": str(rr["last_read_message_id"]),
                        "timestamp": _utc_iso(rr["last_read_at"]),
                    }
                    yield f"event: read_receipt\ndata: {json.dumps(receipt_payload)}\n\n"
                    if rr["last_read_at"] > last_receipt_at:
                        last_receipt_at = rr["last_read_at"]

            # Keepalive
            if now_mono - last_keepalive > CHAT_STREAM_KEEPALIVE_SECONDS:
                last_keepalive = now_mono
                if pubsub is not None:
                    try:
                        await pubsub.ping()
                    except (RedisError, RedisConnectionError, OSError):
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                yield ": keepalive\n\n"

    finally:
        await _close_session_pubsub(pubsub, channel)
        await unregister_waiting(redis, session_id_str, agent_id_str)


def _build_message_payload(row, session_id_str: str, sender_waiting: bool) -> dict[str, Any]:
    """Build the SSE message payload from a chat_messages row."""
    payload: dict[str, Any] = {
        "type": "message",
        "session_id": session_id_str,
        "message_id": str(row["message_id"]),
        "from_alias": row["from_alias"],
        "from_agent_id": str(row["from_agent_id"]),
        "body": row["body"],
        "timestamp": _utc_iso(row["created_at"]),
        "sender_leaving": bool(row.get("sender_leaving", False)),
        "sender_waiting": sender_waiting,
        "hang_on": bool(row.get("hang_on", False)),
    }
    if row.get("hang_on"):
        payload["extends_wait_seconds"] = HANG_ON_EXTENSION_SECONDS
    if row.get("reply_to"):
        payload["reply_to"] = str(row["reply_to"])
    if row.get("from_did"):
        payload["from_did"] = row["from_did"]
    if row.get("signature"):
        payload["signature"] = row["signature"]
    if row.get("signed_payload"):
        payload["signed_payload"] = row["signed_payload"]
    return payload


@router.get("/sessions/{session_id}/stream")
async def stream(
    request: Request,
    session_id: str,
    deadline: str = Query(...),
    after: str | None = Query(default=None),
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        sid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid session_id format")

    session = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND team_address = $2",
        sid, identity.team_address,
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    participant = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_participants}} WHERE session_id = $1 AND agent_id = $2",
        sid, UUID(identity.agent_id),
    )
    if not participant:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    deadline_dt = _parse_deadline(deadline)
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_CHAT_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline

    after_dt = _parse_timestamp(after, "after") if after else None

    return StreamingResponse(
        _sse_events(
            db=db,
            redis=redis,
            session_id=sid,
            agent_id=UUID(identity.agent_id),
            deadline=deadline_dt,
            after=after_dt,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/sessions/{session_id}/messages", response_model=SendMessageResponse)
async def send_message(
    request: Request,
    session_id: str,
    payload: SendMessageRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        sid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid session_id format")

    session = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND team_address = $2",
        sid, identity.team_address,
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    reply_to = UUID(payload.reply_to_message_id) if payload.reply_to_message_id else None
    if reply_to is not None:
        reply_exists = await aweb_db.fetch_one(
            "SELECT 1 FROM {{tables.chat_messages}} WHERE session_id = $1 AND message_id = $2",
            sid, reply_to,
        )
        if reply_exists is None:
            raise HTTPException(status_code=404, detail="Replied-to message not found")

    msg_row = await send_in_session(
        db,
        session_id=sid,
        agent_id=identity.agent_id,
        body=payload.body,
        hang_on=payload.hang_on,
        reply_to=reply_to,
    )
    if msg_row is None:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    extends_wait = HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0

    await publish_chat_session_signal(
        redis, session_id=str(sid), signal_type="message",
        agent_id=identity.agent_id,
        message_id=str(msg_row["message_id"]),
    )

    await fire_mutation_hook(request, "chat.message_sent", {
        "session_id": str(sid),
        "message_id": str(msg_row["message_id"]),
        "from_alias": identity.alias,
        "team_address": identity.team_address,
    })

    return SendMessageResponse(
        message_id=str(msg_row["message_id"]),
        delivered=True,
        extends_wait_seconds=extends_wait,
    )


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    request: Request, db=Depends(get_db), redis=Depends(get_redis),
):
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT s.session_id, s.created_at,
               array_agg(p2.alias ORDER BY p2.alias) AS participants,
               array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_participants}} p
          ON p.session_id = s.session_id AND p.agent_id = $1
        JOIN {{tables.chat_participants}} p2
          ON p2.session_id = s.session_id
        WHERE p.agent_id = $1
        GROUP BY s.session_id, s.created_at
        ORDER BY s.created_at DESC
        """,
        UUID(identity.agent_id),
    )

    sessions = []
    for r in rows:
        participant_aliases = list(r["participants"] or [])
        participant_ids = list(r["participant_ids"] or [])
        other_aliases = [a for a in participant_aliases if a != identity.alias]
        other_ids = [
            pid for pid, alias in zip(participant_ids, participant_aliases)
            if alias != identity.alias
        ]

        waiting_ids = await get_waiting_agents(redis, str(r["session_id"]), other_ids)
        sender_waiting = len(waiting_ids) > 0

        sessions.append(SessionListItem(
            session_id=str(r["session_id"]),
            participants=other_aliases,
            created_at=_utc_iso(r["created_at"]),
            sender_waiting=sender_waiting,
        ))

    return SessionListResponse(sessions=sessions)
