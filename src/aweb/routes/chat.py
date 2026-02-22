from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Any, AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_agent_alias
from aweb.chat_waiting import (
    get_waiting_agents,
    is_agent_waiting,
    register_waiting,
    unregister_waiting,
)
from aweb.custody import sign_on_behalf
from aweb.deps import get_db, get_redis
from aweb.hooks import fire_mutation_hook

logger = logging.getLogger(__name__)


def _utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601, UTC, second precision with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


router = APIRouter(prefix="/v1/chat", tags=["aweb-chat"])

HANG_ON_EXTENSION_SECONDS = 300


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


def _participant_hash(agent_ids: list[str]) -> str:
    normalized = sorted({str(UUID(a)) for a in agent_ids})
    return hashlib.sha256((",".join(normalized)).encode("utf-8")).hexdigest()


async def _get_agent_by_id(db, *, project_id: str, agent_id: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if not row:
        return None
    return dict(row)


async def _get_agent_by_alias(db, *, project_id: str, alias: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, project_id, alias, deleted_at
        FROM {{tables.agents}}
        WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        UUID(project_id),
        alias,
    )
    if not row:
        return None
    return dict(row)


async def _ensure_session(
    db,
    *,
    project_id: str,
    agent_rows: list[dict[str, Any]],
) -> UUID:
    aweb_db = db.get_manager("aweb")
    p_hash = _participant_hash([str(r["agent_id"]) for r in agent_rows])

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_sessions}} (project_id, participant_hash)
        VALUES ($1, $2)
        ON CONFLICT (project_id, participant_hash) DO NOTHING
        RETURNING session_id
        """,
        UUID(project_id),
        p_hash,
    )
    if row and row.get("session_id"):
        session_id = row["session_id"]
    else:
        existing = await aweb_db.fetch_one(
            """
            SELECT session_id
            FROM {{tables.chat_sessions}}
            WHERE project_id = $1 AND participant_hash = $2
            """,
            UUID(project_id),
            p_hash,
        )
        if existing is None:
            logger.error(
                "Chat session not found after INSERT ON CONFLICT DO NOTHING. "
                "project_id=%s participant_hash=%s",
                project_id,
                p_hash,
            )
            raise HTTPException(
                status_code=500,
                detail="Failed to create or retrieve chat session",
            )
        session_id = existing["session_id"]

    for agent in agent_rows:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.chat_session_participants}} (session_id, agent_id, alias)
            VALUES ($1, $2, $3)
            ON CONFLICT (session_id, agent_id) DO UPDATE SET alias = EXCLUDED.alias
            """,
            session_id,
            UUID(str(agent["agent_id"])),
            agent["alias"],
        )

    return UUID(str(session_id))


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
    from_did: str | None = Field(default=None, max_length=256)
    to_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signing_key_id: str | None = Field(default=None, max_length=256)

    @field_validator("to_aliases")
    @classmethod
    def _validate_to_aliases(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if not value:
                continue
            cleaned.append(validate_agent_alias(value))
        if not cleaned:
            raise ValueError("to_aliases must not be empty")
        return cleaned


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
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    sender = await _get_agent_by_id(db, project_id=project_id, agent_id=actor_id)
    if sender is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    to_aliases = [a for a in payload.to_aliases if a]
    if not to_aliases:
        raise HTTPException(status_code=422, detail="to_aliases must not be empty")
    if sender["alias"] in to_aliases:
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

    targets: list[dict[str, Any]] = []
    for alias in to_aliases:
        agent = await _get_agent_by_alias(db, project_id=project_id, alias=alias)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        targets.append(agent)

    # Ensure no duplicate aliases.
    target_ids = sorted({str(t["agent_id"]) for t in targets})
    agent_rows = [sender] + [t for t in targets if str(t["agent_id"]) not in {sender["agent_id"]}]

    session_id = await _ensure_session(db, project_id=project_id, agent_rows=agent_rows)

    aweb_db = db.get_manager("aweb")

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is None:
        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
            UUID(project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        sign_result = await sign_on_behalf(
            actor_id,
            {
                "from": f"{project_slug}/{sender['alias']}",
                "from_did": "",
                "message_id": str(pre_message_id),
                "to": ",".join(f"{project_slug}/{a}" for a in sorted(payload.to_aliases)),
                "to_did": payload.to_did or "",
                "type": "chat",
                "subject": "",
                "body": payload.message,
                "timestamp": _utc_iso(msg_created_at),
            },
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_agent_id, from_alias, body, sender_leaving,
             from_did, to_did, signature, signing_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING message_id, created_at
        """,
        pre_message_id,
        session_id,
        UUID(actor_id),
        sender["alias"],
        payload.message,
        bool(payload.leaving),
        msg_from_did,
        payload.to_did,
        msg_signature,
        msg_signing_key_id,
        msg_created_at,
    )

    # Advance sender's read receipt — sending implies having read up to this point.
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        session_id,
        UUID(actor_id),
        msg_row["message_id"],
        msg_row["created_at"],
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

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "session_id": str(session_id),
            "message_id": str(msg_row["message_id"]),
            "from_agent_id": actor_id,
        },
    )

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
    owner = await _get_agent_by_id(db, project_id=project_id, agent_id=actor_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids,
            lm.body AS last_message,
            lm.from_alias AS last_from,
            lm.created_at AS last_activity,
            COALESCE(unread.cnt, 0) AS unread_count
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
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_agent_id <> $2
              AND m.created_at > COALESCE(rr.last_read_at, 'epoch'::timestamptz)
        ) unread ON TRUE
        WHERE s.project_id = $1
        GROUP BY s.session_id, lm.body, lm.from_alias, lm.created_at, unread.cnt
        HAVING COALESCE(unread.cnt, 0) > 0
        ORDER BY lm.created_at DESC
        """,
        UUID(project_id),
        UUID(actor_id),
    )

    # Unread mail count (best-effort; used only as informational field).
    mail_unread = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.messages}}
        WHERE project_id = $1 AND to_agent_id = $2 AND read_at IS NULL
        """,
        UUID(project_id),
        UUID(actor_id),
    )

    pending_items = []
    for r in rows:
        other_ids = [pid for pid in (r["participant_ids"] or []) if pid != actor_id]
        waiting = await get_waiting_agents(redis, str(r["session_id"]), other_ids)
        pending_items.append(
            {
                "session_id": str(r["session_id"]),
                "participants": list(r["participants"] or []),
                "last_message": r["last_message"] or "",
                "last_from": r["last_from"] or "",
                "unread_count": int(r["unread_count"] or 0),
                "last_activity": _utc_iso(r["last_activity"]) if r["last_activity"] else "",
                "sender_waiting": len(waiting) > 0,
                "time_remaining_seconds": 0,
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
    agent_uuid = UUID(actor_id)

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(project_id),
    )
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
        raise HTTPException(status_code=403, detail="Not authorized for this session")

    rr = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    last_read_at = rr["last_read_at"] if rr else None

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, body, created_at, sender_leaving,
               from_did, to_did, signature, signing_key_id
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND ($2::bool IS FALSE OR (created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz) AND from_agent_id <> $4))
        ORDER BY created_at DESC
        LIMIT $5
        """,
        session_uuid,
        bool(unread_only),
        last_read_at,
        agent_uuid,
        int(limit),
    )
    rows = list(reversed(rows))

    return HistoryResponse(
        messages=[
            {
                "message_id": str(r["message_id"]),
                "from_agent": r["from_alias"],
                "body": r["body"],
                "timestamp": _utc_iso(r["created_at"]),
                "sender_leaving": bool(r["sender_leaving"]),
                "from_did": r["from_did"],
                "to_did": r["to_did"],
                "signature": r["signature"],
                "signing_key_id": r["signing_key_id"],
            }
            for r in rows
        ]
    )


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
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    session_uuid = UUID(session_id.strip())
    up_to_uuid = UUID(payload.up_to_message_id)

    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent_uuid = UUID(actor_id)

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(project_id),
    )
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
        raise HTTPException(status_code=403, detail="Not authorized for this session")

    msg = await aweb_db.fetch_one(
        """
        SELECT created_at
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = $2
        """,
        session_uuid,
        up_to_uuid,
    )
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    up_to_time = msg["created_at"]
    read_time = datetime.now(timezone.utc)

    old = await aweb_db.fetch_one(
        """
        SELECT last_read_at
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1 AND agent_id = $2
        """,
        session_uuid,
        agent_uuid,
    )
    old_last = old["last_read_at"] if old else None

    marked = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND from_agent_id <> $2
          AND created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz)
          AND created_at <= $4
        """,
        session_uuid,
        agent_uuid,
        old_last,
        up_to_time,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        session_uuid,
        agent_uuid,
        up_to_uuid,
        read_time,
    )

    return {"success": True, "messages_marked": int(marked or 0)}


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

    try:
        # Emit an immediate keepalive so ASGI transports that wait for first body chunk
        # can start streaming without blocking on initial DB work.
        yield ": keepalive\n\n"

        if after is not None:
            # Replay only messages newer than the given timestamp (catches the
            # send→SSE connect race window without replaying full history).
            recent = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on,
                       from_did, to_did, signature, signing_key_id
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
                payload = {
                    "type": "message",
                    "session_id": session_id_str,
                    "message_id": str(r["message_id"]),
                    "from_agent": r["from_alias"],
                    "body": r["body"],
                    "sender_leaving": bool(r["sender_leaving"]),
                    "sender_waiting": str(r["from_agent_id"]) in replay_waiting,
                    "hang_on": is_hang_on,
                    "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                    "timestamp": _utc_iso(r["created_at"]),
                    "from_did": r["from_did"],
                    "to_did": r["to_did"],
                    "signature": r["signature"],
                    "signing_key_id": r["signing_key_id"],
                }
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
        else:
            # No replay — poll only for messages arriving after now.
            last_message_at = datetime.now(timezone.utc)

        last_receipt_at = datetime.now(timezone.utc)

        while datetime.now(timezone.utc) < deadline:
            # Refresh registration every 30s.
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, agent_id_str)
                last_refresh = now_mono

            # New messages.
            new_msgs = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, body, created_at,
                       sender_leaving, hang_on,
                       from_did, to_did, signature, signing_key_id
                FROM {{tables.chat_messages}}
                WHERE session_id = $1 AND created_at > $2
                ORDER BY created_at ASC
                LIMIT 200
                """,
                session_id,
                last_message_at,
            )
            for r in new_msgs:
                last_message_at = max(last_message_at, r["created_at"])
                is_hang_on = bool(r["hang_on"])
                sender_waiting = await is_agent_waiting(
                    redis, session_id_str, str(r["from_agent_id"])
                )
                payload = {
                    "type": "message",
                    "session_id": session_id_str,
                    "message_id": str(r["message_id"]),
                    "from_agent": r["from_alias"],
                    "body": r["body"],
                    "sender_leaving": bool(r["sender_leaving"]),
                    "sender_waiting": sender_waiting,
                    "hang_on": is_hang_on,
                    "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                    "timestamp": _utc_iso(r["created_at"]),
                    "from_did": r["from_did"],
                    "to_did": r["to_did"],
                    "signature": r["signature"],
                    "signing_key_id": r["signing_key_id"],
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

            await asyncio.sleep(0.1)
    finally:
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
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(project_id),
    )
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
        raise HTTPException(status_code=403, detail="Not authorized for this session")

    deadline_dt = _parse_deadline(deadline)

    after_dt = _parse_timestamp(after, "after") if after is not None else None

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
    from_did: str | None = Field(default=None, max_length=256)
    to_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signing_key_id: str | None = Field(default=None, max_length=256)


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

    # Verify session exists and belongs to project
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1 AND project_id = $2",
        session_uuid,
        UUID(project_id),
    )
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
        raise HTTPException(
            status_code=403, detail="Not authorized to send messages to this session"
        )
    canonical_alias = participant["alias"]

    extends_wait_seconds = HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is None:
        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
            UUID(project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        sign_result = await sign_on_behalf(
            actor_id,
            {
                "from": f"{project_slug}/{canonical_alias}",
                "from_did": "",
                "message_id": str(pre_message_id),
                "to": "",
                "to_did": payload.to_did or "",
                "type": "chat",
                "subject": "",
                "body": payload.body,
                "timestamp": _utc_iso(msg_created_at),
            },
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_agent_id, from_alias, body, sender_leaving, hang_on,
             from_did, to_did, signature, signing_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING message_id, created_at
        """,
        pre_message_id,
        session_uuid,
        agent_uuid,
        canonical_alias,
        payload.body,
        False,  # sender_leaving only set via create_session with leaving=true
        bool(payload.hang_on),
        msg_from_did,
        payload.to_did,
        msg_signature,
        msg_signing_key_id,
        msg_created_at,
    )

    # Advance sender's read receipt — sending implies having read up to this point.
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_id, agent_id) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        session_uuid,
        agent_uuid,
        msg_row["message_id"],
        msg_row["created_at"],
    )

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "session_id": str(session_uuid),
            "message_id": str(msg_row["message_id"]),
            "from_agent_id": actor_id,
        },
    )

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

    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT s.session_id, s.created_at,
               array_agg(p2.alias ORDER BY p2.alias) AS participants,
               array_agg(p2.agent_id::text ORDER BY p2.alias) AS participant_ids
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_session_participants}} p
          ON p.session_id = s.session_id AND p.agent_id = $2
        JOIN {{tables.chat_session_participants}} p2
          ON p2.session_id = s.session_id
        WHERE s.project_id = $1
        GROUP BY s.session_id, s.created_at
        ORDER BY s.created_at DESC
        """,
        UUID(project_id),
        agent_uuid,
    )

    sessions = []
    for row in rows:
        other_ids = [pid for pid in (row["participant_ids"] or []) if pid != actor_id]
        waiting = await get_waiting_agents(redis, str(row["session_id"]), other_ids)
        sessions.append(
            SessionListItem(
                session_id=str(row["session_id"]),
                participants=list(row["participants"] or []),
                created_at=_utc_iso(row["created_at"]),
                sender_waiting=len(waiting) > 0,
            )
        )

    return SessionListResponse(sessions=sessions)
