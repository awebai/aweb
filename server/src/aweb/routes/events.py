"""Per-agent SSE event stream — lightweight wake signals."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from aweb.deps import get_db, get_redis
from aweb.messaging.chat import get_pending_conversations
from aweb.messaging.waiting import get_waiting_agents
from aweb.team_auth_deps import TeamIdentity, get_team_identity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/events", tags=["aweb-events"])

EVENTS_POLL_INTERVAL = 1.0  # seconds between polls
MAX_STREAM_DURATION = 300  # maximum stream lifetime in seconds


def _parse_deadline(raw: str) -> datetime:
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _mail_wake_mode(priority: str | None) -> str:
    normalized = (priority or "normal").strip().lower()
    if normalized in {"high", "urgent"}:
        return "prompt"
    return "idle"


def _chat_wake_mode(*, sender_waiting: bool) -> str:
    return "interrupt" if sender_waiting else "prompt"


async def _current_actionable_mail(aweb_db, *, inbox_dids: list[str]) -> list[dict[str, Any]]:
    """Return the current actionable unread mail state for an identity."""
    rows = await aweb_db.fetch_all(
        """
        WITH unread AS (
            SELECT message_id, from_alias, subject, priority, created_at
            FROM {{tables.messages}}
            WHERE to_did = ANY($1::text[])
              AND read_at IS NULL
        ),
        windowed AS (
            SELECT message_id, from_alias, subject, priority, created_at
            FROM unread
            ORDER BY created_at DESC, message_id DESC
            LIMIT 50
        )
        SELECT
            message_id,
            from_alias,
            subject,
            priority,
            created_at,
            (SELECT COUNT(*)::int FROM unread) AS unread_count
        FROM windowed
        ORDER BY created_at ASC, message_id ASC
        """,
        inbox_dids,
    )
    return [
        {
            "type": "actionable_mail",
            "message_id": str(r["message_id"]),
            "from_alias": r["from_alias"],
            "subject": r["subject"] or "",
            "priority": (r.get("priority") or "normal").strip().lower(),
            "unread_count": int(r.get("unread_count") or 0),
            "wake_mode": _mail_wake_mode(r.get("priority")),
            "created_at": r["created_at"].astimezone(timezone.utc).isoformat(),
        }
        for r in rows
    ]


def _identity_dids(viewer: dict[str, Any] | None, identity: TeamIdentity | None = None) -> list[str]:
    dids: list[str] = []
    for value in (
        (getattr(identity, "did_aw", None) or "").strip(),
        (getattr(identity, "did_key", None) or "").strip(),
        (viewer.get("did_aw") if viewer else "") or "",
        (viewer.get("did_key") if viewer else "") or "",
    ):
        value = value.strip()
        if value and value not in dids:
            dids.append(value)
    return dids


async def _current_actionable_chat(
    db,
    redis,
    *,
    participant_dids: list[str],
    participant_agent_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return the current actionable unread chat state for an identity."""
    pending_by_session: dict[str, dict[str, Any]] = {}
    viewer_did_set = set(participant_dids)
    for participant_did in participant_dids:
        pending = await get_pending_conversations(
            db,
            participant_did=participant_did,
            participant_agent_id=participant_agent_id,
        )
        for item in pending:
            pending_by_session.setdefault(item["session_id"], item)
    actionable: list[dict[str, Any]] = []
    for item in pending_by_session.values():
        other_dids = [
            did for did in item.get("participant_dids", []) if did not in viewer_did_set
        ]
        waiting = await get_waiting_agents(redis, item["session_id"], other_dids)
        sender_waiting = bool(waiting)
        last_activity = item.get("last_activity")
        actionable.append(
            {
                "type": "actionable_chat",
                "session_id": item["session_id"],
                "participants": list(item.get("participants") or []),
                "from_alias": item.get("last_from") or "",
                "last_from": item.get("last_from") or "",
                "last_message": item.get("last_message") or "",
                "last_activity": (
                    last_activity.astimezone(timezone.utc).isoformat() if last_activity else ""
                ),
                "unread_count": int(item.get("unread_count") or 0),
                "sender_waiting": sender_waiting,
                "wake_mode": _chat_wake_mode(sender_waiting=sender_waiting),
            }
        )
    return actionable


def _index_events(events: list[dict[str, Any]], *, key_field: str) -> dict[str, dict[str, Any]]:
    return {str(evt[key_field]): evt for evt in events}


def _new_or_changed_events(
    current: list[dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    *,
    key_field: str,
) -> list[dict[str, Any]]:
    changed: list[dict[str, Any]] = []
    for evt in current:
        key = str(evt[key_field])
        if previous.get(key) != evt:
            changed.append(evt)
    return changed


async def _poll_control_signals(aweb_db, *, team_id: str, agent_id: UUID) -> list[dict]:
    """Consume and return pending control signals for this agent.

    At-most-once delivery: signals are marked consumed atomically with the read.
    If the connection drops before the client receives the SSE frame, the signal
    is lost.  Acceptable for wake-signal semantics where clients re-fetch state
    after reconnecting.
    """
    rows = await aweb_db.fetch_all(
        """
        UPDATE {{tables.control_signals}}
        SET consumed_at = NOW()
        WHERE signal_id IN (
            SELECT signal_id FROM {{tables.control_signals}}
            WHERE team_id = $1
              AND target_agent_id = $2
              AND consumed_at IS NULL
            ORDER BY created_at ASC
            LIMIT 10
        )
        RETURNING signal_id, signal_type, created_at
        """,
        team_id,
        agent_id,
    )
    return [
        {
            "type": f"control_{r['signal_type']}",
            "signal_id": str(r["signal_id"]),
        }
        for r in rows
    ]


async def _sse_agent_events(
    *,
    request: Request,
    db,
    redis,
    team_id: str,
    agent_id: str,
    identity: TeamIdentity,
    deadline: datetime,
) -> AsyncIterator[str]:
    """Generate per-agent SSE actionable coordination events."""
    aweb_db = db.get_manager("aweb")
    aid = UUID(agent_id)
    viewer = await aweb_db.fetch_one(
        """
        SELECT did_aw, did_key
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        aid,
    )
    viewer_dids = _identity_dids(viewer, identity)
    if not viewer_dids:
        yield f"event: error\ndata: {json.dumps({'type': 'error', 'detail': 'identity incomplete'})}\n\n"
        return

    yield ": keepalive\n\n"

    yield f"event: connected\ndata: {json.dumps({'agent_id': agent_id, 'team_id': team_id})}\n\n"

    # Initial snapshot
    mail_events = await _current_actionable_mail(aweb_db, inbox_dids=viewer_dids)
    chat_events = await _current_actionable_chat(
        db,
        redis,
        participant_dids=viewer_dids,
        participant_agent_id=agent_id,
    )
    control_events = await _poll_control_signals(aweb_db, team_id=team_id, agent_id=aid)
    previous_mail = _index_events(mail_events, key_field="message_id")
    previous_chat = _index_events(chat_events, key_field="session_id")

    for evt in mail_events:
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
    for evt in chat_events:
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
    for evt in control_events:
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"

    while datetime.now(timezone.utc) < deadline:
        await asyncio.sleep(EVENTS_POLL_INTERVAL)

        if await request.is_disconnected():
            break

        # Guard against sleep or is_disconnected taking longer than remaining time.
        if datetime.now(timezone.utc) >= deadline:
            break

        try:
            current_mail = await _current_actionable_mail(aweb_db, inbox_dids=viewer_dids)
            current_chat = await _current_actionable_chat(
                db,
                redis,
                participant_dids=viewer_dids,
                participant_agent_id=agent_id,
            )
            control_events = await _poll_control_signals(aweb_db, team_id=team_id, agent_id=aid)
        except Exception:
            logger.exception("event-stream poll error for agent %s", agent_id)
            yield f"event: error\ndata: {json.dumps({'type': 'error', 'detail': 'poll failure'})}\n\n"
            break

        mail_events = _new_or_changed_events(
            current_mail,
            previous_mail,
            key_field="message_id",
        )
        chat_events = _new_or_changed_events(
            current_chat,
            previous_chat,
            key_field="session_id",
        )

        for evt in mail_events:
            yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
        for evt in chat_events:
            yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
        for evt in control_events:
            yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"

        previous_mail = _index_events(current_mail, key_field="message_id")
        previous_chat = _index_events(current_chat, key_field="session_id")


@router.get("/stream")
async def event_stream(
    request: Request,
    deadline: str = Query(..., min_length=1),
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(get_team_identity),
):
    """Per-agent SSE event stream. Emits lightweight wake events when the agent
    has new mail, chat messages, or available work."""

    try:
        deadline_dt = _parse_deadline(deadline)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid deadline format")

    # Cap deadline so clients cannot hold connections open indefinitely.
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline

    return StreamingResponse(
        _sse_agent_events(
            request=request,
            db=db,
            redis=redis,
            team_id=identity.team_id,
            agent_id=identity.agent_id,
            identity=identity,
            deadline=deadline_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
