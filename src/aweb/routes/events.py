"""Per-agent SSE event stream — lightweight wake signals."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/events", tags=["aweb-events"])

EVENTS_POLL_INTERVAL = 1.0  # seconds between polls
MAX_STREAM_DURATION = 300  # maximum stream lifetime in seconds


def _parse_deadline(raw: str) -> datetime:
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def _poll_unread_mail(aweb_db, *, project_id: UUID, agent_id: UUID, since: datetime) -> list[dict]:
    """Check for new unread mail to this agent since the given timestamp."""
    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, subject, created_at
        FROM {{tables.messages}}
        WHERE project_id = $1
          AND to_agent_id = $2
          AND read_at IS NULL
          AND created_at > $3
        ORDER BY created_at ASC
        LIMIT 50
        """,
        project_id,
        agent_id,
        since,
    )
    return [
        {
            "type": "mail_message",
            "message_id": str(r["message_id"]),
            "from_alias": r["from_alias"],
            "subject": r["subject"] or "",
        }
        for r in rows
    ]


async def _poll_unread_chat(aweb_db, *, project_id: UUID, agent_id: UUID, since: datetime) -> list[dict]:
    """Check for new chat messages to sessions this agent participates in."""
    rows = await aweb_db.fetch_all(
        """
        SELECT cm.message_id, cm.from_alias, cm.session_id, cm.created_at
        FROM {{tables.chat_messages}} cm
        JOIN {{tables.chat_session_participants}} csp
          ON csp.session_id = cm.session_id AND csp.agent_id = $2
        JOIN {{tables.chat_sessions}} cs
          ON cs.session_id = cm.session_id AND cs.project_id = $1
        WHERE cm.from_agent_id != $2
          AND cm.created_at > $3
        ORDER BY cm.created_at ASC
        LIMIT 50
        """,
        project_id,
        agent_id,
        since,
    )
    return [
        {
            "type": "chat_message",
            "message_id": str(r["message_id"]),
            "from_alias": r["from_alias"],
            "session_id": str(r["session_id"]),
        }
        for r in rows
    ]


async def _poll_ready_tasks(aweb_db, *, project_id: UUID) -> list[dict]:
    """Return all unclaimed, unblocked, open tasks in the project."""
    rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title
        FROM {{tables.tasks}} t
        WHERE t.project_id = $1
          AND t.status = 'open'
          AND t.assignee_agent_id IS NULL
          AND t.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.task_dependencies}} d
              JOIN {{tables.tasks}} blocker ON blocker.task_id = d.depends_on_task_id
              WHERE d.task_id = t.task_id
                AND blocker.status != 'closed'
                AND blocker.deleted_at IS NULL
          )
        ORDER BY t.priority ASC, t.task_number ASC
        LIMIT 10
        """,
        project_id,
    )
    return [
        {
            "type": "work_available",
            "task_id": str(r["task_id"]),
            "title": r["title"],
        }
        for r in rows
    ]


async def _sse_agent_events(
    *,
    request: Request,
    db,
    project_id: str,
    agent_id: str,
    deadline: datetime,
) -> AsyncIterator[str]:
    """Generate per-agent SSE wake events."""
    aweb_db = db.get_manager("aweb")
    pid = UUID(project_id)
    aid = UUID(agent_id)

    yield ": keepalive\n\n"

    # Connected event
    yield f"event: connected\ndata: {json.dumps({'agent_id': agent_id, 'project_id': project_id})}\n\n"

    # Initial sweep: check for existing pending items (unread mail, unread chat, ready work).
    # Use epoch as "since" to catch everything that already exists.
    epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)

    mail_events = await _poll_unread_mail(aweb_db, project_id=pid, agent_id=aid, since=epoch)
    chat_events = await _poll_unread_chat(aweb_db, project_id=pid, agent_id=aid, since=epoch)
    work_events = await _poll_ready_tasks(aweb_db, project_id=pid)

    for evt in mail_events:
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
    for evt in chat_events:
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"

    # Track ready task IDs so we only emit newly-appeared tasks on subsequent polls.
    # This avoids depending on updated_at, which misses tasks that become unblocked
    # when their blocker is closed (the dependent's updated_at is not bumped).
    prev_ready_ids: set[str] = set()
    for evt in work_events:
        prev_ready_ids.add(evt["task_id"])
        yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"

    last_check = datetime.now(timezone.utc)

    while datetime.now(timezone.utc) < deadline:
        await asyncio.sleep(EVENTS_POLL_INTERVAL)

        if await request.is_disconnected():
            break

        if datetime.now(timezone.utc) >= deadline:
            break

        now = datetime.now(timezone.utc)

        mail_events = await _poll_unread_mail(aweb_db, project_id=pid, agent_id=aid, since=last_check)
        chat_events = await _poll_unread_chat(aweb_db, project_id=pid, agent_id=aid, since=last_check)
        work_events = await _poll_ready_tasks(aweb_db, project_id=pid)

        for evt in mail_events:
            yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
        for evt in chat_events:
            yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"

        current_ready_ids = {evt["task_id"] for evt in work_events}
        new_ready_ids = current_ready_ids - prev_ready_ids
        for evt in work_events:
            if evt["task_id"] in new_ready_ids:
                yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
        prev_ready_ids = current_ready_ids

        last_check = now


@router.get("/stream")
async def event_stream(
    request: Request,
    deadline: str = Query(..., min_length=1),
    db=Depends(get_db),
):
    """Per-agent SSE event stream. Emits lightweight wake events when the agent
    has new mail, chat messages, or available work."""
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

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
            project_id=project_id,
            agent_id=agent_id,
            deadline=deadline_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
