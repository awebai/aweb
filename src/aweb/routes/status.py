"""Project status snapshot and SSE stream endpoints."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from aweb.auth import get_project_from_auth
from aweb.deps import get_db, get_redis
from aweb.presence import list_agent_presences_by_ids

router = APIRouter(prefix="/v1/status", tags=["aweb-status"])

STATUS_POLL_INTERVAL = 1.0  # seconds between polls in SSE stream


class AgentStatus(BaseModel):
    agent_id: str
    alias: str
    agent_type: str
    role: str | None = None
    program: str | None = None
    online: bool = False
    status: str | None = None


class ClaimStatus(BaseModel):
    task_ref: str
    title: str
    status: str
    assignee_agent_id: str
    assignee_alias: str


class ActivePolicy(BaseModel):
    policy_id: str
    version: int


class StatusResponse(BaseModel):
    project_id: str
    agents: list[AgentStatus]
    claims: list[ClaimStatus]
    active_policy: ActivePolicy | None = None


async def _build_snapshot(aweb_db, redis, project_id: str) -> dict:
    """Build a status snapshot dict for the given project."""
    pid = UUID(project_id)

    # Agents
    agent_rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, agent_type, role, program
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL AND agent_type != 'human'
        ORDER BY alias
        """,
        pid,
    )

    agent_ids = [str(r["agent_id"]) for r in agent_rows]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
    presence_map = {p["agent_id"]: p for p in presences}

    agents = []
    for r in agent_rows:
        aid = str(r["agent_id"])
        p = presence_map.get(aid)
        agents.append(
            {
                "agent_id": aid,
                "alias": r["alias"],
                "agent_type": r.get("agent_type") or "agent",
                "role": r.get("role"),
                "program": r.get("program"),
                "online": p is not None,
                "status": p["status"] if p else None,
            }
        )

    # Claims
    claim_rows = await aweb_db.fetch_all(
        """
        SELECT t.task_number, t.title, t.status,
               t.assignee_agent_id,
               a.alias AS assignee_alias,
               p.slug AS project_slug
        FROM {{tables.tasks}} t
        JOIN {{tables.agents}} a ON a.agent_id = t.assignee_agent_id
        JOIN {{tables.projects}} p ON p.project_id = t.project_id
        WHERE t.project_id = $1
          AND t.assignee_agent_id IS NOT NULL
          AND t.status != 'closed'
          AND t.deleted_at IS NULL
        ORDER BY t.priority, t.updated_at DESC
        """,
        pid,
    )

    claims = [
        {
            "task_ref": f"{r['project_slug']}-{r['task_number']}",
            "title": r["title"],
            "status": r["status"],
            "assignee_agent_id": str(r["assignee_agent_id"]),
            "assignee_alias": r["assignee_alias"],
        }
        for r in claim_rows
    ]

    # Active policy
    policy_row = await aweb_db.fetch_one(
        """
        SELECT pol.policy_id, pol.version
        FROM {{tables.projects}} proj
        JOIN {{tables.policies}} pol ON pol.policy_id = proj.active_policy_id
        WHERE proj.project_id = $1 AND proj.deleted_at IS NULL
        """,
        pid,
    )

    active_policy = None
    if policy_row:
        active_policy = {
            "policy_id": str(policy_row["policy_id"]),
            "version": policy_row["version"],
        }

    return {
        "project_id": project_id,
        "agents": agents,
        "claims": claims,
        "active_policy": active_policy,
    }


@router.get("", response_model=StatusResponse)
async def get_status(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    """Return a snapshot of the project's status: agents, claims, active policy."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    snapshot = await _build_snapshot(aweb_db, redis, project_id)
    return snapshot


def _parse_deadline(raw: str) -> datetime:
    """Parse an ISO 8601 deadline string into a timezone-aware datetime."""
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def _sse_status_events(
    *,
    db,
    redis,
    project_id: str,
    deadline: datetime,
) -> AsyncIterator[str]:
    """Generate SSE events with periodic status snapshots."""
    aweb_db = db.get_manager("aweb")

    # Emit keepalive so ASGI transports start streaming immediately.
    yield ": keepalive\n\n"

    # Emit initial snapshot.
    snapshot = await _build_snapshot(aweb_db, redis, project_id)
    yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"

    prev_snapshot_json = json.dumps(snapshot, sort_keys=True)

    while datetime.now(timezone.utc) < deadline:
        await asyncio.sleep(STATUS_POLL_INTERVAL)

        if datetime.now(timezone.utc) >= deadline:
            break

        snapshot = await _build_snapshot(aweb_db, redis, project_id)
        snapshot_json = json.dumps(snapshot, sort_keys=True)

        if snapshot_json != prev_snapshot_json:
            yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"
            prev_snapshot_json = snapshot_json


@router.get("/stream")
async def status_stream(
    request: Request,
    deadline: str = Query(..., min_length=1),
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    """SSE stream of project status snapshots. Emits a snapshot event on connect
    and whenever state changes (agents, claims, policy)."""
    project_id = await get_project_from_auth(request, db)

    try:
        deadline_dt = _parse_deadline(deadline)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid deadline format")

    return StreamingResponse(
        _sse_status_events(
            db=db,
            redis=redis,
            project_id=project_id,
            deadline=deadline_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
