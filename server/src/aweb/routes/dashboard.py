"""Dashboard read endpoints for hosted dashboard clients.

Authenticated with X-Dashboard-Token (JWT containing team_addresses).
All endpoints are read-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from aweb.config import get_settings
from aweb.deps import get_db
from aweb.team_auth import verify_dashboard_token

router = APIRouter(tags=["dashboard"])


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _get_dashboard_secret(request: Request) -> str:
    secret = getattr(request.app.state, "dashboard_jwt_secret", None)
    if not secret:
        settings = get_settings()
        secret = settings.dashboard_jwt_secret
    return secret or ""


async def _require_dashboard_auth(request: Request, team_address: str) -> dict[str, Any]:
    """Allow anonymous reads for public teams; otherwise verify dashboard JWT."""
    token = request.headers.get("X-Dashboard-Token")
    try:
        visibility = await _get_team_visibility(request, team_address)
    except HTTPException as exc:
        if exc.status_code == 503 and getattr(request.app.state, "awid_registry_client", None) is None:
            raise
        if not token:
            raise
        visibility = "private"

    if visibility == "public":
        return {"user_id": "", "team_addresses": [team_address]}

    if not token:
        raise HTTPException(status_code=401, detail="Missing X-Dashboard-Token header")

    secret = _get_dashboard_secret(request)
    try:
        return verify_dashboard_token(token, secret, required_team=team_address)
    except ValueError as e:
        msg = str(e)
        if "not configured" in msg:
            raise HTTPException(status_code=500, detail="Dashboard auth misconfigured")
        if "not authorized" in msg:
            raise HTTPException(status_code=403, detail=msg)
        raise HTTPException(status_code=401, detail=msg)


async def _get_team_visibility(request: Request, team_address: str) -> str:
    parts = team_address.split("/", 1)
    if len(parts) != 2:
        return "private"

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry unavailable")

    try:
        team = await registry_client.get_team(parts[0], parts[1])
    except Exception:
        raise HTTPException(status_code=503, detail="AWID registry unavailable")

    if team is None:
        return "private"
    return getattr(team, "visibility", "private")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AgentSummary(BaseModel):
    agent_id: str
    alias: str
    did_key: str
    role: str
    status: str
    lifetime: str
    last_seen: Optional[str]
    workspace_path: Optional[str]
    created_at: str


class AgentDetail(BaseModel):
    agent_id: str
    alias: str
    did_key: str
    did_aw: Optional[str]
    address: Optional[str]
    role: str
    status: str
    lifetime: str
    human_name: str
    agent_type: str
    created_at: str


class MessageSummary(BaseModel):
    message_id: str
    from_alias: str
    to_alias: str
    subject: str
    body: str
    priority: str
    created_at: str
    read_at: Optional[str]


class TaskSummary(BaseModel):
    task_id: str
    task_ref: str
    title: str
    status: str
    priority: int
    task_type: str
    assignee_alias: Optional[str]
    created_at: str


class TeamStatus(BaseModel):
    team_address: str
    agent_count: int
    online_agents: list[str]
    active_claims: list[dict[str, Any]]
    active_locks: list[dict[str, Any]]


class UsageMetrics(BaseModel):
    team_address: str
    messages_sent: int
    active_agents: int
    since: Optional[str]
    until: Optional[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/v1/teams/{team_address:path}/agents")
async def list_team_agents(
    request: Request, team_address: str, db=Depends(get_db)
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT a.agent_id, a.alias, a.did_key, a.role, a.status, a.lifetime, a.created_at,
               w.last_seen_at, w.workspace_path
        FROM {{tables.agents}} a
        LEFT JOIN LATERAL (
            SELECT last_seen_at, workspace_path
            FROM {{tables.workspaces}}
            WHERE agent_id = a.agent_id AND team_address = a.team_address AND deleted_at IS NULL
            ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC NULLS LAST, created_at DESC
            LIMIT 1
        ) w ON TRUE
        WHERE a.team_address = $1 AND a.deleted_at IS NULL
        ORDER BY a.alias
        """,
        team_address,
    )

    return {
        "agents": [
            AgentSummary(
                agent_id=str(r["agent_id"]),
                alias=r["alias"],
                did_key=r["did_key"],
                role=r["role"],
                status=r["status"],
                lifetime=r["lifetime"],
                last_seen=(r["last_seen_at"].isoformat() if r["last_seen_at"] else None),
                workspace_path=r["workspace_path"],
                created_at=r["created_at"].isoformat(),
            ).model_dump()
            for r in rows
        ]
    }


@router.get("/v1/teams/{team_address:path}/agents/{alias}")
async def get_team_agent(
    request: Request, team_address: str, alias: str, db=Depends(get_db)
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did_key, did_aw, address, role, status, lifetime,
               human_name, agent_type, created_at
        FROM {{tables.agents}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_address,
        alias,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentDetail(
        agent_id=str(row["agent_id"]),
        alias=row["alias"],
        did_key=row["did_key"],
        did_aw=row.get("did_aw"),
        address=row.get("address"),
        role=row["role"],
        status=row["status"],
        lifetime=row["lifetime"],
        human_name=row["human_name"],
        agent_type=row["agent_type"],
        created_at=row["created_at"].isoformat(),
    ).model_dump()


@router.get("/v1/teams/{team_address:path}/messages")
async def list_team_messages(
    request: Request,
    team_address: str,
    limit: int = Query(default=50, ge=1, le=200),
    db=Depends(get_db),
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_alias, to_alias, subject, body, priority, created_at, read_at
        FROM {{tables.messages}}
        WHERE team_address = $1
        ORDER BY created_at DESC
        LIMIT $2
        """,
        team_address,
        limit,
    )

    return {
        "messages": [
            MessageSummary(
                message_id=str(r["message_id"]),
                from_alias=r["from_alias"],
                to_alias=r["to_alias"],
                subject=r["subject"],
                body=r["body"],
                priority=r["priority"],
                created_at=r["created_at"].isoformat(),
                read_at=r["read_at"].isoformat() if r.get("read_at") else None,
            ).model_dump()
            for r in rows
        ]
    }


@router.get("/v1/teams/{team_address:path}/tasks")
async def list_team_tasks(
    request: Request,
    team_address: str,
    limit: int = Query(default=50, ge=1, le=200),
    db=Depends(get_db),
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    slug = team_address.split("/")[-1]

    rows = await aweb_db.fetch_all(
        """
        SELECT task_id, task_ref_suffix, title, status, priority, task_type,
               assignee_alias, created_at
        FROM {{tables.tasks}}
        WHERE team_address = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT $2
        """,
        team_address,
        limit,
    )

    return {
        "tasks": [
            TaskSummary(
                task_id=str(r["task_id"]),
                task_ref=f"{slug}-{r['task_ref_suffix']}",
                title=r["title"],
                status=r["status"],
                priority=r["priority"],
                task_type=r["task_type"],
                assignee_alias=r.get("assignee_alias"),
                created_at=r["created_at"].isoformat(),
            ).model_dump()
            for r in rows
        ]
    }


@router.get("/v1/teams/{team_address:path}/roles/active")
async def get_active_roles(
    request: Request, team_address: str, db=Depends(get_db)
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT id, version, bundle_json, updated_at
        FROM {{tables.project_roles}}
        WHERE team_address = $1 AND is_active = true
        """,
        team_address,
    )

    if not row:
        return {"roles": None}

    return {
        "roles": {
            "id": str(row["id"]),
            "version": row["version"],
            "bundle": row["bundle_json"],
            "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        }
    }


@router.get("/v1/teams/{team_address:path}/instructions/active")
async def get_active_instructions(
    request: Request, team_address: str, db=Depends(get_db)
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT id, version, document_json, updated_at
        FROM {{tables.project_instructions}}
        WHERE team_address = $1 AND is_active = true
        """,
        team_address,
    )

    if not row:
        return {"instructions": None}

    return {
        "instructions": {
            "id": str(row["id"]),
            "version": row["version"],
            "document": row["document_json"],
            "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        }
    }


@router.get("/v1/teams/{team_address:path}/status")
async def get_team_status(
    request: Request, team_address: str, db=Depends(get_db)
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    agent_count_row = await aweb_db.fetch_one(
        "SELECT COUNT(*)::int AS cnt FROM {{tables.agents}} WHERE team_address = $1 AND deleted_at IS NULL",
        team_address,
    )
    agent_count = agent_count_row["cnt"] if agent_count_row else 0

    # Online = workspaces with recent last_seen_at
    online_rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT alias FROM {{tables.workspaces}}
        WHERE team_address = $1 AND deleted_at IS NULL
          AND last_seen_at > NOW() - INTERVAL '30 minutes'
        """,
        team_address,
    )
    online_agents = [r["alias"] for r in online_rows]

    claim_rows = await aweb_db.fetch_all(
        """
        SELECT task_ref, alias, claimed_at
        FROM {{tables.task_claims}}
        WHERE team_address = $1
        ORDER BY claimed_at DESC
        """,
        team_address,
    )

    lock_rows = await aweb_db.fetch_all(
        """
        SELECT resource_key, holder_alias, acquired_at, expires_at
        FROM {{tables.reservations}}
        WHERE team_address = $1
          AND (expires_at IS NULL OR expires_at > NOW())
        """,
        team_address,
    )

    return TeamStatus(
        team_address=team_address,
        agent_count=agent_count,
        online_agents=online_agents,
        active_claims=[
            {"task_ref": r["task_ref"], "alias": r["alias"], "claimed_at": r["claimed_at"].isoformat()}
            for r in claim_rows
        ],
        active_locks=[
            {
                "resource_key": r["resource_key"],
                "holder_alias": r["holder_alias"],
                "acquired_at": r["acquired_at"].isoformat(),
                "expires_at": r["expires_at"].isoformat() if r.get("expires_at") else None,
            }
            for r in lock_rows
        ],
    ).model_dump()


@router.get("/v1/usage")
async def get_usage(
    request: Request,
    team_address: str = Query(...),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
    db=Depends(get_db),
) -> dict:
    await _require_dashboard_auth(request, team_address)
    aweb_db = db.get_manager("aweb")

    since_dt = _parse_optional_datetime(since)
    until_dt = _parse_optional_datetime(until)

    # Count messages
    msg_query = "SELECT COUNT(*)::int AS cnt FROM {{tables.messages}} WHERE team_address = $1"
    msg_params: list = [team_address]
    idx = 2
    if since_dt:
        msg_query += f" AND created_at >= ${idx}"
        msg_params.append(since_dt)
        idx += 1
    if until_dt:
        msg_query += f" AND created_at <= ${idx}"
        msg_params.append(until_dt)

    msg_row = await aweb_db.fetch_one(msg_query, *msg_params)
    messages_sent = msg_row["cnt"] if msg_row else 0

    # Count active agents
    agent_row = await aweb_db.fetch_one(
        "SELECT COUNT(*)::int AS cnt FROM {{tables.agents}} WHERE team_address = $1 AND deleted_at IS NULL",
        team_address,
    )
    active_agents = agent_row["cnt"] if agent_row else 0

    return UsageMetrics(
        team_address=team_address,
        messages_sent=messages_sent,
        active_agents=active_agents,
        since=since,
        until=until,
    ).model_dump()


def _parse_optional_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid datetime: {value}")
