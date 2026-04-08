from __future__ import annotations

from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from aweb.alias_allocator import suggest_next_name_prefix
from aweb.deps import get_db, get_redis
from aweb.team_auth_deps import TeamIdentity, get_team_identity

from ..presence import list_agent_presences_by_workspace_ids, update_agent_presence

router = APIRouter(prefix="/v1/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AgentView(BaseModel):
    agent_id: str
    alias: str
    did_key: str
    did_aw: Optional[str] = None
    address: Optional[str] = None
    human_name: Optional[str] = None
    agent_type: Optional[str] = None
    workspace_type: Optional[str] = None
    role: Optional[str] = None
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    repo: Optional[str] = None
    status: str = "offline"
    last_seen: Optional[str] = None
    online: bool = False
    lifetime: str = "ephemeral"


class ListAgentsResponse(BaseModel):
    team_address: str
    agents: list[AgentView]


class HeartbeatResponse(BaseModel):
    agent_id: str
    alias: str
    last_seen_at: str


class SuggestAliasPrefixResponse(BaseModel):
    team_address: str
    name_prefix: str


class PatchWorkspaceRequest(BaseModel):
    model_config = {"extra": "forbid"}

    hostname: Optional[str] = Field(None, max_length=256)
    workspace_path: Optional[str] = Field(None, max_length=1024)
    role: Optional[str] = Field(None, max_length=50)
    human_name: Optional[str] = Field(None, max_length=64)


class PatchWorkspaceResponse(BaseModel):
    agent_id: str
    alias: str
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    role: Optional[str] = None
    human_name: Optional[str] = None


class SendControlSignalRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signal: Literal["pause", "resume", "interrupt"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/suggest-alias-prefix", response_model=SuggestAliasPrefixResponse)
async def suggest_alias_prefix(
    request: Request,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> SuggestAliasPrefixResponse:
    """Suggest the next available classic alias for the authenticated team."""
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.workspaces}}
        WHERE team_address = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        identity.team_address,
    )
    name_prefix = suggest_next_name_prefix([str(r.get("alias") or "") for r in rows])
    if name_prefix is None:
        raise HTTPException(status_code=409, detail="alias_exhausted")
    return SuggestAliasPrefixResponse(
        team_address=identity.team_address,
        name_prefix=name_prefix,
    )


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ListAgentsResponse:
    """List agents in the current team."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, did_key, did_aw, address,
               human_name, agent_type, role, lifetime, status
        FROM {{tables.agents}}
        WHERE team_address = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        identity.team_address,
    )

    # Workspace context for each agent
    context_rows = await aweb_db.fetch_all(
        """
        SELECT w.agent_id,
               w.workspace_type,
               w.hostname,
               w.workspace_path,
               w.role AS ws_role,
               r.canonical_origin AS repo
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        WHERE w.team_address = $1 AND w.deleted_at IS NULL
        """,
        identity.team_address,
    )
    context_by_agent = {str(r["agent_id"]): r for r in context_rows}

    # Presence from Redis
    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_workspace_ids(redis, agent_ids) if agent_ids else []
    presence_by_id = {str(p.get("workspace_id")): p for p in presences if p.get("workspace_id")}

    agents: list[AgentView] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        ctx = context_by_agent.get(agent_id)
        presence = presence_by_id.get(agent_id)

        status = "offline"
        last_seen = None
        online = False
        role = (ctx.get("ws_role") if ctx else None) or (r.get("role") or None)

        if presence:
            online = True
            status = presence.get("status") or "active"
            last_seen = presence.get("last_seen") or None
            role = presence.get("role") or role

        agents.append(
            AgentView(
                agent_id=agent_id,
                alias=r["alias"],
                did_key=r["did_key"],
                did_aw=r.get("did_aw"),
                address=r.get("address"),
                human_name=r.get("human_name") or None,
                agent_type=r.get("agent_type") or None,
                workspace_type=(ctx.get("workspace_type") if ctx else None),
                role=role,
                hostname=(ctx.get("hostname") if ctx else None),
                workspace_path=(ctx.get("workspace_path") if ctx else None),
                repo=(ctx.get("repo") if ctx else None),
                status=status,
                last_seen=last_seen,
                online=online,
                lifetime=str(r.get("lifetime") or "ephemeral"),
            )
        )

    return ListAgentsResponse(team_address=identity.team_address, agents=agents)


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(get_team_identity),
) -> HeartbeatResponse:
    """Update workspace last_seen_at and Redis presence."""
    aweb_db = db.get_manager("aweb")

    # Update last_seen_at on the workspace scoped by team_address
    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET last_seen_at = NOW(), updated_at = NOW()
        WHERE team_address = $1 AND agent_id = (
            SELECT agent_id FROM {{tables.agents}}
            WHERE agent_id = $2::UUID AND team_address = $1 AND deleted_at IS NULL
        ) AND deleted_at IS NULL
        """,
        identity.team_address,
        identity.agent_id,
    )

    ttl_seconds = 1800
    last_seen = await update_agent_presence(
        redis,
        agent_id=identity.agent_id,
        alias=identity.alias,
        team_address=identity.team_address,
        ttl_seconds=ttl_seconds,
    )

    return HeartbeatResponse(
        agent_id=identity.agent_id,
        alias=identity.alias,
        last_seen_at=last_seen,
    )


@router.patch("/me", response_model=PatchWorkspaceResponse)
async def patch_agent_workspace(
    request: Request,
    payload: PatchWorkspaceRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> PatchWorkspaceResponse:
    """Update the calling agent's workspace info."""
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT w.workspace_id, w.hostname, w.workspace_path, w.role,
               w.human_name
        FROM {{tables.workspaces}} w
        JOIN {{tables.agents}} a ON a.agent_id = w.agent_id
        WHERE w.team_address = $1
          AND a.agent_id = $2::UUID
          AND a.deleted_at IS NULL
          AND w.deleted_at IS NULL
        """,
        identity.team_address,
        identity.agent_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    new_hostname = payload.hostname if payload.hostname is not None else row["hostname"]
    new_path = payload.workspace_path if payload.workspace_path is not None else row["workspace_path"]
    new_role = payload.role if payload.role is not None else row["role"]
    new_human_name = payload.human_name if payload.human_name is not None else row["human_name"]

    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET hostname = $1, workspace_path = $2, role = $3,
            human_name = $4, updated_at = NOW()
        WHERE workspace_id = $5
        """,
        new_hostname,
        new_path,
        new_role,
        new_human_name,
        row["workspace_id"],
    )

    return PatchWorkspaceResponse(
        agent_id=identity.agent_id,
        alias=identity.alias,
        hostname=new_hostname,
        workspace_path=new_path,
        role=new_role,
        human_name=new_human_name,
    )


@router.post("/{alias}/control")
async def send_control_signal(
    request: Request,
    alias: str,
    payload: SendControlSignalRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
):
    """Send a control signal (pause/resume/interrupt) to another agent."""
    aweb_db = db.get_manager("aweb")

    target = await aweb_db.fetch_one(
        """
        SELECT agent_id FROM {{tables.agents}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        identity.team_address,
        alias,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Agent not found")

    result = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.control_signals}} (team_address, target_agent_id, from_agent_id, signal_type)
        VALUES ($1, $2, $3, $4)
        RETURNING signal_id
        """,
        identity.team_address,
        target["agent_id"],
        UUID(identity.agent_id),
        payload.signal,
    )
    return {"signal_id": str(result["signal_id"]), "signal": payload.signal}
