from __future__ import annotations

from typing import Optional
from uuid import UUID

from aweb.alias_allocator import suggest_next_name_prefix
from aweb.auth import validate_project_slug
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from beadhub.auth import validate_workspace_id, verify_workspace_access
from beadhub.aweb_introspection import get_project_from_auth

from ..beads_sync import is_valid_alias
from ..config import get_settings
from ..db import DatabaseInfra, get_db_infra
from ..presence import list_agent_presences_by_workspace_ids, update_agent_presence
from ..redis_client import get_redis
from ..roles import ROLE_ERROR_MESSAGE, ROLE_MAX_LENGTH, is_valid_role, normalize_role

router = APIRouter(prefix="/v1/agents", tags=["agents"])


def _validate_workspace_id_field(v: str) -> str:
    """Pydantic validator wrapper for workspace_id."""
    try:
        return validate_workspace_id(v)
    except ValueError as e:
        raise ValueError(str(e))


def _validate_alias_field(v: str) -> str:
    """Pydantic validator wrapper for alias."""
    if not is_valid_alias(v):
        raise ValueError("Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars")
    return v


class RegisterAgentRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    alias: str = Field(..., min_length=1, max_length=64)
    human_name: Optional[str] = Field(None, max_length=64)
    project_slug: Optional[str] = Field(None, max_length=63)
    program: Optional[str] = None
    model: Optional[str] = None
    task_description: Optional[str] = None
    repo: Optional[str] = Field(None, max_length=255)
    branch: Optional[str] = Field(None, max_length=255)
    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    ttl_seconds: Optional[int] = Field(
        None, gt=0, le=86400, description="Presence TTL in seconds (default 300, max 86400)"
    )

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id(cls, v: str) -> str:
        return _validate_workspace_id_field(v)

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v: str) -> str:
        return _validate_alias_field(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not is_valid_role(v):
            raise ValueError(ROLE_ERROR_MESSAGE)
        return normalize_role(v)


class AgentInfo(BaseModel):
    alias: str
    human_name: Optional[str] = None
    project_slug: Optional[str] = None
    program: Optional[str] = None
    model: Optional[str] = None
    member: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    role: Optional[str] = None
    registered_at: str


class WorkspaceInfo(BaseModel):
    workspace_id: str


class RegisterAgentResponse(BaseModel):
    agent: AgentInfo
    workspace: WorkspaceInfo


class AgentView(BaseModel):
    agent_id: str
    alias: str
    human_name: Optional[str] = None
    agent_type: Optional[str] = None
    status: str = "offline"
    last_seen: Optional[str] = None
    online: bool = False
    did: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "persistent"
    identity_status: str = "active"
    access_mode: str = "open"


class ListAgentsResponse(BaseModel):
    project_id: str
    agents: list[AgentView]


class SuggestAliasPrefixRequest(BaseModel):
    project_slug: str = Field(..., min_length=1, max_length=256)

    @field_validator("project_slug")
    @classmethod
    def validate_project_slug(cls, v: str) -> str:
        return validate_project_slug(v.strip())


class SuggestAliasPrefixResponse(BaseModel):
    project_slug: str
    project_id: str | None
    name_prefix: str


@router.post("/suggest-alias-prefix", response_model=SuggestAliasPrefixResponse)
async def suggest_alias_prefix(
    payload: SuggestAliasPrefixRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> SuggestAliasPrefixResponse:
    """Suggest the next available classic alias prefix for a project.

    aweb-protocol compatibility: this endpoint is intentionally unauthenticated so new
    agents can bootstrap cleanly in OSS mode.
    """
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, slug
        FROM {{tables.projects}}
        WHERE slug = $1 AND deleted_at IS NULL
        """,
        payload.project_slug,
    )

    if row is None:
        return SuggestAliasPrefixResponse(
            project_slug=payload.project_slug,
            project_id=None,
            name_prefix="alice",
        )

    project_id = str(row["project_id"])
    aliases = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        UUID(project_id),
    )
    name_prefix = suggest_next_name_prefix([r.get("alias") or "" for r in aliases])
    if name_prefix is None:
        raise HTTPException(status_code=409, detail="alias_exhausted")

    return SuggestAliasPrefixResponse(
        project_slug=payload.project_slug,
        project_id=project_id,
        name_prefix=name_prefix,
    )


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListAgentsResponse:
    """List agents in the current project with best-effort presence enrichment."""
    project_id = await get_project_from_auth(request, db_infra)

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, agent_type,
               did, custody, lifetime, status, access_mode
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
          AND agent_type != 'system'
        ORDER BY alias ASC
        """,
        UUID(project_id),
    )

    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_workspace_ids(redis, agent_ids) if agent_ids else []
    presence_by_id = {str(p.get("workspace_id")): p for p in presences if p.get("workspace_id")}

    agents: list[AgentView] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        presence = presence_by_id.get(agent_id)
        status = "offline"
        last_seen = None
        online = False
        if presence and presence.get("project_id") == project_id:
            online = True
            status = presence.get("status") or "active"
            last_seen = presence.get("last_seen") or None

        agents.append(
            AgentView(
                agent_id=agent_id,
                alias=r["alias"],
                human_name=(r.get("human_name") or None),
                agent_type=(r.get("agent_type") or None),
                status=status,
                last_seen=last_seen,
                online=online,
                did=(r.get("did") or None),
                custody=(r.get("custody") or None),
                lifetime=r["lifetime"],
                identity_status=r["status"],
                access_mode=r["access_mode"],
            )
        )

    return ListAgentsResponse(project_id=project_id, agents=agents)


@router.post("/register", response_model=RegisterAgentResponse)
async def register_agent(
    request: Request,
    payload: RegisterAgentRequest,
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> RegisterAgentResponse:
    """
    Register an agent and record presence for its workspace.

    Presence is a cache of SQL; the workspace must exist and be accessible under
    the authenticated project.
    """
    settings = get_settings()

    project_id = await verify_workspace_access(request, payload.workspace_id, db_infra)

    # Fetch workspace metadata for presence indexing (project_slug, repo_id) and to avoid
    # trusting client-supplied identifiers.
    server_db = db_infra.get_manager("server")
    workspace_row = await server_db.fetch_one(
        """
        SELECT
            w.alias,
            w.human_name,
            w.role,
            w.repo_id,
            p.slug AS project_slug
        FROM {{tables.workspaces}} w
        JOIN {{tables.projects}} p ON p.id = w.project_id AND p.deleted_at IS NULL
        WHERE w.workspace_id = $1 AND w.deleted_at IS NULL
        """,
        UUID(payload.workspace_id),
    )
    if not workspace_row:
        # Should be prevented by verify_workspace_access, but keep a defensive error here.
        raise HTTPException(status_code=422, detail="Workspace not found")

    alias = workspace_row["alias"]
    project_slug = workspace_row["project_slug"]
    repo_id = str(workspace_row["repo_id"]) if workspace_row.get("repo_id") else None
    human_name = payload.human_name or (workspace_row.get("human_name") or None)
    role = payload.role or (workspace_row.get("role") or None)

    registered_at = await update_agent_presence(
        redis,
        workspace_id=payload.workspace_id,
        alias=alias,
        human_name=human_name,
        project_id=project_id,
        project_slug=project_slug,
        repo_id=repo_id,
        program=payload.program,
        model=payload.model,
        current_branch=payload.branch,
        role=role,
        ttl_seconds=payload.ttl_seconds or settings.presence_ttl_seconds,
    )

    agent = AgentInfo(
        alias=alias,
        human_name=human_name,
        project_slug=project_slug,
        program=payload.program,
        model=payload.model,
        member=None,
        repo=payload.repo,
        branch=payload.branch,
        role=role,
        registered_at=registered_at,
    )
    workspace = WorkspaceInfo(workspace_id=payload.workspace_id)

    return RegisterAgentResponse(agent=agent, workspace=workspace)
