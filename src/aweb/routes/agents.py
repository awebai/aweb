from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.alias_allocator import suggest_next_name_prefix
from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_project_slug
from aweb.deps import get_db, get_redis
from aweb.presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences_by_ids,
    update_agent_presence,
)

router = APIRouter(prefix="/v1/agents", tags=["aweb-agents"])


class SuggestAliasPrefixRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_slug: str = Field(..., min_length=1, max_length=256)

    @field_validator("project_slug")
    @classmethod
    def _validate_project_slug(cls, v: str) -> str:
        return validate_project_slug(v.strip())


class SuggestAliasPrefixResponse(BaseModel):
    project_slug: str
    project_id: str | None
    name_prefix: str


@router.post("/suggest-alias-prefix", response_model=SuggestAliasPrefixResponse)
async def suggest_alias_prefix(
    payload: SuggestAliasPrefixRequest, db=Depends(get_db)
) -> SuggestAliasPrefixResponse:
    """Suggest the next available classic alias prefix for a project.

    - Does not allocate (no project/agent/key creation).
    - Works without an API key for OSS clean-start UX.
    """
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, slug
        FROM {{tables.projects}}
        WHERE slug = $1 AND deleted_at IS NULL
        """,
        payload.project_slug,
    )

    if row is None:
        # Project doesn't exist yet: first prefix is always available.
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


class AgentView(BaseModel):
    agent_id: str
    alias: str
    human_name: str | None = None
    agent_type: str | None = None
    access_mode: str = "open"
    status: str | None = None
    last_seen: str | None = None
    online: bool = False
    did: str | None = None
    custody: str | None = None
    lifetime: str = "persistent"
    identity_status: str = "active"


class ListAgentsResponse(BaseModel):
    project_id: str
    agents: list[AgentView]


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    include_internal: bool = Query(False),
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    """List all agents in the authenticated project with online status."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    type_filter = "" if include_internal else "AND agent_type != 'human'"
    rows = await aweb_db.fetch_all(
        f"""
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, custody, lifetime, status
        FROM {{{{tables.agents}}}}
        WHERE project_id = $1 AND deleted_at IS NULL
          {type_filter}
        ORDER BY alias
        """,
        UUID(project_id),
    )

    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
    presence_map = {p["agent_id"]: p for p in presences}

    agents = []
    for r in rows:
        aid = str(r["agent_id"])
        p = presence_map.get(aid)
        agents.append(
            AgentView(
                agent_id=aid,
                alias=r["alias"],
                human_name=r.get("human_name"),
                agent_type=r.get("agent_type"),
                access_mode=r.get("access_mode", "open"),
                status=p["status"] if p else None,
                last_seen=p["last_seen"] if p else None,
                online=p is not None,
                did=r.get("did"),
                custody=r.get("custody"),
                lifetime=r.get("lifetime", "persistent"),
                identity_status=r.get("status", "active"),
            )
        )

    return ListAgentsResponse(project_id=project_id, agents=agents)


class HeartbeatResponse(BaseModel):
    agent_id: str
    last_seen: str
    ttl_seconds: int


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: Request, db=Depends(get_db), redis=Depends(get_redis)):
    """Report agent liveness. Refreshes presence TTL in Redis (best-effort)."""
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)

    # Look up the agent's alias for presence
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = DEFAULT_PRESENCE_TTL_SECONDS
    last_seen = await update_agent_presence(
        redis,
        agent_id=agent_id,
        alias=row["alias"],
        project_id=project_id,
        ttl_seconds=ttl,
    )

    return HeartbeatResponse(agent_id=agent_id, last_seen=last_seen, ttl_seconds=ttl)


VALID_ACCESS_MODES = {"open", "contacts_only"}


class PatchAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_mode: str | None = None

    @field_validator("access_mode")
    @classmethod
    def _validate_access_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ACCESS_MODES:
            raise ValueError(f"access_mode must be one of {sorted(VALID_ACCESS_MODES)}")
        return v


class PatchAgentResponse(BaseModel):
    agent_id: str
    access_mode: str


@router.patch("/{agent_id}", response_model=PatchAgentResponse)
async def patch_agent(
    request: Request, agent_id: str, payload: PatchAgentRequest, db=Depends(get_db)
) -> PatchAgentResponse:
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(agent_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid agent_id format")

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, access_mode
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_access_mode = payload.access_mode if payload.access_mode is not None else row["access_mode"]

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET access_mode = $1
        WHERE agent_id = $2 AND project_id = $3
        """,
        new_access_mode,
        agent_uuid,
        UUID(project_id),
    )

    return PatchAgentResponse(agent_id=str(agent_uuid), access_mode=new_access_mode)


class ResolveAgentResponse(BaseModel):
    did: str | None
    address: str
    agent_id: str
    human_name: str | None
    public_key: str | None
    server: str
    custody: str | None
    lifetime: str
    status: str


@router.get("/resolve/{namespace}/{alias}", response_model=ResolveAgentResponse)
async def resolve_agent(
    request: Request,
    namespace: str,
    alias: str,
    db=Depends(get_db),
) -> ResolveAgentResponse:
    """Resolve an agent by namespace (project slug) and alias.

    Authenticated but NOT project-scoped — any valid API key can resolve any agent.
    Per clawdid/sot.md §4.6.
    """
    # Auth check: caller must have a valid API key
    await get_project_from_auth(request, db)

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, a.human_name, a.did, a.public_key,
               a.custody, a.lifetime, a.status, p.slug
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        WHERE p.slug = $1
          AND a.alias = $2
          AND a.deleted_at IS NULL
          AND p.deleted_at IS NULL
        """,
        namespace,
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    server_url = os.environ.get("AWEB_SERVER_URL", "")

    return ResolveAgentResponse(
        did=row["did"],
        address=f"{namespace}/{alias}",
        agent_id=str(row["agent_id"]),
        human_name=row.get("human_name"),
        public_key=row["public_key"],
        server=server_url,
        custody=row["custody"],
        lifetime=row["lifetime"],
        status=row["status"],
    )
