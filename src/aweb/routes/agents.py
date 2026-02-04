from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
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
    status: str | None = None
    last_seen: str | None = None
    online: bool = False


class ListAgentsResponse(BaseModel):
    project_id: str
    agents: list[AgentView]


@router.get("", response_model=ListAgentsResponse)
async def list_agents(request: Request, db=Depends(get_db), redis=Depends(get_redis)):
    """List all agents in the authenticated project with online status."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, agent_type
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
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
                status=p["status"] if p else None,
                last_seen=p["last_seen"] if p else None,
                online=p is not None,
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
