"""Project status snapshot endpoint."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from aweb.auth import get_project_from_auth
from aweb.deps import get_db, get_redis
from aweb.presence import list_agent_presences_by_ids

router = APIRouter(prefix="/v1/status", tags=["aweb-status"])


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


@router.get("", response_model=StatusResponse)
async def get_status(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    """Return a snapshot of the project's status: agents, claims, active policy."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    # Agents
    agent_rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, agent_type, role, program
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL AND agent_type != 'human'
        ORDER BY alias
        """,
        UUID(project_id),
    )

    agent_ids = [str(r["agent_id"]) for r in agent_rows]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
    presence_map = {p["agent_id"]: p for p in presences}

    agents = []
    for r in agent_rows:
        aid = str(r["agent_id"])
        p = presence_map.get(aid)
        agents.append(
            AgentStatus(
                agent_id=aid,
                alias=r["alias"],
                agent_type=r.get("agent_type") or "agent",
                role=r.get("role"),
                program=r.get("program"),
                online=p is not None,
                status=p["status"] if p else None,
            )
        )

    # Claims (active task assignments)
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
        UUID(project_id),
    )

    claims = [
        ClaimStatus(
            task_ref=f"{r['project_slug']}-{r['task_number']}",
            title=r["title"],
            status=r["status"],
            assignee_agent_id=str(r["assignee_agent_id"]),
            assignee_alias=r["assignee_alias"],
        )
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
        UUID(project_id),
    )

    active_policy = None
    if policy_row:
        active_policy = ActivePolicy(
            policy_id=str(policy_row["policy_id"]),
            version=policy_row["version"],
        )

    return StatusResponse(
        project_id=project_id,
        agents=agents,
        claims=claims,
        active_policy=active_policy,
    )
