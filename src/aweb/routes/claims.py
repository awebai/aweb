"""Claims query endpoint: who is working on what."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from aweb.auth import get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/claims", tags=["aweb-claims"])


class ClaimItem(BaseModel):
    task_id: str
    task_ref: str
    title: str
    status: str
    priority: int
    assignee_agent_id: str
    assignee_alias: str


class ClaimsResponse(BaseModel):
    claims: list[ClaimItem]


@router.get("", response_model=ClaimsResponse)
async def list_claims(
    request: Request,
    db=Depends(get_db),
):
    """List active task assignments (tasks with an assignee that are not closed)."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status, t.priority,
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

    return ClaimsResponse(
        claims=[
            ClaimItem(
                task_id=str(r["task_id"]),
                task_ref=f"{r['project_slug']}-{r['task_number']}",
                title=r["title"],
                status=r["status"],
                priority=r["priority"],
                assignee_agent_id=str(r["assignee_agent_id"]),
                assignee_alias=r["assignee_alias"],
            )
            for r in rows
        ]
    )
