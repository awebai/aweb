from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from aweb.auth import get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/projects", tags=["aweb-projects"])


@router.get("/current")
async def current_project(request: Request, db=Depends(get_db)) -> dict:
    """Return the project associated with the current auth context."""
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, slug, name
        FROM {{tables.projects}}
        WHERE project_id = $1 AND deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    return {"project_id": str(row["project_id"]), "slug": row["slug"], "name": row["name"]}
