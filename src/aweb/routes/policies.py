"""Policy CRUD routes: create, list, get by ID, activate, get active."""

from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.auth import get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/policies", tags=["aweb-policies"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CreatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: dict = Field(..., description="Policy content (opaque JSONB)")


class PolicyResponse(BaseModel):
    policy_id: str
    project_id: str
    version: int
    content: dict
    created_at: str


class PolicyListItem(BaseModel):
    policy_id: str
    version: int
    created_at: str
    is_active: bool


class PolicyListResponse(BaseModel):
    policies: list[PolicyListItem]


class ActivateResponse(BaseModel):
    activated: bool
    active_policy_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_content(val) -> dict:
    """Parse content from DB — may be a JSON string or already a dict."""
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=PolicyResponse)
async def create_policy(
    request: Request,
    payload: CreatePolicyRequest,
    db=Depends(get_db),
):
    """Create a new policy version for the project."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    # Atomically allocate the next version number.
    row = await aweb_db.fetch_one(
        """
        WITH next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.policies}}
            WHERE project_id = $1
        )
        INSERT INTO {{tables.policies}} (project_id, version, content)
        SELECT $1, nv.version, $2::jsonb
        FROM next_version nv
        RETURNING policy_id, project_id, version, content, created_at
        """,
        UUID(project_id),
        json.dumps(payload.content),
    )

    return PolicyResponse(
        policy_id=str(row["policy_id"]),
        project_id=str(row["project_id"]),
        version=row["version"],
        content=_parse_content(row["content"]),
        created_at=row["created_at"].isoformat(),
    )


@router.get("/active", response_model=PolicyResponse)
async def get_active_policy(
    request: Request,
    db=Depends(get_db),
):
    """Get the currently active policy for the project."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT pol.policy_id, pol.project_id, pol.version, pol.content, pol.created_at
        FROM {{tables.projects}} p
        JOIN {{tables.policies}} pol ON pol.policy_id = p.active_policy_id
        WHERE p.project_id = $1 AND p.deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="No active policy")

    return PolicyResponse(
        policy_id=str(row["policy_id"]),
        project_id=str(row["project_id"]),
        version=row["version"],
        content=_parse_content(row["content"]),
        created_at=row["created_at"].isoformat(),
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    request: Request,
    policy_id: str,
    db=Depends(get_db),
):
    """Get a specific policy version by ID."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT policy_id, project_id, version, content, created_at
        FROM {{tables.policies}}
        WHERE policy_id = $1 AND project_id = $2
        """,
        UUID(policy_id),
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyResponse(
        policy_id=str(row["policy_id"]),
        project_id=str(row["project_id"]),
        version=row["version"],
        content=_parse_content(row["content"]),
        created_at=row["created_at"].isoformat(),
    )


@router.post("/{policy_id}/activate", response_model=ActivateResponse)
async def activate_policy(
    request: Request,
    policy_id: str,
    db=Depends(get_db),
):
    """Set a policy as the active policy for the project."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    # Verify policy exists and belongs to this project
    policy = await aweb_db.fetch_one(
        """
        SELECT policy_id FROM {{tables.policies}}
        WHERE policy_id = $1 AND project_id = $2
        """,
        UUID(policy_id),
        UUID(project_id),
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    await aweb_db.execute(
        """
        UPDATE {{tables.projects}}
        SET active_policy_id = $1
        WHERE project_id = $2
        """,
        UUID(policy_id),
        UUID(project_id),
    )

    return ActivateResponse(activated=True, active_policy_id=policy_id)


@router.get("", response_model=PolicyListResponse)
async def list_policies(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    db=Depends(get_db),
):
    """List policy versions for the project, newest first."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    # Get active policy ID
    proj = await aweb_db.fetch_one(
        "SELECT active_policy_id FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    active_id = str(proj["active_policy_id"]) if proj and proj["active_policy_id"] else None

    rows = await aweb_db.fetch_all(
        """
        SELECT policy_id, version, created_at
        FROM {{tables.policies}}
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        UUID(project_id),
        limit,
    )

    return PolicyListResponse(
        policies=[
            PolicyListItem(
                policy_id=str(r["policy_id"]),
                version=r["version"],
                created_at=r["created_at"].isoformat(),
                is_active=(str(r["policy_id"]) == active_id),
            )
            for r in rows
        ]
    )
