"""Claims API - view active task claims."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from uuid import UUID

from aweb.team_auth_deps import TeamIdentity, get_team_identity

from ..db import DatabaseInfra, get_db_infra
from ..claims import list_active_claims as list_active_claim_rows
from awid.pagination import encode_cursor, validate_pagination_params

router = APIRouter(prefix="/v1", tags=["claims"])


class Claim(BaseModel):
    """A task claim - indicates a workspace is actively working on a task."""

    task_ref: str
    workspace_id: str
    alias: str
    human_name: Optional[str]
    claimed_at: str
    team_id: str


class ClaimsResponse(BaseModel):
    """Response for GET /v1/claims."""

    claims: List[Claim]
    has_more: bool = False
    next_cursor: Optional[str] = None


@router.get("/claims")
async def list_claims(
    request: Request,
    workspace_id: Optional[str] = Query(None, description="Filter to specific workspace"),
    limit: Optional[int] = Query(None, description="Maximum items per page", ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Pagination cursor from previous response"),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ClaimsResponse:
    """
    List active task claims for a team.

    Claims indicate which workspaces are actively working on which tasks.
    When an agent claims work and marks it in progress, they
    claim that task within the team.

    Args:
        workspace_id: Optional. Filter to claims by a specific workspace.
        limit: Maximum number of claims to return (default 50, max 200).
        cursor: Pagination cursor from previous response for fetching next page.

    Returns:
        List of active claims with task_ref, workspace info, and claim time.
        Ordered by most recently claimed first.
        Includes has_more and next_cursor for pagination.
    """
    team_id = identity.team_id
    # Validate pagination params
    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Validate workspace_id if provided
    validated_workspace_id = None
    if workspace_id:
        try:
            validated_workspace_id = str(UUID(workspace_id.strip()))
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    # Apply cursor (claimed_at < cursor_timestamp for DESC order)
    cursor_timestamp = None
    if cursor_data and "claimed_at" in cursor_data:
        try:
            cursor_timestamp = datetime.fromisoformat(cursor_data["claimed_at"])
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid cursor timestamp: {e}")
    rows = await list_active_claim_rows(
        db_infra,
        team_id=team_id,
        workspace_id=validated_workspace_id,
        claimed_before=cursor_timestamp,
        limit=validated_limit + 1,
    )

    # Check if there are more results
    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]  # Trim to requested limit

    claims = [
        Claim(
            task_ref=row["task_ref"],
            workspace_id=str(row["workspace_id"]),
            alias=row["alias"],
            human_name=row["human_name"],
            claimed_at=row["claimed_at"].isoformat(),
            team_id=row["team_id"],
        )
        for row in rows
    ]

    # Generate next_cursor if there are more results
    next_cursor = None
    if has_more and claims:
        last_claim = claims[-1]
        next_cursor = encode_cursor({"claimed_at": last_claim.claimed_at})

    return ClaimsResponse(claims=claims, has_more=has_more, next_cursor=next_cursor)
