from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from beadhub.auth import enforce_actor_binding, validate_workspace_id
from beadhub.aweb_introspection import get_identity_from_auth, get_project_from_auth

from ..beads_sync import is_valid_alias
from ..db import DatabaseInfra, get_db_infra
from ..events import EscalationCreatedEvent, EscalationRespondedEvent, publish_event
from ..pagination import encode_cursor, validate_pagination_params
from ..presence import get_workspace_project_slug
from ..redis_client import get_redis

router = APIRouter(prefix="/v1/escalations", tags=["escalations"])

# Valid escalation status values
VALID_ESCALATION_STATUSES = frozenset({"pending", "responded", "expired"})

# Error message for invalid alias format
INVALID_ALIAS_MESSAGE = "Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars"


def _validate_workspace_id_field(v: str) -> str:
    """Pydantic validator wrapper for workspace_id."""
    try:
        return validate_workspace_id(v)
    except ValueError as e:
        raise ValueError(str(e))


def _validate_alias_field(v: str) -> str:
    """Pydantic validator wrapper for alias."""
    if not is_valid_alias(v):
        raise ValueError(INVALID_ALIAS_MESSAGE)
    return v


class CreateEscalationRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    alias: str = Field(..., min_length=1, max_length=64)
    subject: str = Field(..., min_length=1)
    situation: str = Field(..., min_length=1)
    options: Optional[List[str]] = None
    expires_in_hours: int = Field(4, gt=0)
    member_email: Optional[str] = Field(None, description="Email of team member to notify")

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id(cls, v: str) -> str:
        return _validate_workspace_id_field(v)

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v: str) -> str:
        return _validate_alias_field(v)


class EscalationSummary(BaseModel):
    escalation_id: str
    alias: str
    subject: str
    status: str
    created_at: str
    expires_at: Optional[str] = None


class CreateEscalationResponse(BaseModel):
    escalation_id: str
    status: str
    created_at: str
    expires_at: Optional[str] = None


class EscalationDetail(BaseModel):
    escalation_id: str
    workspace_id: str
    alias: str
    member_email: Optional[str] = None
    subject: str
    situation: str
    options: Optional[List[str]] = None
    status: str
    response: Optional[str] = None
    response_note: Optional[str] = None
    created_at: str
    responded_at: Optional[str] = None
    expires_at: Optional[str] = None


class ListEscalationsResponse(BaseModel):
    escalations: List[EscalationSummary]
    has_more: bool = False
    next_cursor: Optional[str] = None


class RespondEscalationRequest(BaseModel):
    response: str = Field(..., min_length=1)
    note: Optional[str] = None


class RespondEscalationResponse(BaseModel):
    escalation_id: str
    status: str
    response: str
    response_note: Optional[str] = None
    responded_at: str


@router.post("", response_model=CreateEscalationResponse)
async def create_escalation(
    request: Request,
    payload: CreateEscalationRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> CreateEscalationResponse:
    db = db_infra.get_manager("server")
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    enforce_actor_binding(identity, payload.workspace_id)

    workspace = await db.fetch_one(
        """
        SELECT workspace_id, project_id, alias
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        payload.workspace_id,
    )
    if not workspace:
        raise HTTPException(
            status_code=403,
            detail="Workspace not found or does not belong to your project",
        )
    if workspace["alias"] != payload.alias:
        raise HTTPException(
            status_code=403,
            detail="Alias does not match workspace_id",
        )

    workspace_project_id = str(workspace["project_id"])
    if project_id != workspace_project_id:
        raise HTTPException(
            status_code=403,
            detail="Workspace not found or does not belong to your project",
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=payload.expires_in_hours)

    row = await db.fetch_one(
        """
        INSERT INTO {{tables.escalations}} (
            project_id,
            workspace_id,
            alias,
            member_email,
            subject,
            situation,
            options,
            status,
            created_at,
            expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9)
        RETURNING id, status, created_at, expires_at
        """,
        project_id,
        payload.workspace_id,
        payload.alias,
        payload.member_email,
        payload.subject,
        payload.situation,
        json.dumps(payload.options) if payload.options else None,
        now,
        expires_at,
    )

    # Publish event
    project_slug = await get_workspace_project_slug(redis, payload.workspace_id)
    event = EscalationCreatedEvent(
        workspace_id=payload.workspace_id,
        escalation_id=str(row["id"]),
        alias=payload.alias,
        subject=payload.subject,
        project_slug=project_slug,
    )
    await publish_event(redis, event)

    return CreateEscalationResponse(
        escalation_id=str(row["id"]),
        status=row["status"],
        created_at=row["created_at"].isoformat(),
        expires_at=row["expires_at"].isoformat() if row["expires_at"] else None,
    )


@router.get("", response_model=ListEscalationsResponse)
async def list_escalations(
    request: Request,
    workspace_id: Optional[str] = Query(None, min_length=1),
    repo_id: Optional[str] = Query(None, min_length=36, max_length=36),
    status: Optional[str] = Query(None, max_length=20),
    alias: Optional[str] = Query(None, max_length=64),
    limit: Optional[int] = Query(None, description="Maximum items per page", ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Pagination cursor from previous response"),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListEscalationsResponse:
    """
    List escalations with cursor-based pagination.

    Filter by:
    - workspace_id: Show escalations for a specific workspace
    - project_slug: Show escalations for all workspaces in a project
    - repo_id: Show escalations for all workspaces in a repo (UUID)
    - No filter: Show all escalations (OSS mode)

    Args:
        limit: Maximum number of escalations to return (default 50, max 200).
        cursor: Pagination cursor from previous response for fetching next page.

    Returns:
        List of escalations ordered by most recently created first.
        Includes has_more and next_cursor for pagination.
    """
    db = db_infra.get_manager("server")

    # Validate pagination params
    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    project_id = await get_project_from_auth(request, db_infra)

    conditions: list[str] = []
    params: list[object] = []
    param_idx = 1

    conditions.append(f"project_id = ${param_idx}")
    params.append(UUID(project_id))
    param_idx += 1

    # Determine workspace filter
    if workspace_id:
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
            workspace_check = await db.fetch_one(
                """
                SELECT 1 FROM {{tables.workspaces}}
                WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
                """,
                UUID(validated_workspace_id),
                UUID(project_id),
            )
            if not workspace_check:
                raise HTTPException(
                    status_code=403,
                    detail="Workspace not found or does not belong to your project",
                )
            conditions.append(f"workspace_id = ${param_idx}")
            params.append(UUID(validated_workspace_id))
            param_idx += 1
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    elif repo_id:
        try:
            repo_uuid = UUID(repo_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid repo_id format: expected UUID")
        conditions.append(
            f"workspace_id IN (SELECT workspace_id FROM {{{{tables.workspaces}}}} WHERE project_id = ${param_idx} AND repo_id = ${param_idx + 1} AND deleted_at IS NULL)"
        )
        params.append(UUID(project_id))
        params.append(repo_uuid)
        param_idx += 2

    if status:
        if status not in VALID_ESCALATION_STATUSES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status: must be one of {sorted(VALID_ESCALATION_STATUSES)}",
            )
        conditions.append(f"status = ${param_idx}")
        params.append(status)
        param_idx += 1
    if alias:
        if not is_valid_alias(alias):
            raise HTTPException(status_code=422, detail=INVALID_ALIAS_MESSAGE)
        conditions.append(f"alias = ${param_idx}")
        params.append(alias)
        param_idx += 1

    # Apply cursor (created_at < cursor_timestamp for DESC order)
    if cursor_data and "created_at" in cursor_data:
        try:
            cursor_timestamp = datetime.fromisoformat(cursor_data["created_at"])
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid cursor timestamp: {e}")
        conditions.append(f"created_at < ${param_idx}")
        params.append(cursor_timestamp)
        param_idx += 1

    # Fetch limit + 1 to detect has_more
    params.append(validated_limit + 1)

    base_query = f"""
        SELECT id, alias, subject, status, created_at, expires_at
        FROM {{{{tables.escalations}}}}
        {"WHERE " + " AND ".join(conditions) if conditions else ""}
        ORDER BY created_at DESC
        LIMIT ${param_idx}
    """

    rows = await db.fetch_all(base_query, *params)

    # Check if there are more results
    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]  # Trim to requested limit

    items = [
        EscalationSummary(
            escalation_id=str(r["id"]),
            alias=r["alias"],
            subject=r["subject"],
            status=r["status"],
            created_at=r["created_at"].isoformat(),
            expires_at=r["expires_at"].isoformat() if r["expires_at"] else None,
        )
        for r in rows
    ]

    # Generate next_cursor if there are more results
    next_cursor = None
    if has_more and items:
        last_item = items[-1]
        next_cursor = encode_cursor({"created_at": last_item.created_at})

    return ListEscalationsResponse(escalations=items, has_more=has_more, next_cursor=next_cursor)


def _validate_escalation_id(escalation_id: str) -> UUID:
    """Validate escalation_id is a valid UUID. Raises 422 if not."""
    try:
        return UUID(escalation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid escalation_id: must be a UUID")


@router.get("/{escalation_id}", response_model=EscalationDetail)
async def get_escalation(
    request: Request,
    escalation_id: str = Path(..., min_length=1),
    workspace_id: Optional[str] = Query(None, min_length=1),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> EscalationDetail:
    db = db_infra.get_manager("server")
    validated_eid = _validate_escalation_id(escalation_id)

    project_id = await get_project_from_auth(request, db_infra)
    validated_workspace_id: str | None = None
    if workspace_id:
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    row = await db.fetch_one(
        """
        SELECT
            e.id,
            e.workspace_id,
            e.alias,
            e.member_email,
            e.subject,
            e.situation,
            e.options,
            e.status,
            e.response,
            e.response_note,
            e.created_at,
            e.responded_at,
            e.expires_at
        FROM {{tables.escalations}} AS e
        JOIN {{tables.workspaces}} AS w
            ON e.workspace_id = w.workspace_id
        WHERE e.id = $1 AND e.project_id = $2 AND w.deleted_at IS NULL
          AND ($3::uuid IS NULL OR e.workspace_id = $3::uuid)
        """,
        validated_eid,
        UUID(project_id),
        UUID(validated_workspace_id) if validated_workspace_id else None,
    )

    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")

    try:
        options = json.loads(row["options"]) if row["options"] else None
    except json.JSONDecodeError:
        options = None

    return EscalationDetail(
        escalation_id=str(row["id"]),
        workspace_id=str(row["workspace_id"]),
        alias=row["alias"],
        member_email=row["member_email"],
        subject=row["subject"],
        situation=row["situation"],
        options=options,
        status=row["status"],
        response=row["response"],
        response_note=row["response_note"],
        created_at=row["created_at"].isoformat(),
        responded_at=row["responded_at"].isoformat() if row["responded_at"] else None,
        expires_at=row["expires_at"].isoformat() if row["expires_at"] else None,
    )


@router.post("/{escalation_id}/respond", response_model=RespondEscalationResponse)
async def respond_escalation(
    request: Request,
    escalation_id: str = Path(..., min_length=1),
    payload: RespondEscalationRequest = ...,  # type: ignore[assignment]  # FastAPI pattern
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> RespondEscalationResponse:
    validated_eid = _validate_escalation_id(escalation_id)
    project_id = await get_project_from_auth(request, db_infra)
    db = db_infra.get_manager("server")
    now = datetime.now(timezone.utc)

    row = await db.fetch_one(
        """
        UPDATE {{tables.escalations}} AS e
        SET status = 'responded',
            response = $1,
            response_note = $2,
            responded_at = $3
        FROM {{tables.workspaces}} AS w
        WHERE e.id = $4
          AND e.workspace_id = w.workspace_id
          AND e.project_id = $5
          AND w.deleted_at IS NULL
        RETURNING e.id, e.workspace_id, e.status, e.response, e.response_note, e.responded_at
        """,
        payload.response,
        payload.note,
        now,
        validated_eid,
        UUID(project_id),
    )

    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")

    # Publish event to notify the workspace that created the escalation
    project_slug = await get_workspace_project_slug(redis, str(row["workspace_id"]))
    event = EscalationRespondedEvent(
        workspace_id=str(row["workspace_id"]),
        escalation_id=str(row["id"]),
        response=payload.response,
        project_slug=project_slug,
    )
    await publish_event(redis, event)

    return RespondEscalationResponse(
        escalation_id=str(row["id"]),
        status=row["status"],
        response=row["response"],
        response_note=row["response_note"],
        responded_at=row["responded_at"].isoformat(),
    )
