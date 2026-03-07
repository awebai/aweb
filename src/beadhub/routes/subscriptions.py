"""Bead subscription endpoints for notifications."""

from __future__ import annotations

import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, field_validator

from beadhub.auth import enforce_actor_binding, validate_workspace_id
from beadhub.aweb_introspection import get_identity_from_auth

from ..db import DatabaseInfra, get_db_infra

# Bead ID pattern: optionally namespaced "repo:bead-id" or just "bead-id"
# Each part is alphanumeric with hyphens, 1-100 chars
_BEAD_ID_PART = r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}"
_BEAD_ID_PATTERN = re.compile(rf"^({_BEAD_ID_PART}:)?{_BEAD_ID_PART}$")


router = APIRouter(prefix="/v1/subscriptions", tags=["subscriptions"])


def _validate_workspace_id_field(v: str) -> str:
    """Pydantic validator wrapper for workspace_id."""
    return validate_workspace_id(v)


async def _resolve_workspace(
    db_infra: DatabaseInfra,
    identity_project_id: str,
    workspace_id: str,
) -> str:
    """Validate workspace belongs to project and return its alias.

    Raises HTTPException(403) if workspace not found or not in project.
    """
    db = db_infra.get_manager("server")
    row = await db.fetch_one(
        """
        SELECT alias
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        uuid.UUID(workspace_id),
        uuid.UUID(identity_project_id),
    )
    if not row:
        raise HTTPException(
            status_code=403,
            detail="Workspace not found or does not belong to your project",
        )
    return row["alias"]


class SubscribeRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    bead_id: str = Field(..., min_length=1)
    repo: Optional[str] = None
    event_types: List[str] = Field(default=["status_change"])

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id(cls, v: str) -> str:
        return _validate_workspace_id_field(v)


class SubscribeResponse(BaseModel):
    subscription_id: str
    workspace_id: str
    alias: str
    bead_id: str
    repo: Optional[str] = None
    event_types: List[str]
    created_at: Optional[str] = None


class SubscriptionInfo(BaseModel):
    subscription_id: str
    workspace_id: str
    alias: str
    bead_id: str
    repo: Optional[str] = None
    event_types: List[str]
    created_at: str


class ListSubscriptionsResponse(BaseModel):
    subscriptions: List[SubscriptionInfo]
    count: int


class UnsubscribeResponse(BaseModel):
    subscription_id: str
    deleted: bool


@router.post("", response_model=SubscribeResponse)
async def subscribe(
    request: Request,
    payload: SubscribeRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> SubscribeResponse:
    """Subscribe to receive notifications when a bead changes.

    Requires an authenticated project context. Alias is derived from workspace_id.
    """
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    enforce_actor_binding(identity, payload.workspace_id)

    # Validate bead_id format
    if not _BEAD_ID_PATTERN.match(payload.bead_id):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid bead_id format: {payload.bead_id[:100]}",
        )

    # Validate event_types
    valid_events = {"status_change", "priority_change", "assignee_change", "all"}
    for event_type in payload.event_types:
        if event_type not in valid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event_type: {event_type}. Valid: {valid_events}",
            )

    alias = await _resolve_workspace(db_infra, project_id, payload.workspace_id)

    # Use upsert to handle duplicate subscriptions (idempotent)
    db = db_infra.get_manager("server")
    subscription_id = str(uuid.uuid4())
    sql = """
        INSERT INTO {{tables.subscriptions}}
            (id, project_id, workspace_id, alias, bead_id, repo, event_types)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (project_id, workspace_id, bead_id, COALESCE(repo, ''))
        DO UPDATE SET event_types = $7, alias = $4
        RETURNING id, event_types, created_at
    """
    row = await db.fetch_one(
        sql,
        uuid.UUID(subscription_id),
        uuid.UUID(project_id),
        uuid.UUID(payload.workspace_id),
        alias,
        payload.bead_id,
        payload.repo,
        payload.event_types,
    )

    return SubscribeResponse(
        subscription_id=str(row["id"]),
        workspace_id=payload.workspace_id,
        alias=alias,
        bead_id=payload.bead_id,
        repo=payload.repo,
        event_types=list(row["event_types"]),
        created_at=row["created_at"].isoformat() if row.get("created_at") else None,
    )


@router.get("", response_model=ListSubscriptionsResponse)
async def list_subscriptions(
    request: Request,
    workspace_id: str = Query(..., min_length=1),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListSubscriptionsResponse:
    """List all subscriptions for a workspace.

    Requires an authenticated project context.
    """
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    try:
        workspace_id = validate_workspace_id(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    enforce_actor_binding(identity, workspace_id)

    alias = await _resolve_workspace(db_infra, project_id, workspace_id)

    db = db_infra.get_manager("server")
    sql = """
        SELECT id, workspace_id, bead_id, repo, event_types, created_at
        FROM {{tables.subscriptions}}
        WHERE project_id = $1 AND workspace_id = $2
        ORDER BY created_at DESC
    """
    rows = await db.fetch_all(sql, uuid.UUID(project_id), uuid.UUID(workspace_id))

    subscriptions = [
        SubscriptionInfo(
            subscription_id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            alias=alias,
            bead_id=row["bead_id"],
            repo=row["repo"],
            event_types=list(row["event_types"]),
            created_at=row["created_at"].isoformat(),
        )
        for row in rows
    ]

    return ListSubscriptionsResponse(subscriptions=subscriptions, count=len(subscriptions))


@router.delete("/{subscription_id}", response_model=UnsubscribeResponse)
async def unsubscribe(
    request: Request,
    subscription_id: str = Path(...),
    workspace_id: str = Query(..., min_length=1),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> UnsubscribeResponse:
    """Unsubscribe from a bead.

    Requires an authenticated project context.
    """
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    try:
        workspace_id = validate_workspace_id(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    enforce_actor_binding(identity, workspace_id)

    try:
        sub_uuid = uuid.UUID(subscription_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subscription_id format")

    await _resolve_workspace(db_infra, project_id, workspace_id)

    db = db_infra.get_manager("server")
    sql = """
        DELETE FROM {{tables.subscriptions}}
        WHERE id = $1 AND project_id = $2 AND workspace_id = $3
        RETURNING id
    """
    row = await db.fetch_one(
        sql,
        sub_uuid,
        uuid.UUID(project_id),
        uuid.UUID(workspace_id),
    )

    if not row:
        raise HTTPException(status_code=404, detail="Subscription not found")

    return UnsubscribeResponse(subscription_id=subscription_id, deleted=True)


async def get_subscribers_for_bead(
    db_infra: DatabaseInfra,
    project_id: str,
    bead_id: str,
    event_type: str,
    repo: Optional[str] = None,
) -> List[dict]:
    """Get all agents subscribed to a bead for a specific event type.

    Used by the sync process to send notifications.
    Filters by project_id for tenant isolation, then matches by bead_id
    and optionally by repo for more precise matching.

    JOINs the workspaces table to return the current alias (subscriptions
    may store a stale alias from when the subscription was created).
    """
    db = db_infra.get_manager("server")
    project_uuid = uuid.UUID(project_id)

    if repo:
        sql = """
            SELECT s.workspace_id, w.alias, s.repo
            FROM {{tables.subscriptions}} s
            JOIN {{tables.workspaces}} w
              ON w.workspace_id = s.workspace_id
             AND w.project_id = s.project_id
             AND w.deleted_at IS NULL
            WHERE s.project_id = $1
              AND s.bead_id = $2
              AND s.repo = $3
              AND ($4 = ANY(s.event_types) OR 'all' = ANY(s.event_types))
        """
        rows = await db.fetch_all(sql, project_uuid, bead_id, repo, event_type)
    else:
        sql = """
            SELECT s.workspace_id, w.alias, s.repo
            FROM {{tables.subscriptions}} s
            JOIN {{tables.workspaces}} w
              ON w.workspace_id = s.workspace_id
             AND w.project_id = s.project_id
             AND w.deleted_at IS NULL
            WHERE s.project_id = $1
              AND s.bead_id = $2
              AND ($3 = ANY(s.event_types) OR 'all' = ANY(s.event_types))
        """
        rows = await db.fetch_all(sql, project_uuid, bead_id, event_type)

    return [
        {
            "workspace_id": str(row["workspace_id"]),
            "alias": row["alias"],
            "repo": row["repo"],
        }
        for row in rows
    ]
