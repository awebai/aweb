"""Workspace discovery and registration endpoints."""

from __future__ import annotations

import logging
import uuid as uuid_module
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from awid.team_ids import team_slug
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from redis.asyncio import Redis

from aweb.team_auth_deps import get_team_identity

from ...config import get_settings
from ...db import DatabaseInfra, get_db_infra
from ...input_validation import is_valid_alias, is_valid_canonical_origin, is_valid_human_name
from awid.pagination import encode_cursor, validate_pagination_params
from ...presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences,
    list_agent_presences_by_workspace_ids,
    update_agent_presence,
)
from ...redis_client import get_redis
from ...role_name_compat import normalize_optional_role_name, resolve_role_name_aliases
from ...lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from ..roles import (
    ROLE_MAX_LENGTH,
)

logger = logging.getLogger(__name__)

TEAM_STATUS_DEFAULT_LIMIT = 15
TEAM_STATUS_MAX_LIMIT = 200
TEAM_STATUS_CANDIDATE_MULTIPLIER = 5
TEAM_STATUS_CANDIDATE_MAX = 500

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])


# ---------------------------------------------------------------------------
# Heartbeat models and endpoint
# IMPORTANT: This endpoint MUST be defined BEFORE /{workspace_id} to prevent
# "heartbeat" from matching as a workspace_id parameter.
# ---------------------------------------------------------------------------


class WorkspaceHeartbeatRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    alias: str = Field(..., min_length=1, max_length=64)

    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    role_name: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Canonical selector name for the workspace role",
    )
    hostname: Optional[str] = Field(None, max_length=255)
    workspace_path: Optional[str] = Field(None, max_length=1024)
    human_name: Optional[str] = Field(None, max_length=64)

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id_field(cls, v: str) -> str:
        try:
            UUID(v)
        except ValueError:
            raise ValueError("workspace_id must be a valid UUID")
        return v

    @field_validator("alias")
    @classmethod
    def validate_alias_field(cls, v: str) -> str:
        if not is_valid_alias(v):
            raise ValueError(
                "Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars"
            )
        return v

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, v: Optional[str]) -> Optional[str]:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class WorkspaceHeartbeatResponse(BaseModel):
    ok: bool = True
    workspace_id: str


@router.post("/heartbeat", response_model=WorkspaceHeartbeatResponse)
async def heartbeat(
    payload: WorkspaceHeartbeatRequest,
    request: Request,
    redis: Redis = Depends(get_redis),
    db: DatabaseInfra = Depends(get_db_infra),
) -> WorkspaceHeartbeatResponse:
    """
    Refresh workspace presence, enforcing "presence is a cache of SQL".

    Order of operations:
    1) Ensure workspace exists (SQL)
    2) Update presence (Redis)

    Note: If Redis is unavailable, SQL is still authoritative; presence updates
    are best-effort and will converge once the client retries.
    """
    identity = await get_team_identity(request, db)
    team_id = identity.team_id
    settings = get_settings()

    aweb_db = db.get_manager("aweb")

    # Pre-check: workspace must exist and belong to this team.
    existing = await aweb_db.fetch_one(
        """
        SELECT workspace_id, team_id, alias, repo_id, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        UUID(payload.workspace_id),
    )
    if existing:
        if existing.get("deleted_at") is not None:
            raise HTTPException(
                status_code=410,
                detail="Workspace was deleted. Run 'aw connect' to re-register.",
            )
        if existing.get("team_id") != team_id:
            raise HTTPException(
                status_code=400,
                detail=f"Workspace {payload.workspace_id} does not belong to this team.",
            )
        if existing.get("alias") and existing["alias"] != payload.alias:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Alias mismatch for workspace {payload.workspace_id} "
                    f"(expected '{existing['alias']}', got '{payload.alias}'). "
                    "Run 'aw connect' to re-register."
                ),
            )
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace {payload.workspace_id} not found. Run 'aw connect' to register.",
        )

    # Update mutable workspace fields.
    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET role = COALESCE($2, role),
            hostname = COALESCE($3, hostname),
            workspace_path = COALESCE($4, workspace_path),
            human_name = COALESCE(NULLIF($5, ''), human_name),
            last_seen_at = NOW(),
            updated_at = NOW()
        WHERE workspace_id = $1
        """,
        UUID(payload.workspace_id),
        payload.role,
        payload.hostname,
        payload.workspace_path,
        payload.human_name or "",
    )

    repo_row = None
    if existing.get("repo_id"):
        repo_row = await aweb_db.fetch_one(
            """
            SELECT canonical_origin
            FROM {{tables.repos}}
            WHERE id = $1 AND deleted_at IS NULL
            """,
            existing["repo_id"],
        )

    try:
        await update_agent_presence(
            redis,
            workspace_id=payload.workspace_id,
            alias=payload.alias,
            human_name=payload.human_name or "",
            team_id=team_id,
            repo_id=str(existing["repo_id"]) if existing.get("repo_id") else None,
            program="aw",
            model=None,
            canonical_origin=repo_row["canonical_origin"] if repo_row else None,
            role=payload.role,
            ttl_seconds=settings.presence_ttl_seconds,
        )
    except Exception as e:
        logger.warning(
            "Heartbeat SQL upsert succeeded but presence update failed",
            extra={
                "workspace_id": payload.workspace_id,
                "team_id": team_id,
                "error": str(e),
            },
        )

    return WorkspaceHeartbeatResponse(ok=True, workspace_id=payload.workspace_id)


# ---------------------------------------------------------------------------
# Update workspace (PATCH)
# ---------------------------------------------------------------------------


class UpdateWorkspaceRequest(BaseModel):
    """Request body for PATCH /v1/workspaces/{workspace_id}."""

    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    role_name: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Canonical selector name for the workspace role",
    )
    hostname: Optional[str] = Field(None, max_length=255)
    workspace_path: Optional[str] = Field(None, max_length=4096)
    human_name: Optional[str] = Field(None, max_length=64)
    focus_task_ref: Optional[str] = Field(None, max_length=255)

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, v: Optional[str]) -> Optional[str]:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self

    @field_validator("human_name")
    @classmethod
    def validate_human_name_field(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not is_valid_human_name(v):
            raise ValueError("Invalid human_name format")
        return v


class UpdateWorkspaceResponse(BaseModel):
    workspace_id: str
    alias: str
    updated: bool


@router.patch("/{workspace_id}", response_model=UpdateWorkspaceResponse)
async def update_workspace(
    request: Request,
    workspace_id: str = Path(..., description="Workspace ID to update"),
    payload: UpdateWorkspaceRequest = None,
    db: DatabaseInfra = Depends(get_db_infra),
) -> UpdateWorkspaceResponse:
    """Update mutable workspace fields."""
    try:
        validated_id = str(UUID(workspace_id))
    except ValueError:
        raise HTTPException(status_code=422, detail="workspace_id must be a valid UUID")

    identity = await get_team_identity(request, db)
    team_id = identity.team_id

    aweb_db = db.get_manager("aweb")

    existing = await aweb_db.fetch_one(
        """
        SELECT workspace_id, alias, team_id, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND team_id = $2
        """,
        UUID(validated_id),
        team_id,
    )

    if not existing:
        raise HTTPException(status_code=404, detail=f"Workspace {workspace_id} not found")

    if existing["deleted_at"] is not None:
        raise HTTPException(status_code=410, detail=f"Workspace {workspace_id} is deleted")

    set_clauses = []
    params: list = [UUID(validated_id)]
    idx = 2

    if payload.role is not None:
        set_clauses.append(f"role = ${idx}")
        params.append(payload.role)
        idx += 1

    if payload.hostname is not None:
        set_clauses.append(f"hostname = ${idx}")
        params.append(payload.hostname)
        idx += 1

    if payload.workspace_path is not None:
        set_clauses.append(f"workspace_path = ${idx}")
        params.append(payload.workspace_path)
        idx += 1

    if payload.human_name is not None:
        set_clauses.append(f"human_name = ${idx}")
        params.append(payload.human_name)
        idx += 1

    if payload.focus_task_ref is not None:
        set_clauses.append(f"focus_task_ref = ${idx}")
        params.append(payload.focus_task_ref)
        idx += 1
        set_clauses.append("focus_updated_at = NOW()")

    updated = False
    if set_clauses:
        set_clauses.append("updated_at = NOW()")
        await aweb_db.execute(
            f"""
            UPDATE {{{{tables.workspaces}}}}
            SET {', '.join(set_clauses)}
            WHERE workspace_id = $1
            """,
            *params,
        )
        updated = True

    return UpdateWorkspaceResponse(
        workspace_id=validated_id,
        alias=existing["alias"],
        updated=updated,
    )


# ---------------------------------------------------------------------------
# Delete workspace
# ---------------------------------------------------------------------------


class DeleteWorkspaceResponse(BaseModel):
    """Response for DELETE /v1/workspaces/{workspace_id} endpoint."""

    workspace_id: str
    alias: str
    deleted_at: str
    identity_deleted: bool


def _workspace_delete_conflict_detail(
    *,
    code: str,
    workspace_id: str,
    identity_id,
    lifetime: str | None,
    recommended_next_step: str,
):
    return {
        "code": code,
        "workspace_id": workspace_id,
        "identity_id": str(identity_id) if identity_id is not None else None,
        "lifetime": lifetime or "unknown",
        "recommended_next_step": recommended_next_step,
    }


@router.delete("/{workspace_id}", response_model=DeleteWorkspaceResponse)
async def delete_workspace(
    workspace_id: str = Path(..., description="Workspace ID to delete"),
    request: Request = None,
    db: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> DeleteWorkspaceResponse:
    """Soft-delete a stale ephemeral workspace and its bound identity."""
    try:
        validated_id = str(UUID(workspace_id))
    except ValueError:
        raise HTTPException(status_code=422, detail="workspace_id must be a valid UUID")

    identity = await get_team_identity(request, db)
    team_id = identity.team_id

    aweb_db = db.get_manager("aweb")

    existing = await aweb_db.fetch_one(
        """
        SELECT
            w.workspace_id,
            w.agent_id,
            w.alias,
            w.team_id,
            w.deleted_at,
            w.last_seen_at,
            a.lifetime AS agent_lifetime
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.agents}} a
          ON a.agent_id = w.agent_id
         AND a.team_id = w.team_id
         AND a.deleted_at IS NULL
        WHERE w.workspace_id = $1 AND w.team_id = $2
        """,
        UUID(validated_id),
        team_id,
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace {workspace_id} not found",
        )

    if existing["deleted_at"] is not None:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace {workspace_id} is already deleted",
        )

    agent_lifetime = str(existing.get("agent_lifetime") or "").strip()
    if not agent_lifetime:
        raise HTTPException(
            status_code=409,
            detail=_workspace_delete_conflict_detail(
                code="unknown_lifetime_no_cleanup",
                workspace_id=validated_id,
                identity_id=existing.get("agent_id"),
                lifetime=None,
                recommended_next_step="Inspect the workspace identity before attempting lifecycle cleanup.",
            ),
        )
    if agent_lifetime == "persistent":
        raise HTTPException(
            status_code=409,
            detail=_workspace_delete_conflict_detail(
                code="persistent_identity_not_cleanup_eligible",
                workspace_id=validated_id,
                identity_id=existing.get("agent_id"),
                lifetime=agent_lifetime,
                recommended_next_step="Persistent identities outlive workspace paths; use reconnect/rebind diagnostics or an explicit archive/replace flow.",
            ),
        )
    if agent_lifetime != "ephemeral":
        raise HTTPException(
            status_code=409,
            detail=_workspace_delete_conflict_detail(
                code="unknown_lifetime_no_cleanup",
                workspace_id=validated_id,
                identity_id=existing.get("agent_id"),
                lifetime=agent_lifetime,
                recommended_next_step="Inspect the workspace identity lifetime before attempting lifecycle cleanup.",
            ),
        )

    last_seen_at = existing.get("last_seen_at")
    stale_cutoff = datetime.now(timezone.utc) - timedelta(seconds=DEFAULT_PRESENCE_TTL_SECONDS)
    if last_seen_at is not None and last_seen_at > stale_cutoff:
        raise HTTPException(
            status_code=409,
            detail=_workspace_delete_conflict_detail(
                code="ephemeral_workspace_still_active",
                workspace_id=validated_id,
                identity_id=existing.get("agent_id"),
                lifetime=agent_lifetime,
                recommended_next_step="Wait until presence is stale before deleting an ephemeral workspace.",
            ),
        )

    deleted_at = datetime.now(timezone.utc)
    cascade_result = await apply_lifecycle_cascade(
        aweb_db,
        redis,
        LifecycleCascadeRequest(
            operation="delete_ephemeral_workspace",
            actor=LifecycleActor(
                actor_id=getattr(identity, "agent_id", None),
                actor_type="agent",
                authority="team_identity",
            ),
            team_id=team_id,
            target_agent_id=(
                str(existing["agent_id"]) if existing.get("agent_id") is not None else None
            ),
            target_workspace_ids=(validated_id,),
            workspace_scope="explicit",
            require_lifetime="ephemeral",
            stale_before=stale_cutoff,
            deleted_at=deleted_at,
            mark_ephemeral_agent_deleted=True,
        ),
    )
    if cascade_result.errors:
        error = cascade_result.errors[0]
        raise HTTPException(
            status_code=409,
            detail=_workspace_delete_conflict_detail(
                code=error.code,
                workspace_id=validated_id,
                identity_id=existing.get("agent_id"),
                lifetime=agent_lifetime,
                recommended_next_step=error.message,
            ),
        )
    if cascade_result.post_commit_status == "failed":
        logger.warning(
            "Workspace delete SQL cleanup succeeded but post-commit cleanup failed",
            extra={
                "workspace_id": validated_id,
                "team_id": team_id,
                "failed_event_intents": len(cascade_result.failed_event_intents),
                "presence_cleanup_status": cascade_result.presence_cleanup_status,
            },
        )

    return DeleteWorkspaceResponse(
        workspace_id=validated_id,
        alias=existing["alias"],
        deleted_at=deleted_at.isoformat(),
        identity_deleted=cascade_result.identity_deleted,
    )


# ---------------------------------------------------------------------------
# Listing models and helpers
# ---------------------------------------------------------------------------


class Claim(BaseModel):
    """A task claim - represents a workspace working on a task.

    The apex (apex_task_ref/apex_title/apex_type) is stored on the claim to avoid
    recursive read-time computation. Titles/types are joined from native tasks.
    """

    task_ref: str
    title: Optional[str] = None
    claimed_at: str
    apex_task_ref: Optional[str] = None
    apex_title: Optional[str] = None
    apex_type: Optional[str] = None


class WorkspaceInfo(BaseModel):
    """Workspace information from database with optional presence data."""

    workspace_id: str
    alias: str
    agent_lifetime: Optional[str] = None
    human_name: Optional[str] = None
    context_kind: Optional[str] = None
    team_id: Optional[str] = None
    program: Optional[str] = None
    model: Optional[str] = None
    repo: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    apex_task_ref: Optional[str] = None
    apex_title: Optional[str] = None
    apex_type: Optional[str] = None
    focus_task_ref: Optional[str] = None
    focus_task_title: Optional[str] = None
    focus_task_type: Optional[str] = None
    focus_updated_at: Optional[str] = None
    status: str  # "active", "idle", "offline"
    last_seen: Optional[str] = None
    deleted_at: Optional[str] = None
    claims: List[Claim] = []

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class ListWorkspacesResponse(BaseModel):
    """Response for listing workspaces."""

    workspaces: List[WorkspaceInfo]
    has_more: bool = False
    next_cursor: Optional[str] = None


def _get_team_slug(team_id: str) -> str:
    return team_slug(team_id)


def _title_join(
    alias: str,
    team_id_col: str,
    task_ref_col: str,
    *,
    include_type: bool = False,
    guard_col: str | None = None,
) -> str:
    """Lateral join resolving title (+ optional type) from tasks."""
    select_expr = "t.title, t.task_type AS issue_type" if include_type else "t.title AS title"

    guard = f"\n                  AND {guard_col} IS NOT NULL" if guard_col else ""

    # task_ref = slug || '-' || task_ref_suffix, where slug is the team-name
    # prefix from the colon-form team_id.
    return f"""
        LEFT JOIN LATERAL (
            SELECT {select_expr}
            FROM aweb.tasks t
            WHERE t.team_id = {team_id_col}
              AND split_part({team_id_col}, '/', -1) || '-' || t.task_ref_suffix = {task_ref_col}
              AND t.deleted_at IS NULL{guard}
            LIMIT 1
        ) {alias} ON true"""


def _build_workspace_claims_query(placeholders: str) -> str:
    claim_join = _title_join("claim_info", "c.team_id", "c.task_ref")
    apex_join = _title_join(
        "apex_info",
        "c.team_id",
        "c.apex_task_ref",
        include_type=True,
        guard_col="c.apex_task_ref",
    )
    return f"""
        SELECT
            c.workspace_id,
            c.task_ref AS task_ref,
            c.claimed_at,
            c.apex_task_ref,
            claim_info.title AS claim_title,
            apex_info.title AS apex_title,
            apex_info.issue_type AS apex_type
        FROM {{{{tables.task_claims}}}} c
        {claim_join}
        {apex_join}
        WHERE c.workspace_id IN ({placeholders})
        ORDER BY c.workspace_id, c.claimed_at DESC
    """


def _to_iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.isoformat()


def _timestamp(value: Optional[datetime] | Optional[str]) -> float:
    if not value:
        return 0.0
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


_TEAM_FOCUS_JOIN = _title_join(
    "focus_issue",
    "w.team_id",
    "w.focus_task_ref",
    include_type=True,
    guard_col="w.focus_task_ref",
)

_TEAM_PARTICIPANT_WORKSPACE_SELECT = f"""
        SELECT
            w.workspace_id,
            w.alias,
            w.human_name,
            CASE
                WHEN w.workspace_type = 'agent' THEN 'repo_worktree'::TEXT
                ELSE w.workspace_type
            END AS context_kind,
            w.team_id,
            w.role,
            a.lifetime AS agent_lifetime,
            w.hostname,
            w.workspace_path,
            w.last_seen_at,
            w.focus_task_ref,
            w.focus_updated_at,
            focus_issue.title AS focus_task_title,
            focus_issue.issue_type AS focus_task_type,
            r.canonical_origin AS repo,
            COALESCE(cs.claim_count, 0) AS claim_count,
            cs.last_claimed_at,
            w.updated_at
        FROM {{{{tables.workspaces}}}} w
        LEFT JOIN {{{{tables.agents}}}} a
          ON a.agent_id = w.agent_id
         AND a.team_id = w.team_id
         AND a.deleted_at IS NULL
        LEFT JOIN {{{{tables.repos}}}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        LEFT JOIN claim_stats cs ON cs.workspace_id = w.workspace_id
        {_TEAM_FOCUS_JOIN}
"""


async def _fetch_extra_team_workspace(
    aweb_db,
    workspace_id: str,
    team_id: str,
    *,
    human_name: str | None,
    repo: str | None,
):
    """Fetch a single workspace by ID for the always_include_workspace_id guarantee."""
    params: list = [uuid_module.UUID(workspace_id), team_id]

    query = f"""
        WITH claim_stats AS (
            SELECT workspace_id,
                   COUNT(*) AS claim_count,
                   MAX(claimed_at) AS last_claimed_at
            FROM {{{{tables.task_claims}}}}
            WHERE team_id = $2
            GROUP BY workspace_id
        )
        SELECT *
        FROM (
            {_TEAM_PARTICIPANT_WORKSPACE_SELECT}
            WHERE w.deleted_at IS NULL
        ) participants
        WHERE workspace_id = $1 AND team_id = $2
    """

    if human_name:
        query += f" AND human_name = ${len(params) + 1}"
        params.append(human_name)

    if repo:
        query += f" AND repo = ${len(params) + 1}"
        params.append(repo)

    return await aweb_db.fetch_one(query, *params)


def _row_to_workspace_info(
    row,
    presence: dict | None,
    workspace_claims: list[Claim],
    *,
    include_presence: bool,
) -> WorkspaceInfo:
    workspace_id = str(row["workspace_id"])

    # Extract apex from first claim (most recent by claimed_at)
    first_apex_id = workspace_claims[0].apex_task_ref if workspace_claims else None
    first_apex_title = workspace_claims[0].apex_title if workspace_claims else None
    first_apex_type = workspace_claims[0].apex_type if workspace_claims else None

    role = row["role"]
    status = "offline"
    last_seen = _to_iso(row["last_seen_at"])
    program = None
    model = None

    if include_presence and presence:
        program = presence.get("program")
        model = presence.get("model")
        role = presence.get("role") or role
        status = presence.get("status") or "active"
        last_seen = presence.get("last_seen") or last_seen

    return WorkspaceInfo(
        workspace_id=workspace_id,
        alias=row["alias"],
        agent_lifetime=row.get("agent_lifetime"),
        human_name=row["human_name"],
        context_kind=row.get("context_kind"),
        team_id=row["team_id"],
        program=program,
        model=model,
        repo=row["repo"],
        role=role,
        role_name=role,
        hostname=row["hostname"],
        workspace_path=row["workspace_path"],
        apex_task_ref=first_apex_id,
        apex_title=first_apex_title,
        apex_type=first_apex_type,
        focus_task_ref=row["focus_task_ref"],
        focus_task_title=row["focus_task_title"],
        focus_task_type=row["focus_task_type"],
        focus_updated_at=_to_iso(row["focus_updated_at"]),
        status=status,
        last_seen=last_seen,
        deleted_at=_to_iso(row.get("deleted_at")),
        claims=workspace_claims,
    )


async def _fetch_presence_map(redis: Redis, workspace_id_strings: list[str]) -> Dict[str, dict]:
    presences = await list_agent_presences_by_workspace_ids(redis, workspace_id_strings)
    return {str(p["workspace_id"]): p for p in presences if p.get("workspace_id")}


async def _fetch_claims_map(aweb_db, workspace_ids: list) -> Dict[str, List[Claim]]:
    if not workspace_ids:
        return {}
    placeholders = ", ".join(f"${i}" for i in range(1, len(workspace_ids) + 1))
    claim_rows = await aweb_db.fetch_all(
        _build_workspace_claims_query(placeholders),
        *workspace_ids,
    )
    claims_map: Dict[str, List[Claim]] = {}
    for cr in claim_rows:
        ws_id = str(cr["workspace_id"])
        claim = Claim(
            task_ref=cr["task_ref"],
            title=cr["claim_title"],
            claimed_at=cr["claimed_at"].isoformat() if cr["claimed_at"] else "",
            apex_task_ref=cr["apex_task_ref"],
            apex_title=cr["apex_title"],
            apex_type=cr["apex_type"],
        )
        if ws_id not in claims_map:
            claims_map[ws_id] = []
        claims_map[ws_id].append(claim)
    return claims_map


# ---------------------------------------------------------------------------
# List workspaces
# ---------------------------------------------------------------------------


@router.get("", response_model=ListWorkspacesResponse)
async def list_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    repo: Optional[str] = Query(
        None, description="Filter by repo canonical origin", max_length=255
    ),
    alias: Optional[str] = Query(None, description="Filter by workspace alias", max_length=64),
    hostname: Optional[str] = Query(None, description="Filter by machine hostname", max_length=255),
    include_deleted: bool = Query(False, description="Include soft-deleted workspaces"),
    include_claims: bool = Query(False, description="Include active task claims"),
    include_presence: bool = Query(True, description="Include Redis presence data"),
    limit: Optional[int] = Query(None, description="Maximum items per page", ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Pagination cursor from previous response"),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> ListWorkspacesResponse:
    """
    List all registered workspaces from database with cursor-based pagination.

    Returns workspace information with optional presence/claim enrichment.
    Workspaces without active presence show status='offline'.
    Deleted workspaces are excluded by default (use include_deleted=true to show).

    Args:
        limit: Maximum number of workspaces to return (default 50, max 200).
        cursor: Pagination cursor from previous response for fetching next page.

    Returns:
        List of workspaces ordered by most recently updated first.
        Includes has_more and next_cursor for pagination.

    Use /v1/workspaces/online for only currently active workspaces.
    """
    identity = await get_team_identity(request, db_infra)
    team_id = identity.team_id

    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    aweb_db = db_infra.get_manager("aweb")

    query = (
        """
        SELECT
            w.workspace_id,
            w.alias,
            w.human_name,
            w.team_id,
            w.role,
            a.lifetime AS agent_lifetime,
            w.hostname,
            w.workspace_path,
            w.last_seen_at,
            w.updated_at,
            w.deleted_at,
            w.focus_task_ref,
            w.focus_updated_at,
            focus_issue.title AS focus_task_title,
            focus_issue.issue_type AS focus_task_type,
            r.canonical_origin as repo
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.agents}} a
          ON a.agent_id = w.agent_id
         AND a.team_id = w.team_id
         AND a.deleted_at IS NULL
        LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        """
        + _title_join(
            "focus_issue",
            "w.team_id",
            "w.focus_task_ref",
            include_type=True,
            guard_col="w.focus_task_ref",
        )
        + """
        WHERE 1=1
    """
    )
    params: list = []
    param_idx = 1

    query += f" AND w.team_id = ${param_idx}"
    params.append(team_id)
    param_idx += 1

    if human_name:
        query += f" AND w.human_name = ${param_idx}"
        params.append(human_name)
        param_idx += 1

    if repo:
        if not is_valid_canonical_origin(repo):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid repo format: {repo[:50]}",
            )
        query += f" AND r.canonical_origin = ${param_idx}"
        params.append(repo)
        param_idx += 1

    if alias:
        if not is_valid_alias(alias):
            raise HTTPException(
                status_code=422,
                detail="Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars",
            )
        query += f" AND w.alias = ${param_idx}"
        params.append(alias)
        param_idx += 1

    if hostname:
        if "\x00" in hostname or any(ord(c) < 32 for c in hostname):
            raise HTTPException(
                status_code=422,
                detail="Invalid hostname: contains null bytes or control characters",
            )
        query += f" AND w.hostname = ${param_idx}"
        params.append(hostname)
        param_idx += 1

    if not include_deleted:
        query += " AND w.deleted_at IS NULL"

    if cursor_data and "updated_at" in cursor_data:
        try:
            cursor_timestamp = datetime.fromisoformat(cursor_data["updated_at"])
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid cursor timestamp: {e}")
        query += f" AND w.updated_at < ${param_idx}"
        params.append(cursor_timestamp)
        param_idx += 1

    query += " ORDER BY w.updated_at DESC"

    query += f" LIMIT ${param_idx}"
    params.append(validated_limit + 1)
    param_idx += 1

    rows = await aweb_db.fetch_all(query, *params)

    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]

    workspace_ids = [row["workspace_id"] for row in rows]
    workspace_id_strings = [str(ws_id) for ws_id in workspace_ids]

    presence_map: Dict[str, dict] = {}
    if include_presence and workspace_id_strings:
        presence_map = await _fetch_presence_map(redis, workspace_id_strings)

    claims_map: Dict[str, List[Claim]] = {}
    if include_claims and workspace_ids:
        claims_map = await _fetch_claims_map(aweb_db, workspace_ids)

    workspaces: List[WorkspaceInfo] = []
    for row in rows:
        workspace_claims = claims_map.get(str(row["workspace_id"]), []) if include_claims else []
        workspaces.append(
            _row_to_workspace_info(
                row,
                presence_map.get(str(row["workspace_id"])),
                workspace_claims,
                include_presence=include_presence,
            )
        )

    next_cursor = None
    if has_more and rows:
        last_row = rows[-1]
        next_cursor = encode_cursor({"updated_at": last_row["updated_at"].isoformat()})

    return ListWorkspacesResponse(workspaces=workspaces, has_more=has_more, next_cursor=next_cursor)


# ---------------------------------------------------------------------------
# Team view (prioritized, bounded)
# ---------------------------------------------------------------------------


@router.get("/team", response_model=ListWorkspacesResponse)
async def list_team_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    repo: Optional[str] = Query(
        None, description="Filter by repo canonical origin", max_length=255
    ),
    include_claims: bool = Query(True, description="Include active task claims"),
    include_presence: bool = Query(True, description="Include Redis presence data"),
    only_with_claims: bool = Query(True, description="Only return workspaces with active claims"),
    always_include_workspace_id: Optional[str] = Query(
        None,
        description="Ensure a workspace is included even if filtered out",
    ),
    limit: int = Query(
        TEAM_STATUS_DEFAULT_LIMIT,
        ge=1,
        le=TEAM_STATUS_MAX_LIMIT,
        description="Maximum workspaces to return",
    ),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> ListWorkspacesResponse:
    """
    List a bounded team-status view of workspaces for coordination.

    This endpoint is optimized for CLI usage and always returns a limited,
    prioritized set of workspaces.
    """
    identity = await get_team_identity(request, db_infra)
    team_id = identity.team_id

    aweb_db = db_infra.get_manager("aweb")

    params: list = [team_id]
    param_idx = 2
    claim_stats_where = "WHERE team_id = $1"

    query = f"""
        WITH claim_stats AS (
            SELECT workspace_id,
                   COUNT(*) AS claim_count,
                   MAX(claimed_at) AS last_claimed_at
            FROM {{{{tables.task_claims}}}}
            {claim_stats_where}
            GROUP BY workspace_id
        ),
        participants AS (
            {_TEAM_PARTICIPANT_WORKSPACE_SELECT}
            WHERE w.deleted_at IS NULL
        )
        SELECT *
        FROM participants
        WHERE 1=1
    """

    query += " AND team_id = $1"

    if human_name:
        query += f" AND human_name = ${param_idx}"
        params.append(human_name)
        param_idx += 1

    if repo:
        if not is_valid_canonical_origin(repo):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid repo format: {repo[:50]}",
            )
        query += f" AND repo = ${param_idx}"
        params.append(repo)
        param_idx += 1

    if only_with_claims:
        query += " AND claim_count > 0"

    candidate_limit = limit
    if include_presence:
        candidate_limit = min(
            limit * TEAM_STATUS_CANDIDATE_MULTIPLIER,
            TEAM_STATUS_CANDIDATE_MAX,
        )

    query += """
        ORDER BY
            (claim_count > 0) DESC,
            last_seen_at DESC NULLS LAST,
            last_claimed_at DESC NULLS LAST,
            alias ASC
    """
    query += f" LIMIT ${param_idx}"
    params.append(candidate_limit)

    rows = await aweb_db.fetch_all(query, *params)

    if always_include_workspace_id:
        try:
            validated_id = str(UUID(always_include_workspace_id))
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        if validated_id not in {str(row["workspace_id"]) for row in rows}:
            extra_row = await _fetch_extra_team_workspace(
                aweb_db,
                validated_id,
                team_id,
                human_name=human_name,
                repo=repo,
            )
            if extra_row:
                rows.append(extra_row)

    workspace_ids = [row["workspace_id"] for row in rows]
    workspace_id_strings = [str(ws_id) for ws_id in workspace_ids]

    presence_map: Dict[str, dict] = {}
    if include_presence and workspace_id_strings:
        presence_map = await _fetch_presence_map(redis, workspace_id_strings)

    claims_map: Dict[str, List[Claim]] = {}
    if include_claims and workspace_ids:
        claims_map = await _fetch_claims_map(aweb_db, workspace_ids)

    entries: List[tuple[WorkspaceInfo, int, float, float, int, int]] = []
    for row in rows:
        workspace_id = str(row["workspace_id"])
        presence = presence_map.get(workspace_id) if include_presence else None
        workspace_claims = claims_map.get(workspace_id, []) if include_claims else []

        workspace_info = _row_to_workspace_info(
            row,
            presence,
            workspace_claims,
            include_presence=include_presence,
        )

        claim_count = int(row["claim_count"] or 0)
        entries.append(
            (
                workspace_info,
                1 if claim_count > 0 else 0,
                _timestamp(workspace_info.last_seen),
                _timestamp(row["last_claimed_at"]),
                1 if presence is not None else 0,
                claim_count,
            )
        )

    entries.sort(
        key=lambda item: (
            -item[1],
            -item[4],
            -item[2],
            -item[3],
            item[0].alias,
        )
    )

    workspaces = [entry[0] for entry in entries][:limit]

    return ListWorkspacesResponse(workspaces=workspaces, has_more=False)


# ---------------------------------------------------------------------------
# Online workspaces (presence-only view)
# ---------------------------------------------------------------------------


@router.get("/online", response_model=ListWorkspacesResponse)
async def list_online_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListWorkspacesResponse:
    """
    List only currently online workspaces (active presence in Redis).

    This is a filtered view showing workspaces with recent activity.
    Presence expires after ~5 minutes of inactivity.

    For all registered workspaces (including offline), use GET /v1/workspaces.
    """
    identity = await get_team_identity(request, db_infra)
    team_id = identity.team_id

    presences = await list_agent_presences(redis)

    workspaces: List[WorkspaceInfo] = []
    for presence in presences:
        workspace_id = presence.get("workspace_id")
        alias = presence.get("alias")
        if not workspace_id or not alias:
            continue

        if presence.get("team_id") != team_id:
            continue

        if human_name and presence.get("human_name") != human_name:
            continue

        workspaces.append(
            WorkspaceInfo(
                workspace_id=workspace_id,
                alias=alias,
                human_name=presence.get("human_name"),
                team_id=team_id,
                program=presence.get("program"),
                model=presence.get("model"),
                repo=None,
                role=presence.get("role") or None,
                role_name=presence.get("role") or None,
                status=presence.get("status") or "unknown",
                last_seen=presence.get("last_seen") or "",
            )
        )

    workspaces.sort(key=lambda w: w.last_seen or "", reverse=True)

    return ListWorkspacesResponse(workspaces=workspaces, has_more=False)
