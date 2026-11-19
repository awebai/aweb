"""Repo registration endpoints.

Used by `aw init` / `aw use` to register git repos within a team
and obtain a repo_id (UUID).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from aweb.application_state import RegistryClientUnavailable, application_registry_client

from aweb.audit import OperatorAuditRoute, audit_success

from ...db import DatabaseInfra, get_db_infra
from awid.pagination import encode_cursor, validate_pagination_params
from ...lifecycle import (
    LifecycleActor,
    LocalWorkspaceTarget,
    apply_local_workspace_cleanup,
    load_removed_claim_workspaces,
    lock_workspace_cleanup_targets_on,
    replay_lifecycle_side_effects,
)
from ...redis_client import get_redis
from aweb.team_auth_deps import TeamIdentity, get_team_identity, team_identity_with_grant_scope

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/v1/repos", tags=["repos"], route_class=OperatorAuditRoute)


def canonicalize_git_url(origin_url: str) -> str:
    """
    Normalize a git origin URL to canonical form.

    Converts various git URL formats to a consistent canonical form:
    - git@github.com:org/repo.git -> github.com/org/repo
    - https://github.com/org/repo.git -> github.com/org/repo
    - ssh://git@github.com:22/org/repo.git -> github.com/org/repo

    Args:
        origin_url: Git origin URL in any format

    Returns:
        Canonical form: host/path (e.g., github.com/org/repo)

    Raises:
        ValueError: If the URL cannot be parsed
    """
    if not origin_url or not origin_url.strip():
        raise ValueError("Empty origin URL")

    url = origin_url.strip()

    # Handle scp-like SSH format: [user@]host:path. The host may be an
    # SSH-config alias (a `Host github-co-aweb` block routing to a deploy
    # key), so it is not required to look like a DNS name.
    ssh_match = None
    if "://" not in url:
        ssh_match = re.match(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9._-]+):([^/\\].*)$", url)
    if ssh_match:
        host = ssh_match.group(1)
        path = ssh_match.group(2)
    else:
        # Handle URL format (https://, http://, ssh://)
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid git URL: {origin_url}")

        host = parsed.hostname
        if not host:
            raise ValueError(f"Invalid git URL: {origin_url}")

        # For ssh:// format with user@host:port, parsed.path starts with /
        path = parsed.path.lstrip("/")

    # GitHub documents ssh.github.com:443 as its SSH-over-HTTPS endpoint.
    # Treat it as the same repository host as github.com so machines using
    # different SSH transports share one canonical repo row.
    if host.lower() == "ssh.github.com":
        host = "github.com"

    # Remove .git extension
    if path.endswith(".git"):
        path = path[:-4]

    # Remove trailing slash
    path = path.rstrip("/")

    if not path:
        raise ValueError(f"Invalid git URL (no path): {origin_url}")

    return f"{host}/{path}"


def extract_repo_name(canonical_origin: str) -> str:
    """Extract repo name from canonical origin (last path component)."""
    return canonical_origin.rsplit("/", 1)[-1]


class RepoEnsureRequest(BaseModel):
    origin_url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("origin_url")
    @classmethod
    def validate_origin_url(cls, v: str) -> str:
        try:
            canonicalize_git_url(v)
        except ValueError as e:
            raise ValueError(f"Invalid origin_url: {e}")
        return v


class RepoEnsureResponse(BaseModel):
    repo_id: str
    canonical_origin: str
    name: str
    created: bool


@router.post("/ensure")
async def ensure_repo(
    request: Request,
    payload: RepoEnsureRequest,
    db: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(get_team_identity),
) -> RepoEnsureResponse:
    """Get or create a repo by origin URL within the authenticated team."""
    aweb_db = db.get_manager("aweb")

    canonical_origin = canonicalize_git_url(payload.origin_url)
    name = extract_repo_name(canonical_origin)

    result = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.repos}} (team_id, origin_url, canonical_origin, name)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (team_id, canonical_origin)
        DO UPDATE SET origin_url = EXCLUDED.origin_url, deleted_at = NULL
        RETURNING id, canonical_origin, name, (xmax = 0) AS created
        """,
        identity.team_id,
        payload.origin_url,
        canonical_origin,
        name,
    )

    created = result["created"]
    if created:
        logger.info(
            "Repo created: team=%s canonical=%s id=%s",
            identity.team_id,
            canonical_origin,
            result["id"],
        )

    return RepoEnsureResponse(
        repo_id=str(result["id"]),
        canonical_origin=result["canonical_origin"],
        name=result["name"],
        created=created,
    )


class RepoSummary(BaseModel):
    id: str
    team_id: str
    canonical_origin: str
    name: str
    created_at: datetime
    workspace_count: int


class RepoListResponse(BaseModel):
    repos: list[RepoSummary]
    has_more: bool = False
    next_cursor: Optional[str] = None


@router.get("")
async def list_repos(
    request: Request,
    limit: Optional[int] = Query(default=None, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    db: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> RepoListResponse:
    """List repos for the authenticated team with cursor-based pagination."""

    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    aweb_db = db.get_manager("aweb")

    query = """
        SELECT
            r.id,
            r.team_id,
            r.canonical_origin,
            r.name,
            r.created_at,
            COUNT(w.workspace_id) FILTER (WHERE w.deleted_at IS NULL) AS workspace_count
        FROM {{tables.repos}} r
        LEFT JOIN {{tables.workspaces}} w ON w.repo_id = r.id
        WHERE r.deleted_at IS NULL AND r.team_id = $1
    """

    params: list = [identity.team_id]
    param_idx = 2

    if cursor_data and "created_at" in cursor_data and "id" in cursor_data:
        try:
            cursor_created_at = datetime.fromisoformat(cursor_data["created_at"])
            cursor_id = UUID(cursor_data["id"])
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid cursor: {e}")
        query += f" AND (r.created_at, r.id) > (${param_idx}, ${param_idx + 1})"
        params.extend([cursor_created_at, cursor_id])
        param_idx += 2

    query += """
        GROUP BY r.id, r.team_id, r.canonical_origin, r.name, r.created_at
        ORDER BY r.created_at, r.id
    """

    query += f" LIMIT ${param_idx}"
    params.append(validated_limit + 1)

    rows = await aweb_db.fetch_all(query, *params)

    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]

    next_cursor = None
    if has_more and rows:
        last_row = rows[-1]
        next_cursor = encode_cursor(
            {
                "created_at": last_row["created_at"].isoformat(),
                "id": str(last_row["id"]),
            }
        )

    return RepoListResponse(
        repos=[
            RepoSummary(
                id=str(row["id"]),
                team_id=row["team_id"],
                canonical_origin=row["canonical_origin"],
                name=row["name"],
                created_at=row["created_at"],
                workspace_count=row["workspace_count"],
            )
            for row in rows
        ],
        has_more=has_more,
        next_cursor=next_cursor,
    )


class SkippedWorkspace(BaseModel):
    workspace_id: str
    code: str


class RepoDeleteResponse(BaseModel):
    id: str
    workspaces_deleted: int
    claims_deleted: int
    presence_cleared: int
    repo_deleted: bool = True
    skipped_workspaces: list[SkippedWorkspace] = Field(default_factory=list)
    cleanup_pending: bool = False


@router.delete("/{repo_id}")
async def delete_repo(
    request: Request,
    repo_id: UUID,
    db: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
    identity: TeamIdentity = Depends(get_team_identity),
) -> RepoDeleteResponse:
    """Soft-delete a repo and cascade to workspaces."""
    try:
        registry_client = application_registry_client(request.app.state)
    except RegistryClientUnavailable as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    manager = db.get_manager("aweb")
    async with manager.transaction() as aweb_db:
        repo = await aweb_db.fetch_one(
            """
            SELECT id, team_id FROM {{tables.repos}}
            WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
            """,
            str(repo_id),
            identity.team_id,
        )
        if not repo:
            raise HTTPException(status_code=404, detail="Repo not found")

        workspace_rows = await aweb_db.fetch_all(
            """
            SELECT workspace_id, agent_id FROM {{tables.workspaces}}
            WHERE repo_id = $1 AND team_id = $2 AND deleted_at IS NULL
            ORDER BY workspace_id
            """,
            str(repo_id),
            identity.team_id,
        )
        removed = await load_removed_claim_workspaces(
            aweb_db,
            agent_ids=[row["agent_id"] for row in workspace_rows if row["agent_id"] is not None],
            team_id=identity.team_id,
        )
        # One outer transaction locks the full repo set before any claim release.
        await lock_workspace_cleanup_targets_on(
            aweb_db,
            targets=tuple(
                LocalWorkspaceTarget(workspace_id=row["workspace_id"], agent_id=row["agent_id"])
                for row in workspace_rows + removed
            ),
            team_id=identity.team_id,
        )
        skipped: list[SkippedWorkspace] = []
        deleted_count = 0
        claims_deleted = 0
        operation_ids: list[str] = []
        deleted_at = datetime.now(timezone.utc)
        actor = LifecycleActor(
            actor_id=identity.agent_id, actor_type="agent", authority="team_identity"
        )
        for row in workspace_rows:
            result = await apply_local_workspace_cleanup(
                aweb_db,
                redis,
                team_id=identity.team_id,
                target=LocalWorkspaceTarget(
                    workspace_id=row["workspace_id"], agent_id=row["agent_id"]
                ),
                actor=actor,
                deleted_at=deleted_at,
                registry_client=registry_client,
                request_context=request,
            )
            if result.errors:
                skipped.append(
                    SkippedWorkspace(
                        workspace_id=str(row["workspace_id"]), code=result.errors[0].code
                    )
                )
                continue
            deleted_count += len(result.workspace_changes)
            claims_deleted += result.task_unclaim_count
            if result.outbox_operation_id is not None:
                operation_ids.append(result.outbox_operation_id)

        # A repo with surviving workspaces remains available to those sessions.
        if not skipped:
            await aweb_db.execute(
                "UPDATE {{tables.repos}} SET deleted_at=$2 WHERE id=$1",
                str(repo_id),
                deleted_at,
            )

        await audit_success(aweb_db, request, identity.team_id)

    presence_cleared = 0
    cleanup_pending = False
    for operation_id in operation_ids:
        replay = await replay_lifecycle_side_effects(manager, redis, operation_id=operation_id)
        presence_cleared += replay.presence_cleared_count
        cleanup_pending = cleanup_pending or replay.pending_count > 0
    if cleanup_pending:
        logger.warning(
            "Repo cleanup committed with lifecycle side effects pending",
            extra={"repo_id": str(repo_id)},
        )

    return RepoDeleteResponse(
        id=str(repo_id),
        workspaces_deleted=deleted_count,
        claims_deleted=claims_deleted,
        presence_cleared=presence_cleared,
        repo_deleted=not skipped,
        skipped_workspaces=skipped,
        cleanup_pending=cleanup_pending,
    )
