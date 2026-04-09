"""Repo registration endpoints.

Used by `aw init` / `aw use` to register git repos within a team
and obtain a repo_id (UUID).
"""

from __future__ import annotations

import logging
import re
import uuid as uuid_module
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from ...db import DatabaseInfra, get_db_infra
from awid.pagination import encode_cursor, validate_pagination_params
from ...presence import clear_workspace_presence
from ...redis_client import get_redis
from aweb.team_auth_deps import get_team_identity

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/v1/repos", tags=["repos"])


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

    # Handle SSH format: git@host:path
    ssh_match = re.match(r"^git@([^:]+):(.+)$", url)
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


class RepoLookupRequest(BaseModel):
    origin_url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("origin_url")
    @classmethod
    def validate_origin_url(cls, v: str) -> str:
        try:
            canonicalize_git_url(v)
        except ValueError as e:
            raise ValueError(f"Invalid origin_url: {e}")
        return v


class RepoLookupResponse(BaseModel):
    repo_id: str
    team_id: str
    canonical_origin: str
    name: str


class RepoLookupCandidate(BaseModel):
    repo_id: str
    team_id: str


@router.post("/lookup")
async def lookup_repo(
    request: Request,
    payload: RepoLookupRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> RepoLookupResponse:
    """Look up a repo by origin URL. Returns the repo and its team if found."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    canonical_origin = canonicalize_git_url(payload.origin_url)

    results = await aweb_db.fetch_all(
        """
        SELECT id as repo_id, canonical_origin, name, team_id
        FROM {{tables.repos}}
        WHERE canonical_origin = $1 AND deleted_at IS NULL
        ORDER BY team_id
        """,
        canonical_origin,
    )

    if not results:
        raise HTTPException(
            status_code=404,
            detail=f"Repo not found: {canonical_origin}",
        )

    if len(results) == 1:
        result = results[0]
        return RepoLookupResponse(
            repo_id=str(result["repo_id"]),
            team_id=result["team_id"],
            canonical_origin=result["canonical_origin"],
            name=result["name"],
        )

    candidates = [
        RepoLookupCandidate(
            repo_id=str(r["repo_id"]),
            team_id=r["team_id"],
        )
        for r in results
    ]
    team_ids = [c.team_id for c in candidates]

    raise HTTPException(
        status_code=409,
        detail={
            "message": f"Repo {canonical_origin} exists in multiple teams: {', '.join(team_ids)}.",
            "canonical_origin": canonical_origin,
            "candidates": [c.model_dump() for c in candidates],
        },
    )


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
) -> RepoEnsureResponse:
    """Get or create a repo by origin URL within the authenticated team."""
    identity = await get_team_identity(request, db)
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
) -> RepoListResponse:
    """List repos for the authenticated team with cursor-based pagination."""
    identity = await get_team_identity(request, db)

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


class RepoDeleteResponse(BaseModel):
    id: str
    workspaces_deleted: int
    claims_deleted: int
    presence_cleared: int


@router.delete("/{repo_id}")
async def delete_repo(
    request: Request,
    repo_id: UUID,
    db: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> RepoDeleteResponse:
    """Soft-delete a repo and cascade to workspaces."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

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
        SELECT workspace_id FROM {{tables.workspaces}}
        WHERE repo_id = $1 AND deleted_at IS NULL
        """,
        str(repo_id),
    )
    workspace_ids = [str(row["workspace_id"]) for row in workspace_rows]

    # Soft-delete workspaces
    if workspace_ids:
        await aweb_db.execute(
            """
            UPDATE {{tables.workspaces}}
            SET deleted_at = NOW()
            WHERE repo_id = $1 AND deleted_at IS NULL
            """,
            str(repo_id),
        )

    # Delete claims for affected workspaces
    claims_deleted = 0
    if workspace_ids:
        result = await aweb_db.fetch_one(
            """
            WITH deleted AS (
                DELETE FROM {{tables.task_claims}}
                WHERE workspace_id = ANY($1::uuid[])
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            """,
            workspace_ids,
        )
        claims_deleted = result["count"] if result else 0

    # Clear Redis presence
    presence_cleared = await clear_workspace_presence(redis, workspace_ids)

    # Soft-delete the repo
    await aweb_db.execute(
        """
        UPDATE {{tables.repos}}
        SET deleted_at = NOW()
        WHERE id = $1
        """,
        str(repo_id),
    )

    logger.info(
        "Repo soft-deleted: id=%s workspaces=%d claims=%d presence=%d",
        repo_id,
        len(workspace_ids),
        claims_deleted,
        presence_cleared,
    )

    return RepoDeleteResponse(
        id=str(repo_id),
        workspaces_deleted=len(workspace_ids),
        claims_deleted=claims_deleted,
        presence_cleared=presence_cleared,
    )
