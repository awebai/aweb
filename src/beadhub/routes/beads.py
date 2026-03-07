from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from beadhub.auth import validate_workspace_id
from beadhub.aweb_context import resolve_aweb_identity
from beadhub.aweb_introspection import get_project_from_auth

from ..beads_sync import (
    DEFAULT_BRANCH,
    BeadsSyncResult,
    _sync_issues_to_db,
    is_valid_branch_name,
    is_valid_canonical_origin,
    validate_issues_from_list,
)
from ..db import DatabaseInfra, get_db_infra
from ..events import publish_bead_status_events
from ..jsonl import JSONLParseError, parse_jsonl
from ..notifications import process_notification_outbox, record_notification_intents
from ..pagination import encode_cursor, validate_pagination_params
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

VALID_ISSUE_TYPES = {"bug", "feature", "task", "epic", "chore"}
VALID_STATUSES = {"open", "in_progress", "closed"}


async def _record_upload_audit(
    db_infra: DatabaseInfra,
    project_id: str,
    repo: str,
    branch: str,
    result: BeadsSyncResult,
    source: str,
) -> None:
    """Record audit log entry for a beads upload."""
    server_db = db_infra.get_manager("server")
    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "beads_uploaded",
        json.dumps(
            {
                "project_id": project_id,
                "repo": repo,
                "branch": branch,
                "issues_synced": result.issues_synced,
                "issues_added": result.issues_added,
                "issues_updated": result.issues_updated,
                "source": source,
            }
        ),
    )


async def _process_status_notifications(
    db_infra: DatabaseInfra,
    project_id: str,
    request: Request,
    redis: Redis,
    result: BeadsSyncResult,
) -> tuple[int, int]:
    """Process notification intents and SSE events for status changes.

    Returns (notifications_sent, notifications_failed).
    """
    if not result.status_changes:
        return 0, 0

    await record_notification_intents(result.status_changes, project_id, db_infra)
    identity = await resolve_aweb_identity(request, db_infra)
    sent, failed = await process_notification_outbox(
        project_id,
        db_infra,
        sender_agent_id=identity.agent_id,
        sender_alias=identity.alias,
    )
    await publish_bead_status_events(
        redis,
        workspace_id=identity.agent_id,
        project_slug=identity.project_slug,
        status_changes=result.status_changes,
        alias=identity.alias,
    )
    return sent, failed


def _upload_response(
    repo: str, result: BeadsSyncResult, notifications_sent: int, notifications_failed: int
) -> dict:
    """Build the standard response dict for beads upload endpoints."""
    return {
        "status": "completed" if notifications_failed == 0 else "completed_with_errors",
        "repo": repo,
        "branch": result.branch,
        "issues_synced": result.issues_synced,
        "issues_added": result.issues_added,
        "issues_updated": result.issues_updated,
        "conflicts": result.conflicts,
        "conflicts_count": result.conflicts_count,
        "notifications_sent": notifications_sent,
        "notifications_failed": notifications_failed,
        "synced_at": result.synced_at,
    }


def _escape_like_pattern(s: str) -> str:
    r"""Escape SQL LIKE metacharacters in user input.

    Prevents user input containing %, _, or \ from being interpreted
    as wildcards in LIKE/ILIKE patterns.
    """
    return s.replace("\\", r"\\").replace("%", r"\%").replace("_", r"\_")


router = APIRouter(prefix="/v1/beads", tags=["beads"])


class BeadsUploadRequest(BaseModel):
    """Request body for uploading beads issues."""

    repo: str = Field(
        ..., min_length=1, max_length=255, description="Canonical origin (e.g. github.com/org/repo)"
    )
    branch: Optional[str] = Field(None, description="Git branch name (default: 'main')")
    issues: List[dict] = Field(..., description="List of issue objects to sync")

    @field_validator("repo")
    @classmethod
    def validate_repo(cls, v: str) -> str:
        if not is_valid_canonical_origin(v):
            raise ValueError(
                "Invalid repository: must be canonical origin format like github.com/org/repo"
            )
        return v


@router.post("/upload")
async def beads_upload(
    request: Request,
    payload: BeadsUploadRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> dict:
    """
    Upload beads issues via JSON payload.

    This endpoint accepts issues directly without requiring filesystem access,
    making it suitable for deployments where the server doesn't have
    access to the client's git repository.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db_infra)
    beads_db = db_infra.get_manager("beads")

    # repo is already validated by BeadsUploadRequest.validate_repo field_validator

    # Apply defaults and validate branch
    branch_name = payload.branch or DEFAULT_BRANCH
    if not is_valid_branch_name(branch_name):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid branch name: {branch_name[:50]}",
        )

    # Validate issues
    issues = validate_issues_from_list(payload.issues)

    # Sync to database
    result: BeadsSyncResult = await _sync_issues_to_db(
        issues, beads_db, project_id=project_id, repo=payload.repo, branch=branch_name
    )

    await _record_upload_audit(db_infra, project_id, payload.repo, branch_name, result, "json")
    notifications_sent, notifications_failed = await _process_status_notifications(
        db_infra, project_id, request, redis, result
    )
    return _upload_response(payload.repo, result, notifications_sent, notifications_failed)


MAX_JSONL_SIZE = 10 * 1024 * 1024  # 10MB
MAX_ISSUES_COUNT = 10000  # Maximum issues per upload
MAX_JSON_DEPTH = 10  # Maximum nesting depth per issue


@router.post("/upload-jsonl")
async def beads_upload_jsonl(
    request: Request,
    repo: str = Query(..., min_length=1, max_length=255, description="Repository name"),
    branch: Optional[str] = Query(None, description="Git branch name (default: 'main')"),
    body: str = Body(..., media_type="text/plain", max_length=MAX_JSONL_SIZE),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> dict:
    """
    Upload beads issues via raw JSONL content.

    Accepts the raw content of a .beads/issues.jsonl file directly.
    Each line should be a valid JSON object representing an issue.
    Empty lines are skipped.

    Limits:
    - Maximum body size: 10MB
    - Maximum issues per upload: 10,000
    - Maximum JSON nesting depth: 10 levels

    This enables shell scripts to upload without jq dependency.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db_infra)
    beads_db = db_infra.get_manager("beads")

    # Validate repo (canonical origin format like github.com/org/repo)
    if not is_valid_canonical_origin(repo):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid repo: {repo[:50]}",
        )

    # Apply defaults and validate branch
    branch_name = branch or DEFAULT_BRANCH
    if not is_valid_branch_name(branch_name):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid branch name: {branch_name[:50]}",
        )

    # Parse JSONL into list of issues (validates count and depth incrementally)
    try:
        issues_raw = parse_jsonl(body, max_depth=MAX_JSON_DEPTH, max_count=MAX_ISSUES_COUNT)
    except JSONLParseError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Validate issues
    issues = validate_issues_from_list(issues_raw)

    # Sync to database
    result: BeadsSyncResult = await _sync_issues_to_db(
        issues, beads_db, project_id=project_id, repo=repo, branch=branch_name
    )

    await _record_upload_audit(db_infra, project_id, repo, branch_name, result, "jsonl")
    notifications_sent, notifications_failed = await _process_status_notifications(
        db_infra, project_id, request, redis, result
    )
    return _upload_response(repo, result, notifications_sent, notifications_failed)


@router.get("/issues")
async def beads_issues(
    request: Request,
    repo: Optional[str] = Query(
        None,
        max_length=255,
        description="Filter by repo (canonical origin, e.g. github.com/org/repo)",
    ),
    branch: Optional[str] = Query(None, max_length=255, description="Filter by branch name"),
    status: Optional[str] = Query(
        None,
        description="Filter by status (open, in_progress, closed). Supports comma-separated values.",
    ),
    assignee: Optional[str] = Query(None),
    created_by: Optional[str] = Query(None, max_length=255, description="Filter by creator"),
    label: Optional[str] = Query(None),
    type: Optional[str] = Query(
        None, description="Filter by issue type (bug, feature, task, epic, chore)"
    ),
    q: Optional[str] = Query(
        None,
        max_length=255,
        description="Search by bead_id (prefix) or title (substring, case-insensitive)",
    ),
    limit: int = Query(50, gt=0, le=200, description="Maximum items to return (1-200)"),
    cursor: Optional[str] = Query(None, description="Pagination cursor from previous response"),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict:
    """
    List synced Beads issues from Postgres, enriched with simple reservation info.

    Supports filtering by repo, branch, status, assignee, created_by, label, type.
    Supports search via `q` parameter: matches bead_id prefix or title substring.
    Supports cursor-based pagination with limit/cursor parameters.

    Requires an authenticated project context.

    Returns:
        issues: List of issues for current page
        count: Number of issues in current page
        has_more: True if more results exist
        next_cursor: Cursor for fetching next page (null if no more)
        synced_at: Timestamp of last sync (may be null)
    """

    project_id = await get_project_from_auth(request, db_infra)
    db = db_infra.get_manager("beads")

    # Validate pagination params
    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Validate optional filters
    if repo and not is_valid_canonical_origin(repo):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid repo: {repo[:50]}",
        )
    if branch and not is_valid_branch_name(branch):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid branch name: {branch[:50]}",
        )
    if type and type not in VALID_ISSUE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid issue type: {type}. Must be one of: {', '.join(sorted(VALID_ISSUE_TYPES))}",
        )

    # Always filter by project_id for tenant isolation
    conditions: List[str] = ["project_id = $1"]
    params: List[object] = [project_id]
    param_idx = 2

    if repo:
        conditions.append(f"repo = ${param_idx}")
        params.append(repo)
        param_idx += 1
    if branch:
        conditions.append(f"branch = ${param_idx}")
        params.append(branch)
        param_idx += 1
    if status:
        status_list = [s.strip() for s in status.split(",") if s.strip()]
        if status_list:
            invalid_statuses = [s for s in status_list if s not in VALID_STATUSES]
            if invalid_statuses:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid status: {', '.join(invalid_statuses)}. Must be one of: {', '.join(sorted(VALID_STATUSES))}",
                )
            if len(status_list) == 1:
                conditions.append(f"status = ${param_idx}")
                params.append(status_list[0])
            else:
                conditions.append(f"status = ANY(${param_idx})")
                params.append(status_list)
            param_idx += 1
    if assignee:
        conditions.append(f"assignee = ${param_idx}")
        params.append(assignee)
        param_idx += 1
    if created_by:
        conditions.append(f"created_by = ${param_idx}")
        params.append(created_by)
        param_idx += 1
    if label:
        conditions.append(f"${param_idx} = ANY(labels)")
        params.append(label)
        param_idx += 1
    if type:
        conditions.append(f"issue_type = ${param_idx}")
        params.append(type)
        param_idx += 1
    if q:
        # Search: bead_id prefix match OR title case-insensitive substring
        # Escape LIKE metacharacters (%, _, \) to prevent unintended wildcards
        escaped_q = _escape_like_pattern(q)
        conditions.append(
            f"(bead_id ILIKE ${param_idx} ESCAPE '\\' OR title ILIKE ${param_idx + 1} ESCAPE '\\')"
        )
        params.append(f"{escaped_q}%")  # bead_id prefix
        params.append(f"%{escaped_q}%")  # title substring
        param_idx += 2

    base_query = """
        SELECT bead_id,
               repo,
               branch,
               title,
               status,
               priority,
               issue_type,
               assignee,
               created_by,
               labels,
               blocked_by,
               parent_id,
               created_at,
               updated_at,
               synced_at
        FROM {{tables.beads_issues}}
    """

    # conditions always has at least project_id
    base_query += " WHERE " + " AND ".join(conditions)

    # Apply cursor condition AFTER all filters (filters narrow, cursor paginates)
    # ORDER BY: COALESCE(updated_at, synced_at) DESC, priority ASC, bead_id ASC
    # "After" cursor means: smaller sort_time, OR same time with larger (priority, bead_id)
    if cursor_data:
        cursor_sort_time_str = cursor_data.get("sort_time")
        cursor_priority = cursor_data.get("priority")
        cursor_bead_id = cursor_data.get("bead_id")

        # All three fields must be present together or none
        has_any = any(
            x is not None for x in [cursor_sort_time_str, cursor_priority, cursor_bead_id]
        )
        has_all = all(
            x is not None for x in [cursor_sort_time_str, cursor_priority, cursor_bead_id]
        )
        if has_any and not has_all:
            raise HTTPException(
                status_code=422,
                detail="Invalid cursor: incomplete sort key (missing sort_time, priority, or bead_id)",
            )

        if has_all:
            # Parse ISO timestamp string to datetime (asyncpg requires datetime objects)
            # Type assertion: has_all guarantees cursor_sort_time_str is not None
            assert isinstance(cursor_sort_time_str, str)
            try:
                cursor_sort_time = datetime.fromisoformat(cursor_sort_time_str)
            except (ValueError, TypeError) as e:
                raise HTTPException(status_code=422, detail=f"Invalid cursor: bad timestamp ({e})")
            # Each $N needs its own param slot (positional, not named)
            base_query += f""" AND (
                COALESCE(updated_at, synced_at) < ${param_idx}
                OR (
                    COALESCE(updated_at, synced_at) = ${param_idx + 1}
                    AND (priority, bead_id) > (${param_idx + 2}, ${param_idx + 3})
                )
            )"""
            params.append(cursor_sort_time)  # for < comparison
            params.append(cursor_sort_time)  # for = comparison
            params.append(cursor_priority)
            params.append(cursor_bead_id)
            param_idx += 4

    base_query += (
        f" ORDER BY COALESCE(updated_at, synced_at) DESC, priority ASC, bead_id ASC"
        f" LIMIT ${param_idx}"
    )
    # Fetch limit+1 to detect if there are more results
    params.append(validated_limit + 1)

    rows = await db.fetch_all(base_query, *params)

    # Check if there are more results beyond this page
    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]  # Trim to requested limit

    issues: list[dict] = []
    for row in rows:
        bead_id = row["bead_id"]
        # Reservation enrichment: simple scan for reservations with matching bead_id in reason.
        reservations: list[dict] = []
        # For now, we do not implement full reservation scanning here to keep
        # implementation minimal; current_reservation will be null.
        current_reservation = None

        # asyncpg returns JSONB as strings (no auto-deserialization by default)
        blocked_by = row["blocked_by"]
        if isinstance(blocked_by, str):
            blocked_by = json.loads(blocked_by)

        parent_id = row["parent_id"]
        if isinstance(parent_id, str):
            parent_id = json.loads(parent_id)

        issues.append(
            {
                "bead_id": bead_id,
                "repo": row["repo"],
                "branch": row["branch"],
                "title": row["title"],
                "status": row["status"],
                "priority": row["priority"],
                "type": row["issue_type"],
                "assignee": row["assignee"],
                "created_by": row["created_by"],
                "labels": row["labels"],
                "blocked_by": blocked_by,
                "parent_id": parent_id,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
                "current_reservation": current_reservation,
                "reservations": reservations,
            }
        )

    # Generate next_cursor from last row if there are more results
    next_cursor = None
    if has_more and rows:
        last_row = rows[-1]
        # Cursor encodes the sort key values for the last item
        sort_time = last_row["updated_at"] or last_row["synced_at"]
        next_cursor = encode_cursor(
            {
                "sort_time": sort_time.isoformat() if sort_time else None,
                "priority": last_row["priority"],
                "bead_id": last_row["bead_id"],
            }
        )

    return {
        "issues": issues,
        "count": len(issues),
        "has_more": has_more,
        "next_cursor": next_cursor,
        "synced_at": None,
    }


@router.get("/issues/{bead_id}")
async def get_issue_by_bead_id(
    request: Request,
    bead_id: str = Path(..., min_length=1, max_length=255),
    repo: Optional[str] = Query(
        None,
        max_length=255,
        description="Filter by repo (canonical origin) for O(1) indexed lookup",
    ),
    branch: Optional[str] = Query(
        None, max_length=255, description="Filter by branch name for O(1) indexed lookup"
    ),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict:
    """
    Get a single issue by its bead_id.

    When repo and branch are provided, uses the unique index
    (project_id, repo, branch, bead_id) for O(1) lookup.

    When repo/branch are omitted, falls back to O(log N) lookup and returns
    the alphabetically first match by repo, then branch.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db_infra)
    db = db_infra.get_manager("beads")

    # Validate repo/branch format if provided
    if repo is not None and not is_valid_canonical_origin(repo):
        raise HTTPException(status_code=422, detail=f"Invalid repo: {repo}")
    if branch is not None and not is_valid_branch_name(branch):
        raise HTTPException(status_code=422, detail=f"Invalid branch name: {branch}")

    if repo is not None and branch is not None:
        # O(1) indexed lookup using unique index
        row = await db.fetch_one(
            """
            SELECT bead_id,
                   repo,
                   branch,
                   title,
                   description,
                   status,
                   priority,
                   issue_type,
                   assignee,
                   created_by,
                   labels,
                   blocked_by,
                   parent_id,
                   created_at,
                   updated_at
            FROM {{tables.beads_issues}}
            WHERE project_id = $1 AND repo = $2 AND branch = $3 AND bead_id = $4
            """,
            project_id,
            repo,
            branch,
            bead_id,
        )
    else:
        # Fallback: scan by project_id + bead_id, return first match
        row = await db.fetch_one(
            """
            SELECT bead_id,
                   repo,
                   branch,
                   title,
                   description,
                   status,
                   priority,
                   issue_type,
                   assignee,
                   created_by,
                   labels,
                   blocked_by,
                   parent_id,
                   created_at,
                   updated_at
            FROM {{tables.beads_issues}}
            WHERE project_id = $1 AND bead_id = $2
            ORDER BY repo ASC, branch ASC
            LIMIT 1
            """,
            project_id,
            bead_id,
        )

    if row is None:
        raise HTTPException(status_code=404, detail="Issue not found")

    blocked_by = row["blocked_by"]
    if isinstance(blocked_by, str):
        blocked_by = json.loads(blocked_by)

    parent_id = row["parent_id"]
    if isinstance(parent_id, str):
        parent_id = json.loads(parent_id)

    return {
        "bead_id": row["bead_id"],
        "project_id": project_id,
        "repo": row["repo"],
        "branch": row["branch"],
        "title": row["title"],
        "description": row["description"],
        "status": row["status"],
        "priority": row["priority"],
        "type": row["issue_type"],
        "assignee": row["assignee"],
        "created_by": row["created_by"],
        "labels": row["labels"],
        "blocked_by": blocked_by,
        "parent_id": parent_id,
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        "current_reservation": None,
    }


@router.get("/ready")
async def beads_ready(
    request: Request,
    workspace_id: str = Query(..., min_length=1),
    repo: Optional[str] = Query(
        None,
        max_length=255,
        description="Filter by repo (canonical origin, e.g. github.com/org/repo)",
    ),
    branch: Optional[str] = Query(None, max_length=255, description="Filter by branch name"),
    limit: int = Query(10, gt=0),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict:
    """
    Get issues that are ready to work on (open, unblocked, not reserved).

    Returns ready issues across all repos, or filtered by repo if specified.

    Requires an authenticated project context.

    An issue is ready if:
    - status = 'open'
    - All blockers in blocked_by are either closed or don't exist in DB
      (supports cross-repo dependencies)
    """
    # Validate workspace_id
    try:
        validate_workspace_id(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Validate optional filters
    if repo and not is_valid_canonical_origin(repo):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid repo: {repo[:50]}",
        )
    if branch and not is_valid_branch_name(branch):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid branch name: {branch[:50]}",
        )

    project_id = await get_project_from_auth(request, db_infra)
    db = db_infra.get_manager("beads")

    # Build WHERE conditions - always filter by project_id for tenant isolation
    conditions = [
        "i.project_id = $1",
        "i.status = 'open'",
        # No open or missing blockers exist for this issue.
        # Uses LEFT JOIN so missing blockers (not yet synced) are treated as blocking.
        # An issue is ready only if ALL blockers exist in DB AND are closed.
        # blocked_by is JSONB array of {repo, branch, bead_id} objects.
        # Note: blockers must also be in same project for cross-project isolation
        """NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(i.blocked_by) AS blocker
            LEFT JOIN {{tables.beads_issues}} b ON
                b.project_id = i.project_id AND
                b.repo = blocker->>'repo' AND
                b.branch = blocker->>'branch' AND
                b.bead_id = blocker->>'bead_id'
            WHERE b.bead_id IS NULL OR b.status != 'closed'
        )""",
    ]
    params: List[object] = [project_id]
    param_idx = 2

    if repo:
        conditions.append(f"i.repo = ${param_idx}")
        params.append(repo)
        param_idx += 1
    if branch:
        conditions.append(f"i.branch = ${param_idx}")
        params.append(branch)
        param_idx += 1

    base_query = f"""
        SELECT i.bead_id,
               i.repo,
               i.branch,
               i.title,
               i.status,
               i.priority,
               i.issue_type,
               i.blocked_by
        FROM {{{{tables.beads_issues}}}} i
        WHERE {" AND ".join(conditions)}
        ORDER BY i.priority ASC, i.bead_id ASC
        LIMIT ${param_idx}
    """
    params.append(limit)

    rows = await db.fetch_all(base_query, *params)

    ready = []
    for row in rows:
        bead_id = row["bead_id"]
        # For now, we ignore Redis reservation state and assume no reservations.

        # asyncpg returns JSONB as strings (no auto-deserialization by default)
        blocked_by = row["blocked_by"]
        if isinstance(blocked_by, str):
            blocked_by = json.loads(blocked_by)

        ready.append(
            {
                "bead_id": bead_id,
                "repo": row["repo"],
                "branch": row["branch"],
                "title": row["title"],
                "status": row["status"],
                "priority": row["priority"],
                "type": row["issue_type"],
                "blocked_by": blocked_by,
                "current_reservation": None,
            }
        )

    return {
        "issues": ready,
        "count": len(ready),
    }
