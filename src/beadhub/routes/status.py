from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from redis.asyncio import Redis

from beadhub.auth import validate_workspace_id
from beadhub.aweb_introspection import get_project_from_auth

from ..db import DatabaseInfra, get_db_infra
from ..events import EventCategory, stream_events_multi
from ..internal_auth import is_public_reader
from ..presence import (
    list_agent_presences_by_workspace_ids,
)
from ..redis_client import get_redis
from .workspaces import is_valid_canonical_origin

DEFAULT_WORKSPACE_LIMIT = 200
MAX_WORKSPACE_LIMIT = 1000
VALID_SSE_EVENT_TYPES = frozenset(c.value for c in EventCategory)
# Short TTL keeps SSE subscriptions fresh while reducing DB churn.
WORKSPACE_IDS_CACHE_TTL_SECONDS = 10


@dataclass
class _WorkspaceIDsCacheEntry:
    workspace_ids: List[str]
    fetched_at: float
    limit: int


_WORKSPACE_IDS_CACHE: dict[tuple[int, str], _WorkspaceIDsCacheEntry] = {}


def _get_workspace_ids_cache_key(db_infra: DatabaseInfra, project_id: str) -> tuple[int, str]:
    # Scope cache to the DatabaseInfra instance to avoid cross-DB bleed.
    return (id(db_infra), project_id)


def _get_cached_workspace_ids(
    db_infra: DatabaseInfra, limit: int, project_id: str
) -> Optional[List[str]]:
    key = _get_workspace_ids_cache_key(db_infra, project_id)
    entry = _WORKSPACE_IDS_CACHE.get(key)
    if entry is None:
        return None
    if time.monotonic() - entry.fetched_at > WORKSPACE_IDS_CACHE_TTL_SECONDS:
        _WORKSPACE_IDS_CACHE.pop(key, None)
        return None
    if entry.limit < limit:
        return None
    return entry.workspace_ids[:limit]


def _update_workspace_ids_cache(
    db_infra: DatabaseInfra, limit: int, project_id: str, workspace_ids: List[str]
) -> None:
    key = _get_workspace_ids_cache_key(db_infra, project_id)
    _WORKSPACE_IDS_CACHE[key] = _WorkspaceIDsCacheEntry(
        workspace_ids=workspace_ids,
        fetched_at=time.monotonic(),
        limit=limit,
    )


async def get_all_workspace_ids_from_db(
    db_infra: DatabaseInfra,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    project_id: str = "",
) -> List[str]:
    """Get all registered workspace IDs from the database (excluding soft-deleted).

    Args:
        db_infra: Database infrastructure.
        limit: Maximum number of workspace IDs to return.
        project_id: Scope to this project (tenant isolation).

    Returns:
        List of workspace IDs, ordered by most recently updated first.
    """
    if not project_id:
        raise ValueError("project_id is required")

    cached = _get_cached_workspace_ids(db_infra, limit, project_id)
    if cached is not None:
        return cached

    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        """
        SELECT workspace_id FROM {{tables.workspaces}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY updated_at DESC LIMIT $2
        """,
        uuid.UUID(project_id),
        limit,
    )
    workspace_ids = [str(row["workspace_id"]) for row in rows]
    _update_workspace_ids_cache(db_infra, limit, project_id, workspace_ids)
    return workspace_ids


async def get_workspace_ids_by_repo_from_db(
    db_infra: DatabaseInfra,
    repo: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    project_id: str = "",
) -> List[str]:
    """Get workspace IDs for a repo by canonical_origin from the database.

    Args:
        db_infra: Database infrastructure.
        repo: Canonical origin (e.g., "github.com/org/repo").
        limit: Maximum number of workspace IDs to return.
        project_id: Scope by project (tenant isolation).

    Returns:
        List of workspace IDs belonging to the repo.
    """
    if not project_id:
        raise ValueError("project_id is required")

    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        """
        SELECT w.workspace_id
        FROM {{tables.workspaces}} w
        JOIN {{tables.repos}} r ON w.repo_id = r.id
        WHERE r.canonical_origin = $1 AND w.project_id = $2 AND w.deleted_at IS NULL AND r.deleted_at IS NULL
        ORDER BY w.updated_at DESC
        LIMIT $3
        """,
        repo,
        uuid.UUID(project_id),
        limit,
    )
    return [str(row["workspace_id"]) for row in rows]


async def get_workspace_ids_by_repo_id_from_db(
    db_infra: DatabaseInfra,
    repo_id: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    project_id: str = "",
) -> List[str]:
    """Get workspace IDs for a repo by repo UUID from the database.

    Args:
        db_infra: Database infrastructure.
        repo_id: Repo UUID.
        limit: Maximum number of workspace IDs to return.
        project_id: Scope by project (tenant isolation).

    Returns:
        List of workspace IDs belonging to the repo.
    """
    if not project_id:
        raise ValueError("project_id is required")

    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE repo_id = $1 AND project_id = $2 AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT $3
        """,
        uuid.UUID(repo_id),
        uuid.UUID(project_id),
        limit,
    )
    return [str(row["workspace_id"]) for row in rows]


async def get_workspace_ids_by_human_name_from_db(
    db_infra: DatabaseInfra,
    human_name: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    project_id: str = "",
) -> List[str]:
    """Get workspace IDs for workspaces owned by a specific human.

    Args:
        db_infra: Database infrastructure.
        human_name: Owner name to filter by.
        limit: Maximum number of workspace IDs to return.
        project_id: Scope by project (tenant isolation).

    Returns:
        List of workspace IDs owned by the human.
    """
    if not project_id:
        raise ValueError("project_id is required")

    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE human_name = $1 AND project_id = $2 AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT $3
        """,
        human_name,
        uuid.UUID(project_id),
        limit,
    )
    return [str(row["workspace_id"]) for row in rows]


router = APIRouter(prefix="/v1", tags=["status"])


@router.get("/status")
async def status(
    request: Request,
    workspace_id: Optional[str] = Query(None, min_length=1),
    repo_id: Optional[str] = Query(None, min_length=36, max_length=36),
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> Dict[str, Any]:
    """
    Aggregate workspace status: agent presence and escalations.

    Filter by:
    - workspace_id: Show status for a specific workspace
    - repo_id: Show aggregated status for all workspaces in a repo (UUID)
    """
    project_id = await get_project_from_auth(request, db_infra)
    public_reader = is_public_reader(request)
    project_uuid = uuid.UUID(project_id)
    server_db = db_infra.get_manager("server")

    project_row = await server_db.fetch_one(
        """
        SELECT slug
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_uuid,
    )
    if not project_row:
        raise HTTPException(status_code=500, detail="Authenticated project not found")
    project_slug = project_row["slug"]

    # Determine which workspace_ids to include
    workspace_ids: List[str] = []

    if workspace_id:
        # Validate specific workspace_id
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        row = await server_db.fetch_one(
            """
            SELECT workspace_id FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            uuid.UUID(validated_workspace_id),
            project_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        workspace_ids = [validated_workspace_id]
    elif repo_id:
        # Validate UUID format at API boundary
        try:
            uuid.UUID(repo_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid repo_id format: expected UUID")
        workspace_ids = await get_workspace_ids_by_repo_id_from_db(
            db_infra, repo_id, DEFAULT_WORKSPACE_LIMIT, project_id=project_id
        )
    else:
        workspace_ids = await get_all_workspace_ids_from_db(
            db_infra, DEFAULT_WORKSPACE_LIMIT, project_id=project_id
        )

    # Build workspace info based on the filter that was used
    if workspace_id:
        workspace_info: Dict[str, Any] = {
            "workspace_id": workspace_id,
            "project_id": project_id,
            "project_slug": project_slug,
        }
    elif repo_id:
        workspace_info = {
            "repo_id": repo_id,
            "workspace_count": len(workspace_ids),
            "project_id": project_id,
            "project_slug": project_slug,
        }
    else:
        workspace_info = {
            "project_id": project_id,
            "project_slug": project_slug,
            "workspace_count": len(workspace_ids),
        }

    # Agent presences from Redis (filtered by workspace_ids from database)
    # Always use workspace_ids for filtering - the database is the authoritative source
    # for which workspaces exist. Empty workspace_ids = empty presences (fail closed).
    all_presences: List[Dict[str, str]] = []
    if workspace_ids:
        all_presences = await list_agent_presences_by_workspace_ids(redis, workspace_ids)

    # Convert workspace_ids to UUIDs for database queries
    uuid_workspace_ids = [uuid.UUID(ws_id) for ws_id in workspace_ids] if workspace_ids else []

    row = await server_db.fetch_one(
        "SELECT COUNT(*) AS count FROM {{tables.escalations}} WHERE status = 'pending' AND project_id = $1",
        project_uuid,
    )
    escalations_pending = int(row["count"]) if row and "count" in row else 0
    if public_reader:
        escalations_pending = 0

    # Claims - active bead claims with claimant count for conflict detection
    if uuid_workspace_ids:
        placeholders = ", ".join(f"${i}" for i in range(1, len(uuid_workspace_ids) + 1))
        where_clause = f"WHERE c.workspace_id IN ({placeholders})"
        params = uuid_workspace_ids
    else:
        where_clause = ""
        params = []

    # Query claims with a count of how many workspaces have claimed each bead.
    # Title resolved from aweb tasks (primary) with beads_issues fallback.
    from .workspaces import _title_join

    claim_rows = await server_db.fetch_all(
        f"""
        SELECT c.bead_id, c.workspace_id, c.alias, c.human_name, c.claimed_at, c.project_id,
               counts.claimant_count, bi.title
        FROM {{{{tables.bead_claims}}}} c
        JOIN (
            SELECT project_id, bead_id, COUNT(*) as claimant_count
            FROM {{{{tables.bead_claims}}}}
            GROUP BY project_id, bead_id
        ) counts ON c.project_id = counts.project_id AND c.bead_id = counts.bead_id
        {_title_join("bi", "c.project_id", "c.bead_id")}
        {where_clause}
        ORDER BY c.claimed_at DESC
        """,
        *params,
    )
    claims = [
        {
            "bead_id": r["bead_id"],
            "workspace_id": str(r["workspace_id"]),
            "alias": r["alias"],
            "human_name": r["human_name"],
            "claimed_at": r["claimed_at"].isoformat(),
            "claimant_count": r["claimant_count"],
            "title": r["title"],
            "project_id": str(r["project_id"]),
        }
        for r in claim_rows
    ]

    # Build claims lookup map for populating current_issue in agents
    # Note: A workspace may have multiple claims; use the most recent (first in list due to ORDER BY)
    claims_by_workspace: Dict[str, str] = {}
    for r in claim_rows:
        ws_id = str(r["workspace_id"])
        if ws_id not in claims_by_workspace:
            claims_by_workspace[ws_id] = r["bead_id"]

    # Build agent info for all agents, enriched with current_issue from claims
    agents: List[Dict[str, Any]] = []
    for presence in all_presences:
        ws_id = presence.get("workspace_id", "")
        agents.append(
            {
                "workspace_id": ws_id,
                "alias": presence.get("alias", ""),
                "member": None if public_reader else (presence.get("member_email") or None),
                "human_name": presence.get("human_name") or None,
                "program": presence.get("program") or None,
                "role": presence.get("role") or None,
                "status": presence.get("status") or "unknown",
                "current_branch": presence.get("current_branch") or None,
                "canonical_origin": presence.get("canonical_origin") or None,
                "timezone": presence.get("timezone") or None,
                "current_issue": claims_by_workspace.get(ws_id),
                "last_seen": presence.get("last_seen"),
            }
        )

    # Identify conflicts: beads with multiple claimants
    conflicts = []
    seen_beads: Dict[str, List[Dict[str, Any]]] = {}
    for claim in claims:
        if claim["claimant_count"] > 1:
            bead_id = claim["bead_id"]
            if bead_id not in seen_beads:
                seen_beads[bead_id] = []
            seen_beads[bead_id].append(
                {
                    "alias": claim["alias"],
                    "human_name": claim["human_name"],
                    "workspace_id": claim["workspace_id"],
                }
            )
    for bead_id, claimants in seen_beads.items():
        conflicts.append(
            {
                "bead_id": bead_id,
                "claimants": claimants,
            }
        )

    return {
        "workspace": workspace_info,
        "agents": agents,
        "claims": claims,
        "conflicts": conflicts,
        "escalations_pending": escalations_pending,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status/stream")
async def status_stream(
    request: Request,
    workspace_id: Optional[str] = Query(None, min_length=1),
    repo: Optional[str] = Query(
        None,
        max_length=255,
        description="Filter by repo canonical origin (e.g., 'github.com/org/repo')",
    ),
    human_name: Optional[str] = Query(
        None,
        max_length=64,
        description="Filter by workspace owner name",
    ),
    limit: int = Query(
        DEFAULT_WORKSPACE_LIMIT,
        ge=1,
        le=MAX_WORKSPACE_LIMIT,
        description="Maximum workspaces to subscribe to (ignored when workspace_id is specified)",
    ),
    event_types: Optional[str] = Query(
        None, description="Comma-separated event categories to filter (e.g., 'message,bead')"
    ),
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> StreamingResponse:
    """
    Server-Sent Events (SSE) stream for real-time updates.

    Subscribes to events and streams them as they occur. Events include
    messages, escalations, and bead status changes.

    Filter by:
    - workspace_id: Stream events for a specific workspace
    - repo: Stream aggregated events for all workspaces in a repo (canonical origin)
    - human_name: Stream events for all workspaces owned by a specific human
    - No filter: Stream events for all workspaces in the authenticated project (bounded, ordered by recent activity)

    Args:
        workspace_id: UUID of a specific workspace to stream events for
        repo: Repo canonical origin (e.g., "github.com/org/repo") to stream events
              for all its workspaces
        human_name: Owner name to stream events for all their workspaces
        limit: Maximum number of workspaces to subscribe to (default 200, max 1000).
               Ignored when workspace_id is specified. Workspaces are ordered by
               recent activity, so the limit prioritizes active workspaces.
        event_types: Optional comma-separated filter for event categories.
                     Valid categories: reservation, message, escalation, bead, chat.
                     If not specified, all events are streamed.

    Returns:
        SSE stream with events in the format:
        ```
        data: {"type": "message.delivered", "workspace_id": "...", ...}

        data: {"type": "bead.status_changed", "workspace_id": "...", ...}
        ```
    """
    effective_project_id = await get_project_from_auth(request, db_infra)

    # Determine which workspace_ids to subscribe to
    workspace_ids: List[str] = []

    if workspace_id:
        # Validate specific workspace_id
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        server_db = db_infra.get_manager("server")
        row = await server_db.fetch_one(
            """
            SELECT 1 FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            uuid.UUID(validated_workspace_id),
            uuid.UUID(effective_project_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        workspace_ids = [validated_workspace_id]
    elif repo:
        # Validate repo format (canonical origin)
        if not is_valid_canonical_origin(repo):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid repo format: {repo[:50]}",
            )
        # Look up workspace_ids for this repo from database (scoped by project_id if present)
        workspace_ids = await get_workspace_ids_by_repo_from_db(
            db_infra, repo, limit, project_id=effective_project_id
        )
    elif human_name:
        # Look up workspace_ids for this owner from database
        workspace_ids = await get_workspace_ids_by_human_name_from_db(
            db_infra, human_name, limit, project_id=effective_project_id
        )
    else:
        # No filter - stream registered workspaces from database (limited)
        workspace_ids = await get_all_workspace_ids_from_db(
            db_infra, limit, project_id=effective_project_id
        )

    # Handle empty workspace lists:
    # - If user provided specific filters (repo/human_name) that matched nothing,
    #   return 404 so they know their filter was wrong
    # - If just project-level filtering (or no filter), allow keepalive stream
    #   for new projects that don't have workspaces yet
    if not workspace_ids:
        if repo or human_name:
            raise HTTPException(
                status_code=404,
                detail="No workspaces found for the provided filter",
            )

    # Parse event type filter
    event_type_set: Optional[set[str]] = None
    if event_types:
        event_type_set = {t.strip().lower() for t in event_types.split(",")}
        # Validate event types
        invalid = event_type_set - VALID_SSE_EVENT_TYPES
        if invalid:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid event types: {invalid}. Valid types: {sorted(VALID_SSE_EVENT_TYPES)}",
            )

    return StreamingResponse(
        stream_events_multi(
            redis,
            workspace_ids,
            event_type_set,
            check_disconnected=request.is_disconnected,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )
