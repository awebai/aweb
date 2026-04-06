from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from redis.asyncio import Redis

from aweb.auth import validate_workspace_id
from aweb.team_auth_deps import TeamIdentity, get_team_identity

from ..db import DatabaseInfra, get_db_infra
from ..events import EventCategory, stream_events_multi
from ._reservation_utils import reservation_metadata
from ..presence import (
    list_agent_presences_by_workspace_ids,
)
from ..redis_client import get_redis
from ..input_validation import is_valid_canonical_origin

DEFAULT_WORKSPACE_LIMIT = 200
MAX_WORKSPACE_LIMIT = 1000
VALID_SSE_EVENT_TYPES = frozenset(c.value for c in EventCategory)
# Short TTL keeps SSE subscriptions fresh while reducing DB churn.
WORKSPACE_IDS_CACHE_TTL_SECONDS = 10
WORKSPACE_IDS_CACHE_MAX_SIZE = 1000


@dataclass
class _WorkspaceIDsCacheEntry:
    workspace_ids: List[str]
    fetched_at: float
    limit: int


_WORKSPACE_IDS_CACHE: OrderedDict[
    tuple[int, str], _WorkspaceIDsCacheEntry
] = OrderedDict()


def _get_workspace_ids_cache_key(db_infra: DatabaseInfra, team_address: str) -> tuple[int, str]:
    # Scope cache to the DatabaseInfra instance to avoid cross-DB bleed.
    return (id(db_infra), team_address)


def _get_cached_workspace_ids(
    db_infra: DatabaseInfra, limit: int, team_address: str
) -> Optional[List[str]]:
    key = _get_workspace_ids_cache_key(db_infra, team_address)
    entry = _WORKSPACE_IDS_CACHE.get(key)
    if entry is None:
        return None
    if time.monotonic() - entry.fetched_at > WORKSPACE_IDS_CACHE_TTL_SECONDS:
        _WORKSPACE_IDS_CACHE.pop(key, None)
        return None
    if entry.limit < limit:
        return None
    _WORKSPACE_IDS_CACHE.move_to_end(key)
    return entry.workspace_ids[:limit]


def _update_workspace_ids_cache(
    db_infra: DatabaseInfra, limit: int, team_address: str, workspace_ids: List[str]
) -> None:
    key = _get_workspace_ids_cache_key(db_infra, team_address)
    _WORKSPACE_IDS_CACHE[key] = _WorkspaceIDsCacheEntry(
        workspace_ids=workspace_ids,
        fetched_at=time.monotonic(),
        limit=limit,
    )
    _WORKSPACE_IDS_CACHE.move_to_end(key)
    while len(_WORKSPACE_IDS_CACHE) > WORKSPACE_IDS_CACHE_MAX_SIZE:
        _WORKSPACE_IDS_CACHE.popitem(last=False)


def _title_join(
    alias: str,
    team_address_col: str,
    task_ref_col: str,
    *,
    include_type: bool = False,
    guard_col: str | None = None,
) -> str:
    """Lateral join resolving title (+ optional type) from aweb tasks.

    Matches task_ref (e.g. 'myteam-42') against team_address and task_ref_suffix
    by reconstructing the full ref from the team slug and suffix.
    """
    select_expr = "t.title, t.task_type AS issue_type" if include_type else "t.title AS title"

    guard = f"\n                  AND {guard_col} IS NOT NULL" if guard_col else ""

    return f"""
        LEFT JOIN LATERAL (
            SELECT {select_expr}
            FROM {{{{tables.tasks}}}} t
            WHERE t.team_address = {team_address_col}
              AND {task_ref_col} = (substring({team_address_col} from '[^/]+$') || '-' || t.task_ref_suffix)
              AND t.deleted_at IS NULL{guard}
            LIMIT 1
        ) {alias} ON true"""


async def get_all_workspace_ids_from_db(
    db_infra: DatabaseInfra,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    team_address: str = "",
) -> List[str]:
    """Get all registered workspace IDs from the database (excluding soft-deleted).

    Args:
        db_infra: Database infrastructure.
        limit: Maximum number of workspace IDs to return.
        team_address: Scope to this team (tenant isolation).

    Returns:
        List of workspace IDs, ordered by most recently updated first.
    """
    if not team_address:
        raise ValueError("team_address is required")

    cached = _get_cached_workspace_ids(db_infra, limit, team_address)
    if cached is not None:
        return cached

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE team_address = $1 AND deleted_at IS NULL
        ORDER BY updated_at DESC LIMIT $2
        """,
        team_address,
        limit,
    )
    workspace_ids = [str(row["workspace_id"]) for row in rows]
    _update_workspace_ids_cache(db_infra, limit, team_address, workspace_ids)
    return workspace_ids


async def get_workspace_ids_by_repo_from_db(
    db_infra: DatabaseInfra,
    repo: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    team_address: str = "",
) -> List[str]:
    """Get workspace IDs for a repo by canonical_origin from the database.

    Args:
        db_infra: Database infrastructure.
        repo: Canonical origin (e.g., "github.com/org/repo").
        limit: Maximum number of workspace IDs to return.
        team_address: Scope by team (tenant isolation).

    Returns:
        List of workspace IDs belonging to the repo.
    """
    if not team_address:
        raise ValueError("team_address is required")

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT w.workspace_id
        FROM {{tables.workspaces}} w
        JOIN {{tables.repos}} r ON w.repo_id = r.id
        WHERE r.canonical_origin = $1 AND w.team_address = $2 AND w.deleted_at IS NULL AND r.deleted_at IS NULL
        ORDER BY w.updated_at DESC
        LIMIT $3
        """,
        repo,
        team_address,
        limit,
    )
    return [str(row["workspace_id"]) for row in rows]


async def get_workspace_ids_by_repo_id_from_db(
    db_infra: DatabaseInfra,
    repo_id: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    team_address: str = "",
) -> List[str]:
    """Get workspace IDs for a repo by repo UUID from the database.

    Args:
        db_infra: Database infrastructure.
        repo_id: Repo UUID.
        limit: Maximum number of workspace IDs to return.
        team_address: Scope by team (tenant isolation).

    Returns:
        List of workspace IDs belonging to the repo.
    """
    if not team_address:
        raise ValueError("team_address is required")

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE repo_id = $1 AND team_address = $2 AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT $3
        """,
        repo_id,
        team_address,
        limit,
    )
    return [str(row["workspace_id"]) for row in rows]


async def get_workspace_ids_by_human_name_from_db(
    db_infra: DatabaseInfra,
    human_name: str,
    limit: int = DEFAULT_WORKSPACE_LIMIT,
    team_address: str = "",
) -> List[str]:
    """Get workspace IDs for workspaces owned by a specific human.

    Args:
        db_infra: Database infrastructure.
        human_name: Owner name to filter by.
        limit: Maximum number of workspace IDs to return.
        team_address: Scope by team (tenant isolation).

    Returns:
        List of workspace IDs owned by the human.
    """
    if not team_address:
        raise ValueError("team_address is required")

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE human_name = $1 AND team_address = $2 AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT $3
        """,
        human_name,
        team_address,
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
    identity: TeamIdentity = Depends(get_team_identity),
) -> Dict[str, Any]:
    """
    Aggregate workspace status: agent presence, claims, and conflicts.

    Filter by:
    - workspace_id: Show status for a specific workspace
    - repo_id: Show aggregated status for all workspaces in a repo (UUID)
    """
    team_address = identity.team_address
    aweb_db = db_infra.get_manager("aweb")

    # Determine which workspace_ids to include
    workspace_ids: List[str] = []

    if workspace_id:
        # Validate specific workspace_id
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        row = await aweb_db.fetch_one(
            """
            SELECT workspace_id
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND team_address = $2 AND deleted_at IS NULL
            """,
            validated_workspace_id,
            team_address,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        workspace_ids = [validated_workspace_id]
    elif repo_id:
        workspace_ids = await get_workspace_ids_by_repo_id_from_db(
            db_infra, repo_id, DEFAULT_WORKSPACE_LIMIT, team_address=team_address
        )
    else:
        workspace_ids = await get_all_workspace_ids_from_db(
            db_infra, DEFAULT_WORKSPACE_LIMIT, team_address=team_address
        )

    # Build workspace info based on the filter that was used
    if workspace_id:
        workspace_info: Dict[str, Any] = {
            "workspace_id": workspace_id,
            "team_address": team_address,
        }
    elif repo_id:
        workspace_info = {
            "repo_id": repo_id,
            "workspace_count": len(workspace_ids),
            "team_address": team_address,
        }
    else:
        workspace_info = {
            "team_address": team_address,
            "workspace_count": len(workspace_ids),
        }

    now = datetime.now(timezone.utc)

    if not workspace_ids:
        return {
            "workspace": workspace_info,
            "agents": [],
            "claims": [],
            "locks": [],
            "conflicts": [],
            "timestamp": now.isoformat(),
        }

    # Agent presences from Redis (filtered by workspace_ids from database).
    all_presences: List[Dict[str, str]] = []
    if workspace_ids:
        all_presences = await list_agent_presences_by_workspace_ids(redis, workspace_ids)
    presence_by_workspace = {
        p.get("workspace_id", ""): p for p in all_presences if p.get("workspace_id")
    }

    workspace_rows = await aweb_db.fetch_all(
        f"""
        SELECT
            w.workspace_id,
            w.alias,
            w.human_name,
            w.role,
            w.hostname,
            w.workspace_path,
            w.focus_task_ref,
            w.focus_updated_at,
            w.last_seen_at,
            r.canonical_origin AS repo,
            focus_info.title AS focus_task_title,
            focus_info.issue_type AS focus_task_type
        FROM {{{{tables.workspaces}}}} w
        LEFT JOIN {{{{tables.repos}}}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        {_title_join("focus_info", "w.team_address", "w.focus_task_ref", include_type=True, guard_col="w.focus_task_ref")}
        WHERE w.team_address = $1
          AND w.deleted_at IS NULL
          AND w.workspace_id = ANY($2::uuid[])
        ORDER BY w.updated_at DESC, w.alias ASC
        """,
        team_address,
        workspace_ids,
    )
    workspace_rows_by_id = {str(row["workspace_id"]): row for row in workspace_rows}
    ordered_workspace_ids = [
        ws_id for ws_id in workspace_ids if ws_id in workspace_rows_by_id
    ] or [str(row["workspace_id"]) for row in workspace_rows]

    claim_rows = await aweb_db.fetch_all(
        f"""
        SELECT
            c.task_ref,
            c.workspace_id,
            c.alias,
            c.human_name,
            c.claimed_at,
            c.team_address,
            c.apex_task_ref,
            counts.claimant_count,
            claim_info.title AS title,
            apex_info.title AS apex_title,
            apex_info.issue_type AS apex_type
        FROM {{{{tables.task_claims}}}} c
        JOIN (
            SELECT team_address, task_ref, COUNT(*) AS claimant_count
            FROM {{{{tables.task_claims}}}}
            WHERE team_address = $1
            GROUP BY team_address, task_ref
        ) counts ON c.team_address = counts.team_address AND c.task_ref = counts.task_ref
        {_title_join("claim_info", "c.team_address", "c.task_ref")}
        {_title_join("apex_info", "c.team_address", "c.apex_task_ref", include_type=True, guard_col="c.apex_task_ref")}
        WHERE c.team_address = $1
          AND c.workspace_id = ANY($2::uuid[])
        ORDER BY c.claimed_at DESC
        """,
        team_address,
        workspace_ids,
    )

    claims: List[Dict[str, Any]] = []
    claims_by_workspace: Dict[str, List[Dict[str, Any]]] = {}
    current_task_by_workspace: Dict[str, str] = {}
    apex_by_workspace: Dict[str, Dict[str, Any]] = {}
    for row in claim_rows:
        ws_id = str(row["workspace_id"])
        claim = {
            "task_ref": row["task_ref"],
            "workspace_id": ws_id,
            "alias": row["alias"],
            "human_name": row["human_name"],
            "claimed_at": row["claimed_at"].isoformat(),
            "claimant_count": row["claimant_count"],
            "title": row["title"],
            "team_address": row["team_address"],
            "apex_task_ref": row["apex_task_ref"],
            "apex_title": row["apex_title"],
            "apex_type": row["apex_type"],
        }
        claims.append(claim)
        claims_by_workspace.setdefault(ws_id, []).append(claim)
        current_task_by_workspace.setdefault(ws_id, row["task_ref"])
        apex_by_workspace.setdefault(
            ws_id,
            {
                "apex_task_ref": row["apex_task_ref"],
                "apex_title": row["apex_title"],
                "apex_type": row["apex_type"],
            },
        )

    reservation_rows = await aweb_db.fetch_all(
        """
        SELECT team_address, resource_key, holder_agent_id, holder_alias,
               acquired_at, expires_at, metadata_json
        FROM {{tables.reservations}}
        WHERE team_address = $1
          AND expires_at > NOW()
          AND holder_agent_id = ANY($2::uuid[])
        ORDER BY resource_key ASC
        """,
        team_address,
        workspace_ids,
    )
    reservations: List[Dict[str, Any]] = []
    reservations_by_workspace: Dict[str, List[Dict[str, Any]]] = {}
    for row in reservation_rows:
        metadata = reservation_metadata(row["metadata_json"])
        reason = metadata.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            reason = None
        reservation = {
            "team_address": row["team_address"],
            "resource_key": row["resource_key"],
            "holder_agent_id": str(row["holder_agent_id"]),
            "holder_alias": row["holder_alias"],
            "acquired_at": row["acquired_at"].isoformat(),
            "expires_at": row["expires_at"].isoformat(),
            "ttl_remaining_seconds": max(int((row["expires_at"] - now).total_seconds()), 0),
            "reason": reason,
            "metadata": metadata,
        }
        reservations.append(reservation)
        reservations_by_workspace.setdefault(str(row["holder_agent_id"]), []).append(reservation)

    agents: List[Dict[str, Any]] = []
    for ws_id in ordered_workspace_ids:
        row = workspace_rows_by_id.get(ws_id)
        if row is None:
            continue
        presence = presence_by_workspace.get(ws_id, {})
        agent_role = presence.get("role") or row["role"] or None
        agent = {
            "workspace_id": ws_id,
            "alias": presence.get("alias") or row["alias"],
            "human_name": presence.get("human_name") or row["human_name"] or None,
            "role": agent_role,
            "role_name": agent_role,
            "status": presence.get("status") or "offline",
            "canonical_origin": presence.get("canonical_origin") or row["repo"] or None,
            "hostname": row["hostname"] or None,
            "workspace_path": row["workspace_path"] or None,
            "current_task_ref": current_task_by_workspace.get(ws_id),
            "focus_task_ref": row["focus_task_ref"],
            "focus_task_title": row["focus_task_title"],
            "focus_task_type": row["focus_task_type"],
            "focus_updated_at": row["focus_updated_at"].isoformat() if row["focus_updated_at"] else None,
            "apex_task_ref": apex_by_workspace.get(ws_id, {}).get("apex_task_ref"),
            "apex_title": apex_by_workspace.get(ws_id, {}).get("apex_title"),
            "apex_type": apex_by_workspace.get(ws_id, {}).get("apex_type"),
            "claims": claims_by_workspace.get(ws_id, []),
            "reservations": reservations_by_workspace.get(ws_id, []),
            "last_seen": presence.get("last_seen")
            or (row["last_seen_at"].isoformat() if row["last_seen_at"] else None),
        }
        agents.append(agent)

    # Identify conflicts: tasks with multiple claimants
    conflicts = []
    seen_tasks: Dict[str, List[Dict[str, Any]]] = {}
    for claim in claims:
        if claim["claimant_count"] > 1:
            task_ref = claim["task_ref"]
            if task_ref not in seen_tasks:
                seen_tasks[task_ref] = []
            seen_tasks[task_ref].append(
                {
                    "alias": claim["alias"],
                    "human_name": claim["human_name"],
                    "workspace_id": claim["workspace_id"],
                }
            )
    for task_ref, claimants in seen_tasks.items():
        conflicts.append(
            {
                "task_ref": task_ref,
                "claimants": claimants,
            }
        )

    return {
        "workspace": workspace_info,
        "agents": agents,
        "claims": claims,
        "locks": reservations,
        "conflicts": conflicts,
        "timestamp": now.isoformat(),
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
        None, description="Comma-separated event categories to filter (e.g., 'message,task')"
    ),
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(get_team_identity),
) -> StreamingResponse:
    """
    Server-Sent Events (SSE) stream for real-time updates.

    Subscribes to events and streams them as they occur. Events include
    messages and task status changes.

    Filter by:
    - workspace_id: Stream events for a specific workspace
    - repo: Stream aggregated events for all workspaces in a repo (canonical origin)
    - human_name: Stream events for all workspaces owned by a specific human
    - No filter: Stream events for all workspaces in the authenticated team (bounded, ordered by recent activity)

    Args:
        workspace_id: UUID of a specific workspace to stream events for
        repo: Repo canonical origin (e.g., "github.com/org/repo") to stream events
              for all its workspaces
        human_name: Owner name to stream events for all their workspaces
        limit: Maximum number of workspaces to subscribe to (default 200, max 1000).
               Ignored when workspace_id is specified. Workspaces are ordered by
               recent activity, so the limit prioritizes active workspaces.
        event_types: Optional comma-separated filter for event categories.
                     Valid categories: reservation, message, task, chat.
                     If not specified, all events are streamed.

    Returns:
        SSE stream with events in the format:
        ```
        data: {"type": "message.delivered", "workspace_id": "...", ...}

        data: {"type": "task.status_changed", "workspace_id": "...", ...}
        ```
    """
    team_address = identity.team_address

    # Determine which workspace_ids to subscribe to
    workspace_ids: List[str] = []

    if workspace_id:
        # Validate specific workspace_id
        try:
            validated_workspace_id = validate_workspace_id(workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        aweb_db = db_infra.get_manager("aweb")
        row = await aweb_db.fetch_one(
            """
            SELECT 1
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND team_address = $2 AND deleted_at IS NULL
            """,
            validated_workspace_id,
            team_address,
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
        # Look up workspace_ids for this repo from database (scoped by team_address)
        workspace_ids = await get_workspace_ids_by_repo_from_db(
            db_infra, repo, limit, team_address=team_address
        )
    elif human_name:
        # Look up workspace_ids for this owner from database
        workspace_ids = await get_workspace_ids_by_human_name_from_db(
            db_infra, human_name, limit, team_address=team_address
        )
    else:
        # No filter - stream registered workspaces from database (limited)
        workspace_ids = await get_all_workspace_ids_from_db(
            db_infra, limit, team_address=team_address
        )

    # Handle empty workspace lists:
    # - If user provided specific filters (repo/human_name) that matched nothing,
    #   return 404 so they know their filter was wrong
    # - If just team-level filtering (or no filter), allow keepalive stream
    #   for teams that don't have workspaces yet
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
