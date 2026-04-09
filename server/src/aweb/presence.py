from __future__ import annotations

from datetime import datetime
from datetime import timezone as timezone_mod
from typing import Dict, List, Optional
from urllib.parse import quote

from redis.asyncio import Redis

from .coordination.roles import ROLE_MAX_LENGTH, is_valid_role, normalize_role

DEFAULT_PRESENCE_TTL_SECONDS = 1800  # 30 minutes


def _safe_key_component(value: str) -> str:
    """URL-encode a value for safe use in Redis keys.

    Prevents key collision attacks where values containing colons could
    create ambiguous key boundaries. For example, without encoding:
      team_id="abc", alias="xyz:def" -> "idx:alias:abc:xyz:def"
      team_id="abc:xyz", alias="def" -> "idx:alias:abc:xyz:def" (COLLISION!)

    With encoding:
      team_id="abc", alias="xyz:def" -> "idx:alias:abc:xyz%3Adef"
      team_id="abc:xyz", alias="def" -> "idx:alias:abc%3Axyz:def" (DISTINCT)
    """
    return quote(value, safe="")


def _presence_key(workspace_id: str) -> str:
    """Presence key: one agent per workspace."""
    return f"presence:{workspace_id}"


def _team_workspaces_index_key(team_id: str) -> str:
    """Secondary index: workspace_ids by team_id."""
    return f"idx:team_workspaces:{team_id}"


def _repo_workspaces_index_key(repo_id: str) -> str:
    """Secondary index: workspace_ids by repo_id."""
    return f"idx:repo_workspaces:{repo_id}"


def _branch_workspaces_index_key(repo_id: str, branch: str) -> str:
    """Secondary index: workspace_ids by repo_id and branch."""
    return f"idx:branch_workspaces:{repo_id}:{_safe_key_component(branch)}"


def _all_workspaces_index_key() -> str:
    """Global index: all workspace_ids with active presence."""
    return "idx:all_workspaces"


def _alias_index_key(team_id: str, alias: str) -> str:
    """Secondary index: workspace_id by (team_id, alias).

    Enables O(1) alias collision checking instead of SCAN.
    Key maps to a single workspace_id (aliases are unique per team).
    """
    return f"idx:alias:{_safe_key_component(team_id)}:{_safe_key_component(alias)}"


async def update_agent_presence(
    redis: Redis,
    workspace_id: Optional[str] = None,
    alias: str = "",
    program: Optional[str] = None,
    model: Optional[str] = None,
    human_name: Optional[str] = None,
    team_id: Optional[str] = None,
    repo_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    member_email: str = "",
    status: str = "active",
    current_branch: Optional[str] = None,
    role: Optional[str] = None,
    canonical_origin: Optional[str] = None,
    timezone: Optional[str] = None,
    ttl_seconds: int = DEFAULT_PRESENCE_TTL_SECONDS,
) -> str:
    """
    Upsert agent presence in Redis and return the ISO timestamp used.

    Args:
        workspace_id: UUID identifying the workspace.
        alias: Human-friendly workspace identifier for addressing.
        human_name: Name of the human who owns this workspace.
        team_id: Team address (for secondary index).
        repo_id: UUID of the repo (for secondary index).
        current_branch: Optional branch name.
        role: Brief description of workspace purpose (max 50 chars).
        canonical_origin: Normalized repo origin (e.g. "github.com/org/repo").
        timezone: IANA timezone (e.g. "Europe/Madrid"). Preserved when None.
        ttl_seconds: How long until presence expires if not refreshed. Default 5 minutes.
    """
    workspace_id = workspace_id or agent_id
    if not workspace_id:
        raise ValueError("workspace_id or agent_id is required")

    key = _presence_key(workspace_id)
    now = datetime.now(timezone_mod.utc).isoformat()

    fields = {
        "workspace_id": workspace_id,
        "alias": alias,
        "human_name": human_name or "",
        "team_id": team_id or "",
        "repo_id": repo_id or "",
        "member_email": member_email,
        "program": program or "",
        "model": model or "",
        "status": status,
        "current_branch": current_branch or "",
        "last_seen": now,
    }
    if canonical_origin is not None:
        fields["canonical_origin"] = canonical_origin
    if role is not None and len(role) <= ROLE_MAX_LENGTH and is_valid_role(role):
        fields["role"] = normalize_role(role)
    if timezone is not None:
        fields["timezone"] = timezone

    await redis.hset(key, mapping=fields)
    await redis.expire(key, ttl_seconds)

    # Update secondary indexes
    # Index TTL is 2x presence TTL to ensure index entries outlive presence keys,
    # allowing lazy cleanup to detect stale entries via EXISTS checks.
    # Note: workspace → team is immutable (see architecture docs), so team_id
    # doesn't change for a given workspace. Branch and repo indexes may have
    # transient staleness (up to TTL*2) when workspaces switch branches.

    # Global all_workspaces index (always maintained)
    all_idx_key = _all_workspaces_index_key()
    await redis.sadd(all_idx_key, workspace_id)
    await redis.expire(all_idx_key, ttl_seconds * 2)

    if team_id:
        idx_key = _team_workspaces_index_key(team_id)
        await redis.sadd(idx_key, workspace_id)
        await redis.expire(idx_key, ttl_seconds * 2)

        # Alias index for O(1) collision checking (1:1 mapping, not a set)
        alias_idx_key = _alias_index_key(team_id, alias)
        await redis.set(alias_idx_key, workspace_id, ex=ttl_seconds * 2)

    if repo_id:
        idx_key = _repo_workspaces_index_key(repo_id)
        await redis.sadd(idx_key, workspace_id)
        await redis.expire(idx_key, ttl_seconds * 2)

        if current_branch:
            idx_key = _branch_workspaces_index_key(repo_id, current_branch)
            await redis.sadd(idx_key, workspace_id)
            await redis.expire(idx_key, ttl_seconds * 2)

    return now


async def get_agent_presence(
    redis: Redis,
    workspace_id: str,
) -> Optional[Dict[str, str]]:
    """
    Fetch an agent's presence record from Redis.

    One agent per workspace architecture: workspace_id is the only key.

    Args:
        workspace_id: UUID identifying the workspace.
    """
    key = _presence_key(workspace_id)
    data: Dict[str, str] = await redis.hgetall(key)
    if not data:
        return None
    return data


async def list_agent_presences(
    redis: Redis,
    workspace_id: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    List agent presence records.

    Uses the all_workspaces secondary index for O(M) lookup where M is the
    number of active workspaces, instead of O(N) SCAN over all Redis keys.

    Args:
        workspace_id: If provided, return the presence for this workspace only.
                      Otherwise, list all presences.
    """
    if workspace_id:
        # One agent per workspace - direct lookup
        key = _presence_key(workspace_id)
        data: Dict[str, str] = await redis.hgetall(key)
        return [data] if data else []

    # List all presences using secondary index (avoids SCAN)
    idx_key = _all_workspaces_index_key()
    workspace_ids = await _filter_valid_workspace_ids(redis, idx_key)

    if not workspace_ids:
        return []

    # Batch fetch all presence hashes with pipeline (N round-trips → 1)
    pipe = redis.pipeline()
    for ws_id in workspace_ids:
        pipe.hgetall(_presence_key(ws_id))
    presence_data = await pipe.execute()

    results: List[Dict[str, str]] = []
    for data in presence_data:
        if data:
            results.append(data)

    return results


async def list_agent_presences_by_workspace_ids(
    redis: Redis,
    workspace_ids: List[str],
) -> List[Dict[str, str]]:
    """
    Fetch presence records for specific workspace IDs.

    This avoids scanning global indexes when callers already know which
    workspaces they need to enrich with presence.
    """
    if not workspace_ids:
        return []

    pipe = redis.pipeline()
    for ws_id in workspace_ids:
        pipe.hgetall(_presence_key(ws_id))
    presence_data = await pipe.execute()

    results: List[Dict[str, str]] = []
    for data in presence_data:
        if data:
            results.append(data)

    return results


async def list_agent_presences_by_ids(
    redis: Redis,
    agent_ids: List[str],
) -> List[Dict[str, str]]:
    """Compatibility wrapper for the upstream agent-level presence API."""
    return await list_agent_presences_by_workspace_ids(redis, agent_ids)


async def _filter_valid_workspace_ids(
    redis: Redis,
    idx_key: str,
) -> List[str]:
    """
    Filter workspace_ids from a secondary index, removing stale entries.

    Uses Redis pipeline to batch EXISTS checks (N+1 round-trips → 2:
    one SMEMBERS + one pipeline for all EXISTS checks).

    Stale entries (presence expired but index entry remains) are lazily
    removed from the index. There's a theoretical race where a workspace
    could be removed from the index just as it refreshes presence, but
    the entry gets re-added on next presence update.

    Args:
        redis: Redis client.
        idx_key: Key for the secondary index (Set).

    Returns:
        List of workspace_ids with active presence.
    """
    members = await redis.smembers(idx_key)
    if not members:
        return []

    # Normalize to strings
    workspace_ids = [
        ws_id.decode("utf-8") if isinstance(ws_id, bytes) else ws_id for ws_id in members
    ]

    # Batch EXISTS checks with pipeline (N round-trips → 1)
    pipe = redis.pipeline()
    for ws_id in workspace_ids:
        pipe.exists(_presence_key(ws_id))
    exists_results = await pipe.execute()

    # Separate valid and stale workspace_ids
    valid_workspace_ids: List[str] = []
    stale_workspace_ids: List[str] = []
    for ws_id, exists in zip(workspace_ids, exists_results):
        if exists:
            valid_workspace_ids.append(ws_id)
        else:
            stale_workspace_ids.append(ws_id)

    # Lazy cleanup: remove stale entries from index
    if stale_workspace_ids:
        cleanup_pipe = redis.pipeline()
        for ws_id in stale_workspace_ids:
            cleanup_pipe.srem(idx_key, ws_id)
        await cleanup_pipe.execute()

    return valid_workspace_ids


async def get_workspace_ids_by_team_id(
    redis: Redis,
    team_id: str,
) -> List[str]:
    """
    Get all workspace_ids that belong to a team by address.

    Uses secondary index for O(1) lookup. Stale entries (presence expired but
    index entry remains) are filtered out and lazily removed from the index.

    Args:
        team_id: Team address string.

    Returns:
        List of workspace_ids in the team.
    """
    idx_key = _team_workspaces_index_key(team_id)
    return await _filter_valid_workspace_ids(redis, idx_key)


async def get_workspace_ids_by_repo_id(
    redis: Redis,
    repo_id: str,
) -> List[str]:
    """
    Get all workspace_ids that belong to a repo by ID.

    Uses secondary index for O(1) lookup. Stale entries (presence expired but
    index entry remains) are filtered out and lazily removed from the index.

    Args:
        repo_id: Repo UUID.

    Returns:
        List of workspace_ids in the repo.
    """
    idx_key = _repo_workspaces_index_key(repo_id)
    return await _filter_valid_workspace_ids(redis, idx_key)


async def get_workspace_ids_by_branch(
    redis: Redis,
    repo_id: str,
    branch: str,
) -> List[str]:
    """
    Get all workspace_ids working on a specific branch of a repo.

    Uses secondary index for O(1) lookup. Stale entries (presence expired but
    index entry remains) are filtered out and lazily removed from the index.

    Args:
        repo_id: Repo UUID.
        branch: Branch name.

    Returns:
        List of workspace_ids on the branch.
    """
    idx_key = _branch_workspaces_index_key(repo_id, branch)
    return await _filter_valid_workspace_ids(redis, idx_key)


async def get_all_workspace_ids(
    redis: Redis,
) -> List[str]:
    """
    Get all workspace_ids with active presence.

    Uses the global all_workspaces index. Stale entries (presence expired but
    index entry remains) are filtered out and lazily removed from the index.

    Returns:
        List of all active workspace_ids.
    """
    idx_key = _all_workspaces_index_key()
    return await _filter_valid_workspace_ids(redis, idx_key)


async def get_workspace_id_by_alias(
    redis: Redis,
    team_id: str,
    alias: str,
) -> Optional[str]:
    """
    Get the workspace_id using a specific alias within a team.

    Uses the alias secondary index for O(1) lookup. Returns the workspace_id
    if the alias is in use and the workspace has active presence, None otherwise.

    Note: This is for presence-based collision checking only. The database
    (workspaces table) is the authoritative source for alias ownership.

    Args:
        team_id: Team address string.
        alias: The alias to look up.

    Returns:
        workspace_id if alias is in use with active presence, None otherwise.
    """
    idx_key = _alias_index_key(team_id, alias)
    workspace_id = await redis.get(idx_key)

    if not workspace_id:
        return None

    # Normalize to string (may be bytes depending on Redis client config)
    ws_id = workspace_id.decode("utf-8") if isinstance(workspace_id, bytes) else workspace_id

    # Verify presence is still active (index may outlive presence due to TTL difference)
    presence_key = _presence_key(ws_id)
    if not await redis.exists(presence_key):
        # Stale index entry - lazy cleanup
        await redis.delete(idx_key)
        return None

    return ws_id


async def clear_workspace_presence(
    redis: Redis,
    workspace_ids: List[str],
) -> int:
    """
    Clear presence for a list of workspaces.

    Deletes presence keys and removes from all secondary indexes.
    Used when soft-deleting repos or projects.

    Args:
        workspace_ids: List of workspace UUIDs to clear.

    Returns:
        Number of presence keys deleted.
    """
    if not workspace_ids:
        return 0

    # Delete presence keys
    pipe = redis.pipeline()
    for ws_id in workspace_ids:
        pipe.delete(_presence_key(ws_id))
    results = await pipe.execute()
    deleted_count = sum(1 for r in results if r)

    # Remove from all secondary indexes (lazy cleanup handles misses)
    # We remove from all possible indexes to ensure cleanup
    all_idx_key = _all_workspaces_index_key()
    pipe = redis.pipeline()
    for ws_id in workspace_ids:
        pipe.srem(all_idx_key, ws_id)
    await pipe.execute()

    return deleted_count
