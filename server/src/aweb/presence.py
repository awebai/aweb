from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone as timezone_mod
from typing import Dict, List, Optional, cast

from redis.asyncio import Redis

from .coordination.roles import ROLE_MAX_LENGTH, is_valid_role, normalize_role

DEFAULT_PRESENCE_TTL_SECONDS = 1800  # 30 minutes
_PRESENCE_PROJECTION_FIELDS = frozenset({
    "program", "model", "human_name", "repo_id", "member_email", "status",
    "current_branch", "role", "canonical_origin", "timezone",
})


@dataclass(frozen=True)
class HostedHeartbeatPresence:
    """Already-loaded host fields for an exact workspace and canonical team."""

    workspace_id: str
    team_id: str
    projection: Mapping[str, str | None]


def _presence_key(workspace_id: str) -> str:
    """Presence key: one agent per workspace."""
    return f"presence:{workspace_id}"


def _presence_coordinates_key(workspace_id: str) -> str:
    """Durable cleanup coordinates that outlive the primary presence key."""
    return f"presence_coordinates:{workspace_id}"


def _all_workspaces_index_key() -> str:
    """Global index: all workspace_ids with active presence."""
    return "idx:all_workspaces"


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
    member_email: Optional[str] = None,
    status: Optional[str] = None,
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
        status: Preserved when omitted. A new record defaults to active.
        current_branch: Optional branch name.
        role: Brief description of workspace purpose (max 50 chars).
        canonical_origin: Normalized repo origin (e.g. "github.com/org/repo").
        timezone: IANA timezone (e.g. "Europe/Madrid"). Preserved when None.
        ttl_seconds: How long until presence expires if not refreshed. Defaults to the configured heartbeat window at each serving caller.
    """
    workspace_id = workspace_id or agent_id
    if not workspace_id:
        raise ValueError("workspace_id or agent_id is required")

    now = datetime.now(timezone_mod.utc).isoformat()

    fields = {
        "workspace_id": workspace_id,
        "alias": alias,
        "team_id": team_id or "",
        "last_seen": now,
    }
    # None means this heartbeat did not carry the coordinate. An explicit
    # empty string still clears it; narrow heartbeats cannot erase richer ones.
    for name, value in {
        "human_name": human_name,
        "repo_id": repo_id,
        "member_email": member_email,
        "status": status,
        "program": program,
        "model": model,
        "current_branch": current_branch,
    }.items():
        if value is not None:
            fields[name] = value
    if canonical_origin is not None:
        fields["canonical_origin"] = canonical_origin
    if role is not None and len(role) <= ROLE_MAX_LENGTH and is_valid_role(role):
        fields["role"] = normalize_role(role)
    if timezone is not None:
        fields["timezone"] = timezone

    await _store_presence_fields(
        redis,
        workspace_id=workspace_id,
        fields=fields,
        ttl_seconds=ttl_seconds,
    )

    return now


async def refresh_agent_presence(
    redis: Redis,
    *,
    workspace_id: str,
    team_id: str,
    alias: str,
    ttl_seconds: int = DEFAULT_PRESENCE_TTL_SECONDS,
    projection: Mapping[str, str | None] | None = None,
) -> dict[str, str]:
    """Refresh a verified workspace with known projection fields and return its merged hash."""
    supplied = projection if projection is not None else {}
    if supplied.keys() - _PRESENCE_PROJECTION_FIELDS:
        raise ValueError("Unknown field in the workspace presence projection")
    fields = {name: value for name, value in supplied.items() if value is not None and value != ""}
    if role := fields.pop("role", None):
        if len(role) <= ROLE_MAX_LENGTH and is_valid_role(role):
            fields["role"] = normalize_role(role)
    fields.update(
        workspace_id=workspace_id,
        team_id=team_id,
        alias=alias,
        last_seen=datetime.now(timezone_mod.utc).isoformat(),
    )
    return await _store_presence_fields(redis, workspace_id=workspace_id, fields=fields, ttl_seconds=ttl_seconds)


_STORE_PRESENCE = """
local key, coordinates = KEYS[1], KEYS[2]
local workspace, ttl = ARGV[1], tonumber(ARGV[2])
local index_ttl = ttl * 2

-- Match urllib.parse.quote(value, safe="") over UTF-8 bytes, including
-- preserved values read from Redis and values supplied by this writer.
local function key_component(value)
    return string.gsub(value, '([^A-Za-z0-9_%.~%-])', function(byte)
        return string.format('%%%02X', string.byte(byte))
    end)
end

redis.call('HSET', key, unpack(ARGV, 3))
redis.call('HSETNX', key, 'status', 'active')
local merged = redis.call('HGETALL', key)
local fields = {}
for i = 1, #merged, 2 do
    fields[merged[i]] = merged[i + 1]
end
redis.call('EXPIRE', key, ttl)

local function renew_set(index)
    redis.call('SADD', index, workspace)
    redis.call('EXPIRE', index, index_ttl)
    redis.call('HSET', coordinates, 'set:' .. index, '1')
end
renew_set('idx:all_workspaces')
if fields.team_id and fields.team_id ~= '' then
    renew_set('idx:team_workspaces:' .. fields.team_id)
    local alias = 'idx:alias:' .. key_component(fields.team_id) .. ':' .. key_component(fields.alias or '')
    redis.call('SET', alias, workspace, 'EX', index_ttl)
    redis.call('HSET', coordinates, 'alias:' .. alias, workspace)
end
if fields.repo_id and fields.repo_id ~= '' then
    renew_set('idx:repo_workspaces:' .. fields.repo_id)
    if fields.current_branch and fields.current_branch ~= '' then
        renew_set('idx:branch_workspaces:' .. fields.repo_id .. ':' .. key_component(fields.current_branch))
    end
end
redis.call('PERSIST', coordinates)
return merged
"""


async def _store_presence_fields(
    redis: Redis,
    *,
    workspace_id: str,
    fields: dict[str, str],
    ttl_seconds: int,
) -> dict[str, str]:
    """Commit one metadata generation and its current indices atomically."""
    arguments = [entry for item in fields.items() for entry in item]
    reply = await cast(Awaitable[list[str | bytes]], redis.eval(
        _STORE_PRESENCE, 2, _presence_key(workspace_id), _presence_coordinates_key(workspace_id),
        workspace_id, ttl_seconds, *arguments,
    ))
    values = [value.decode("utf-8") if isinstance(value, bytes) else value for value in reply]
    return dict(zip(values[::2], values[1::2], strict=True))


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


async def list_agent_presences_by_workspace_ids(
    redis: Redis,
    workspace_ids: List[str],
    *,
    fields: tuple[str, ...] | None = None,
) -> List[Dict[str, str]]:
    """
    Fetch presence records for specific workspace IDs.

    This avoids scanning global indexes when callers already know which
    workspaces they need to enrich with presence. A projection avoids reading
    the full hashes when a caller only consumes named fields.
    """
    if not workspace_ids:
        return []

    pipe = redis.pipeline()
    if fields is None:
        for ws_id in workspace_ids:
            pipe.hgetall(_presence_key(ws_id))
        return [data for data in await pipe.execute() if data]

    hash_fields = list(fields)
    for ws_id in workspace_ids:
        pipe.hmget(_presence_key(ws_id), hash_fields)
    results = []
    for values in await pipe.execute():
        projected = {
            field: value
            for field, value in zip(hash_fields, values, strict=True)
            if value is not None
        }
        if projected:
            results.append(projected)
    return results


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

    def text(value) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    async def recover_pre_coordinate_indices(ws_id: str) -> None:
        coordinates_key = _presence_coordinates_key(ws_id)
        if await redis.exists(coordinates_key):
            return
        # Upgrade fallback for presence written before reverse coordinates
        # existed (or by an interrupted older writer). A completed scan is
        # persisted before cleanup, so failure never becomes false success.
        recovered = {"scan-complete": "1"}
        for pattern in (
            "idx:team_workspaces:*",
            "idx:repo_workspaces:*",
            "idx:branch_workspaces:*",
        ):
            async for raw_key in redis.scan_iter(match=pattern):
                index_key = text(raw_key)
                if await redis.sismember(index_key, ws_id):
                    recovered[f"set:{index_key}"] = "1"
        async for raw_key in redis.scan_iter(match="idx:alias:*"):
            index_key = text(raw_key)
            if text(await redis.get(index_key)) == ws_id:
                recovered[f"alias:{index_key}"] = ws_id
        await redis.hset(coordinates_key, mapping=recovered)

    # Redis executes each script atomically: coordinates remain available until
    # every referenced set/alias mutation succeeds, then both primary and
    # coordinates are deleted as the final operations in the same commit.
    cleanup_script = """
        local primary_existed = redis.call('exists', KEYS[1])
        local coordinates = redis.call('hgetall', KEYS[2])
        for index = 1, #coordinates, 2 do
            local coordinate = coordinates[index]
            local expected = coordinates[index + 1]
            if string.sub(coordinate, 1, 4) == 'set:' then
                redis.call('srem', string.sub(coordinate, 5), ARGV[1])
            elseif string.sub(coordinate, 1, 6) == 'alias:' then
                local key = string.sub(coordinate, 7)
                if redis.call('get', key) == expected then
                    redis.call('del', key)
                end
            end
        end
        redis.call('srem', ARGV[2], ARGV[1])
        redis.call('del', KEYS[1])
        redis.call('del', KEYS[2])
        return primary_existed
    """
    deleted_count = 0
    for ws_id in workspace_ids:
        await recover_pre_coordinate_indices(ws_id)
        deleted_count += int(
            await redis.eval(
                cleanup_script,
                2,
                _presence_key(ws_id),
                _presence_coordinates_key(ws_id),
                ws_id,
                _all_workspaces_index_key(),
            )
        )
    return deleted_count
