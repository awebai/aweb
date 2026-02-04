"""Agent-level presence tracking via Redis with TTL.

Tracks which agents are currently online within a project. Presence is
ephemeral (Redis-backed with TTL) and best-effort — the agents table in
PostgreSQL is authoritative for identity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

DEFAULT_PRESENCE_TTL_SECONDS = 1800  # 30 minutes


def _presence_key(agent_id: str) -> str:
    return f"aweb:presence:{agent_id}"


def _project_agents_index_key(project_id: str) -> str:
    return f"aweb:idx:project_agents:{project_id}"


async def update_agent_presence(
    redis,
    agent_id: str,
    alias: str,
    project_id: str,
    *,
    status: str = "active",
    ttl_seconds: int = DEFAULT_PRESENCE_TTL_SECONDS,
) -> str:
    """Upsert agent presence in Redis. Returns the ISO timestamp used."""
    if redis is None:
        return datetime.now(timezone.utc).isoformat()

    now = datetime.now(timezone.utc).isoformat()

    fields = {
        "agent_id": agent_id,
        "alias": alias,
        "project_id": project_id,
        "status": status,
        "last_seen": now,
    }

    key = _presence_key(agent_id)
    await redis.hset(key, mapping=fields)
    await redis.expire(key, ttl_seconds)

    # Secondary index: agents by project. TTL is 2x presence TTL so stale
    # entries can be lazily cleaned up (they outlive the presence key).
    idx_key = _project_agents_index_key(project_id)
    await redis.sadd(idx_key, agent_id)
    await redis.expire(idx_key, ttl_seconds * 2)

    return now


async def get_agent_presence(
    redis,
    agent_id: str,
) -> Optional[dict[str, str]]:
    """Fetch an agent's presence record, or None if absent/expired."""
    if redis is None:
        return None

    data: dict[str, str] = await redis.hgetall(_presence_key(agent_id))
    return data if data else None


async def list_agent_presences_by_project(
    redis,
    project_id: str,
) -> list[dict[str, str]]:
    """List all agents with active presence in a project."""
    if redis is None:
        return []

    idx_key = _project_agents_index_key(project_id)
    valid_ids = await _filter_valid_agent_ids(redis, idx_key)
    if not valid_ids:
        return []

    pipe = redis.pipeline()
    for aid in valid_ids:
        pipe.hgetall(_presence_key(aid))
    results = await pipe.execute()

    return [d for d in results if d]


async def list_agent_presences_by_ids(
    redis,
    agent_ids: list[str],
) -> list[dict[str, str]]:
    """Fetch presence records for specific agent IDs."""
    if redis is None or not agent_ids:
        return []

    pipe = redis.pipeline()
    for aid in agent_ids:
        pipe.hgetall(_presence_key(aid))
    results = await pipe.execute()

    return [d for d in results if d]


async def clear_agent_presence(
    redis,
    agent_ids: list[str],
) -> int:
    """Clear presence for a list of agents. Returns count deleted."""
    if redis is None or not agent_ids:
        return 0

    pipe = redis.pipeline()
    for aid in agent_ids:
        pipe.delete(_presence_key(aid))
    results = await pipe.execute()
    return sum(1 for r in results if r)


async def _filter_valid_agent_ids(
    redis,
    idx_key: str,
) -> list[str]:
    """Filter agent_ids from a secondary index, removing stale entries.

    Uses pipeline batching for EXISTS checks and lazily removes stale
    entries from the index.
    """
    members = await redis.smembers(idx_key)
    if not members:
        return []

    agent_ids = [m.decode("utf-8") if isinstance(m, bytes) else m for m in members]

    pipe = redis.pipeline()
    for aid in agent_ids:
        pipe.exists(_presence_key(aid))
    exists_results = await pipe.execute()

    valid = []
    stale = []
    for aid, exists in zip(agent_ids, exists_results):
        if exists:
            valid.append(aid)
        else:
            stale.append(aid)

    if stale:
        cleanup = redis.pipeline()
        for aid in stale:
            cleanup.srem(idx_key, aid)
        await cleanup.execute()

    return valid
