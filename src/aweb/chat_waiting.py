"""Chat SSE connection tracking via Redis sorted sets.

Tracks which agents have active SSE streams on a chat session. Uses
ZADD with timestamp scores for registration, ZSCORE for presence checks,
and ZREM for cleanup. All functions gracefully degrade when redis is None.
"""

from __future__ import annotations

import time


def _chat_waiting_key(session_id: str) -> str:
    return f"chat:waiting:{session_id}"


async def register_waiting(
    redis,
    session_id: str,
    agent_id: str,
    ttl_seconds: int = 90,
) -> None:
    """Register an agent as waiting (connected via SSE) on a session."""
    if redis is None:
        return

    key = _chat_waiting_key(session_id)
    await redis.zadd(key, {agent_id: time.time()})
    await redis.expire(key, ttl_seconds)


async def unregister_waiting(
    redis,
    session_id: str,
    agent_id: str,
) -> None:
    """Unregister an agent from a session (SSE disconnected)."""
    if redis is None:
        return

    await redis.zrem(_chat_waiting_key(session_id), agent_id)


async def is_agent_waiting(
    redis,
    session_id: str,
    agent_id: str,
    max_age_seconds: int = 90,
) -> bool:
    """Check if an agent has an active (non-stale) SSE connection on a session."""
    if redis is None:
        return False

    key = _chat_waiting_key(session_id)
    score = await redis.zscore(key, agent_id)
    if score is None:
        return False

    if time.time() - score > max_age_seconds:
        await redis.zrem(key, agent_id)
        return False

    return True


async def get_waiting_agents(
    redis,
    session_id: str,
    agent_ids: list[str],
    max_age_seconds: int = 90,
) -> list[str]:
    """Return the subset of agent_ids that have active SSE connections."""
    if redis is None or not agent_ids:
        return []

    key = _chat_waiting_key(session_id)
    cutoff = time.time() - max_age_seconds

    pipe = redis.pipeline()
    for aid in agent_ids:
        pipe.zscore(key, aid)
    scores = await pipe.execute()

    waiting = []
    for aid, score in zip(agent_ids, scores):
        if score is not None and score >= cutoff:
            waiting.append(aid)

    return waiting
