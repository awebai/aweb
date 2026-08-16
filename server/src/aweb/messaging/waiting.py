"""Chat SSE connection tracking via Redis sorted sets.

Tracks which agents have active SSE streams on a chat session. Uses
ZADD with timestamp scores for registration, ZSCORE for presence checks,
and ZREM for cleanup. User-facing helpers gracefully degrade when Redis is
unavailable; durable lifecycle delivery uses a strict unregister variant that
propagates Redis errors for retry.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

# Lua script for atomic stale-entry cleanup: only removes the member if
# its score is still below the cutoff (avoids TOCTOU race with concurrent refresh).
_STALE_CHECK_SCRIPT = """
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not score then
    return -1
end
if tonumber(score) < tonumber(ARGV[2]) then
    redis.call('ZREM', KEYS[1], ARGV[1])
    return 0
end
return 1
"""


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

    try:
        key = _chat_waiting_key(session_id)
        pipe = redis.pipeline()
        pipe.zadd(key, {agent_id: time.time()})
        pipe.expire(key, ttl_seconds)
        await pipe.execute()
    except Exception:
        logger.warning("Failed to register waiting for %s in %s", agent_id, session_id)


async def unregister_waiting_strict(
    redis,
    session_id: str,
    agent_id: str,
) -> None:
    """Unregister waiting state, propagating failure to durable callers."""
    if redis is None:
        return
    await redis.zrem(_chat_waiting_key(session_id), agent_id)


async def unregister_waiting(
    redis,
    session_id: str,
    agent_id: str,
) -> None:
    """Unregister an agent from a session (SSE disconnected)."""
    try:
        await unregister_waiting_strict(redis, session_id, agent_id)
    except Exception:
        logger.warning("Failed to unregister waiting for %s in %s", agent_id, session_id)


async def is_agent_waiting(
    redis,
    session_id: str,
    agent_id: str,
    max_age_seconds: int = 90,
) -> bool:
    """Check if an agent has an active (non-stale) SSE connection on a session."""
    if redis is None:
        return False

    try:
        key = _chat_waiting_key(session_id)
        cutoff = time.time() - max_age_seconds
        # Atomic check-and-cleanup: returns 1 if fresh, 0 if stale (removed), -1 if absent.
        result = await redis.eval(_STALE_CHECK_SCRIPT, 1, key, agent_id, cutoff)
        return result == 1
    except Exception:
        logger.warning("Failed to check waiting for %s in %s", agent_id, session_id)
        return False


async def get_waiting_agents(
    redis,
    session_id: str,
    agent_ids: list[str],
    max_age_seconds: int = 90,
) -> list[str]:
    """Return the subset of agent_ids that have active SSE connections."""
    if redis is None or not agent_ids:
        return []

    try:
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
    except Exception:
        logger.warning("Failed to get waiting agents for %s", session_id)
        return []


async def get_waiting_agents_by_session(
    redis,
    session_agents: dict[str, list[str]],
    max_age_seconds: int = 90,
) -> dict[str, list[str]]:
    """Return active waiting agents for multiple sessions in one Redis pipeline."""
    if redis is None or not session_agents:
        return {}

    try:
        cutoff = time.time() - max_age_seconds
        pipe = redis.pipeline()
        ordered_pairs: list[tuple[str, str]] = []
        for session_id, agent_ids in session_agents.items():
            for aid in agent_ids:
                ordered_pairs.append((session_id, aid))
                pipe.zscore(_chat_waiting_key(session_id), aid)
        scores = await pipe.execute()

        waiting: dict[str, list[str]] = {session_id: [] for session_id in session_agents}
        for (session_id, aid), score in zip(ordered_pairs, scores):
            if score is not None and score >= cutoff:
                waiting.setdefault(session_id, []).append(aid)
        return waiting
    except Exception:
        logger.warning("Failed to get waiting agents for %s sessions", len(session_agents))
        return {session_id: [] for session_id in session_agents}
