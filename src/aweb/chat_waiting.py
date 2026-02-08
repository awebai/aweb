"""Chat SSE connection tracking via Redis sorted sets.

Tracks which agents have active SSE streams on a chat session. Uses
ZADD with timestamp scores for registration, ZSCORE for presence checks,
and ZREM for cleanup. All functions gracefully degrade when redis is None
or on Redis errors.
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


async def unregister_waiting(
    redis,
    session_id: str,
    agent_id: str,
) -> None:
    """Unregister an agent from a session (SSE disconnected)."""
    if redis is None:
        return

    try:
        await redis.zrem(_chat_waiting_key(session_id), agent_id)
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
