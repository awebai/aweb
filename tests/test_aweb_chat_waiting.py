from __future__ import annotations

import time

import pytest

from aweb.chat_waiting import (
    get_waiting_agents,
    is_agent_waiting,
    register_waiting,
    unregister_waiting,
)


@pytest.mark.asyncio
async def test_register_and_check_waiting(async_redis):
    session_id = "sess-001"
    agent_id = "agent-aaa"

    await register_waiting(async_redis, session_id, agent_id)
    assert await is_agent_waiting(async_redis, session_id, agent_id) is True


@pytest.mark.asyncio
async def test_unregister_waiting(async_redis):
    session_id = "sess-002"
    agent_id = "agent-bbb"

    await register_waiting(async_redis, session_id, agent_id)
    assert await is_agent_waiting(async_redis, session_id, agent_id) is True

    await unregister_waiting(async_redis, session_id, agent_id)
    assert await is_agent_waiting(async_redis, session_id, agent_id) is False


@pytest.mark.asyncio
async def test_stale_entry_detected(async_redis):
    session_id = "sess-003"
    agent_id = "agent-ccc"

    # Register with a score far in the past (simulate stale entry).
    key = f"chat:waiting:{session_id}"
    await async_redis.zadd(key, {agent_id: time.time() - 200})

    # With default max_age_seconds=90, this should be stale.
    assert await is_agent_waiting(async_redis, session_id, agent_id, max_age_seconds=90) is False

    # Stale entry should have been auto-cleaned.
    score = await async_redis.zscore(key, agent_id)
    assert score is None


@pytest.mark.asyncio
async def test_get_waiting_agents_batch(async_redis):
    session_id = "sess-004"
    agent_a = "agent-aaa"
    agent_b = "agent-bbb"
    agent_c = "agent-ccc"

    await register_waiting(async_redis, session_id, agent_a)
    await register_waiting(async_redis, session_id, agent_b)
    # agent_c is NOT registered.

    waiting = await get_waiting_agents(async_redis, session_id, [agent_a, agent_b, agent_c])
    assert sorted(waiting) == sorted([agent_a, agent_b])


@pytest.mark.asyncio
async def test_session_isolation(async_redis):
    session_a = "sess-aaa"
    session_b = "sess-bbb"
    agent_id = "agent-111"

    await register_waiting(async_redis, session_a, agent_id)

    assert await is_agent_waiting(async_redis, session_a, agent_id) is True
    assert await is_agent_waiting(async_redis, session_b, agent_id) is False
    assert await get_waiting_agents(async_redis, session_b, [agent_id]) == []


@pytest.mark.asyncio
async def test_none_redis_graceful():
    session_id = "sess-005"
    agent_id = "agent-ddd"

    await register_waiting(None, session_id, agent_id)
    assert await is_agent_waiting(None, session_id, agent_id) is False
    await unregister_waiting(None, session_id, agent_id)
    assert await get_waiting_agents(None, session_id, [agent_id]) == []
