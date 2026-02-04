"""Tests for aweb agent presence module."""

from __future__ import annotations

import pytest

from aweb.presence import (
    clear_agent_presence,
    get_agent_presence,
    list_agent_presences_by_ids,
    list_agent_presences_by_project,
    update_agent_presence,
)


@pytest.mark.asyncio
async def test_update_and_get_presence(async_redis):
    ts = await update_agent_presence(
        async_redis,
        agent_id="agent-111",
        alias="alice",
        project_id="proj-aaa",
    )
    assert ts  # returns ISO timestamp

    presence = await get_agent_presence(async_redis, "agent-111")
    assert presence is not None
    assert presence["agent_id"] == "agent-111"
    assert presence["alias"] == "alice"
    assert presence["project_id"] == "proj-aaa"
    assert presence["status"] == "active"
    assert presence["last_seen"] == ts


@pytest.mark.asyncio
async def test_get_presence_nonexistent(async_redis):
    presence = await get_agent_presence(async_redis, "does-not-exist")
    assert presence is None


@pytest.mark.asyncio
async def test_list_presences_by_project(async_redis):
    await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
    )
    await update_agent_presence(
        async_redis, agent_id="a2", alias="bob", project_id="proj-1",
    )
    await update_agent_presence(
        async_redis, agent_id="a3", alias="carol", project_id="proj-2",
    )

    proj1 = await list_agent_presences_by_project(async_redis, "proj-1")
    assert len(proj1) == 2
    aliases = {p["alias"] for p in proj1}
    assert aliases == {"alice", "bob"}

    proj2 = await list_agent_presences_by_project(async_redis, "proj-2")
    assert len(proj2) == 1
    assert proj2[0]["alias"] == "carol"


@pytest.mark.asyncio
async def test_list_presences_by_ids(async_redis):
    await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
    )
    await update_agent_presence(
        async_redis, agent_id="a2", alias="bob", project_id="proj-1",
    )

    result = await list_agent_presences_by_ids(async_redis, ["a1"])
    assert len(result) == 1
    assert result[0]["alias"] == "alice"

    result = await list_agent_presences_by_ids(async_redis, ["a1", "a2"])
    assert len(result) == 2

    result = await list_agent_presences_by_ids(async_redis, ["nonexistent"])
    assert len(result) == 0

    result = await list_agent_presences_by_ids(async_redis, [])
    assert len(result) == 0


@pytest.mark.asyncio
async def test_clear_presence(async_redis):
    await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
    )
    await update_agent_presence(
        async_redis, agent_id="a2", alias="bob", project_id="proj-1",
    )

    deleted = await clear_agent_presence(async_redis, ["a1"])
    assert deleted == 1

    assert await get_agent_presence(async_redis, "a1") is None
    assert await get_agent_presence(async_redis, "a2") is not None


@pytest.mark.asyncio
async def test_presence_ttl_expires(async_redis):
    """Presence with very short TTL should expire."""
    await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
        ttl_seconds=1,
    )
    presence = await get_agent_presence(async_redis, "a1")
    assert presence is not None

    import asyncio
    await asyncio.sleep(1.5)

    presence = await get_agent_presence(async_redis, "a1")
    assert presence is None


@pytest.mark.asyncio
async def test_update_refreshes_presence(async_redis):
    """Updating presence should refresh the TTL and last_seen."""
    ts1 = await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
    )

    import asyncio
    await asyncio.sleep(0.1)

    ts2 = await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
    )
    assert ts2 > ts1

    presence = await get_agent_presence(async_redis, "a1")
    assert presence["last_seen"] == ts2


@pytest.mark.asyncio
async def test_stale_index_entries_cleaned_lazily(async_redis):
    """When presence expires but index entry remains, listing should clean up."""
    await update_agent_presence(
        async_redis, agent_id="a1", alias="alice", project_id="proj-1",
        ttl_seconds=1,
    )
    await update_agent_presence(
        async_redis, agent_id="a2", alias="bob", project_id="proj-1",
        ttl_seconds=3600,
    )

    import asyncio
    await asyncio.sleep(1.5)

    # a1's presence expired, but index may still reference it
    result = await list_agent_presences_by_project(async_redis, "proj-1")
    assert len(result) == 1
    assert result[0]["alias"] == "bob"


@pytest.mark.asyncio
async def test_none_redis_returns_empty():
    """All presence functions should handle redis=None gracefully."""
    assert await get_agent_presence(None, "a1") is None
    assert await list_agent_presences_by_project(None, "proj-1") == []
    assert await list_agent_presences_by_ids(None, ["a1"]) == []
    assert await clear_agent_presence(None, ["a1"]) == 0
