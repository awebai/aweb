"""Presence cleanup runs the real Redis transactions, scans and Lua script."""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from aweb.presence import clear_workspace_presence, update_agent_presence


@pytest_asyncio.fixture
async def world():
    token = uuid4().hex
    async with Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as redis:
        env = SimpleNamespace(
            redis=redis,
            workspace=f"workspace-{token}",
            live=f"live-{token}",
            agent=f"agent-{token}",
            team=f"backend-{token}:acme.test",
            repo=f"repo-{token}",
            next_repo=f"next-repo-{token}",
        )
        env.alias = f"idx:alias:backend-{token}%3Aacme.test:worker"
        env.next_alias = f"idx:alias:backend-{token}%3Aacme.test:worker-next"
        try:
            yield env
        finally:
            # Only this fixture's IDs/indices; never flush shared Redis.
            await clear_workspace_presence(redis, [env.workspace, env.live, env.agent])
            await redis.delete(
                f"idx:team_workspaces:{env.team}",
                f"idx:repo_workspaces:{env.repo}",
                f"idx:branch_workspaces:{env.repo}:main",
                f"idx:repo_workspaces:{env.next_repo}",
                f"idx:branch_workspaces:{env.next_repo}:next",
                env.alias,
                env.next_alias,
            )


async def _heartbeat(world):
    await update_agent_presence(
        world.redis,
        workspace_id=world.workspace,
        alias="worker",
        team_id=world.team,
        repo_id=world.repo,
        current_branch="main",
    )


async def _assert_absent(world):
    redis = world.redis
    assert not await redis.exists(f"presence:{world.workspace}")
    assert not await redis.exists(f"presence_coordinates:{world.workspace}")
    for key in (
        "idx:all_workspaces",
        f"idx:team_workspaces:{world.team}",
        f"idx:repo_workspaces:{world.repo}",
        f"idx:branch_workspaces:{world.repo}:main",
        f"idx:repo_workspaces:{world.next_repo}",
        f"idx:branch_workspaces:{world.next_repo}:next",
    ):
        assert not await redis.sismember(key, world.workspace), key


@pytest.mark.asyncio
async def test_clear_workspace_presence_removes_every_production_index(world):
    await _heartbeat(world)
    assert await clear_workspace_presence(world.redis, [world.workspace]) == 1
    await _assert_absent(world)
    assert await world.redis.get(world.alias) is None


@pytest.mark.asyncio
async def test_clear_workspace_presence_uses_all_historical_coordinates_after_primary_expires(
    world,
):
    redis = world.redis
    await _heartbeat(world)
    await update_agent_presence(
        redis,
        workspace_id=world.workspace,
        alias="worker-next",
        team_id=world.team,
        repo_id=world.next_repo,
        current_branch="next",
    )
    await update_agent_presence(
        redis,
        workspace_id=world.live,
        alias="live",
        team_id=world.team,
        repo_id=world.next_repo,
        current_branch="next",
        ttl_seconds=100,
    )
    # Redis expires the actual primary; reverse coordinates must outlive it.
    await redis.pexpire(f"presence:{world.workspace}", 0)
    assert not await redis.exists(f"presence:{world.workspace}")
    assert await redis.ttl(f"presence_coordinates:{world.workspace}") == -1
    assert 0 < await redis.pttl(f"idx:repo_workspaces:{world.next_repo}") <= 200_000
    assert await clear_workspace_presence(redis, [world.workspace]) == 0
    await _assert_absent(world)
    assert await redis.get(world.alias) is None
    assert await redis.get(world.next_alias) is None
    assert await redis.sismember(f"idx:team_workspaces:{world.team}", world.live)
    assert await redis.sismember(f"idx:repo_workspaces:{world.next_repo}", world.live)


@pytest.mark.asyncio
async def test_clear_workspace_presence_removes_workspace_and_agent_heartbeat_ids(world):
    redis = world.redis
    await _heartbeat(world)
    await update_agent_presence(redis, agent_id=world.agent, alias="worker", team_id=world.team)
    assert await clear_workspace_presence(redis, [world.workspace, world.agent]) == 2
    await _assert_absent(world)
    assert not await redis.sismember("idx:all_workspaces", world.agent)
    assert not await redis.sismember(f"idx:team_workspaces:{world.team}", world.agent)
    assert not await redis.exists(f"presence_coordinates:{world.agent}")
    assert await redis.get(world.alias) is None


async def _pre_coordinate_presence(world):
    redis = world.redis
    for key in (
        "idx:all_workspaces",
        f"idx:team_workspaces:{world.team}",
        f"idx:repo_workspaces:{world.repo}",
        f"idx:branch_workspaces:{world.repo}:main",
    ):
        await redis.sadd(key, world.workspace)
    await redis.set(world.alias, world.workspace)


@pytest.mark.asyncio
async def test_clear_workspace_presence_recovers_pre_coordinate_indices(world):
    await _pre_coordinate_presence(world)
    assert await clear_workspace_presence(world.redis, [world.workspace]) == 0
    await _assert_absent(world)
    assert await world.redis.get(world.alias) is None


@pytest.mark.asyncio
async def test_pre_coordinate_enumeration_failure_is_non_success_then_retryable(world, monkeypatch):
    await _pre_coordinate_presence(world)
    real_scan = world.redis.scan_iter
    failed = False

    async def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise ConnectionError("enumeration unavailable")
        async for key in real_scan(*args, **kwargs):
            yield key

    # Interrupt transport enumeration, never substitute its index results.
    with monkeypatch.context() as patch:
        patch.setattr(world.redis, "scan_iter", fail_once)
        with pytest.raises(ConnectionError, match="enumeration unavailable"):
            await clear_workspace_presence(world.redis, [world.workspace])
        assert await world.redis.sismember(f"idx:team_workspaces:{world.team}", world.workspace)
        assert not await world.redis.exists(f"presence_coordinates:{world.workspace}")
        assert await clear_workspace_presence(world.redis, [world.workspace]) == 0
    await _assert_absent(world)


@pytest.mark.asyncio
async def test_pre_coordinate_map_commit_response_loss_is_retryable(world, monkeypatch):
    await _pre_coordinate_presence(world)
    real_hset = world.redis.hset
    failed = False

    async def lose_once(name, *args, **kwargs):
        nonlocal failed
        result = await real_hset(name, *args, **kwargs)
        if name == f"presence_coordinates:{world.workspace}" and not failed:
            failed = True
            raise ConnectionError("lost response after fallback map commit")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(world.redis, "hset", lose_once)
        with pytest.raises(ConnectionError, match="fallback map commit"):
            await clear_workspace_presence(world.redis, [world.workspace])
        assert await world.redis.exists(f"presence_coordinates:{world.workspace}")
        assert await world.redis.sismember(f"idx:team_workspaces:{world.team}", world.workspace)
        assert await clear_workspace_presence(world.redis, [world.workspace]) == 0
    await _assert_absent(world)
    assert await world.redis.get(world.alias) is None


@pytest.mark.asyncio
async def test_clear_workspace_presence_retries_after_atomic_commit_response_loss(
    world, monkeypatch
):
    await _heartbeat(world)
    real_eval = world.redis.eval
    failed = False

    async def lose_once(*args, **kwargs):
        nonlocal failed
        result = await real_eval(*args, **kwargs)
        if not failed:
            failed = True
            raise ConnectionError("lost Redis response after atomic cleanup")
        return result

    # The actual Lua script commits before the response-loss fault.
    with monkeypatch.context() as patch:
        patch.setattr(world.redis, "eval", lose_once)
        with pytest.raises(ConnectionError, match="lost Redis response"):
            await clear_workspace_presence(world.redis, [world.workspace])
        await _assert_absent(world)
        assert await clear_workspace_presence(world.redis, [world.workspace]) == 0
    await _assert_absent(world)
    assert await world.redis.get(world.alias) is None


@pytest.mark.asyncio
async def test_clear_workspace_presence_preserves_concurrently_reused_alias(world):
    await _heartbeat(world)
    await update_agent_presence(
        world.redis,
        workspace_id=world.live,
        alias="worker",
        team_id=world.team,
    )
    assert await world.redis.get(world.alias) == world.live
    assert await clear_workspace_presence(world.redis, [world.workspace]) == 1
    assert await world.redis.get(world.alias) == world.live
    assert await world.redis.exists(f"presence:{world.live}")
    await _assert_absent(world)
