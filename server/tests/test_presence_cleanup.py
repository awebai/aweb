"""Presence cleanup runs the real Redis transactions, scans and Lua script."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from urllib.parse import quote
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import Depends, Request
from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from aweb.presence import (
    clear_workspace_presence,
    refresh_agent_presence,
    update_agent_presence,
)
from test_dashboard_privacy import privacy_app as privacy_app

__all__ = ["privacy_app"]


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
async def test_clear_workspace_presence_removes_workspace_and_agent_heartbeat_ids(
    world,
):
    redis = world.redis
    await _heartbeat(world)
    await update_agent_presence(
        redis, agent_id=world.agent, alias="worker", team_id=world.team
    )
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
async def test_pre_coordinate_enumeration_failure_is_non_success_then_retryable(
    world, monkeypatch
):
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
        assert await world.redis.sismember(
            f"idx:team_workspaces:{world.team}", world.workspace
        )
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
        assert await world.redis.sismember(
            f"idx:team_workspaces:{world.team}", world.workspace
        )
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "branch", ["feat/slash", "literal%", "remote:branch", "with space", "é/分支"]
)
async def test_presence_refresh_renews_the_encoded_index_for_supplied_and_retained_branches(
    world, branch
):
    redis = world.redis
    await update_agent_presence(
        redis,
        workspace_id=world.workspace,
        alias="worker",
        team_id=world.team,
        repo_id=world.repo,
        current_branch=branch,
        program="aw",
        model="test-model",
        status="busy",
        timezone="Europe/Madrid",
        ttl_seconds=30,
    )
    index = f"idx:branch_workspaces:{world.repo}:{quote(branch, safe='')}"
    assert await redis.sismember(index, world.workspace)
    await redis.expire(index, 5)
    retained = await refresh_agent_presence(
        redis,
        workspace_id=world.workspace,
        alias="worker",
        team_id=world.team,
        ttl_seconds=30,
        projection={"program": None, "model": ""},
    )
    assert retained["repo_id"] == world.repo
    assert retained["current_branch"] == branch
    assert (
        retained["status"],
        retained["program"],
        retained["model"],
        retained["timezone"],
    ) == (
        "busy",
        "aw",
        "test-model",
        "Europe/Madrid",
    )
    assert 5 < await redis.ttl(index) <= 60

    await redis.expire(index, 5)
    changed = await refresh_agent_presence(
        redis,
        workspace_id=world.workspace,
        alias="worker",
        team_id=world.team,
        ttl_seconds=30,
        projection={"current_branch": "next"},
    )
    assert changed["current_branch"] == "next"
    assert 0 < await redis.ttl(index) <= 5
    assert await redis.sismember(
        f"idx:branch_workspaces:{world.repo}:next", world.workspace
    )

    last_seen = await update_agent_presence(
        redis,
        workspace_id=world.workspace,
        alias="worker",
        team_id=world.team,
        program="",
        current_branch="",
        ttl_seconds=30,
    )
    stored = await redis.hgetall(f"presence:{world.workspace}")
    assert (
        stored["program"],
        stored["current_branch"],
        stored["status"],
        stored["last_seen"],
    ) == (
        "",
        "",
        "busy",
        last_seen,
    )
    await clear_workspace_presence(redis, [world.workspace])
    assert not await redis.sismember(index, world.workspace)
    assert not await redis.sismember(
        f"idx:branch_workspaces:{world.repo}:next", world.workspace
    )


@pytest.mark.asyncio
async def test_twenty_concurrent_presence_writers_retain_one_complete_generation(world):
    await _heartbeat(world)
    redis = world.redis
    results = await asyncio.gather(
        *(
            refresh_agent_presence(
                redis,
                workspace_id=world.workspace,
                alias="worker",
                team_id=world.team,
                projection={"program": f"worker-{index}"},
            )
            for index in range(20)
        )
    )
    assert {result["program"] for result in results} == {
        f"worker-{index}" for index in range(20)
    }
    assert {
        (result["repo_id"], result["current_branch"], result["status"])
        for result in results
    } == {
        (world.repo, "main", "active"),
    }
    assert await redis.sismember(
        f"idx:branch_workspaces:{world.repo}:main", world.workspace
    )


@pytest.mark.asyncio
async def test_presence_cleanup_racing_an_atomic_writer_leaves_only_the_winning_generation(
    world,
):
    await _heartbeat(world)
    redis = world.redis
    await asyncio.gather(
        clear_workspace_presence(redis, [world.workspace]),
        update_agent_presence(
            redis,
            workspace_id=world.workspace,
            alias="worker-next",
            team_id=world.team,
            repo_id=world.next_repo,
            current_branch="next",
        ),
    )
    stored = await redis.hgetall(f"presence:{world.workspace}")
    if not stored:
        await _assert_absent(world)
        return
    assert stored["repo_id"] == world.next_repo
    assert stored["current_branch"] == "next"
    assert await redis.get(world.next_alias) == world.workspace
    assert await redis.sismember(
        f"idx:branch_workspaces:{world.next_repo}:next", world.workspace
    )
    await clear_workspace_presence(redis, [world.workspace])
    await _assert_absent(world)


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
@pytest.mark.parametrize(
    "hosted_scope", ["none", "exact", "wrong-team", "wrong-workspace"]
)
async def test_native_heartbeat_writes_presence_once(
    privacy_app, monkeypatch, expired, hosted_scope
):
    from aweb.deps import get_db
    from aweb.presence import HostedHeartbeatPresence
    from test_dashboard_privacy import TEAM
    from test_messages_http import _signed_team_headers
    from test_team_auth_deps import _admitted_cert_info

    env = privacy_app
    member, _ = await _admitted_cert_info(env, alias="bob")
    workspace = str(
        await env.db.fetch_value(
            "SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id=$1 AND deleted_at IS NULL",
            member.id,
        )
    )
    assert workspace != "None"
    await update_agent_presence(
        env.redis,
        workspace_id=workspace,
        alias="bob",
        team_id=TEAM,
        program="rich",
        status="busy",
    )
    key = f"presence:{workspace}"
    if expired:
        await env.redis.pexpire(key, 0)
    if hosted_scope != "none":
        path = "/v1/agents/heartbeat"
        route = next(
            item for item in env.app.routes if getattr(item, "path", None) == path
        )
        authenticate = next(
            dep.call for dep in route.dependant.dependencies if dep.name == "identity"
        )
        projection = {
            "canonical_origin": "example.test/repo",
            "current_branch": "feature/x",
            "human_name": "Fixture",
            "member_email": "seat@example.test",
            "repo_id": str(uuid4()),
            "role": "analyst",
        }
        hosted = HostedHeartbeatPresence(
            str(uuid4()) if hosted_scope == "wrong-workspace" else workspace,
            "other:example.test" if hosted_scope == "wrong-team" else TEAM,
            projection,
        )

        async def embedded_identity(request: Request, db=Depends(get_db)):
            identity = await authenticate(request, db)
            request.state.hosted_heartbeat_presence = hosted
            return identity

        monkeypatch.setitem(
            env.app.dependency_overrides, authenticate, embedded_identity
        )
    calls = []
    execute = env.redis.execute_command

    async def observe(command, *args, **kwargs):
        calls.append((command, args))
        return await execute(command, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(env.redis, "execute_command", observe)
        response = await env.client.post(
            "/v1/agents/heartbeat",
            headers=_signed_team_headers(
                member.sk,
                member.did,
                TEAM,
                member.certificate,
                b"",
            ),
        )
    assert response.status_code == 200, response.text
    assert [command for command, args in calls if key in args] == ["EVAL"]
    stored = await env.redis.hgetall(key)
    assert stored["last_seen"] == response.json()["last_seen_at"]
    assert (stored.get("program"), stored["status"]) == (
        (None, "active") if expired else ("rich", "busy")
    )
    if hosted_scope != "none":
        assert {key: stored.get(key) for key in projection} == (
            projection if hosted_scope == "exact" else dict.fromkeys(projection)
        )
    await clear_workspace_presence(env.redis, [workspace])
