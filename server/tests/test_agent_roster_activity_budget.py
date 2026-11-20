"""Real native roster budget and newest-of-all-three activity evidence."""

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from pgdbm import AsyncDatabaseManager

from aweb import connection_scope
from aweb.embedding import OutboxRecoveryOwnership
from aweb.presence import clear_workspace_presence, update_agent_presence
from test_dashboard_privacy import TEAM, privacy_stack
from test_messages_http import _signed_team_headers
from test_team_room import admit_room_member
from test_workspace_liveness_http import GrantHeartbeatRoute, _send_grant_heartbeat


@pytest_asyncio.fixture
async def roster_stack(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


async def roster(env):
    actor = env.actors["alice"]
    response = await env.client.get(
        "/v1/agents",
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert response.status_code == 200, response.text
    return response.json()["agents"]


@pytest.mark.asyncio
async def test_warm_roster_uses_three_statements_and_one_pool_checkout(
    roster_stack, shared_test_pool, monkeypatch
):
    env = roster_stack
    await admit_room_member(env, alias="alice")
    await roster(env)
    statements, checkouts = [], []

    def observe_statement(original):
        async def observed(manager, sql, *args, **kwargs):
            if manager is env.db:
                statements.append(sql)
            return await original(manager, sql, *args, **kwargs)

        return observed

    for name in ("fetch_all", "fetch_one", "fetch_value", "execute"):
        monkeypatch.setattr(
            AsyncDatabaseManager,
            name,
            observe_statement(getattr(AsyncDatabaseManager, name)),
        )
    acquire = connection_scope._acquire_from

    async def observed_acquire(pool):
        if pool is shared_test_pool:
            checkouts.append(pool)
        return await acquire(pool)

    monkeypatch.setattr(connection_scope, "_acquire_from", observed_acquire)
    agents = await roster(env)
    assert any(agent["alias"] == "alice" for agent in agents)
    print(f"ROSTER_COST statements={len(statements)} checkouts={len(checkouts)}")
    assert len(statements) == 3, {"count": len(statements), "statements": statements}
    assert len(checkouts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("newest", ["grant", "redis", "sql"])
async def test_listening_roster_keeps_the_newest_activity_source(roster_stack, newest):
    env = roster_stack
    actor = env.actors["alice"]
    await admit_room_member(env, alias="alice")
    grant_id = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    now = datetime.now(UTC).replace(microsecond=0)
    times = {name: now - timedelta(minutes=5) for name in ("grant", "redis", "sql")}
    times[newest] = now - timedelta(minutes=1)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=$2 WHERE workspace_id=$1",
        actor.workspace,
        times["sql"],
    )
    await env.db.execute(
        "UPDATE {{tables.identity_grant_liveness}} SET last_seen_at=$2 WHERE grant_id=$1",
        grant_id,
        times["grant"],
    )
    await update_agent_presence(
        env.redis,
        workspace_id=str(actor.workspace),
        alias="alice",
        team_id=TEAM,
        status="listening",
    )
    await env.redis.hset(f"presence:{actor.workspace}", "last_seen", times["redis"].isoformat())
    try:
        agent = next(agent for agent in await roster(env) if agent["alias"] == "alice")
        assert agent["online"] is True
        assert agent["status"] == "listening"
        assert datetime.fromisoformat(agent["last_seen"]) == times[newest]
    finally:
        await clear_workspace_presence(env.redis, [str(actor.workspace)])


@pytest.mark.asyncio
async def test_invalid_newest_grant_does_not_hide_older_valid_activity(roster_stack):
    env = roster_stack
    actor = env.actors["alice"]
    await admit_room_member(env, alias="alice")
    older = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    newer = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    now = datetime.now(UTC).replace(microsecond=0)
    expected = now - timedelta(minutes=2)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=$2 WHERE workspace_id=$1",
        actor.workspace,
        now - timedelta(hours=1),
    )
    await env.db.execute(
        "UPDATE {{tables.identity_grant_liveness}} SET last_seen_at=$2 WHERE grant_id=$1",
        older,
        expected,
    )
    await env.db.execute(
        "UPDATE {{tables.identity_grant_liveness}} SET last_seen_at=$2 WHERE grant_id=$1",
        newer,
        now,
    )
    revoked = await env.client.post(
        f"/v1/identity-grants/{newer}/revoke",
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert revoked.status_code == 200, revoked.text
    # No root presence can supply the expected online time.
    await clear_workspace_presence(env.redis, [str(actor.workspace)])
    agent = next(agent for agent in await roster(env) if agent["alias"] == "alice")
    assert agent["online"] is True
    assert datetime.fromisoformat(agent["last_seen"]) == expected
