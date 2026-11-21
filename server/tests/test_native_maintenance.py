"""Maintenance through real PostgreSQL, Redis, AWID, and HTTP writes."""

import asyncio
import json

import pytest
import pytest_asyncio

from aweb.application_state import RegistryClientUnavailable
from aweb.embedding import OutboxRecoveryOwnership
from aweb.events import team_events_channel_name
from aweb.maintenance import (
    NativeMaintenanceError,
    NativeMaintenanceStage,
    run_native_maintenance,
)
from aweb.presence import clear_workspace_presence
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM, privacy_stack


@pytest_asyncio.fixture
async def maintenance_app(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


@pytest.mark.asyncio
async def test_native_maintenance_publishes_presence_during_outbox_recovery(
    maintenance_app,
):
    env = maintenance_app
    # Age any starting activity so the signed heartbeat is the online edge.
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE team_id=$1",
        TEAM,
    )
    await clear_workspace_presence(
        env.redis, [str(actor.workspace) for actor in env.actors.values()]
    )
    arguments = dict(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        on_mutation=env.app.state.on_mutation,
    )
    await run_native_maintenance(**arguments)
    async with env.redis.pubsub() as subscriber:
        await subscriber.subscribe(team_events_channel_name(TEAM))
        subscribed = await subscriber.get_message(timeout=3)
        assert subscribed is not None and subscribed["type"] == "subscribe"
        response = await request_as(
            env, alias="alice", method="POST", path="/v1/agents/heartbeat"
        )
        assert response.status_code == 200, response.text
        assert (
            await run_native_maintenance(**arguments)
        ).presence.events_published == 1
        assert (
            await run_native_maintenance(**arguments)
        ).presence.events_published == 0
        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE workspace_id=$1",
            env.actors["alice"].workspace,
        )
        await clear_workspace_presence(env.redis, [str(env.actors["alice"].workspace)])
        assert (
            await run_native_maintenance(**arguments)
        ).presence.events_published == 1
        received = []
        async with asyncio.timeout(3):
            async for frame in subscriber.listen():
                if frame["type"] != "message":
                    continue
                event = json.loads(frame["data"])
                if event["type"] in {"agent.online", "agent.offline"}:
                    received.append((event["type"], event["alias"]))
                    if len(received) == 2:
                        break
    assert received == [("agent.online", "alice"), ("agent.offline", "alice")]


@pytest.mark.asyncio
async def test_missing_registry_reports_presence_failure_after_outbox_progress(
    maintenance_app,
):
    env = maintenance_app
    with pytest.raises(NativeMaintenanceError) as refused:
        await run_native_maintenance(
            db_infra=env.infra,
            redis=env.redis,
            registry_client=None,
            on_mutation=env.app.state.on_mutation,
        )
    assert refused.value.completed_stages == frozenset(
        {NativeMaintenanceStage.OUTBOX_RECOVERY}
    )
    (failure,) = refused.value.failures
    assert failure.stage is NativeMaintenanceStage.PRESENCE_RECONCILIATION
    assert isinstance(failure.error, RegistryClientUnavailable)
