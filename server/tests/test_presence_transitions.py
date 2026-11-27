"""Real DB/Redis presence transitions, independent of dashboard subscribers."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio

from aweb.events import team_events_channel_name
from aweb.presence_transitions import PresenceReconciliationError, reconcile_presence
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_stack
from aweb.embedding import OutboxRecoveryOwnership


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool, monkeypatch):
    # Exercise the supported HOST scheduler mode: these tests call its public
    # maintenance operation explicitly, without an uncontrolled second timer.
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


@pytest_asyncio.fixture(autouse=True)
async def owned_transition_snapshot(privacy_app):
    # The module's team has stable authority across disposable DB fixtures;
    # this projection belongs to this test and must not cross those fixtures.
    key = "presence-transitions:" + hashlib.sha256(TEAM.encode()).hexdigest()
    await privacy_app.redis.delete(key)
    for alias in privacy_app.actors:
        heartbeat = await request_as(
            privacy_app, alias=alias, method="POST", path="/v1/agents/heartbeat"
        )
        assert heartbeat.status_code == 200, heartbeat.text
        await privacy_app.redis.delete(
            f"presence:{privacy_app.actors[alias].workspace}"
        )
    try:
        yield
    finally:
        await privacy_app.redis.delete(key)


async def _event(pubsub):
    async with asyncio.timeout(5):
        while True:
            frame = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
            if frame is not None:
                return json.loads(frame["data"])


async def _through_barrier(env, stream):
    # Redis processes this publication after every awaited product transaction.
    # Drain through it instead of treating a short quiet interval as no events.
    barrier = {"type": "test.presence.barrier", "barrier": uuid4().hex}
    await env.redis.publish(team_events_channel_name(TEAM), json.dumps(barrier))
    events = []
    while True:
        event = await _event(stream)
        if event == barrier:
            return events
        events.append(event)


@pytest.mark.asyncio
async def test_presence_is_published_once_with_concurrent_maintenance_and_no_dashboard(
    privacy_app,
):
    env = privacy_app
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        # These are observers of the product publisher, not dashboard writers.
        await asyncio.gather(
            *(
                reconcile_presence(
                    env.infra,
                    env.redis,
                    registry_client=env.app.state.awid_registry_client,
                )
                for _ in range(3)
            )
        )
        events = await _through_barrier(env, stream)
        assert len(events) == len(env.actors)
        assert {(event["type"], event["alias"]) for event in events} == {
            ("agent.online", alias) for alias in env.actors
        }
        await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        assert await _through_barrier(env, stream) == []

        deleted = await request_as(
            env,
            alias="alice",
            method="DELETE",
            path=f"/v1/workspaces/{env.actors['alice'].workspace}",
        )
        assert deleted.status_code == 200, deleted.text
        await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        events = await _through_barrier(env, stream)
        assert [(event["type"], event["alias"]) for event in events] == [
            ("agent.offline", "alice")
        ]


@pytest.mark.asyncio
async def test_presence_reconciles_after_a_period_without_subscribers(privacy_app):
    env = privacy_app
    await reconcile_presence(
        env.infra, env.redis, registry_client=env.app.state.awid_registry_client
    )
    for alias, actor in env.actors.items():
        deleted = await request_as(
            env, alias=alias, method="DELETE", path=f"/v1/workspaces/{actor.workspace}"
        )
        assert deleted.status_code == 200, deleted.text
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        result = await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        assert result.events_published == len(env.actors)
        events = await _through_barrier(env, stream)
        assert len(events) == len(env.actors)
        assert {(event["type"], event["alias"]) for event in events} == {
            ("agent.offline", alias) for alias in env.actors
        }


@pytest.mark.asyncio
async def test_corrupt_projection_is_not_empty_presence(privacy_app):
    env = privacy_app
    key = "presence-transitions:" + hashlib.sha256(TEAM.encode()).hexdigest()
    await env.redis.set(key, "{broken")
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        with pytest.raises(
            PresenceReconciliationError, match="Presence reconciliation incomplete"
        ) as refused:
            await reconcile_presence(
                env.infra, env.redis, registry_client=env.app.state.awid_registry_client
            )
        assert len(refused.value.failures) == 1
        assert refused.value.failures[0].team_id == TEAM
        assert isinstance(refused.value.failures[0].error, json.JSONDecodeError)
        assert await env.redis.get(key) == "{broken"
        assert await _through_barrier(env, stream) == []


@pytest.mark.asyncio
async def test_older_observer_cannot_restore_an_expired_alias(privacy_app):
    from aweb.presence_transitions import _publish_transition

    env = privacy_app
    now = datetime.now(UTC)
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        assert (
            await _publish_transition(
                env.redis, team_id=TEAM, aliases=["alice"], observed_at=now
            )
            == 1
        )
        assert (await _event(stream))["type"] == "agent.online"
        assert (
            await _publish_transition(
                env.redis,
                team_id=TEAM,
                aliases=[],
                observed_at=now + timedelta(seconds=2),
            )
            == 1
        )
        assert (await _event(stream))["type"] == "agent.offline"
        assert (
            await _publish_transition(
                env.redis,
                team_id=TEAM,
                aliases=["alice"],
                observed_at=now + timedelta(seconds=1),
            )
            == 0
        )
        assert await _through_barrier(env, stream) == []


@pytest.mark.asyncio
async def test_two_dashboard_readers_survive_bad_frames_and_observe_one_transition(
    privacy_app,
):
    from test_dashboard import _make_jwt
    from test_dashboard_privacy import _next_event

    env = privacy_app
    headers = {"X-Dashboard-Token": _make_jwt([TEAM])}
    path = f"/v1/teams/{TEAM}/events/stream"
    async with env.client.stream("GET", path, headers=headers) as first:
        async with env.client.stream("GET", path, headers=headers) as second:
            assert first.status_code == second.status_code == 200
            readers = [first.aiter_lines(), second.aiter_lines()]
            for reader in readers:
                assert (await _next_event(reader))["type"] == "connected"
                snapshot = await _next_event(reader)
                assert snapshot["online_aliases"] == sorted(env.actors)
            for payload in (b"\xff", "{invalid", "null", "[]", '{"type":12}'):
                await env.redis.publish(team_events_channel_name(TEAM), payload)
            await reconcile_presence(
                env.infra, env.redis, registry_client=env.app.state.awid_registry_client
            )
            barrier = {"type": "test.presence.barrier", "barrier": uuid4().hex}
            await env.redis.publish(team_events_channel_name(TEAM), json.dumps(barrier))
            for reader in readers:
                events = []
                while (event := await _next_event(reader)) != barrier:
                    events.append(event)
                assert len(events) == len(env.actors)
                assert {(event["type"], event["alias"]) for event in events} == {
                    ("agent.online", alias) for alias in env.actors
                }
