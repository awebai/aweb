"""Real DB/Redis presence transitions, independent of dashboard subscribers."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from aweb.events import team_events_channel_name
from aweb.presence_transitions import PresenceReconciliationError, reconcile_presence
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app


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
        events = [await _event(stream) for _ in env.actors]
        assert {(event["type"], event["alias"]) for event in events} == {
            ("agent.online", alias) for alias in env.actors
        }
        await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        assert (
            await stream.get_message(ignore_subscribe_messages=True, timeout=0.1)
            is None
        )

        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
            datetime.now(UTC) - timedelta(days=2),
            env.actors["alice"].workspace,
        )
        await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        event = await _event(stream)
        assert (event["type"], event["alias"]) == ("agent.offline", "alice")
        assert (
            await stream.get_message(ignore_subscribe_messages=True, timeout=0.1)
            is None
        )


@pytest.mark.asyncio
async def test_presence_reconciles_after_a_period_without_subscribers(privacy_app):
    env = privacy_app
    await reconcile_presence(
        env.infra, env.redis, registry_client=env.app.state.awid_registry_client
    )
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE team_id=$1",
        TEAM,
    )
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        result = await reconcile_presence(
            env.infra, env.redis, registry_client=env.app.state.awid_registry_client
        )
        assert result.events_published == len(env.actors)
        events = [await _event(stream) for _ in env.actors]
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
        ):
            await reconcile_presence(
                env.infra, env.redis, registry_client=env.app.state.awid_registry_client
            )
        assert await env.redis.get(key) == "{broken"
        assert (
            await stream.get_message(ignore_subscribe_messages=True, timeout=0.1)
            is None
        )


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
        assert (
            await stream.get_message(ignore_subscribe_messages=True, timeout=0.1)
            is None
        )


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
            for reader in readers:
                events = [await _next_event(reader) for _ in env.actors]
                assert {(event["type"], event["alias"]) for event in events} == {
                    ("agent.online", alias) for alias in env.actors
                }
