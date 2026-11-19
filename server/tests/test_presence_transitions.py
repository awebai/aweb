"""Real DB/Redis presence transitions, independent of dashboard subscribers."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from aweb.events import team_events_channel_name
from aweb.presence_transitions import reconcile_presence
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app


async def _event(pubsub):
    async with asyncio.timeout(5):
        while True:
            frame = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
            if frame is not None:
                return json.loads(frame["data"])


@pytest.mark.asyncio
async def test_presence_is_published_once_with_concurrent_maintenance_and_no_dashboard(privacy_app):
    env = privacy_app
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        # These are observers of the product publisher, not dashboard writers.
        await asyncio.gather(*(
            reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
            for _ in range(3)
        ))
        events = [await _event(stream) for _ in env.actors]
        assert {(event["type"], event["alias"]) for event in events} == {
            ("agent.online", alias) for alias in env.actors
        }
        await reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
        assert await stream.get_message(ignore_subscribe_messages=True, timeout=0.1) is None

        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
            datetime.now(UTC) - timedelta(days=2), env.actors["alice"].workspace,
        )
        await reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
        event = await _event(stream)
        assert (event["type"], event["alias"]) == ("agent.offline", "alice")
        assert await stream.get_message(ignore_subscribe_messages=True, timeout=0.1) is None


@pytest.mark.asyncio
async def test_presence_reconciles_after_a_period_without_subscribers(privacy_app):
    env = privacy_app
    await reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE team_id=$1", TEAM,
    )
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        result = await reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
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
        with pytest.raises(Exception, match="Presence reconciliation incomplete"):
            await reconcile_presence(env.infra, env.redis, registry_client=env.app.state.awid_registry_client)
        assert await env.redis.get(key) == "{broken"
        assert await stream.get_message(ignore_subscribe_messages=True, timeout=0.1) is None
