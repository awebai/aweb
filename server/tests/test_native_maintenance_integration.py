"""The serving timer publishes presence without dashboard viewers."""

import asyncio
import hashlib
import json

import pytest

from aweb.events import team_events_channel_name
from aweb.outbox_recovery import stop_outbox_recovery
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM, privacy_app

__all__ = ["privacy_app"]


async def _read_event(stream):
    async with asyncio.timeout(5):
        while True:
            frame = await stream.get_message(ignore_subscribe_messages=True, timeout=1)
            if frame is not None:
                return json.loads(frame["data"])


@pytest.mark.asyncio
async def test_serving_timer_reconciles_presence_without_viewers(
    privacy_app, monkeypatch
):
    env = privacy_app
    monkeypatch.setattr("aweb.outbox_recovery.OUTBOX_RECOVERY_INTERVAL_SECONDS", 0.05)
    snapshot = "presence-transitions:" + hashlib.sha256(TEAM.encode()).hexdigest()
    await env.redis.delete(snapshot)
    try:
        async with env.redis.pubsub() as stream:
            await stream.subscribe(team_events_channel_name(TEAM))
            subscribed = await stream.get_message(timeout=3)
            assert subscribed is not None and subscribed["type"] == "subscribe"
            # The mounted app starts recovery on this first ordinary request.
            response = await request_as(
                env, alias="alice", method="POST", path="/v1/agents/heartbeat"
            )
            assert response.status_code == 200, response.text
            online = await _read_event(stream)
            assert (online["type"], online["alias"]) == ("agent.online", "alice")
            deleted = await request_as(
                env,
                alias="alice",
                method="DELETE",
                path=f"/v1/workspaces/{env.actors['alice'].workspace}",
            )
            assert deleted.status_code == 200, deleted.text
            offline = await _read_event(stream)
            assert (offline["type"], offline["alias"]) == ("agent.offline", "alice")
    finally:
        await stop_outbox_recovery(env.app)
        await env.redis.delete(snapshot)
    assert env.app.state.outbox_recovery_task.done()
