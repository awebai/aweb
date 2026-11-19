"""The shared serving timer publishes presence without dashboard viewers."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import test_certificate_projection
import test_outbox_recovery

from aweb.events import team_events_channel_name
from aweb.outbox_recovery import start_outbox_recovery, stop_outbox_recovery
from tests.test_federation_activation_delivery import _DB

projection_member = test_certificate_projection.projection_member
redis = test_outbox_recovery.redis


@pytest.mark.asyncio
async def test_serving_timer_reconciles_presence_without_viewers(
    projection_member, redis
):
    env = projection_member
    team_id = env.initial.certificate.claims["team_id"]
    snapshot = "presence-transitions:" + hashlib.sha256(team_id.encode()).hexdigest()
    await redis.delete(snapshot)
    app = SimpleNamespace(
        state=SimpleNamespace(
            db=_DB(env.stack.aweb_db),
            redis=redis,
            on_mutation=None,
            awid_registry_client=env.sdk,
        )
    )

    async def event(stream):
        async with asyncio.timeout(5):
            while True:
                frame = await stream.get_message(
                    ignore_subscribe_messages=True, timeout=1
                )
                if frame is not None:
                    return json.loads(frame["data"])

    try:
        async with redis.pubsub() as stream:
            await stream.subscribe(team_events_channel_name(team_id))
            start_outbox_recovery(app, interval_seconds=0.05)
            online = await event(stream)
            assert (online["type"], online["alias"]) == ("agent.online", "worker")
            await env.stack.aweb_db.execute(
                "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
                datetime.now(UTC) - timedelta(days=2),
                env.planned.workspace_id,
            )
            offline = await event(stream)
            assert (offline["type"], offline["alias"]) == ("agent.offline", "worker")
    finally:
        await stop_outbox_recovery(app)
        await redis.delete(snapshot)
    assert app.state.outbox_recovery_task.done()
