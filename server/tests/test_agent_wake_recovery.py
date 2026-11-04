"""Agent event streams recover what a lost wake would have told them.

The real stack (server, AWID, Postgres, Redis); Redis faults are real link
cuts through a TCP proxy. Mail rows written straight into Postgres stand for a
write whose wake never arrived.
"""

from __future__ import annotations

import asyncio
import os
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis

import aweb.routes.events as events_routes
from aweb.agent_wake import AgentWakeHub, AgentWakePublisher, did_wake_key, wake_channel, wake_mark
from tests.redis_fault_proxy import RedisFaultProxy
from test_agent_wake_latency import _quiet, _send_mail, agent_stream, wake_app  # noqa: F401
from test_dashboard_privacy import privacy_app  # noqa: F401

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def _insert_unread_mail(env, recipient="bob"):
    message_id = uuid4()
    await env.db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body)
        VALUES ($1, $2, $3, 'alice', $4, 'unannounced', 'body')
        """,
        message_id, env.actors["alice"].did, env.actors[recipient].did, recipient,
    )
    return str(message_id)


@pytest_asyncio.fixture
async def proxy():
    proxy = RedisFaultProxy(REDIS_URL)
    await proxy.start()
    yield proxy
    await proxy.stop()


@pytest.mark.asyncio
async def test_lost_publication_is_recovered_by_the_counter_reconcile(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    hub = AgentWakeHub(env.redis)
    await hub.start()
    env.app.state.agent_wake_hub = hub
    try:
        async with agent_stream(env, "bob") as next_event:
            await _quiet(next_event)
            message_id = await _insert_unread_mail(env)
            # The writer counted the change; its PUBLISH was lost.
            await env.redis.incr(wake_mark(did_wake_key(env.actors["bob"].did), "mail"))
            started = time.monotonic()
            event = await next_event(events_routes.EVENTS_RECONCILE_INTERVAL + 1.0)
            assert time.monotonic() - started <= events_routes.EVENTS_RECONCILE_INTERVAL + 1.0
    finally:
        await hub.close()
    assert event["type"] == "actionable_mail"
    assert event["message_id"] == message_id


@pytest.mark.asyncio
async def test_reconcile_without_a_moved_counter_reads_nothing(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    monkeypatch.setattr(events_routes, "EVENTS_RECONCILE_INTERVAL", 0.2)
    hub = AgentWakeHub(env.redis)
    await hub.start()
    env.app.state.agent_wake_hub = hub
    try:
        async with agent_stream(env, "bob") as next_event:
            await _quiet(next_event)
            # Unannounced and uncounted: several reconciles pass without reading it.
            await _insert_unread_mail(env)
            await _quiet(next_event, seconds=1.0)
    finally:
        await hub.close()


@pytest.mark.asyncio
async def test_subscriber_reconnect_resyncs_streams_at_once(privacy_app, proxy, monkeypatch):  # noqa: F811
    env = privacy_app
    monkeypatch.setattr(events_routes, "EVENTS_RECONCILE_INTERVAL", 3600.0)
    monkeypatch.setattr(events_routes, "random", SimpleNamespace(uniform=lambda low, high: high))
    link = Redis.from_url(proxy.url, decode_responses=True, socket_connect_timeout=1)
    hub = AgentWakeHub(link)
    await hub.start()
    env.app.state.agent_wake_hub = hub
    try:
        async with agent_stream(env, "bob") as next_event:
            await _quiet(next_event)
            proxy.cut()
            message_id = await _insert_unread_mail(env)
            await asyncio.sleep(0.3)
            proxy.restore()
            started = time.monotonic()
            event = await next_event(5.0)
            assert time.monotonic() - started < 5.0
    finally:
        await hub.close()
        await link.aclose()
    assert event["message_id"] == message_id


@pytest.mark.asyncio
async def test_publisher_fault_is_delivered_once_redis_takes_the_wake(wake_app, proxy, caplog):  # noqa: F811
    env = wake_app
    faulty = Redis.from_url(proxy.url, decode_responses=True, socket_timeout=1, socket_connect_timeout=1)
    publisher = AgentWakePublisher(faulty)
    env.app.state.agent_wake_publisher = publisher
    try:
        async with agent_stream(env, "bob") as next_event:
            await _quiet(next_event)
            proxy.cut()
            fault_started = time.monotonic()
            sent = await _send_mail(env)
            # The write succeeded although no wake could be published.
            await _quiet(next_event, seconds=2.0)
            proxy.restore()
            fault_seconds = time.monotonic() - fault_started
            event = await next_event(15.0)
            assert time.monotonic() - fault_started <= fault_seconds + 15.0
    finally:
        await publisher.close()
        await faulty.aclose()
    assert event["message_id"] == sent["message_id"]
    assert any(
        r.getMessage().startswith("Agent wake publication failed; retrying") for r in caplog.records
    )


@pytest.mark.asyncio
async def test_closing_a_stream_releases_its_wake_channels(wake_app):
    env = wake_app
    channel = wake_channel(did_wake_key(env.actors["bob"].did))
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        assert dict(await env.redis.pubsub_numsub(channel))[channel] == 1
    async with asyncio.timeout(2):
        while dict(await env.redis.pubsub_numsub(channel))[channel] != 0:
            await asyncio.sleep(0.02)
