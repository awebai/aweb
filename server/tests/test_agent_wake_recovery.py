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
from aweb.agent_wake import (
    AgentWakeHub,
    AgentWakePublisher,
    agent_wake_key,
    agent_wake_scope,
    did_wake_key,
    record_agent_wake,
    wake_channel,
    wake_mark,
)
from tests.redis_fault_proxy import RedisFaultProxy
from test_agent_wake_latency import _open_chat, _quiet, _send_mail, agent_stream, wake_app  # noqa: F401
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_team_room import metadata as room_metadata, post_payload as room_post_payload



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
    proxy = RedisFaultProxy(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
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


async def _insert_unread_chat(env, recipient="bob"):
    session_id, message_id = uuid4(), uuid4()
    alice, bob = env.actors["alice"], env.actors[recipient]
    await env.db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by) VALUES ($1, $2, $3)",
        session_id, TEAM, alice.did,
    )
    await env.db.execute(
        """INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES ($1, $2, $3, 'alice'), ($1, $4, $5, $6)""",
        session_id, alice.did, alice.id, bob.did, bob.id, recipient,
    )
    await env.db.execute(
        """INSERT INTO {{tables.chat_messages}} (message_id, session_id, from_did, from_alias, body)
        VALUES ($1, $2, $3, 'alice', 'unannounced chat')""",
        message_id, session_id, alice.did,
    )
    return str(session_id)


async def _events_until(next_event, wanted: set[str], timeout: float):
    seen: dict[str, dict] = {}
    async with asyncio.timeout(timeout):
        while not wanted <= set(seen):
            event = await next_event(timeout)
            seen[event["type"]] = event
    return seen


@pytest.mark.asyncio
@pytest.mark.parametrize("lost", ["chat", "mail"])
async def test_a_wake_for_one_kind_also_reads_kinds_whose_counter_moved(wake_app, lost):  # noqa: F811
    env = wake_app
    bob_key = did_wake_key(env.actors["bob"].did)
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        # A committed write whose counter moved but whose PUBLISH was lost.
        if lost == "chat":
            unannounced = await _insert_unread_chat(env)
        else:
            unannounced = await _insert_unread_mail(env)
        await env.redis.incr(wake_mark(bob_key, lost))
        # Then an ordinary wake for the other kind arrives.
        if lost == "chat":
            await _send_mail(env)
        else:
            await _open_chat(env)
        seen = await _events_until(next_event, {"actionable_mail", "actionable_chat"}, 2.0)
    if lost == "chat":
        assert seen["actionable_chat"]["session_id"] == unannounced
    else:
        assert seen["actionable_mail"]["message_id"] == unannounced


async def _insert_control_signals(env, count, recipient="bob"):
    for _ in range(count):
        await env.db.execute(
            """INSERT INTO {{tables.control_signals}} (team_id, target_agent_id, from_agent_id, signal_type)
            VALUES ($1, $2, $3, 'pause')""",
            TEAM, env.actors[recipient].id, env.actors["alice"].id,
        )


@pytest.mark.asyncio
async def test_more_control_signals_than_one_batch_are_all_delivered(wake_app):  # noqa: F811
    env = wake_app
    await _insert_control_signals(env, 11)
    async with agent_stream(env, "bob") as next_event:
        opening = [await next_event(2.0) for _ in range(11)]
        assert {event["type"] for event in opening} == {"control_pause"}
        await _quiet(next_event)
        # Eleven more, announced by one coalesced wake.
        await _insert_control_signals(env, 11)
        with agent_wake_scope(env.app.state.agent_wake_publisher):
            record_agent_wake(agent_wake_key(str(env.actors["bob"].id)), "control")
        woken = [await next_event(2.0) for _ in range(11)]
        assert {event["type"] for event in woken} == {"control_pause"}
        await _quiet(next_event)
    assert await env.db.fetch_val(
        "SELECT count(*) FROM {{tables.control_signals}} WHERE target_agent_id=$1 AND consumed_at IS NULL",
        env.actors["bob"].id,
    ) == 0


@pytest.mark.asyncio
async def test_room_notices_wait_out_unavailable_authority_on_the_same_stream(wake_app):  # noqa: F811
    from awid.registry import RegistryClient

    from aweb.messaging.room import RoomPost, post_room_message
    from aweb.team_auth_deps import TeamIdentity
    from tests.real_stack import ServiceTransport

    env = wake_app
    room = await room_metadata(env)
    alice = env.actors["alice"]
    author = TeamIdentity(
        team_id=TEAM, alias="alice", did_key=alice.did, did_aw="", address="",
        identity_scope="local", agent_id=str(alice.id), certificate_id="privacy-alice",
    )
    reachable = env.app.state.awid_registry_client
    transport = ServiceTransport(env.registry_app)
    flaky = RegistryClient(registry_url="http://registry.test", transport=transport)
    try:
        async with agent_stream(env, "bob") as next_event:
            await _quiet(next_event)
            env.app.state.awid_registry_client = flaky
            transport.down = True
            with agent_wake_scope(env.app.state.agent_wake_publisher):
                posted = await post_room_message(
                    env.infra, author, RoomPost.model_validate(room_post_payload(env, room)),
                )
            # Unavailable authority emits nothing ...
            await _quiet(next_event, seconds=1.5)
            transport.down = False
            # ... and the same notice is retried, with no further post.
            event = await next_event(6.0)
    finally:
        env.app.state.awid_registry_client = reachable
        await flaky.aclose()
    assert event["type"] == "actionable_room_post"
    assert event["message_id"] == posted["message_id"]
