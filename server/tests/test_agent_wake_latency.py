"""A write on each surface wakes the recipient's agent event stream at once.

The stream's reconcile is pushed an hour out, so an event arriving within the
latency bound can only have been carried by the write path's wake. The server,
AWID registry, Postgres and Redis are all real (the privacy_app stack).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio

import aweb.routes.events as events_routes
from aweb.agent_wake import AgentWakeHub, AgentWakePublisher
from aweb.api import create_app
from test_awid_transport import awid, db_infra  # noqa: F401  (fixtures)
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401  (fixture)
from test_messages_http import _signed_team_headers
from test_team_room import metadata as room_metadata, post as room_post

WAKE_LATENCY_BOUND_SECONDS = 1.0


@pytest_asyncio.fixture
async def wake_app(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    monkeypatch.setattr(events_routes, "EVENTS_RECONCILE_INTERVAL", 3600.0)
    monkeypatch.setattr(events_routes, "random", SimpleNamespace(uniform=lambda low, high: high))
    hub = AgentWakeHub(env.redis)
    await hub.start()
    publisher = AgentWakePublisher(env.redis)
    env.app.state.agent_wake_hub = hub
    env.app.state.agent_wake_publisher = publisher
    try:
        yield env
    finally:
        await hub.close()
        await publisher.close()


@asynccontextmanager
async def agent_stream(env, alias):
    """Open alias's event stream; yields a function returning its next event."""
    actor = env.actors[alias]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat()
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    async with env.client.stream(
        "GET", "/v1/events/stream", params={"deadline": deadline}, headers=headers,
        timeout=None,
    ) as response:
        assert response.status_code == 200
        events: asyncio.Queue = asyncio.Queue()

        async def read():
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    event = json.loads(line[6:])
                    # The connected frame's data carries no type.
                    if "type" in event:
                        events.put_nowait(event)

        reader = asyncio.create_task(read())

        async def next_event(timeout: float):
            async with asyncio.timeout(timeout):
                return await events.get()

        try:
            yield next_event
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader


async def _quiet(next_event, seconds=0.3):
    with pytest.raises(TimeoutError):
        await next_event(seconds)


@pytest.mark.asyncio
async def test_library_lifespan_runs_one_wake_hub_and_publisher(awid, db_infra):  # noqa: F811
    app = create_app(db_infra=db_infra, redis=awid.redis, awid_transport=awid.transport)
    async with app.router.lifespan_context(app):
        hub = app.state.agent_wake_hub
        publisher = app.state.agent_wake_publisher
        assert isinstance(hub, AgentWakeHub)
        assert isinstance(publisher, AgentWakePublisher)
        assert hub._task is not None and not hub._task.done()
    assert hub._task is None


@pytest.mark.asyncio
async def test_rest_mail_send_wakes_recipient(wake_app):
    env = wake_app
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        response = await _request(env, "alice", "POST", "/v1/messages", {
            "to_did": env.actors["bob"].did, "subject": "wake", "body": "now",
        })
        assert response.status_code == 200, response.text
        event = await next_event(WAKE_LATENCY_BOUND_SECONDS)
        assert time.monotonic() - started < WAKE_LATENCY_BOUND_SECONDS
    assert event["type"] == "actionable_mail"
    assert event["message_id"] == response.json()["message_id"]


async def _team_request(env, actor, method, path, body=None):
    identity = env.actors[actor]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_team_headers(identity.sk, identity.did, TEAM, identity.certificate, content)
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=content, headers=headers)


async def _send_mail(env, sender="alice", recipient="bob", subject="wake"):
    response = await _request(env, sender, "POST", "/v1/messages", {
        "to_did": env.actors[recipient].did, "subject": subject, "body": "now",
    })
    assert response.status_code == 200, response.text
    return response.json()


async def _open_chat(env, sender="alice", recipient="bob", message="hello"):
    response = await _request(env, sender, "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors[recipient].did], "message": message,
    })
    assert response.status_code == 200, response.text
    return response.json()


async def _expect_within_bound(next_event, started, event_type):
    event = await next_event(WAKE_LATENCY_BOUND_SECONDS)
    assert time.monotonic() - started < WAKE_LATENCY_BOUND_SECONDS
    assert event["type"] == event_type, event
    return event


@pytest.mark.asyncio
async def test_rest_mail_ack_wakes_reader_with_new_unread_count(wake_app):
    env = wake_app
    first = await _send_mail(env, subject="first")
    await _send_mail(env, subject="second")
    async with agent_stream(env, "bob") as next_event:
        assert {(await next_event(2))["unread_count"] for _ in range(2)} == {2}
        await _quiet(next_event)
        started = time.monotonic()
        ack = await _request(env, "bob", "POST", f"/v1/messages/{first['message_id']}/ack")
        assert ack.status_code == 200, ack.text
        event = await _expect_within_bound(next_event, started, "actionable_mail")
    assert event["unread_count"] == 1


@pytest.mark.asyncio
async def test_rest_chat_session_send_wakes_recipient(wake_app):
    env = wake_app
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        chat = await _open_chat(env)
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["session_id"] == chat["session_id"]


@pytest.mark.asyncio
async def test_rest_chat_reply_wakes_recipient(wake_app):
    env = wake_app
    chat = await _open_chat(env)
    async with agent_stream(env, "bob") as next_event:
        assert (await next_event(2))["unread_count"] == 1
        await _quiet(next_event)
        started = time.monotonic()
        reply = await _request(env, "alice", "POST", f"/v1/chat/sessions/{chat['session_id']}/messages", {
            "body": "again",
        })
        assert reply.status_code == 200, reply.text
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["unread_count"] == 2


@pytest.mark.asyncio
async def test_rest_chat_read_wakes_reader_with_new_unread_count(wake_app):
    env = wake_app
    chat = await _open_chat(env)
    reply = await _request(env, "alice", "POST", f"/v1/chat/sessions/{chat['session_id']}/messages", {
        "body": "again",
    })
    assert reply.status_code == 200, reply.text
    async with agent_stream(env, "bob") as next_event:
        assert (await next_event(2))["unread_count"] == 2
        await _quiet(next_event)
        started = time.monotonic()
        read = await _request(env, "bob", "POST", f"/v1/chat/sessions/{chat['session_id']}/read", {
            "message_ids": [chat["message_id"]],
        })
        assert read.status_code == 200, read.text
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["unread_count"] == 1


@pytest.mark.asyncio
async def test_chat_waiting_register_and_unregister_wake_the_other_participant(wake_app):
    env = wake_app
    chat = await _open_chat(env)
    alice = env.actors["alice"]
    async with agent_stream(env, "bob") as next_event:
        first = await next_event(2)
        assert first["sender_waiting"] is False
        await _quiet(next_event)
        deadline = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
        started = time.monotonic()
        async with env.client.stream(
            "GET", f"/v1/chat/sessions/{chat['session_id']}/stream", params={"deadline": deadline},
            headers=_signed_team_headers(alice.sk, alice.did, TEAM, alice.certificate), timeout=None,
        ) as waiting:
            assert waiting.status_code == 200
            event = await _expect_within_bound(next_event, started, "actionable_chat")
            assert event["sender_waiting"] is True
            assert event["wake_mode"] == "interrupt"
        # Leaving unregisters at once, though the disconnect cancels the
        # chat stream; the wake is measured from that write.
        waiting_key = f"chat:waiting:{chat['session_id']}"
        async with asyncio.timeout(2):
            while await env.redis.zscore(waiting_key, alice.did) is not None:
                await asyncio.sleep(0.01)
        started = time.monotonic()
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["sender_waiting"] is False


@pytest.mark.asyncio
async def test_rest_control_signal_wakes_target(wake_app):
    env = wake_app
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        sent = await _team_request(env, "alice", "POST", "/v1/agents/bob/control", {"signal": "pause"})
        assert sent.status_code == 200, sent.text
        event = await _expect_within_bound(next_event, started, "control_pause")
    assert event["signal_id"] == sent.json()["signal_id"]


@pytest.mark.asyncio
async def test_room_post_wakes_team_members(wake_app):
    env = wake_app
    room = await room_metadata(env)
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        sent = await room_post(env, room)
        assert sent.status_code == 200, sent.text
        event = await _expect_within_bound(next_event, started, "actionable_room_post")
    assert event["message_id"] == sent.json()["message_id"]
