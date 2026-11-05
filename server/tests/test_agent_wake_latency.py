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
from aweb.federation.activation import build_federation_authority_activation
from aweb.mcp.server import create_mcp_app
from aweb.app_registry import AppEmitKey, AppEventType
from tests.installation_fixtures import install_fixture_app as install_app
from aweb.agent_wake import AgentWakeHub, AgentWakePublisher
from aweb.api import create_app
from chat_pair_support import route_pair  # noqa: F401  (fixture)
from test_awid_transport import awid, db_infra  # noqa: F401  (fixtures)
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401  (fixture)
from test_app_events_http import _make_app_keypair, _signed_app_headers
from test_messages_http import _signed_team_headers
from test_team_room import metadata as room_metadata, post as room_post, post_payload as room_post_payload

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


async def _install_emitting_app(env):
    signing_key, did_key = _make_app_keypair()
    await install_app(
        env.db,
        team_id=TEAM,
        app_id="folio",
        origin="https://folio.aweb.ai",
        app_version="1.x",
        manifest_version=1,
        digest="sha256:" + "0" * 64,
        granted_scopes=["folio:read"],
        installed_by_agent_id=str(env.actors["alice"].id),
        event_types=[AppEventType(type="doc.changed", default_delivery_intent="wake")],
        emit_keys=[AppEmitKey(kid="emit-1", did_key=did_key)],
    )
    return signing_key, did_key


async def _emit_app_event(env, signing_key, did_key, resource_ref="doc-1"):
    body = json.dumps({"type": "folio/doc.changed", "resource_ref": resource_ref, "payload": {}}).encode()
    headers = _signed_app_headers(
        signing_key=signing_key, did_key=did_key, body=body, team_id=TEAM,
        aud=env.app.state.public_origin,
    )
    response = await env.client.post("/v1/events/app", content=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_app_event_wakes_subscribed_agents_only(wake_app):
    env = wake_app
    signing_key, did_key = await _install_emitting_app(env)
    subscribed = await _team_request(env, "bob", "POST", "/v1/events/subscriptions", {
        "type": "folio/doc.changed",
    })
    assert subscribed.status_code == 200, subscribed.text
    async with agent_stream(env, "bob") as bob_events, agent_stream(env, "carol") as carol_events:
        await _quiet(bob_events)
        started = time.monotonic()
        emitted = await _emit_app_event(env, signing_key, did_key)
        event = await _expect_within_bound(bob_events, started, "app_event")
        await _quiet(carol_events)
    assert event["event_id"] == emitted["event_id"]


@pytest.mark.asyncio
async def test_app_subscription_wakes_its_agent_with_recent_events(wake_app):
    env = wake_app
    signing_key, did_key = await _install_emitting_app(env)
    emitted = await _emit_app_event(env, signing_key, did_key)
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        subscribed = await _team_request(env, "bob", "POST", "/v1/events/subscriptions", {
            "type": "folio/doc.changed",
        })
        assert subscribed.status_code == 200, subscribed.text
        event = await _expect_within_bound(next_event, started, "app_event")
    assert event["event_id"] == emitted["event_id"]


@pytest_asyncio.fixture
async def mcp_call(wake_app):
    """Call a tool on the real MCP app mounted in the wake_app server."""
    env = wake_app
    origin = env.app.state.public_origin
    authority = build_federation_authority_activation(env.infra, public_origin=origin)
    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis, registry_client=env.app.state.awid_registry_client,
        federation_authority=authority, public_origin=origin,
    )
    env.app.mount("/wake-mcp", mcp)
    await mcp.startup()

    async def call(actor, name, **arguments):
        identity = env.actors[actor]
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }).encode()
        response = await env.client.post("/wake-mcp/", content=body, headers={
            **_signed_team_headers(identity.sk, identity.did, TEAM, identity.certificate, body),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }, timeout=30)
        assert response.status_code == 200, response.text
        result = response.json()
        assert "error" not in result, result
        tool = result["result"]
        assert not tool.get("isError"), tool
        value = json.loads(tool["content"][0]["text"])
        assert not (isinstance(value, dict) and "error" in value), value
        return value

    try:
        yield call
    finally:
        await mcp.shutdown()
        await authority.aclose()


@pytest.mark.asyncio
async def test_mcp_send_mail_wakes_recipient(wake_app, mcp_call):
    env = wake_app
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        sent = await mcp_call("alice", "send_mail", to="bob", subject="wake", body="now")
        event = await _expect_within_bound(next_event, started, "actionable_mail")
    assert event["message_id"] == sent["message_id"]


@pytest.mark.asyncio
async def test_mcp_check_mail_auto_ack_wakes_reader(wake_app, mcp_call):
    env = wake_app
    await _send_mail(env, subject="first")
    await _send_mail(env, subject="second")
    async with agent_stream(env, "bob") as next_event:
        assert {(await next_event(2))["unread_count"] for _ in range(2)} == {2}
        await _quiet(next_event)
        await mcp_call("bob", "check_mail", limit=1)
        started = time.monotonic()
        event = await _expect_within_bound(next_event, started, "actionable_mail")
    assert event["unread_count"] == 1


@pytest.mark.asyncio
async def test_mcp_send_chat_wakes_recipient(wake_app, mcp_call):
    env = wake_app
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        sent = await mcp_call("alice", "send_chat", to="bob", message="hello")
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["session_id"] == sent["session_id"]


@pytest.mark.asyncio
async def test_mcp_chat_wait_wakes_recipient_as_interrupt(wake_app, mcp_call):
    env = wake_app
    chat = await _open_chat(env)
    async with agent_stream(env, "bob") as next_event:
        assert (await next_event(2))["sender_waiting"] is False
        await _quiet(next_event)
        started = time.monotonic()
        waiting = asyncio.create_task(mcp_call(
            "alice", "send_chat", conversation_id=chat["session_id"], message="still there?",
            wait=True, wait_seconds=2,
        ))
        try:
            events = [await next_event(WAKE_LATENCY_BOUND_SECONDS)]
            if not events[0]["sender_waiting"]:
                events.append(await next_event(WAKE_LATENCY_BOUND_SECONDS))
            assert time.monotonic() - started < WAKE_LATENCY_BOUND_SECONDS
            assert events[-1]["sender_waiting"] is True
            assert events[-1]["wake_mode"] == "interrupt"
        finally:
            await waiting
        started = time.monotonic()
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["sender_waiting"] is False


@pytest.mark.asyncio
async def test_mcp_mark_chat_read_wakes_reader(wake_app, mcp_call):
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
        await mcp_call("bob", "mark_chat_read", conversation_id=chat["session_id"],
                       message_ids=[chat["message_id"]])
        event = await _expect_within_bound(next_event, started, "actionable_chat")
    assert event["unread_count"] == 1


@pytest.mark.asyncio
async def test_mcp_room_post_wakes_team_members(wake_app, mcp_call):
    env = wake_app
    room = await room_metadata(env)
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        posted = await mcp_call("alice", "room_post", signed_post=room_post_payload(env, room))
        event = await _expect_within_bound(next_event, started, "actionable_room_post")
    assert event["message_id"] == posted["message_id"]


@pytest.mark.asyncio
async def test_stream_on_a_host_without_agent_wakes_says_so_once(privacy_app, monkeypatch, caplog):  # noqa: F811
    env = privacy_app
    monkeypatch.setattr(events_routes, "_missing_wake_hub_reported", False)
    with caplog.at_level("WARNING", logger="aweb.routes.events"):
        for _ in range(2):
            async with agent_stream(env, "bob") as next_event:
                await _quiet(next_event, seconds=0.1)
    reports = [r for r in caplog.records if "Agent wakes are not started" in r.getMessage()]
    assert len(reports) == 1


@pytest.mark.asyncio
async def test_stream_on_a_host_with_agent_wakes_reports_nothing(wake_app, monkeypatch, caplog):
    monkeypatch.setattr(events_routes, "_missing_wake_hub_reported", False)
    with caplog.at_level("WARNING", logger="aweb.routes.events"):
        async with agent_stream(wake_app, "bob") as next_event:
            await _quiet(next_event, seconds=0.1)
    assert not [r for r in caplog.records if "Agent wakes are not started" in r.getMessage()]


@pytest.mark.asyncio
async def test_succession_addressed_mail_wakes_the_successor(route_pair):  # noqa: F811
    from aweb.agent_wake import did_wake_key
    from aweb.messaging.participant_succession import succeed_local_human_participant_on
    from chat_pair_support import _actor, _submission
    from test_actl_fresh_chat import _post
    from test_participant_succession import _human, _retire, _send

    node = route_pair.source
    old, agent = node.local, node.global_actor
    successor = await _actor(node, "account-human", global_identity=True)
    await _human(old)
    await _human(successor)
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200, response.text
    queued = _submission(agent, old, "mail", continuation=str(first.cid))
    await _retire(old)
    async with node.db.transaction() as tx:
        await succeed_local_human_participant_on(
            tx, predecessor_did=old.stable or old.did, successor_did=successor.stable
        )
    hub = node.server.app.state.agent_wake_hub
    # The successor's stream subscribes only to its own DIDs.
    async with hub.subscribe([did_wake_key(successor.stable), did_wake_key(successor.did)]) as wakes:
        started = time.monotonic()
        response = await _post(agent, queued)
        assert response.status_code == 200, response.text
        await asyncio.wait_for(wakes.wait(), WAKE_LATENCY_BOUND_SECONDS)
        assert time.monotonic() - started < WAKE_LATENCY_BOUND_SECONDS
        assert "mail" in wakes.take().kinds
    row = await node.db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", queued[2].mid
    )
    # The stored target remains the predecessor's; the wake still reached H.
    assert row["to_did"] == (old.stable or old.did)


@pytest.mark.asyncio
async def test_a_send_that_commits_then_fails_still_wakes_the_recipient(wake_app, monkeypatch):
    import aweb.messaging.messages as messages_module

    env = wake_app
    record_did_wakes = messages_module.record_did_wakes

    def record_then_fail(dids, kind):
        record_did_wakes(dids, kind)
        raise RuntimeError("failed after the message committed")

    first = await _send_mail(env, subject="opening")
    await _request(env, "bob", "POST", f"/v1/messages/{first['message_id']}/ack")
    # A first send commits its conversation and message together, so a
    # failure inside it commits nothing; a continuation's message commits alone.
    monkeypatch.setattr(messages_module, "record_did_wakes", record_then_fail)
    async with agent_stream(env, "bob") as next_event:
        await _quiet(next_event)
        started = time.monotonic()
        response = await _request(env, "alice", "POST", "/v1/messages", {
            "conversation_id": first["conversation_id"], "subject": "committed", "body": "then failed",
        })
        assert response.status_code == 500
        event = await _expect_within_bound(next_event, started, "actionable_mail")
    assert event["subject"] == "committed"
