"""Agent activity ingress through the real app, AWID registry, PostgreSQL and Redis.

An agent's host publishes signed activity while the agent works (aweb-acah.2,
docs/agent-activity.md). The server verifies it, relays it with a per-agent
revision, and keeps only the latest event for at most 60 seconds. Fixture
provisioning and removing the app's Redis for the unavailable case are the
only direct state changes.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import logging

import pytest
from redis.asyncio import Redis

from awid.signing import canonical_json_bytes, sign_message
from aweb.messaging.activity_stream import SessionActivity
from test_agent_status_host_http import _team_request
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair, _signed_identity_headers

PATH = "/v1/agents/me/activity"


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(env, actor, *, from_did=None, seq=1, turn_id="turn-1", session_id=None, **changes):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    event = {
        "v": 1,
        "type": "agent_activity",
        "from_did": from_did or env.actors[actor].did,
        "team_id": TEAM,
        "session_id": session_id,
        "turn_id": turn_id,
        "seq": seq,
        "phase": "tool",
        "tool": "Bash",
        "summary": "Running pytest",
        "timestamp": _ts(now),
        "expires_at": _ts(now + timedelta(seconds=60)),
    }
    event.update(changes)
    return event


def _body(signing_key, event):
    canonical = canonical_json_bytes(event)
    return {
        "signed_payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
        "signature": sign_message(signing_key, canonical),
    }


async def _publish(env, actor, event):
    return await _team_request(env, actor, "POST", PATH, _body(env.actors[actor].sk, event))


async def _latest(env, actor):
    stored = await env.redis.get(f"agent-activity:{env.actors[actor].id}")
    return json.loads(stored) if stored else None


async def _session(env, sender, *recipients):
    response = await _request(env, sender, "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors[alias].did for alias in recipients], "message": "hello",
    })
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


async def _next_relay(pubsub):
    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=2)
    assert message is not None, "no activity was relayed"
    return json.loads(message["data"])


@pytest.mark.asyncio
async def test_team_certificate_caller_publishes_and_the_event_is_relayed(privacy_app):
    env = privacy_app
    event = _event(env, "alice")
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(f"agent-activity:{env.actors['alice'].id}")
        await pubsub.get_message(timeout=1)  # subscription acknowledgement

        response = await _publish(env, "alice", event)

        assert response.status_code == 202, response.text
        relayed = await _next_relay(pubsub)
    assert relayed["rev"] == 1
    assert relayed["event"] == event
    assert relayed["alias"] == "alice"
    assert relayed == await _latest(env, "alice")
    ttl = await env.redis.pttl(f"agent-activity:{env.actors['alice'].id}")
    assert 0 < ttl <= 60_000
    assert await env.redis.ttl(f"agent-activity-rev:{env.actors['alice'].id}") > 3000


async def _global_member(env, alias="dave"):
    sk, _, did = _make_keypair()
    agent_id, did_aw = uuid4(), f"did:aw:{alias}{uuid4().hex[:12]}"
    await env.db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, team_id, did_key, did_aw, address, alias, identity_scope, inbound_mode) "
        "VALUES ($1, $2, $3, $4, $5, $6, 'global', 'open')",
        agent_id, TEAM, did, did_aw, f"example.test/{alias}", alias,
    )
    certificate = _encode_certificate(_make_certificate(
        env.team_sk, env.team_did, did, team_id=TEAM, alias=alias, identity_scope="global",
        member_did_aw=did_aw, member_address=f"example.test/{alias}", certificate_id=f"activity-{alias}",
    ))
    env.actors[alias] = SimpleNamespace(sk=sk, did=did, id=agent_id, certificate=certificate, did_aw=did_aw)
    return env.actors[alias]


@pytest.mark.asyncio
async def test_global_member_certificate_publishes_with_its_stable_id(privacy_app):
    env = privacy_app
    member = await _global_member(env)

    response = await _publish(env, "dave", _event(env, "dave", from_stable_id=member.did_aw))
    wrong = await _publish(env, "dave", _event(env, "dave", seq=2, from_stable_id="did:aw:someoneelse"))

    assert response.status_code == 202, response.text
    assert (await _latest(env, "dave"))["event"]["from_stable_id"] == member.did_aw
    assert wrong.status_code == 422
    assert wrong.json()["detail"].startswith("stable_id_mismatch: ")


@pytest.mark.asyncio
async def test_activity_attributed_to_a_session_the_agent_is_in_is_accepted(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")

    response = await _publish(env, "alice", _event(env, "alice", session_id=session_id))

    assert response.status_code == 202, response.text
    assert (await _latest(env, "alice"))["event"]["session_id"] == session_id


@pytest.mark.asyncio
async def test_absent_and_foreign_sessions_get_the_same_not_found(privacy_app):
    env = privacy_app
    foreign = await _session(env, "bob", "carol")

    absent = await _publish(env, "alice", _event(env, "alice", session_id=str(uuid4())))
    not_participant = await _publish(env, "alice", _event(env, "alice", seq=2, session_id=foreign))

    for response in (absent, not_participant):
        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}
    assert absent.content == not_participant.content
    assert absent.headers["content-type"] == not_participant.headers["content-type"]
    assert await _latest(env, "alice") is None


@pytest.mark.asyncio
async def test_turn_ended_is_kept_as_an_end_marker_with_the_next_revision(privacy_app):
    env = privacy_app
    assert (await _publish(env, "alice", _event(env, "alice"))).status_code == 202

    end = _event(env, "alice", seq=2, phase="turn_ended")
    del end["tool"], end["summary"]
    response = await _publish(env, "alice", end)

    assert response.status_code == 202, response.text
    latest = await _latest(env, "alice")
    assert latest["rev"] == 2
    assert latest["event"]["phase"] == "turn_ended"


@pytest.mark.asyncio
async def test_racing_publishes_keep_latest_state_and_channel_in_revision_order(privacy_app):
    env = privacy_app
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(f"agent-activity:{env.actors['alice'].id}")
        await pubsub.get_message(timeout=1)

        responses = await asyncio.gather(*(
            _publish(env, "alice", _event(env, "alice", seq=seq)) for seq in range(1, 9)
        ))

        assert [response.status_code for response in responses] == [202] * 8
        relayed = [await _next_relay(pubsub) for _ in range(8)]
    revisions = [message["rev"] for message in relayed]
    assert revisions == sorted(revisions) == list(range(1, 9))
    assert (await _latest(env, "alice")) == relayed[-1]


@pytest.mark.asyncio
async def test_refusals_carry_their_codes(privacy_app):
    env = privacy_app
    mismatched = await _publish(env, "alice", _event(env, "alice", from_did=env.actors["bob"].did))
    malformed = await _team_request(env, "alice", "POST", PATH, {"signed_payload": "not base64!", "signature": "x"})
    oversize = await _team_request(env, "alice", "POST", PATH, {"signed_payload": "a" * 2100, "signature": "x"})

    assert mismatched.status_code == 422
    assert mismatched.json()["detail"].startswith("signer_mismatch: ")
    assert malformed.status_code == 422
    assert malformed.json()["detail"].startswith("malformed_payload: ")
    assert oversize.status_code == 413
    assert oversize.json()["detail"].startswith("request_too_large: ")
    assert await _latest(env, "alice") is None


@pytest.mark.asyncio
async def test_rate_limit_allows_ten_per_window_then_refuses(privacy_app):
    env = privacy_app
    for seq in range(1, 11):
        response = await _publish(env, "alice", _event(env, "alice", seq=seq))
        assert response.status_code == 202, response.text

    refused = await _publish(env, "alice", _event(env, "alice", seq=11))

    assert refused.status_code == 429
    assert refused.json()["detail"].startswith("rate_limited: ")
    assert 1 <= int(refused.headers["Retry-After"]) <= 5
    assert 0 < await env.redis.ttl(f"agent-activity-rate:{env.actors['alice'].id}") <= 5
    assert (await _latest(env, "alice"))["event"]["seq"] == 10


@pytest.mark.asyncio
async def test_without_redis_publishing_is_unavailable_and_not_an_error(privacy_app, caplog):
    env = privacy_app
    redis, env.app.state.redis = env.app.state.redis, None
    try:
        with caplog.at_level(logging.WARNING, logger="aweb.routes.agent_activity"):
            response = await _publish(env, "alice", _event(env, "alice"))
    finally:
        env.app.state.redis = redis

    assert response.status_code == 503
    assert response.json()["detail"].startswith("publishing_unavailable: ")
    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []


@pytest.mark.asyncio
async def test_failing_redis_is_unavailable_and_the_failure_is_logged(privacy_app, caplog):
    env = privacy_app
    # A real client for a port nothing listens on: every command fails to connect.
    unreachable = Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)
    redis, env.app.state.redis = env.app.state.redis, unreachable
    try:
        with caplog.at_level(logging.ERROR, logger="aweb.routes.agent_activity"):
            response = await _publish(env, "alice", _event(env, "alice"))
    finally:
        env.app.state.redis = redis
        await unreachable.aclose()

    assert response.status_code == 503
    assert response.json()["detail"].startswith("publishing_unavailable: ")
    assert [record.getMessage() for record in caplog.records] == [
        f"Activity rate limit failed for {env.actors['alice'].id}"
    ]
    assert caplog.records[0].exc_info is not None


async def _grant_publish(env, alias, scopes, *, event_from_session_key=True):
    origin = str(env.client.base_url).rstrip("/")
    env.app.state.public_origin = origin
    signing_key, grant_did = _session_keypair()
    minted = await _team_request(
        env, alias, "POST", "/v1/identity-grants",
        {"grant_did_key": grant_did, "scopes": scopes, "ttl_seconds": 600},
    )
    assert minted.status_code == 200, minted.text
    event = _event(env, alias, from_did=grant_did if event_from_session_key else None)
    content = json.dumps(_body(signing_key, event)).encode()
    response = await env.client.post(
        PATH,
        content=content,
        headers=_grant_headers(
            signing_key=signing_key, did_key=grant_did, grant_id=minted.json()["grant_id"],
            method="POST", path=PATH, body=content, aud=origin,
        ),
    )
    return response, event


@pytest.mark.asyncio
async def test_grant_with_chat_send_publishes_as_its_subject(privacy_app):
    env = privacy_app

    response, event = await _grant_publish(env, "alice", ["chat.send"])

    assert response.status_code == 202, response.text
    latest = await _latest(env, "alice")
    assert latest["event"] == event
    assert latest["alias"] == "alice"


@pytest.mark.asyncio
async def test_grant_event_naming_the_subject_key_is_a_signer_mismatch(privacy_app):
    env = privacy_app

    response, _ = await _grant_publish(env, "alice", ["chat.send"], event_from_session_key=False)

    assert response.status_code == 422
    assert response.json()["detail"].startswith("signer_mismatch: ")


@pytest.mark.asyncio
async def test_grant_without_chat_send_is_outside_its_scope(privacy_app):
    env = privacy_app

    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(f"agent-activity:{env.actors['alice'].id}")
        await pubsub.get_message(timeout=1)

        response, _ = await _grant_publish(env, "alice", ["mail.read", "chat.read"])

        assert response.status_code == 403
        assert response.json()["detail"] == "outside grant scope"
        assert await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.5) is None
    alice = env.actors["alice"].id
    for key in (f"agent-activity:{alice}", f"agent-activity-rev:{alice}", f"agent-activity-rate:{alice}"):
        assert not await env.redis.exists(key)


@pytest.mark.asyncio
async def test_bare_identity_caller_is_not_authenticated_for_activity(privacy_app):
    env = privacy_app

    unique = await _request(env, "alice", "POST", PATH, _body(env.actors["alice"].sk, _event(env, "alice")))
    sk, _, did = _make_keypair()
    env.actors["stranger"] = SimpleNamespace(sk=sk, did=did, id=uuid4())
    unresolved = await _request(env, "stranger", "POST", PATH, _body(sk, _event(env, "stranger")))

    assert unique.status_code == 401
    assert unresolved.status_code == 401
    assert await _latest(env, "alice") is None


@pytest.mark.asyncio
async def test_message_ingress_refuses_signed_activity_bytes(privacy_app):
    env = privacy_app
    event = _event(env, "alice")
    canonical = canonical_json_bytes(event)
    signed = {
        "from_did": env.actors["alice"].did,
        "message_id": str(uuid4()),
        "timestamp": event["timestamp"],
        "signature": sign_message(env.actors["alice"].sk, canonical),
        "signed_payload": canonical.decode(),
    }

    chat = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors["bob"].did], "message": "hello", **signed,
    })
    mail = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["bob"].did, "subject": "s", "body": "hello", **signed,
    })

    assert chat.status_code == 422
    assert chat.json()["detail"] == "signed_payload type must be chat"
    assert mail.status_code == 422
    assert mail.json()["detail"] == "signed_payload type must be mail"


# Delivery over the chat session stream.


class _Stream:
    """An open chat session stream, read frame by frame."""

    def __init__(self, lines):
        self._lines = lines

    async def next(self, name, timeout=5):
        async with asyncio.timeout(timeout):
            event = None
            async for line in self._lines:
                if line.startswith("event: "):
                    event = line[len("event: "):]
                elif line.startswith("data: ") and event == name:
                    return json.loads(line[len("data: "):])
        raise AssertionError(f"stream ended before an {name} frame")

    async def frames_until(self, name, timeout=5):
        seen = []
        async with asyncio.timeout(timeout):
            event = None
            async for line in self._lines:
                if line.startswith("event: "):
                    event = line[len("event: "):]
                elif line.startswith("data: "):
                    seen.append(event)
                    if event == name:
                        return seen
        raise AssertionError(f"stream ended before an {name} frame")


def _stream(env, viewer, session_id, *, include=None, seconds=8):
    identity = env.actors[viewer]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    params = {"deadline": deadline}
    if include is not None:
        params["include"] = include
    return env.client.stream(
        "GET", f"/v1/chat/sessions/{session_id}/stream", params=params,
        headers=_signed_identity_headers(identity.sk, identity.did, "", b""),
    )


async def _subscribed(env, actor):
    channel = f"agent-activity:{env.actors[actor].id}"
    async with asyncio.timeout(5):
        while dict(await env.redis.pubsub_numsub(channel))[channel] < 1:
            await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_opted_in_participant_sees_the_signed_event_live(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    event = _event(env, "alice", session_id=session_id)
    body = _body(env.actors["alice"].sk, event)

    async with _stream(env, "bob", session_id, include="agent_activity") as response:
        assert response.status_code == 200
        stream = _Stream(response.aiter_lines())
        await _subscribed(env, "alice")
        published = await _team_request(env, "alice", "POST", PATH, body)
        assert published.status_code == 202, published.text

        frame = await stream.next("agent_activity")

    assert frame == {
        "agent": "alice",
        "signed_payload": body["signed_payload"],
        "signature": body["signature"],
        "from_did": env.actors["alice"].did,
        "phase": "tool",
        "tool": "Bash",
        "summary": "Running pytest",
        "turn_id": "turn-1",
        "seq": 1,
        "expires_at": event["expires_at"],
    }


@pytest.mark.asyncio
async def test_opening_mid_turn_shows_the_current_state(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    assert (await _publish(env, "alice", _event(env, "alice", session_id=session_id, seq=4))).status_code == 202

    async with _stream(env, "bob", session_id, include="agent_activity") as response:
        frame = await _Stream(response.aiter_lines()).next("agent_activity")

    assert (frame["agent"], frame["seq"]) == ("alice", 4)


@pytest.mark.asyncio
async def test_work_in_another_session_shows_busy_then_cleared(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    elsewhere = await _session(env, "carol", "alice")

    async with _stream(env, "bob", session_id, include="agent_activity") as response:
        stream = _Stream(response.aiter_lines())
        await _subscribed(env, "alice")
        busy = _event(env, "alice", session_id=elsewhere)
        assert (await _publish(env, "alice", busy)).status_code == 202
        busy_frame = await stream.next("agent_activity")
        end = _event(env, "alice", session_id=elsewhere, seq=2, phase="turn_ended")
        del end["tool"], end["summary"]
        assert (await _publish(env, "alice", end)).status_code == 202
        cleared_frame = await stream.next("agent_activity")

    assert busy_frame == {"agent": "alice", "phase": "busy_elsewhere", "expires_at": busy["expires_at"]}
    assert cleared_frame == {"agent": "alice", "phase": "cleared"}


@pytest.mark.asyncio
async def test_stream_without_include_never_subscribes_to_activity(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    channel = f"agent-activity:{env.actors['alice'].id}"

    async with _stream(env, "bob", session_id) as response:
        stream = _Stream(response.aiter_lines())
        assert (await _publish(env, "alice", _event(env, "alice", session_id=session_id))).status_code == 202
        reply = await _request(env, "alice", "POST", f"/v1/chat/sessions/{session_id}/messages", {"body": "done"})
        assert reply.status_code == 200, reply.text

        seen = await stream.frames_until("message")
        subscribers = dict(await env.redis.pubsub_numsub(channel))[channel]

    assert "agent_activity" not in seen
    assert subscribers == 0


@pytest.mark.asyncio
async def test_include_does_not_open_a_session_for_a_non_participant(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")

    async with _stream(env, "carol", session_id, include="agent_activity") as response:
        await response.aread()

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


@pytest.mark.asyncio
async def test_a_viewer_does_not_receive_its_own_activity(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")

    async with _stream(env, "bob", session_id, include="agent_activity") as response:
        stream = _Stream(response.aiter_lines())
        await _subscribed(env, "alice")
        own_channel = f"agent-activity:{env.actors['bob'].id}"
        own_subscribers = dict(await env.redis.pubsub_numsub(own_channel))[own_channel]
        assert (await _publish(env, "bob", _event(env, "bob", session_id=session_id))).status_code == 202
        assert (await _publish(env, "alice", _event(env, "alice", session_id=session_id))).status_code == 202

        frame = await stream.next("agent_activity")

    assert own_subscribers == 0
    assert frame["agent"] == "alice"


@pytest.mark.asyncio
async def test_message_sent_while_activity_is_being_set_up_arrives_once(privacy_app, monkeypatch):
    # A barrier around the real subscription: the stream's activity setup is
    # paused after Redis confirms it, while a real chat message is sent.
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    confirmed, resume = asyncio.Event(), asyncio.Event()
    subscribe = SessionActivity.subscribe

    async def paused_subscribe(self, pubsub):
        pending = await subscribe(self, pubsub)
        confirmed.set()
        await resume.wait()
        return pending

    monkeypatch.setattr(SessionActivity, "subscribe", paused_subscribe)

    async with _stream(env, "bob", session_id, include="agent_activity", seconds=4) as response:
        lines = response.aiter_lines()
        async with asyncio.timeout(5):
            await confirmed.wait()
        sent = await _request(env, "alice", "POST", f"/v1/chat/sessions/{session_id}/messages", {"body": "during setup"})
        assert sent.status_code == 200, sent.text
        # Setup outlasts the send by more than any clock difference between
        # this process and the database.
        await asyncio.sleep(1)
        resume.set()

        bodies = []
        event = None
        async with asyncio.timeout(10):
            async for line in lines:
                if line.startswith("event: "):
                    event = line[len("event: "):]
                elif line.startswith("data: ") and event == "message":
                    bodies.append(json.loads(line[len("data: "):])["body"])

    assert bodies == ["during setup"]


@pytest.mark.asyncio
async def test_session_id_with_a_trailing_newline_is_invalid_not_a_server_error(privacy_app):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")

    response = await _publish(env, "alice", _event(env, "alice", session_id=session_id + "\n"))

    assert response.status_code == 422
    assert response.json()["detail"].startswith("invalid_value: ")
    assert await _latest(env, "alice") is None
