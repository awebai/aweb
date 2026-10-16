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

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_agent_status_host_http import _team_request
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair

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
async def test_without_redis_publishing_is_unavailable(privacy_app):
    env = privacy_app
    redis, env.app.state.redis = env.app.state.redis, None
    try:
        response = await _publish(env, "alice", _event(env, "alice"))
    finally:
        env.app.state.redis = redis

    assert response.status_code == 503
    assert response.json()["detail"].startswith("publishing_unavailable: ")


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
