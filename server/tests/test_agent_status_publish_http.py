"""Signed status publishing through the real app, AWID registry, PostgreSQL and Redis.

The designated status host, or the agent itself when none is designated,
publishes a signed status document for the agent (aweb-acah.3,
docs/agent-health.md). Fixture provisioning and clearing the per-agent rate
window between deliberate repeat publishes are the only direct state writes.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json

import pytest

from awid.signing import canonical_json_bytes, canonical_payload, sign_message
from test_agent_status_host_http import _team_request
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _document(env, subject, publisher, *, seq=None, reachable="no", **changes):
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    document = {
        "v": 1,
        "type": "agent_status",
        "team_id": TEAM,
        "agent": env.actors[subject].did,
        "publisher_did": env.actors[publisher].did,
        "seq": seq if seq is not None else int(observed.timestamp() * 1000),
        "reachable": reachable,
        "observed_at": _ts(observed),
        "valid_until": _ts(observed + timedelta(minutes=5)),
    }
    if reachable != "yes":
        document["reason"] = {"code": "oats.grant_expired", "text": "Its connection expired."}
        document["fixing"] = {"by": "automatic", "text": "Its server is renewing the connection."}
    document.update(changes)
    return document


def _body(env, publisher, document, *, raw=None):
    canonical = raw if raw is not None else canonical_json_bytes(document)
    return {
        "signed_payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
        "signature": sign_message(env.actors[publisher].sk, canonical),
    }


async def _publish(env, publisher, subject, document, *, raw=None):
    return await _team_request(
        env, publisher, "PUT", f"/v1/agents/{subject}/status", _body(env, publisher, document, raw=raw),
    )


async def _open_rate_window(env, subject):
    await env.redis.delete(f"agent-status-rate:{env.actors[subject].id}")


async def _stored(env, subject):
    row = await env.db.fetch_one(
        "SELECT publisher_did, seq, reachable FROM {{tables.agent_status}} WHERE agent_id = $1",
        env.actors[subject].id,
    )
    return dict(row) if row else None


async def _designate(env, subject, host):
    response = await _team_request(
        env, subject, "PUT", "/v1/agents/me/status-host", {"host_did": env.actors[host].did},
    )
    assert response.status_code == 200, response.text


def _status_events(env):
    return [context for event, context in env.dispatched if event == "agent.status"]


@pytest.mark.asyncio
async def test_agent_publishes_its_own_status_when_no_host_is_designated(privacy_app):
    env = privacy_app
    document = _document(env, "alice", "alice")

    response = await _publish(env, "alice", "alice", document)

    assert response.status_code == 200, response.text
    assert response.json() == {"agent_id": str(env.actors["alice"].id), "alias": "alice", "seq": document["seq"]}
    assert await _stored(env, "alice") == {
        "publisher_did": env.actors["alice"].did, "seq": document["seq"], "reachable": "no",
    }


@pytest.mark.asyncio
async def test_designated_host_publishes_for_the_agent(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")

    response = await _publish(env, "bob", "alice", _document(env, "alice", "bob"))

    assert response.status_code == 200, response.text
    assert (await _stored(env, "alice"))["publisher_did"] == env.actors["bob"].did


@pytest.mark.asyncio
async def test_only_the_designated_host_may_publish(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")

    for publisher in ("alice", "carol"):
        response = await _publish(env, publisher, "alice", _document(env, "alice", publisher))
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "not_status_host: not the status host for alice"
    assert await _stored(env, "alice") is None


@pytest.mark.asyncio
async def test_another_member_cannot_publish_for_an_agent_without_a_host(privacy_app):
    env = privacy_app

    response = await _publish(env, "carol", "alice", _document(env, "alice", "carol"))

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "not_status_host: not the status host for alice"


@pytest.mark.asyncio
async def test_grant_callers_cannot_publish(privacy_app):
    env = privacy_app

    response = await env.client.put(
        "/v1/agents/alice/status",
        headers={"Authorization": "AWEB-Grant DIDKey did:key:z6Mkexample sig"},
    )

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "outside grant scope"


@pytest.mark.asyncio
async def test_host_that_left_the_team_cannot_publish(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at = NOW(), status = 'deleted' WHERE agent_id = $1",
        env.actors["bob"].id,
    )

    response = await _publish(env, "bob", "alice", _document(env, "alice", "bob"))

    assert response.status_code == 403, response.text
    assert await _stored(env, "alice") is None


@pytest.mark.asyncio
async def test_seq_must_increase(privacy_app):
    env = privacy_app
    first = _document(env, "alice", "alice", seq=1000)
    assert (await _publish(env, "alice", "alice", first)).status_code == 200

    for seq in (1000, 999):
        await _open_rate_window(env, "alice")
        response = await _publish(env, "alice", "alice", _document(env, "alice", "alice", seq=seq))
        assert response.status_code == 409, response.text
        assert response.json()["detail"].startswith("stale_seq:")
    await _open_rate_window(env, "alice")
    assert (await _publish(env, "alice", "alice", _document(env, "alice", "alice", seq=1001))).status_code == 200
    assert (await _stored(env, "alice"))["seq"] == 1001


@pytest.mark.asyncio
async def test_expired_window_is_refused(privacy_app):
    env = privacy_app
    observed = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=2)
    document = _document(
        env, "alice", "alice", observed_at=_ts(observed), valid_until=_ts(observed + timedelta(minutes=1)),
    )

    response = await _publish(env, "alice", "alice", document)

    assert response.status_code == 422, response.text
    assert response.json()["detail"].startswith("expired:")
    assert await _stored(env, "alice") is None


@pytest.mark.asyncio
async def test_mail_payload_is_refused_as_a_status(privacy_app):
    env = privacy_app
    mail = {
        "from": "alice", "from_did": env.actors["alice"].did, "to": "bob", "to_did": env.actors["bob"].did,
        "type": "mail", "message_id": "8b1c2c69-7c2a-4fbb-9f4a-3dfb7d7a26c0", "subject": "s", "body": "b",
        "timestamp": _ts(datetime.now(timezone.utc)),
    }

    response = await _publish(env, "alice", "alice", mail, raw=canonical_payload(mail))

    assert response.status_code == 422, response.text
    assert response.json()["detail"].startswith("wrong_type:")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes,code",
    [
        ({"agent": "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2"}, "agent_mismatch"),
        ({"team_id": "other:example.test"}, "team_mismatch"),
    ],
)
async def test_document_must_name_the_path_agent_and_the_authenticated_team(privacy_app, changes, code):
    env = privacy_app

    response = await _publish(env, "alice", "alice", _document(env, "alice", "alice", **changes))

    assert response.status_code == 422, response.text
    assert response.json()["detail"].startswith(f"{code}:")


@pytest.mark.asyncio
async def test_unknown_agent_is_not_found(privacy_app):
    env = privacy_app

    response = await _publish(env, "alice", "nobody", _document(env, "alice", "alice"))

    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "agent_not_found: Agent not found"


@pytest.mark.asyncio
async def test_second_publish_within_five_seconds_is_rate_limited(privacy_app):
    env = privacy_app
    assert (await _publish(env, "alice", "alice", _document(env, "alice", "alice", seq=1))).status_code == 200

    response = await _publish(env, "alice", "alice", _document(env, "alice", "alice", seq=2))

    assert response.status_code == 429, response.text
    assert response.json()["detail"] == "rate_limited: at most one status per agent every 5 seconds"
    assert 1 <= int(response.headers["Retry-After"]) <= 5
    assert (await _stored(env, "alice"))["seq"] == 1


@pytest.mark.asyncio
async def test_publishing_is_not_message_metering(privacy_app):
    env = privacy_app

    response = await _publish(env, "alice", "alice", _document(env, "alice", "alice"))

    assert response.status_code == 200, response.text
    assert [event for event, _ in env.dispatched if event.startswith(("message.", "chat."))] == []


@pytest.mark.asyncio
async def test_changing_the_host_drops_the_previous_publishers_status(privacy_app):
    env = privacy_app
    assert (await _publish(env, "alice", "alice", _document(env, "alice", "alice"))).status_code == 200

    await _designate(env, "alice", "bob")
    assert await _stored(env, "alice") is None

    await _open_rate_window(env, "alice")
    assert (await _publish(env, "bob", "alice", _document(env, "alice", "bob", seq=5))).status_code == 200
    await _designate(env, "alice", "bob")
    assert (await _stored(env, "alice"))["seq"] == 5

    cleared = await _team_request(env, "alice", "DELETE", "/v1/agents/me/status-host")
    assert cleared.status_code == 200, cleared.text
    assert await _stored(env, "alice") is None


@pytest.mark.asyncio
async def test_status_event_fires_only_when_the_verdict_changes(privacy_app):
    env = privacy_app
    pubsub = env.redis.pubsub()
    await pubsub.subscribe(f"team-events:{TEAM}")
    try:
        documents = [
            _document(env, "alice", "alice", seq=1),
            _document(env, "alice", "alice", seq=2),
            _document(env, "alice", "alice", seq=3, reachable="yes"),
        ]
        for document in documents:
            await _open_rate_window(env, "alice")
            response = await _publish(env, "alice", "alice", document)
            assert response.status_code == 200, response.text

        contexts = _status_events(env)
        assert [context["reachable"] for context in contexts] == ["no", "yes"]
        relayed = []
        for _ in range(50):
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message is not None:
                payload = json.loads(message["data"])
                if payload["type"] == "agent.status":
                    relayed.append(payload)
            if len(relayed) == 2:
                break
    finally:
        await pubsub.unsubscribe()
        await pubsub.aclose()

    assert [event["reachable"] for event in relayed] == ["no", "yes"]
    first = relayed[0]
    assert first["alias"] == "alice"
    assert first["agent_id"] == str(env.actors["alice"].id)
    assert first["reason_text"] == "Its connection expired."
    assert first["fixing_by"] == "automatic"
    assert first["fixing_text"] == "Its server is renewing the connection."
    assert first["valid_until"] == documents[0]["valid_until"]


@pytest.mark.asyncio
async def test_retiring_the_agent_removes_its_status(privacy_app):
    env = privacy_app
    assert (await _publish(env, "alice", "alice", _document(env, "alice", "alice"))).status_code == 200

    retired = await _team_request(env, "alice", "DELETE", f"/v1/workspaces/{env.actors['alice'].workspace}")

    assert retired.status_code == 200, retired.text
    assert await _stored(env, "alice") is None

