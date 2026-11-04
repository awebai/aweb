"""An exact retry of a signed mail send returns what the first send stored, with no second effect."""
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from test_messages_http import _build_test_app, _insert_agent, _insert_team, _make_keypair


async def _sender(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    alice_sk, _, alice_key = _make_keypair()
    _, _, bob_key = _make_keypair()
    await _insert_team(db, "backend:acme.com")
    alice = await _insert_agent(db, team_id="backend:acme.com", alias="alice",
                               did_key=alice_key, did_aw="did:aw:alice", address="acme.com/alice")
    await _insert_agent(db, team_id="backend:acme.com", alias="bob",
                        did_key=bob_key, did_aw="did:aw:bob", address="acme.com/bob")
    app = _build_test_app(db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)
    events = []

    async def on_mutation(event_type, context):
        events.append((event_type, context["message_id"]))

    app.state.on_mutation = on_mutation

    async def auth():
        return MessagingAuth(did_key=alice_key, did_aw="did:aw:alice", address="acme.com/alice",
                             team_id="backend:acme.com", alias="alice", agent_id=alice)

    app.dependency_overrides[get_messaging_auth] = auth
    return db, app, events, alice_sk, alice_key, bob_key


def _signed_send(alice_sk, alice_key, bob_key, *, conversation_id=None, body="nonce"):
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    claims = {
        "type": "mail", "from": "acme.com/alice", "from_did": alice_key,
        "from_stable_id": "did:aw:alice", "to": "bob", "to_did": bob_key, "to_stable_id": "did:aw:bob",
        "subject": "retry", "body": body, "priority": "normal",
        "message_id": message_id, "timestamp": timestamp,
    }
    if conversation_id is not None:
        claims["conversation_id"] = conversation_id
    signed = canonical_json_bytes(claims)
    request = {"to_alias": "bob", "message_id": message_id, "from_did": alice_key, "timestamp": timestamp,
               "subject": "retry", "body": body, "signature": sign_message(alice_sk, signed),
               "signed_payload": signed.decode()}
    if conversation_id is not None:
        request["conversation_id"] = conversation_id
    return request


def _both_past_the_lookup(monkeypatch):
    """Hold each request after its stored-send lookup until both have looked:
    both see no row, so both go on to insert."""
    import asyncio

    import aweb.routes.messages as message_routes

    lookup = message_routes._stored_exact_send
    arrived = 0
    both = asyncio.Event()

    async def held(*args, **kwargs):
        nonlocal arrived
        result = await lookup(*args, **kwargs)
        if not both.is_set():
            arrived += 1
            if arrived == 2:
                both.set()
            await asyncio.wait_for(both.wait(), timeout=5)
        return result

    monkeypatch.setattr(message_routes, "_stored_exact_send", held)


async def _counts(db):
    messages = await db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
    conversations = await db.fetch_value("SELECT count(*) FROM {{tables.conversations}}")
    return messages, conversations


@pytest.mark.asyncio
@pytest.mark.parametrize("caller_conversation", [True, False])
async def test_an_exact_retry_returns_the_stored_send_with_no_second_effect(aweb_cloud_db, caller_conversation):
    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    request = _signed_send(
        alice_sk, alice_key, bob_key, conversation_id=str(uuid4()) if caller_conversation else None,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=request)
        assert first.status_code == 200, first.text
        after_first = await _counts(db)
        retry = await client.post("/v1/messages", json=request)

    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == first.json()["message_id"] == request["message_id"]
    assert retry.json()["conversation_id"] == first.json()["conversation_id"]
    assert retry.json()["delivered_at"] == first.json()["delivered_at"]
    assert await _counts(db) == after_first == (1, 1)
    assert events == [("message.sent", request["message_id"])]


@pytest.mark.asyncio
async def test_a_different_message_with_the_same_conversation_id_continues_it(aweb_cloud_db):
    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    conversation_id = str(uuid4())
    first_request = _signed_send(alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="first")
    other_request = _signed_send(alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="other")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=first_request)
        assert first.status_code == 200, first.text
        other = await client.post("/v1/messages", json=other_request)

    assert other.status_code == 200, other.text
    assert other.json()["conversation_id"] == conversation_id
    assert other.json()["message_id"] == other_request["message_id"]
    assert await _counts(db) == (2, 1)
    assert events == [("message.sent", first_request["message_id"]), ("message.sent", other_request["message_id"])]


@pytest.mark.asyncio
async def test_a_refused_send_leaves_no_conversation_behind(aweb_cloud_db):
    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    first_request = _signed_send(alice_sk, alice_key, bob_key, body="first")
    reused = _signed_send(alice_sk, alice_key, bob_key, body="different content")
    reused = {**reused, "message_id": first_request["message_id"]}
    claims = __import__("json").loads(reused["signed_payload"])
    claims["message_id"] = first_request["message_id"]
    signed = canonical_json_bytes(claims)
    reused["signed_payload"] = signed.decode()
    reused["signature"] = sign_message(alice_sk, signed)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=first_request)
        assert first.status_code == 200, first.text
        refused = await client.post("/v1/messages", json=reused)

    assert refused.status_code == 409, refused.text
    assert await _counts(db) == (1, 1)
    assert events == [("message.sent", first_request["message_id"])]


@pytest.mark.asyncio
@pytest.mark.parametrize("caller_conversation", [True, False])
async def test_concurrent_identical_sends_deliver_once_and_both_succeed(
    aweb_cloud_db, caller_conversation, monkeypatch,
):
    import asyncio

    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    request = _signed_send(
        alice_sk, alice_key, bob_key, conversation_id=str(uuid4()) if caller_conversation else None,
    )
    _both_past_the_lookup(monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await asyncio.gather(*(client.post("/v1/messages", json=request) for _ in range(2)))

    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    assert {r.json()["message_id"] for r in responses} == {request["message_id"]}
    assert len({r.json()["conversation_id"] for r in responses}) == 1
    assert await _counts(db) == (1, 1)
    assert events == [("message.sent", request["message_id"])]


@pytest.mark.asyncio
async def test_concurrent_identical_continuations_deliver_once_and_both_succeed(aweb_cloud_db, monkeypatch):
    import asyncio

    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    conversation_id = str(uuid4())
    opening = _signed_send(alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="opening")
    retried = _signed_send(alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="retried")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/v1/messages", json=opening)).status_code == 200
        _both_past_the_lookup(monkeypatch)
        responses = await asyncio.gather(*(client.post("/v1/messages", json=retried) for _ in range(2)))

    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    assert {r.json()["message_id"] for r in responses} == {retried["message_id"]}
    assert await _counts(db) == (2, 1)
    assert events == [("message.sent", opening["message_id"]), ("message.sent", retried["message_id"])]


@pytest.mark.asyncio
@pytest.mark.parametrize("continuation", [False, True])
async def test_an_exact_retry_is_refused_once_the_recipient_no_longer_admits_the_sender(aweb_cloud_db, continuation):
    db, app, events, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    conversation_id = str(uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        if continuation:
            opening = _signed_send(alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="opening")
            assert (await client.post("/v1/messages", json=opening)).status_code == 200
        request = _signed_send(
            alice_sk, alice_key, bob_key, conversation_id=conversation_id if continuation else None, body="retried",
        )
        assert (await client.post("/v1/messages", json=request)).status_code == 200
        await db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE did_key = $1", bob_key,
        )
        retry = await client.post("/v1/messages", json=request)

    assert retry.status_code == 403, retry.text
