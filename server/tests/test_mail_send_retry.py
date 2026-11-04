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
async def test_a_different_message_reusing_a_conversation_id_is_still_refused(aweb_cloud_db):
    db, app, _, alice_sk, alice_key, bob_key = await _sender(aweb_cloud_db)
    conversation_id = str(uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=_signed_send(
            alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="first"))
        assert first.status_code == 200, first.text
        other = await client.post("/v1/messages", json=_signed_send(
            alice_sk, alice_key, bob_key, conversation_id=conversation_id, body="other"))

    assert other.status_code == 409
    assert other.json()["detail"] == "conversation_exists"
    assert await _counts(db) == (1, 1)
