"""Recipient sends start fresh; only an explicit ID selects a continuation."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from json import dumps
from messaging_actor_support import (
    admit_privacy_actor,
    messaging_actor_headers,
    set_messaging_inbound_mode,
)
from test_dashboard_privacy import privacy_app  # noqa: F401


def json_bytes(payload):
    return dumps(payload).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["alias", "did", "stable_id", "address"])
@pytest.mark.parametrize("new_flag", [False, True])
async def test_new_mail_conversation(privacy_app, target, new_flag):
    env = privacy_app
    db = env.db
    alice = await admit_privacy_actor(env, "alice", address="example.test/alice")
    bob = await admit_privacy_actor(env, "bob", address="example.test/bob")
    alice_sk, alice_key, bob_key = alice.sk, alice.did, bob.did
    recipient = {
        "alias": {"to_alias": "bob"},
        "did": {"to_did": bob_key},
        "stable_id": {"to_stable_id": bob.stable_id},
        "address": {"to_address": bob.address},
    }[target]

    class SignedSender:
        async def post(self, path, *, json):
            raw = json_bytes(json)
            return await env.client.post(
                path,
                content=raw,
                headers=messaging_actor_headers(alice.registered, body=raw),
            )

    client = SignedSender()
    original = await client.post("/v1/messages", json={**recipient, "body": "original"})
    assert original.status_code == 200, original.text
    old = original.json()["conversation_id"]
    ordinary = await client.post(
        "/v1/messages",
        json={**recipient, "body": "ordinary", "new_conversation": new_flag},
    )
    assert ordinary.status_code == 200, ordinary.text
    assert ordinary.json()["conversation_id"] != old
    fresh, message = str(uuid4()), str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = canonical_json_bytes(
        {
            "type": "mail",
            "from": alice.address,
            "from_did": alice_key,
            "from_stable_id": alice.stable_id,
            "to": next(iter(recipient.values())),
            "to_did": bob_key,
            "to_stable_id": bob.stable_id,
            "subject": "fresh",
            "body": "nonce",
            "priority": "normal",
            "conversation_id": fresh,
            "message_id": message,
            "timestamp": timestamp,
        }
    )
    request = {
        **recipient,
        "new_conversation": new_flag,
        "conversation_id": fresh,
        "message_id": message,
        "from_did": alice_key,
        "timestamp": timestamp,
        "subject": "fresh",
        "body": "nonce",
        "signature": sign_message(alice_sk, signed),
        "signed_payload": signed.decode(),
    }
    response = await client.post("/v1/messages", json=request)
    assert response.status_code == 200, response.text
    assert response.json()["conversation_id"] == fresh != old
    assert response.json()["message_id"] == message
    rows = await db.fetch_all(
        "SELECT message_id FROM {{tables.messages}} WHERE conversation_id=$1",
        UUID(fresh),
    )
    assert [str(row["message_id"]) for row in rows] == [message]
    # The deprecated flag does not change explicit continuation or fresh send.
    continuation = await client.post(
        "/v1/messages",
        json={
            "new_conversation": new_flag,
            "conversation_id": old,
            "body": "explicit continuation",
        },
    )
    assert continuation.status_code == 200, continuation.text
    assert continuation.json()["conversation_id"] == old
    count = await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}")
    assert count["n"] == 4

    # The accepted flag does not make a changed signed conversation ID valid.
    tampered = await client.post(
        "/v1/messages", json={**request, "conversation_id": str(uuid4())}
    )
    assert tampered.status_code == 422, tampered.text
    assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 4

    blocked = await admit_privacy_actor(
        env,
        "carol",
        team_id="ops:otherco.com",
        address="otherco.com/blocked",
        new_identity=True,
    )
    blocked_key = blocked.did
    await set_messaging_inbound_mode(env, blocked.registered, mode="team_and_contacts")
    denied_id = str(uuid4())
    denied = await client.post(
        "/v1/messages",
        json={
            "to_did": blocked_key,
            "new_conversation": True,
            "conversation_id": denied_id,
            "body": "must not send",
        },
    )
    assert denied.status_code == 403, denied.text
    assert (
        await db.fetch_one(
            "SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1",
            UUID(denied_id),
        )
        is None
    )
    assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 4
