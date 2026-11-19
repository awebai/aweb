"""Malformed retry metadata remains a request refusal after a real acceptance."""

import json
from uuid import UUID

import pytest

from test_mcp_chat_send_parity import chat_server as chat_server
from test_mcp_mail_conversation_parity import mail_server as mail_server
from test_messages_http import _signed_identity_headers


@pytest.mark.asyncio
async def test_named_plaintext_replay_without_timestamp_is_a_request_refusal(chat_server):
    env = chat_server
    session_id, message_id = await env.first_chat(
        "mcp", "pilot", "accepted original", to_alias="bob"
    )
    row = await env.db.fetch_one(
        "SELECT signature,signed_payload FROM {{tables.chat_messages}} WHERE message_id=$1",
        UUID(message_id),
    )
    signed = json.loads(row["signed_payload"])
    payload = {
        "to_dids": [env.dids["bob"]],
        "session_id": session_id,
        "message_id": message_id,
        "message": signed["body"],
        "wait_seconds": signed.get("wait_seconds"),
        "leaving": signed.get("sender_leaving", False),
        "hang_on": signed.get("hang_on", False),
        "from_did": signed["from_did"],
        "signature": row["signature"],
        "signed_payload": row["signed_payload"],
    }
    before = list(env.mutations)

    async def post(body):
        raw = json.dumps(body).encode()
        sk, did = env.keys["pilot"]
        return await env.client.post(
            "/v1/chat/sessions",
            content=raw,
            headers={
                **_signed_identity_headers(sk, did, env.dids["pilot"], raw),
                "Content-Type": "application/json",
            },
        )

    refused = await post(payload)
    assert refused.status_code == 422, refused.text
    assert "message_id and timestamp are required" in refused.text
    assert "X-AWEB-Error-Code" not in refused.headers
    valid = await post({**payload, "timestamp": signed["timestamp"]})
    assert valid.status_code == 200, valid.text
    assert valid.json()["message_id"] == message_id
    assert valid.json()["session_id"] == session_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 1
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}") == 1
    assert env.mutations == before


def _accepted_plaintext_request(row):
    signed = json.loads(row["signed_payload"])
    return {
        "message_id": str(row["message_id"]),
        "body": signed["body"],
        "wait_seconds": signed.get("wait_seconds"),
        "leaving": signed.get("sender_leaving", False),
        "hang_on": signed.get("hang_on", False),
        "from_did": signed["from_did"],
        "timestamp": signed["timestamp"],
        "signature": row["signature"],
        "signed_payload": row["signed_payload"],
    }


@pytest.mark.asyncio
async def test_exact_continued_plaintext_retry_survives_retained_departure(chat_server):
    env = chat_server
    session_id, _ = await env.first_chat("mcp", "pilot", "opened", to_alias="bob")
    message_id = await env.continued_chat("mcp", "pilot", session_id, "accepted original")
    row = await env.db.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(message_id)
    )
    # Current sends' `leaving` flag ends a wait; it does not write left_at.
    # Exercise the retained legacy departure shape on actual accepted parties.
    await env.db.execute(
        "UPDATE {{tables.chat_participants}} SET left_at=NOW() WHERE session_id=$1 AND did=$2",
        UUID(session_id), env.dids["bob"],
    )
    before = list(env.mutations)
    payload = _accepted_plaintext_request(row)
    raw = json.dumps(payload).encode()
    sk, did = env.keys["pilot"]
    repeated = await env.client.post(
        f"/v1/chat/sessions/{session_id}/messages", content=raw,
        headers={**_signed_identity_headers(sk, did, env.dids["pilot"], raw),
                 "Content-Type": "application/json"},
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["message_id"] == message_id
    assert repeated.json()["conversation_id"] == session_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 2
    assert env.mutations == before


@pytest.mark.asyncio
async def test_named_exact_retry_retains_local_party_after_current_key_gains_global_did(mail_server):
    from messaging_actor_support import admit_messaging_actor
    from test_local_policy_refusal_boundaries import admitted_local_recipient

    env = mail_server
    bob = await admitted_local_recipient(env, team="ops:acme.com")
    accepted = await env.mcp_call(
        "send_chat", to="local-bob", message="accepted before registration", plaintext=True
    )
    assert "error" not in accepted, accepted
    message_id, session_id = accepted["message_id"], accepted["session_id"]
    row = await env.db.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(message_id)
    )
    await env.registry.revoke_team_certificate(
        "acme.com", "ops", team_controller_signing_key=env.fixture.team_sk,
        certificate_id=bob.certificate_id,
    )
    global_bob = await admit_messaging_actor(
        env.fixture, alias=bob.alias, team_id=bob.team, signing_key=bob.sk,
        address="acme.com/local-bob",
    )
    assert global_bob.did_key == bob.did and global_bob.stable_id.startswith("did:aw:")
    assert await env.db.fetch_value(
        "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
        UUID(session_id), bob.did,
    ) == bob.did
    before = list(env.custody.payloads)
    payload = _accepted_plaintext_request(row)
    payload["message"] = payload.pop("body")
    payload.update(session_id=session_id, to_aliases=["local-bob"])
    raw = json.dumps(payload).encode()
    repeated = await env.client.post(
        "/v1/chat/sessions", content=raw,
        headers={**_signed_identity_headers(env.pilot_key, env.pilot_did, env.pilot_stable, raw),
                 "X-Team-ID": "ops:acme.com", "Content-Type": "application/json"},
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["message_id"] == message_id
    assert repeated.json()["session_id"] == session_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 1
    assert env.custody.payloads == before
