"""Malformed retry metadata remains a request refusal after a real acceptance."""

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from nacl.signing import SigningKey
from awid.signing import canonical_json_bytes, sign_message

from messaging_actor_support import messaging_actor_headers, remove_messaging_agent_from_sessions
from test_mcp_chat_send_parity import chat_server as chat_server
from test_mcp_mail_conversation_parity import mail_server as mail_server
from test_messages_http import _signed_identity_headers

__all__ = ["chat_server", "mail_server"]


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
async def test_chat_cleanup_preserves_history_but_rejects_a_changed_live_replay(chat_server):
    env = chat_server
    pilot, bob = env.actors["pilot"], env.actors["bob"]
    session_id, message_id = await env.first_chat(
        "mcp", "pilot", "accepted original", to_alias="bob"
    )
    row = await env.db.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(message_id)
    )
    payload = _accepted_plaintext_request(row)
    payload["message"] = payload.pop("body")
    payload.update(session_id=session_id, to_dids=[env.dids["bob"]])
    raw = json.dumps(payload).encode()

    async def retry():
        return await env.client.post(
            "/v1/chat/sessions",
            content=raw,
            headers={
                **messaging_actor_headers(pilot, body=raw, team=False),
                "X-Team-ID": pilot.team_id,
            },
        )

    mail_body = json.dumps({
        "to_did": bob.stable_id, "subject": "Existing thread", "body": "retained mail",
    }).encode()
    mail = await env.client.post(
        "/v1/messages", content=mail_body,
        headers=messaging_actor_headers(pilot, body=mail_body, team=False),
    )
    assert mail.status_code == 200, mail.text

    async def history(params=None):
        response = await env.client.get(
            "/v1/conversations", params=params,
            headers=messaging_actor_headers(pilot, team=False),
        )
        assert response.status_code == 200, response.text
        return {item["conversation_type"]: item for item in response.json()["conversations"]}

    before = (await history())["chat"]
    assert before["conversation_id"] == session_id
    assert bob.stable_id in before["participant_dids"]
    assert bob.address in before["participant_addresses"]

    accepted = await retry()
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["message_id"] == message_id
    await remove_messaging_agent_from_sessions(
        env.db, env.fixture.redis, team_id=pilot.team_id, agent_id=bob.agent_id,
        registry_client=env.registry,
    )
    refused = await retry()
    assert refused.status_code == 409, refused.text
    assert "The stored chat participants differ from the resolved recipients" in refused.text
    assert await env.db.fetch_value(
        "SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1", UUID(session_id)
    ) == 1

    for params in (None, {"participant_did": bob.stable_id}, {"participant_address": bob.address}):
        filtered = await history(params)
        assert set(filtered) == {"mail", "chat"}
        after = filtered["chat"]
        assert after["conversation_id"] == session_id
        for field in ("participants", "participant_dids", "participant_addresses", "participant_details"):
            assert after[field] == before[field]

    departed = await env.client.get(
        "/v1/conversations", params={"conversation_type": "chat"},
        headers=messaging_actor_headers(bob, team=False),
    )
    assert departed.status_code == 200, departed.text
    assert departed.json()["conversations"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("valid_signature", [False, True])
async def test_changed_continued_chat_proof_verifies_before_the_age_only_refusal(
    chat_server, valid_signature
):
    env = chat_server
    session_id, _ = await env.first_chat("mcp", "pilot", "opened", to_alias="bob")
    message_id = await env.continued_chat("mcp", "pilot", session_id, "accepted original")
    row = await env.db.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(message_id)
    )
    signed = json.loads(row["signed_payload"])
    signed["timestamp"] = (
        (datetime.now(timezone.utc) - timedelta(minutes=6)).replace(microsecond=0).isoformat()
    )
    changed_bytes = canonical_json_bytes(signed)
    sender_key, sender_did = env.keys["pilot"]
    signer = sender_key if valid_signature else bytes(SigningKey.generate())
    changed = _accepted_plaintext_request(
        {
            **dict(row),
            "signed_payload": changed_bytes.decode(),
            "signature": sign_message(signer, changed_bytes),
        }
    )
    before = list(env.mutations)

    async def post(payload):
        raw = json.dumps(payload).encode()
        return await env.client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            content=raw,
            headers={
                **_signed_identity_headers(sender_key, sender_did, env.dids["pilot"], raw),
                "Content-Type": "application/json",
            },
        )

    refused = await post(changed)
    assert refused.status_code == 422, refused.text
    if valid_signature:
        assert refused.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
    else:
        assert "X-AWEB-Error-Code" not in refused.headers
        assert refused.json()["detail"] == (
            "The message signature does not verify. Sign the message again with "
            "the authenticated sender's key and resend it."
        )
    repeated = await post(_accepted_plaintext_request(row))
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["message_id"] == message_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 2
    assert env.mutations == before


@pytest.mark.asyncio
async def test_named_exact_retry_retains_local_party_after_current_key_gains_global_did(
    mail_server,
):
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
        "acme.com",
        "ops",
        team_controller_signing_key=env.fixture.team_sk,
        certificate_id=bob.certificate_id,
    )
    global_bob = await admit_messaging_actor(
        env.fixture,
        alias=bob.alias,
        team_id=bob.team,
        signing_key=bob.sk,
        address="acme.com/local-bob",
    )
    assert global_bob.did_key == bob.did and global_bob.stable_id.startswith("did:aw:")
    assert (
        await env.db.fetch_value(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
            UUID(session_id),
            bob.did,
        )
        == bob.did
    )
    before = list(env.custody.payloads)
    payload = _accepted_plaintext_request(row)
    payload["message"] = payload.pop("body")
    payload.update(session_id=session_id, to_aliases=["local-bob"])
    raw = json.dumps(payload).encode()
    repeated = await env.client.post(
        "/v1/chat/sessions",
        content=raw,
        headers={
            **_signed_identity_headers(env.pilot_key, env.pilot_did, env.pilot_stable, raw),
            "X-Team-ID": "ops:acme.com",
            "Content-Type": "application/json",
        },
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["message_id"] == message_id
    assert repeated.json()["session_id"] == session_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 1
    assert env.custody.payloads == before
