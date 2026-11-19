"""Malformed retry metadata remains a request refusal after a real acceptance."""

import json
from uuid import UUID

import pytest

from test_mcp_chat_send_parity import chat_server as chat_server
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
        "wait_seconds": signed.get("wait_seconds", 30),
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
