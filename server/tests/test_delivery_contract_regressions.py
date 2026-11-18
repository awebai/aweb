# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Delivery boundaries through the real apps, keys, registry and databases."""

import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.mcp.server import create_mcp_app
from identity_binding_support import register_global_identity
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


async def _send(env, payload):
    actor = env.actors["alice"]
    body = json.dumps(payload).encode()
    return await env.client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["to_did", "to_stable_id", "to_address"])
async def test_matching_agent_selector_preserves_identity_participant(
    privacy_app, selector
):
    env = privacy_app
    bob = env.actors["bob"]
    if selector == "to_stable_id":
        stable = await register_global_identity(env, bob)
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1, did_aw_verified_key=did_key, identity_scope='global' WHERE agent_id=$2",
            stable,
            bob.id,
        )
        target = stable
    else:
        target = bob.did if selector == "to_did" else "example.test/bob"
    payload = {
        selector: target,
        "to_agent_id": str(bob.id),
        "body": "matching identity",
    }
    response = await _send(env, payload)
    assert response.status_code == 200, response.text
    participant = await env.db.fetch_one(
        "SELECT agent_id FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        UUID(response.json()["conversation_id"]),
        target if selector != "to_address" else bob.did,
    )
    assert participant is not None and participant["agent_id"] is None
    mismatch = await _send(env, {**payload, "to_agent_id": str(env.actors["carol"].id)})
    assert mismatch.status_code == 422, mismatch.text
    assert mismatch.json()["detail"].endswith("Check the recipient and try again.")
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
@pytest.mark.parametrize("recipient_claims", [True, False])
async def test_plaintext_send_verifies_signature_before_any_effect(
    privacy_app, valid, recipient_claims
):
    env = privacy_app
    alice, bob, carol = (env.actors[name] for name in ("alice", "bob", "carol"))
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = {
        "type": "mail",
        "from": "alice",
        "from_did": alice.did,
        "body": "signature-bound",
        "subject": "",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "timestamp": timestamp,
    }
    if recipient_claims:
        signed.update(to=bob.did, to_did=bob.did)
    original = canonical_json_bytes(signed).decode()
    response = await _send(
        env,
        {
            "to_did": bob.did,
            "from_did": alice.did,
            "body": signed["body"],
            "message_id": message_id,
            "conversation_id": conversation_id,
            "timestamp": timestamp,
            "signed_payload": original,
            "signature": sign_message(
                alice.sk if valid else carol.sk, original.encode()
            ),
        },
    )
    if valid:
        assert response.status_code == 200, response.text
        row = await env.db.fetch_one(
            "SELECT signed_payload FROM {{tables.messages}} WHERE message_id=$1",
            UUID(message_id),
        )
        assert row["signed_payload"] == original
    else:
        assert response.status_code == 422, response.text
        assert (
            response.json()["detail"]
            == "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
        )
        for table in (
            "messages",
            "conversations",
            "conversation_participants",
            "message_ingress_receipts",
        ):
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables." + table + "}}"
                )
                == 0
            )


@pytest.mark.asyncio
async def test_mounted_mcp_mail_reports_the_same_removed_sender_state(privacy_app):
    env = privacy_app
    sent = await _send(env, {"to_alias": "bob", "body": "before sender retirement"})
    assert sent.status_code == 200, sent.text
    await env.db.execute(
        "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1",
        env.actors["alice"].id,
    )
    bob = env.actors["bob"]
    headers = _signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
    inbox = await env.client.get("/v1/messages/inbox", headers=headers)
    assert inbox.status_code == 200, inbox.text
    expected = inbox.json()["messages"][0]["sender_membership"]
    assert expected["state"] == "inactive"
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
    )
    env.app.mount("/sender-state-mcp", mcp)
    await mcp.startup()
    try:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "check_mail",
                    "arguments": {},
                },
            }
        ).encode()
        response = await env.client.post(
            "/sender-state-mcp/",
            content=body,
            headers={
                **_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate, body),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        tool = response.json()["result"]
        assert not tool.get("isError"), tool
        messages = json.loads(tool["content"][0]["text"])["messages"]
        assert messages[0]["sender_membership"] == expected
    finally:
        await mcp.shutdown()
