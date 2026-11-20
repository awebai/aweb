"""Exact bound attachments still obey the recipient's current public policy."""

import json
from types import SimpleNamespace

import pytest

from chat_pair_support import route_pair as route_pair
from test_attachments_http import managed_fixture
from test_dashboard_privacy import _request
from test_messages_http import _signed_team_headers
from test_federated_chat_create_retry import connect_pair_actor


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_exact_attachment_retry_obeys_public_contacts_only_policy(
    route_pair, kind
):
    node = route_pair.source
    sender, recipient = node.local, node.global_actor
    for actor in (sender, recipient):
        await connect_pair_actor(actor)
    env = SimpleNamespace(
        actors={"alice": sender, "bob": recipient},
        app=node.server.app,
        db=node.db,
        client=node.client,
        team_id=node.team_id,
    )
    _, _, wire, conversation_id = await managed_fixture(env, kind)
    path = (
        "/v1/messages"
        if kind == "mail"
        else f"/v1/chat/sessions/{conversation_id}/messages"
    )
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    before = await node.db.fetch_value(
        "SELECT sum(binds) FROM {{tables.attachment_test_storage}}"
    )
    if kind == "mail":
        assert wire["to_stable_id"] == recipient.stable
        key_only = {key: value for key, value in wire.items() if key != "to_stable_id"}
        selector_refused = await _request(env, "alice", "POST", path, key_only)
        assert selector_refused.status_code == 409, selector_refused.text
        assert selector_refused.json()["detail"] == {
            "code": "attachment_conflict",
            "message": "conversation_id recipient does not match the requested recipient. Use the stored recipient or start a new conversation.",
        }
    table = "messages" if kind == "mail" else "chat_messages"
    rows_before = await node.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")
    raw = json.dumps({"inbound_mode": "contacts_only"}).encode()
    changed = await node.client.patch(
        "/v1/agents/me/inbound-mode",
        content=raw,
        headers={
            **_signed_team_headers(
                recipient.sk,
                recipient.did,
                node.team_id,
                recipient.encoded_certificate,
                raw,
            ),
            "Content-Type": "application/json",
        },
    )
    assert changed.status_code == 200, changed.text
    refused = await _request(env, "alice", "POST", path, wire)
    assert refused.status_code == 403, refused.text
    assert refused.json()["reason"] == "recipient_policy_rejected"
    assert refused.json()["detail"] == (
        "Recipient only accepts messages from exact active contacts. Ask the recipient to add your exact address as a contact or check their inbound policy."
    )
    assert (
        await node.db.fetch_value(
            "SELECT sum(binds) FROM {{tables.attachment_test_storage}}"
        )
        == before
        == 1
    )

    assert await node.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == rows_before
