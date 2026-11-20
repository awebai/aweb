"""Exact bound attachments still obey the recipient's current public policy."""

import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from chat_pair_support import route_pair as route_pair
from test_attachments_http import managed_fixture
from test_dashboard_privacy import _request
from test_messages_http import _signed_team_headers
from test_federated_chat_create_retry import connect_pair_actor


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_exact_attachment_retry_obeys_public_contacts_only_policy(route_pair, kind):
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
    assert wire["encrypted_envelope"]["routing"]["to_stable_id"] == recipient.stable
    if kind == "mail":
        assert wire["to_did"] == recipient.did
        assert "to_stable_id" not in wire
    path = "/v1/messages" if kind == "mail" else f"/v1/chat/sessions/{conversation_id}/messages"
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    before = await node.db.fetch_value("SELECT sum(binds) FROM {{tables.attachment_test_storage}}")
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
        await node.db.fetch_value("SELECT sum(binds) FROM {{tables.attachment_test_storage}}")
        == before
        == 1
    )

    assert await node.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == rows_before


@pytest.mark.asyncio
async def test_accepted_key_only_attachment_retry_keeps_its_protected_recipient(route_pair):
    from aweb.e2ee_messages import encrypt_e2ee_message

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
    _, descriptor, wire, conversation_id = await managed_fixture(env, "mail")
    assert "to_stable_id" not in wire
    path = "/v1/messages"
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    repeated = await _request(env, "alice", "POST", path, wire)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == accepted.json()

    changed_artifact = encrypt_e2ee_message(
        kind="mail",
        sender=env.attachment_keys["alice"],
        recipients=[env.attachment_keys["bob"]],
        body="a different signed artifact",
        attachments=[descriptor],
        message_id=wire["message_id"],
        conversation_id=conversation_id,
    )
    for changed in (
        {**wire, "to_did": sender.did},
        {
            **wire,
            "encrypted_envelope": changed_artifact,
            "timestamp": changed_artifact["created_at"],
        },
    ):
        refused = await _request(env, "alice", "POST", path, changed)
        assert refused.status_code == 409, refused.text
        assert refused.json()["detail"]["code"] == "attachment_conflict"
        assert refused.json()["detail"]["message"] == (
            "conversation_id recipient does not match the requested recipient. "
            "Use the stored recipient or start a new conversation."
        )
    assert await node.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1
    assert (
        await node.db.fetch_value("SELECT sum(binds) FROM {{tables.attachment_test_storage}}") == 1
    )


@pytest.mark.asyncio
async def test_exact_encrypted_chat_retry_survives_retained_departure(route_pair):
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
    _, _, wire, conversation_id = await managed_fixture(env, "chat")
    path = f"/v1/chat/sessions/{conversation_id}/messages"
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    # Retained legacy departure state on actual admitted parties, as in the
    # plaintext control. Today's leaving flag ends a wait, not membership.
    await node.db.execute(
        "UPDATE {{tables.chat_participants}} SET left_at=NOW() WHERE session_id=$1 AND did=$2",
        UUID(conversation_id),
        recipient.stable,
    )
    repeated = await _request(env, "alice", "POST", path, wire)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == accepted.json()
    assert await node.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 2
    assert (
        await node.db.fetch_value("SELECT sum(binds) FROM {{tables.attachment_test_storage}}") == 1
    )
