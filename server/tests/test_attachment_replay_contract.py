"""Shared replay comparison on real managed attachment mail/chat paths."""

import base64
from copy import deepcopy

import pytest

from test_attachments_http import managed_fixture
from test_dashboard_privacy import _request, privacy_app as privacy_app

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_managed_attachment_exact_retry_never_binds_or_emits_twice(
    privacy_app, kind
):
    env = privacy_app
    _, descriptor, wire, conversation_id = await managed_fixture(env, kind)
    path = (
        "/v1/messages"
        if kind == "mail"
        else f"/v1/chat/sessions/{conversation_id}/messages"
    )
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    event_count = len(env.dispatched)
    original = await _request(env, "alice", "POST", path, wire)
    assert original.status_code == 200, original.text
    assert original.json() == accepted.json()
    changed = deepcopy(wire)
    ciphertext = changed["encrypted_envelope"]["ciphertext"]
    corrupted = bytearray(base64.b64decode(ciphertext + "=" * (-len(ciphertext) % 4)))
    corrupted[0] ^= 1
    changed["encrypted_envelope"]["ciphertext"] = (
        base64.b64encode(corrupted).decode().rstrip("=")
    )
    refused = await _request(env, "alice", "POST", path, changed)
    # Corruption fails ordinary integrity before the replay comparison.
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"] == {
        "code": "request_invalid",
        "message": "ciphertext hash mismatch. Check whether the original message was delivered before preparing a new encrypted message.",
    }
    # A valid new artifact under that ID reaches the shared collision rule.
    from datetime import datetime
    from aweb.e2ee_messages import encrypt_e2ee_message

    recipient = {
        key: value
        for key, value in env.attachment_keys["bob"].items()
        if key not in {"private_key", "signing_key"}
    }
    changed = deepcopy(wire)
    changed["encrypted_envelope"] = encrypt_e2ee_message(
        kind=kind,
        sender=env.attachment_keys["alice"],
        recipients=[recipient],
        body="different message",
        attachments=[descriptor],
        message_id=wire["message_id"],
        conversation_id=conversation_id,
        created_at=datetime.fromisoformat(wire["timestamp"].replace("Z", "+00:00")),
    )
    refused = await _request(env, "alice", "POST", path, changed)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == {
        "code": "attachment_conflict",
        "message": "message_id already exists for a different signed message. Retry the original request unchanged; choose a new message_id only if you intend to send a different message.",
    }
    if kind == "chat":
        changed = {**wire, "hang_on": not wire.get("hang_on", False)}
        refused = await _request(env, "alice", "POST", path, changed)
        assert refused.status_code == 409, refused.text
        assert refused.json()["detail"] == {
            "code": "attachment_conflict",
            "message": "message_id already exists for a different signed message. Retry the original request unchanged; choose a new message_id only if you intend to send a different message.",
        }
    assert len(env.dispatched) == event_count
    assert (
        await env.db.fetch_value(
            "SELECT sum(binds) FROM {{tables.attachment_test_storage}}"
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_exact_attachment_retry_keeps_the_encrypted_ingestion_deadline(
    privacy_app, kind
):
    import asyncio
    from datetime import datetime, timedelta, timezone
    from aweb.e2ee_messages import E2EE_INGESTION_WINDOW

    env = privacy_app
    from test_native_mail_admission_commit import connect_policy_members

    await connect_policy_members(env)
    created = datetime.now(timezone.utc) - E2EE_INGESTION_WINDOW + timedelta(seconds=10)
    _, _, wire, conversation_id = await managed_fixture(env, kind, created_at=created)
    path = (
        "/v1/messages"
        if kind == "mail"
        else f"/v1/chat/sessions/{conversation_id}/messages"
    )
    accepted = await _request(env, "alice", "POST", path, wire)
    assert accepted.status_code == 200, accepted.text
    before = list(env.dispatched)
    deadline = datetime.fromisoformat(
        wire["encrypted_envelope"]["expires_at"].replace("Z", "+00:00")
    )
    await asyncio.sleep(
        max(0, (deadline - datetime.now(timezone.utc)).total_seconds()) + 0.1
    )
    assert datetime.now(timezone.utc) > deadline
    repeated = await _request(env, "alice", "POST", path, wire)
    assert repeated.status_code == 422, repeated.text
    assert repeated.json()["detail"] == {
        "code": "request_invalid",
        "message": "encrypted envelope expired. Check whether the original message was delivered before preparing a new encrypted message.",
    }
    assert env.dispatched == before
    assert (
        await env.db.fetch_value(
            "SELECT sum(binds) FROM {{tables.attachment_test_storage}}"
        )
        == 1
    )
