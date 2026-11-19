"""Shared replay comparison on real managed attachment mail/chat paths."""

from copy import deepcopy

import pytest

from test_attachments_http import managed_fixture
from test_dashboard_privacy import _request, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_managed_attachment_exact_retry_never_binds_or_emits_twice(
    privacy_app, kind
):
    env = privacy_app
    _, _, wire, conversation_id = await managed_fixture(env, kind)
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
    changed["encrypted_envelope"]["ciphertext"] += "A"
    refused = await _request(env, "alice", "POST", path, changed)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == {
        "code": "attachment_conflict",
        "message": "This message ID already has a different attachment request. Retry the original request unchanged, or choose a new message ID for a new message.",
    }
    if kind == "chat":
        changed = {**wire, "hang_on": not wire.get("hang_on", False)}
        refused = await _request(env, "alice", "POST", path, changed)
        assert refused.status_code == 409, refused.text
        assert refused.json()["detail"]["message"].endswith(
            "choose a new message ID for a new message."
        )
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
    assert repeated.json()["detail"] == (
        "encrypted envelope expired. Check whether the original message was delivered before preparing a new encrypted message."
    )
    assert env.dispatched == before
    assert (
        await env.db.fetch_value(
            "SELECT sum(binds) FROM {{tables.attachment_test_storage}}"
        )
        == 1
    )
