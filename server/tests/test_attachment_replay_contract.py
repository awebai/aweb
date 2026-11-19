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
