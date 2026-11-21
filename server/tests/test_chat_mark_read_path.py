# ruff: noqa: F811 -- pytest imports the shared real-stack fixture by name.
"""Authenticated malformed paths and a real existing-session read neighbour."""

from uuid import uuid4

import pytest

from test_dashboard_privacy import _request, privacy_app as privacy_app

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_mark_read_malformed_path_is_actionable_and_existing_session_still_reads(
    privacy_app,
):
    env = privacy_app
    opened = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [env.actors["bob"].did],
            "message": "Unread boundary neighbour",
        },
    )
    assert opened.status_code == 200, opened.text
    message_id = opened.json()["message_id"]
    session_id = opened.json()["session_id"]
    receipts_before = await env.db.fetch_all(
        "SELECT * FROM {{tables.chat_read_receipts}} ORDER BY session_id,did"
    )
    malformed = await _request(
        env,
        "bob",
        "POST",
        "/v1/chat/sessions/not-a-uuid/read",
        {
            "message_ids": [message_id],
        },
    )
    assert malformed.status_code == 422, malformed.text
    assert malformed.json() == {
        "detail": "Invalid session_id format. Choose a session_id from aw chat pending and retry."
    }
    assert (
        await env.db.fetch_all(
            "SELECT * FROM {{tables.chat_read_receipts}} ORDER BY session_id,did"
        )
        == receipts_before
    )
    outsider = await _request(
        env,
        "carol",
        "POST",
        f"/v1/chat/sessions/{session_id}/read",
        {
            "message_ids": [message_id],
        },
    )
    assert outsider.status_code == 404, outsider.text
    missing = await _request(
        env,
        "bob",
        "POST",
        f"/v1/chat/sessions/{uuid4()}/read",
        {
            "message_ids": [message_id],
        },
    )
    assert missing.status_code == 404, missing.text
    assert (
        await env.db.fetch_all(
            "SELECT * FROM {{tables.chat_read_receipts}} ORDER BY session_id,did"
        )
        == receipts_before
    )
    read = await _request(
        env,
        "bob",
        "POST",
        f"/v1/chat/sessions/{session_id}/read",
        {
            "message_ids": [message_id],
        },
    )
    assert read.status_code == 200, read.text
    assert read.json() == {"success": True, "messages_marked": 1}
    retry = await _request(
        env,
        "bob",
        "POST",
        f"/v1/chat/sessions/{session_id}/read",
        {
            "message_ids": [message_id],
        },
    )
    assert retry.status_code == 200 and retry.json()["messages_marked"] == 0
