from __future__ import annotations

import uuid

import pytest

from .harness import AwebTarget


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_creates_persistent_session_and_returns_expected_shape(
    aweb_client, aweb_target: AwebTarget
) -> None:
    message = f"hello-{uuid.uuid4().hex}"
    resp = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": message,
            "leaving": False,
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert isinstance(data.get("session_id"), str) and data["session_id"]
    assert isinstance(data.get("message_id"), str) and data["message_id"]
    assert data.get("sse_url") == f"/v1/chat/sessions/{data['session_id']}/stream"

    participants = data.get("participants")
    assert isinstance(participants, list) and len(participants) >= 2
    aliases = {p.get("alias") for p in participants}
    assert aweb_target.agent_1.alias in aliases
    assert aweb_target.agent_2.alias in aliases

    # Informational fields, but must exist and be lists.
    assert isinstance(data.get("targets_connected"), list)
    assert isinstance(data.get("targets_left"), list)


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_session_is_unique_for_participant_set(aweb_client, aweb_client_2, aweb_target: AwebTarget) -> None:
    msg_1 = f"m1-{uuid.uuid4().hex}"
    msg_2 = f"m2-{uuid.uuid4().hex}"

    r1 = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": msg_1,
            "leaving": False,
        },
    )
    assert r1.status_code == 200, r1.text
    d1 = r1.json()

    # Reverse direction; must still return the same persistent session.
    r2 = await aweb_client_2.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_1.alias],
            "message": msg_2,
            "leaving": False,
        },
    )
    assert r2.status_code == 200, r2.text
    d2 = r2.json()

    assert d2["session_id"] == d1["session_id"]
    assert d2["message_id"] != d1["message_id"]


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_pending_and_mark_read_flow(aweb_client, aweb_client_2, aweb_target: AwebTarget) -> None:
    msg = f"pending-{uuid.uuid4().hex}"

    send = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": msg,
            "leaving": False,
        },
    )
    assert send.status_code == 200, send.text
    send_data = send.json()
    session_id = send_data["session_id"]
    message_id = send_data["message_id"]

    pending = await aweb_client_2.get("/v1/chat/pending")
    assert pending.status_code == 200, pending.text
    pending_data = pending.json()

    conversations = pending_data.get("pending") or []
    assert isinstance(conversations, list)
    found = next((c for c in conversations if c.get("session_id") == session_id), None)
    assert found is not None, f"Expected to find session_id={session_id} in pending"
    assert found["unread_count"] >= 1
    assert found["last_from"] == aweb_target.agent_1.alias
    assert isinstance(found.get("sender_waiting"), bool)

    history_unread = await aweb_client_2.get(
        f"/v1/chat/sessions/{session_id}/messages",
        params={"unread_only": True, "limit": 1000},
    )
    assert history_unread.status_code == 200, history_unread.text
    messages = history_unread.json().get("messages") or []
    assert any(m.get("message_id") == message_id for m in messages)

    mark = await aweb_client_2.post(
        f"/v1/chat/sessions/{session_id}/read",
        json={"up_to_message_id": message_id},
    )
    assert mark.status_code == 200, mark.text
    mark_data = mark.json()
    assert mark_data.get("success") is True
    assert isinstance(mark_data.get("messages_marked"), int)

    pending_after = await aweb_client_2.get("/v1/chat/pending")
    assert pending_after.status_code == 200, pending_after.text
    conversations_after = pending_after.json().get("pending") or []
    assert all(c.get("session_id") != session_id for c in conversations_after)


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_targets_left_semantics(aweb_client, aweb_client_2, aweb_target: AwebTarget) -> None:
    # 1) Agent 2 sends a leaving message to Agent 1.
    leave = await aweb_client_2.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_1.alias],
            "message": "final message",
            "leaving": True,
        },
    )
    assert leave.status_code == 200, leave.text
    leave_data = leave.json()
    session_id = leave_data["session_id"]

    # 2) Agent 1 sends again; targets_left must include agent 2 alias.
    again = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": "ping after leave",
            "leaving": False,
        },
    )
    assert again.status_code == 200, again.text
    again_data = again.json()

    assert again_data["session_id"] == session_id
    assert aweb_target.agent_2.alias in (again_data.get("targets_left") or [])
