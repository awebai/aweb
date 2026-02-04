from __future__ import annotations

import uuid

import pytest

from .harness import AwebTarget


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_mail_send_inbox_ack_roundtrip(
    aweb_client, aweb_client_2, aweb_target: AwebTarget
) -> None:
    subject = f"conformance-{uuid.uuid4().hex[:8]}"
    body = f"hello-{uuid.uuid4().hex}"

    send = await aweb_client.post(
        "/v1/messages",
        json={
            "to_agent_id": aweb_target.agent_2.agent_id,
            "subject": subject,
            "body": body,
            "priority": "normal",
            "thread_id": None,
        },
    )
    assert send.status_code == 200, send.text
    send_data = send.json()
    assert send_data["status"] == "delivered"
    message_id = send_data["message_id"]
    assert message_id

    inbox = await aweb_client_2.get(
        "/v1/messages/inbox",
        params={"unread_only": True, "limit": 200},
    )
    assert inbox.status_code == 200, inbox.text
    inbox_data = inbox.json()
    messages = inbox_data.get("messages") or []
    found = next((m for m in messages if m.get("message_id") == message_id), None)
    assert found is not None, f"Expected to find message_id={message_id} in inbox"
    assert found["from_alias"] == aweb_target.agent_1.alias
    assert found["subject"] == subject
    assert found["body"] == body

    ack = await aweb_client_2.post(
        f"/v1/messages/{message_id}/ack",
    )
    assert ack.status_code == 200, ack.text
    ack_data = ack.json()
    assert ack_data["message_id"] == message_id
    assert ack_data["acknowledged_at"]

    inbox_after = await aweb_client_2.get(
        "/v1/messages/inbox",
        params={"unread_only": True, "limit": 200},
    )
    assert inbox_after.status_code == 200, inbox_after.text
    messages_after = inbox_after.json().get("messages") or []
    assert all(m.get("message_id") != message_id for m in messages_after)


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_mail_rejects_actor_fields_in_request(aweb_client, aweb_target: AwebTarget) -> None:
    resp = await aweb_client.post(
        "/v1/messages",
        json={
            "from_agent_id": aweb_target.agent_1.agent_id,
            "from_alias": "not-the-canonical-alias",
            "to_agent_id": aweb_target.agent_2.agent_id,
            "subject": "alias mismatch conformance",
            "body": "should be rejected",
            "priority": "normal",
            "thread_id": None,
        },
    )
    assert resp.status_code in (400, 422), resp.text
