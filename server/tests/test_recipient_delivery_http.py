# ruff: noqa: F811 -- pytest imports the shared real-stack fixture by name.
"""Real native rows and both mounted send paths consume one recipient owner."""

from uuid import UUID

import pytest

from aweb.messaging import messages
from aweb.messaging.recipient import Recipient, RecipientResidence
from test_dashboard_privacy import _request, privacy_app as privacy_app

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_shared_recipient_projection_keeps_identity_mail_and_chat_actor_free(
    privacy_app,
):
    env = privacy_app
    bob = env.actors["bob"]
    row = await messages.get_agent_by_id(env.infra, agent_id=str(bob.id))
    assert isinstance(row, Recipient) and row.agent_id == bob.id
    assert row.did_key == bob.did and row.residence is RecipientResidence.LOCAL

    mail = await _request(
        env,
        "alice",
        "POST",
        "/v1/messages",
        {
            "to_did": bob.did,
            "subject": "Recipient projection",
            "body": "Mail neighbour",
        },
    )
    assert mail.status_code == 200, mail.text
    stored = await env.db.fetch_one(
        "SELECT to_did,to_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(mail.json()["message_id"]),
    )
    assert stored["to_did"] == bob.did and stored["to_agent_id"] is None
    readable = await _request(
        env, "bob", "GET", "/v1/messages/" + mail.json()["message_id"]
    )
    assert readable.status_code == 200, readable.text

    sent = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [bob.did],
            "message": "Chat neighbour",
        },
    )
    assert sent.status_code == 200, sent.text
    party = await env.db.fetch_one(
        "SELECT did,agent_id FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
        UUID(sent.json()["session_id"]),
        bob.did,
    )
    assert party["did"] == bob.did and party["agent_id"] is None
    history = await _request(
        env,
        "bob",
        "GET",
        "/v1/chat/sessions/" + sent.json()["session_id"] + "/messages",
    )
    assert history.status_code == 200, history.text
