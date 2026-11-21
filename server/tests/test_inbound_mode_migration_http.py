"""Mail and chat refuse the persisted global policy that needs migration."""

import json
from uuid import UUID

import pytest

from messaging_actor_support import register_messaging_actors, set_messaging_inbound_mode
from test_messages_http import _signed_identity_headers
from test_messages_http import registered_mail_actors as registered_mail_actors


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["mail", "chat"])
async def test_global_recipient_without_migrated_inbound_mode_is_refused(
    registered_mail_actors, route
):
    env, actors = registered_mail_actors
    alice = actors["alice"]
    recipients = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob-migration",), local=False
    )
    bob = recipients["bob-migration"]
    await set_messaging_inbound_mode(env, bob, mode="open")
    # unreachable-state: a pre-migration global row has a NULL policy that current admission cannot create.
    await env.db.execute(
        "UPDATE {{tables.agents}} SET inbound_mode = NULL WHERE agent_id=$1",
        UUID(bob.agent_id),
    )

    if route == "mail":
        path, payload = "/v1/messages", {"to_did": bob.stable_id, "subject": "blocked", "body": "hi"}
    else:
        path, payload = "/v1/chat/sessions", {"to_dids": [bob.stable_id], "message": "blocked"}
    body = json.dumps(payload).encode()
    response = await env.client.post(
        path,
        content=body,
        headers={
            **_signed_identity_headers(alice.signing_key, alice.did_key, alice.stable_id, body),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 403, response.text
    assert "inbound_mode migration required" in response.text
    assert await env.db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.contacts}}
        WHERE owner_did = $1 AND contact_address = $2
        """,
        alice.stable_id,
        bob.address,
    ) == 0
