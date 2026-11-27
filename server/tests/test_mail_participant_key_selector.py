"""A retained read-attribution key alone does not select a stable send recipient."""

import json
import pytest
from test_mcp_mail_conversation_parity import mail_server as mail_server
from test_messages_http import _signed_identity_headers
from aweb.messaging.mail_routing import explicit_mail_target_matches_participant

__all__ = ["mail_server"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "stable", "matches"),
    [
        ("did:key:recorded-recipient", None, False),
        ("did:key:another-recipient", None, False),
        ("did:key:recorded-recipient", "did:aw:recipient", True),
        ("did:aw:recipient", None, True),
    ],
)
async def test_send_selector_needs_the_recorded_identity_not_only_its_retained_key(
    key, stable, matches
):
    class NoMembershipLookup:
        def get_manager(self, _name):
            raise AssertionError(
                "Explicit stored-party selection does not choose a new member"
            )

    participant = {
        "did": "did:aw:recipient",
        "current_did_key": "did:key:recorded-recipient",
        "alias": "recipient",
    }
    assert (
        await explicit_mail_target_matches_participant(
            NoMembershipLookup(), participant, to_did=key, to_stable_id=stable
        )
        is matches
    )


@pytest.mark.asyncio
async def test_continued_mail_retained_key_alone_does_not_replace_stable_binding(
    mail_server,
):
    env = mail_server
    first = await env.human_mail()
    conversation_id = first["conversation_id"]
    payload = {
        "conversation_id": conversation_id,
        "to_did": env.human_did,
        "subject": "retained key selector",
        "body": "new continuation",
    }

    async def post(body):
        raw = json.dumps(body).encode()
        return await env.client.post(
            "/v1/messages",
            content=raw,
            headers={
                **_signed_identity_headers(
                    env.pilot_key, env.pilot_did, env.pilot_stable, raw
                ),
                "Content-Type": "application/json",
            },
        )

    refused = await post(payload)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == (
        "conversation_id recipient does not match the requested recipient. Use the stored recipient or start a new conversation."
    )
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1
    accepted = await post({**payload, "to_stable_id": env.human_stable})
    assert accepted.status_code == 200, accepted.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 2
