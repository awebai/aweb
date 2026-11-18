"""Federation delivers to an exact resident identity without granting a team actor."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

import httpx
import pytest
from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)
from test_same_origin_delivery import (
    foreign_receiver,  # noqa: F401
    same_origin,  # noqa: F401
    same_origin_registry_socket,  # noqa: F401
)


class ResidenceAdmission(StrEnum):
    CURRENT_MEMBER = "current-member"
    SUPERSEDED_MEMBER = "superseded-member"


async def _supersede_resident_membership(fixture, receiver) -> None:
    """Rotate the actual registry team, then admit another member on the receiver."""
    env = fixture.env
    next_sk, _, next_did = _make_keypair()
    registry = env.app.state.awid_registry_client
    await registry.rotate_team_key(
        "recipient.test",
        "recipients",
        new_team_did_key=next_did,
        namespace_controller_signing_key=env.team_sk,
    )
    member_sk, _, member_did = _make_keypair()
    certificate = _encode_certificate(
        _make_certificate(
            next_sk,
            next_did,
            member_did,
            team_id="recipients:recipient.test",
            alias="new-member",
            identity_scope="local",
            certificate_id="reissued-" + uuid4().hex,
        )
    )
    body = b"{}"
    async with httpx.AsyncClient(base_url=receiver.origin) as client:
        connected = await client.post(
            "/v1/connect",
            content=body,
            headers={
                **_signed_team_headers(
                    member_sk, member_did, "recipients:recipient.test", certificate, body
                ),
                "Content-Type": "application/json",
            },
        )
    assert connected.status_code == 200, connected.text
    row = await receiver.db.fetch_one(
        "SELECT a.accepted_team_did_key,t.team_did_key FROM {{tables.agents}} a "
        "JOIN {{tables.teams}} t ON t.team_id=a.team_id WHERE a.agent_id=$1",
        fixture.target.id,
    )
    assert row["team_did_key"] == next_did
    assert row["accepted_team_did_key"] != next_did


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("admission", list(ResidenceAdmission))
async def test_federation_first_contact_and_new_continuation_keep_identity_residence(
    same_origin,
    foreign_receiver,
    monkeypatch,
    kind,
    admission,
):
    # identity-messaging-contract.md:262-277: the registry address supplies
    # canonical DID/key/route; residence does not require current membership.
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    if admission is ResidenceAdmission.SUPERSEDED_MEMBER:
        await _supersede_resident_membership(same_origin, foreign_receiver)
    first_response, first = await same_origin.send(kind, "global")
    assert first_response.status_code == 200, first_response.text
    second_response, second = await same_origin.send(kind, "global", continuation=first)
    assert second_response.status_code == 200, second_response.text
    assert second.message_id != first.message_id
    table = "messages" if kind == "mail" else "chat_messages"
    rows = await foreign_receiver.db.fetch_all(
        "SELECT message_id,from_did FROM {{tables." + table + "}} WHERE message_id=ANY($1::uuid[])",
        [first.message_id, second.message_id],
    )
    assert {row["message_id"] for row in rows} == {first.message_id, second.message_id}
    assert {row["from_did"] for row in rows} == {first.signed["from_stable_id"]}
    assert foreign_receiver.statuses == [200, 200]
    participants = await foreign_receiver.db.fetch_all(
        "SELECT agent_id FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        first.conversation_id,
        same_origin.target_did,
    )
    assert len(participants) == 1
    assert participants[0]["agent_id"] is None
