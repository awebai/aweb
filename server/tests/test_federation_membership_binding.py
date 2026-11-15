"""Federation's certificate metadata never supplies same-team authority."""

import base64
import json
from dataclasses import replace
from uuid import UUID

import pytest
from aweb_naapp_testing import Member
from awid.federation_errors import FederationAuthorityError
from nacl.signing import SigningKey

from aweb.federation.delivery import deliver_federated_phase_b
from tests.test_federation_activation_delivery import _DB, _envelope, _seed_recipient_and_authority


@pytest.mark.asyncio
async def test_reused_certificate_metadata_cannot_manufacture_federation_membership(real_stack):
    manager = real_stack.aweb_db
    registered = Member(team_id="backend:beta.example", alias="admitted", certificate_id="active-id")
    await real_stack.awid_db.execute(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
        "VALUES ('beta.example', 'backend', $1, 'public')",
        registered.team_did_key,
    )
    await real_stack.awid_db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, alias, issued_at, certificate) "
        "SELECT team_uuid, $1, $2, $3, now(), $4 FROM {{tables.teams}} "
        "WHERE domain='beta.example' AND name='backend'",
        registered.certificate_id, registered.did_key, registered.alias,
        base64.b64encode(json.dumps(registered.certificate()).encode()).decode(),
    )
    sender = replace(registered, member_key=SigningKey.generate(), alias="forged")
    envelope = _envelope().model_copy(update={
        "sender_current_did_key": sender.did_key,
        "sender_active_team_id": registered.team_id,
        "sender_team_certificate": sender.certificate(),
    })
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await manager.execute(
        "UPDATE {{tables.agents}} SET inbound_mode='team_and_contacts' WHERE agent_id=$1",
        recipient["agent_id"],
    )
    with pytest.raises(FederationAuthorityError) as refused:
        await deliver_federated_phase_b(
            _DB(manager), envelope=envelope, signature="signed-message",
            recipient=recipient, authority_token=token,
        )
    assert refused.value.reason == "recipient_policy_rejected"
    assert await manager.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await manager.fetch_value("SELECT count(*) FROM {{tables.agents}}") == 1

    # Identity-only open delivery still succeeds, without creating a team member.
    await manager.execute(
        "UPDATE {{tables.agents}} SET inbound_mode='open' WHERE agent_id=$1",
        recipient["agent_id"],
    )
    result = await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )
    assert result["message_id"] == envelope.message_id
    assert await manager.fetch_value(
        "SELECT count(*) FROM {{tables.messages}} WHERE message_id=$1", UUID(envelope.message_id)
    ) == 1
    assert await manager.fetch_value("SELECT count(*) FROM {{tables.agents}}") == 1
