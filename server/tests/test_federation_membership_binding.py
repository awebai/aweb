"""Federation's certificate metadata never supplies same-team authority."""

import base64
import json
from dataclasses import replace
from fastapi import HTTPException
from tests.test_protected_membership_retained import membership_env as membership_env
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


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize("change", ["genuine", "key", "alias"])
async def test_phase_b_rechecks_retained_same_team_membership(membership_env, protected, change):
    env = membership_env
    manager = env.stack.aweb_db
    member = env.member
    claimed = member
    if change == "key":
        claimed = replace(member, member_key=SigningKey.generate())
    elif change == "alias":
        claimed = replace(member, alias="impostor")
    await manager.execute(
        "INSERT INTO {{tables.agents}} "
        "(team_id,alias,did_key,certificate_id,identity_scope,status) VALUES ($1,$2,$3,$4,'local','active')",
        member.team_id, claimed.alias, claimed.did_key, member.certificate_id,
    )
    if protected:
        await env.stack.awid_db.execute(
            "INSERT INTO {{tables.team_protection}} "
            "(domain,name,service_id,service_did_key,generation) VALUES ('beta.example','backend','test-signer',$1,1)",
            Member(team_id=member.team_id).did_key,
        )
    # A local identity avoids unrelated global identity/route setup. Both
    # participants still pass the actual Phase-B policy and transaction.
    envelope = _envelope().model_copy(update={
        "sender_did_aw": claimed.did_key,
        "sender_current_did_key": claimed.did_key,
    })
    recipient = dict(await manager.fetch_one(
        "INSERT INTO {{tables.agents}} "
        "(team_id,alias,did_key,did_aw,did_aw_verified_key,address,identity_scope,inbound_mode) "
        "VALUES ($1,'recipient',$2,$3,$2,$4,'global','team_and_contacts') RETURNING *",
        member.team_id, envelope.target_current_did_key, envelope.target_did_aw, envelope.target_address,
    ))
    async def deliver():
        return await deliver_federated_phase_b(
            _DB(manager), envelope=envelope, signature="signed-message", recipient=recipient,
            authority_token=None, registry_client=env.registry,
        )
    if protected and change != "genuine":
        with pytest.raises(HTTPException) as refused:
            await deliver()
        assert refused.value.status_code == 401
        assert "certificate_binding_mismatch" in str(refused.value.detail)
        assert await manager.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    else:
        result = await deliver()
        assert result["message_id"] == envelope.message_id


@pytest.mark.asyncio
async def test_exact_contact_still_delivers_when_same_team_projection_is_invalid(membership_env):
    from tests.test_federation_activation_delivery import _seed_sender_authority

    env = membership_env
    manager = env.stack.aweb_db
    envelope = _envelope()
    token = await _seed_sender_authority(manager, envelope)
    await manager.execute(
        "INSERT INTO {{tables.agents}} "
        "(team_id,alias,did_key,did_aw,did_aw_verified_key,certificate_id,identity_scope,status) "
        "VALUES ($1,'impostor',$2,$3,$2,$4,'global','active')",
        env.member.team_id, envelope.sender_current_did_key, envelope.sender_did_aw, env.member.certificate_id,
    )
    recipient = dict(await manager.fetch_one(
        "INSERT INTO {{tables.agents}} "
        "(team_id,alias,did_key,did_aw,did_aw_verified_key,address,identity_scope,inbound_mode) "
        "VALUES ($1,'recipient',$2,$3,$2,$4,'global','team_and_contacts') RETURNING *",
        env.member.team_id, envelope.target_current_did_key, envelope.target_did_aw, envelope.target_address,
    ))
    await manager.execute(
        "INSERT INTO {{tables.contacts}} (owner_did,contact_address,contact_did_aw,binding_controller_did,reference_type,status,binding_accepted_at) "
        "VALUES ($1,$2,$3,$4,'identity','active',now())",
        envelope.target_did_aw, envelope.sender_address, envelope.sender_did_aw, env.member.team_did_key,
    )
    await env.stack.awid_db.execute(
        "INSERT INTO {{tables.team_protection}} "
        "(domain,name,service_id,service_did_key,generation) VALUES ('beta.example','backend','test-signer',$1,1)",
        Member(team_id=env.member.team_id).did_key,
    )
    result = await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message", recipient=recipient,
        authority_token=token, registry_client=env.registry,
    )
    assert result["message_id"] == envelope.message_id
