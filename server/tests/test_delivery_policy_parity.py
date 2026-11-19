"""The real local and federation policy paths read the same membership state."""

from uuid import uuid4

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_did_key
from awid.federation_errors import FederationAuthorityError
from aweb.db import TransactionInfra
from aweb.federation.delivery import _authorize_policy
from aweb.messaging.messages import authorize_message_delivery
from aweb.service_errors import ForbiddenError
from test_federation_activation_delivery import _envelope


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["local", "federation"])
@pytest.mark.parametrize("selected_shared", [True, False])
@pytest.mark.parametrize("active_sender", [True, False])
async def test_inbound_policy_uses_all_current_active_memberships(
    aweb_cloud_db,
    transport,
    selected_shared,
    active_sender,
):
    manager = aweb_cloud_db.aweb_db

    def key():
        return did_from_public_key(bytes(SigningKey.generate().verify_key))

    sender_key, recipient_key, team_key = key(), key(), key()
    sender_did, recipient_did = (
        stable_id_from_did_key(sender_key),
        stable_id_from_did_key(recipient_key),
    )
    teams = [f"policy-{uuid4().hex[:10]}:example.test" for _ in range(2)]
    for team in teams:
        await manager.execute(
            "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1,'example.test',$2,$3)",
            team,
            team.split(":")[0],
            team_key,
        )
    recipients = []
    for team in teams:
        row = await manager.fetch_one(
            """INSERT INTO {{tables.agents}}
            (team_id, alias, did_key, did_aw, did_aw_verified_key, identity_scope, inbound_mode, accepted_team_did_key)
            VALUES ($1,'bob',$2,$3,$2,'global','team_and_contacts',$4) RETURNING *""",
            team,
            recipient_key,
            recipient_did,
            team_key,
        )
        recipients.append(dict(row))
    await manager.execute(
        """INSERT INTO {{tables.agents}}
        (team_id, alias, did_key, did_aw, did_aw_verified_key, identity_scope, inbound_mode, status, accepted_team_did_key)
        VALUES ($1,'alice',$2,$3,$2,'global','open',$4,$5)""",
        teams[1],
        sender_key,
        sender_did,
        "active" if active_sender else "retired",
        team_key,
    )
    recipient = recipients[1 if selected_shared else 0]
    envelope = _envelope().model_copy(
        update={"sender_did_aw": sender_did, "sender_current_did_key": sender_key}
    )
    allowed = True
    try:
        async with manager.transaction() as tx:
            if transport == "federation":
                await _authorize_policy(
                    tx,
                    envelope=envelope,
                    recipient=recipient,
                    stored_route_continuation=False,
                )
            else:
                await authorize_message_delivery(
                    TransactionInfra(None, tx),
                    recipient_agent=recipient,
                    sender_did=sender_did,
                    sender_address=envelope.sender_address,
                    sender_team_id=teams[1],
                    sender_verified_dids=[sender_did, sender_key],
                )
    except (ForbiddenError, FederationAuthorityError) as exc:
        allowed = False
        assert exc.detail.endswith(
            "Ask the recipient to add your exact address as a contact or check their inbound policy."
        )
    assert allowed == active_sender
