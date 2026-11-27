"""The real local and federation policy paths read the same membership state."""

from uuid import UUID, uuid4

import pytest

from awid.federation_errors import FederationAuthorityError
from aweb.application_state import application_registry_client
from aweb.db import TransactionInfra
from aweb.federation.delivery import _authorize_policy
from aweb.messaging.messages import authorize_message_delivery
from aweb.service_errors import ForbiddenError
from messaging_actor_support import (
    admit_messaging_actor,
    archive_messaging_actor,
    register_messaging_team,
    set_messaging_inbound_mode,
)
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_federation_activation_delivery import _envelope

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["local", "federation"])
@pytest.mark.parametrize("selected_shared", [True, False])
@pytest.mark.parametrize("active_sender", [True, False])
async def test_inbound_policy_uses_all_current_active_memberships(
    privacy_app,
    transport,
    selected_shared,
    active_sender,
):
    env = privacy_app
    manager = env.db
    registry_client = application_registry_client(env.app.state)
    shared_team = f"policy-{uuid4().hex[:10]}:example.test"
    await register_messaging_team(env, team_id=shared_team)
    recipients = [
        await admit_messaging_actor(
            env, alias="bob", team_id=team, signing_key=env.actors["bob"].sk
        )
        for team in (TEAM, shared_team)
    ]
    await set_messaging_inbound_mode(env, recipients[0], "team_and_contacts")
    sender = await admit_messaging_actor(
        env, alias="policy-sender", team_id=shared_team
    )
    if not active_sender:
        await archive_messaging_actor(
            manager,
            env.redis,
            team_id=sender.team_id,
            agent_id=sender.agent_id,
            registry_client=registry_client,
        )
    selected = recipients[1 if selected_shared else 0]
    recipient = dict(
        await manager.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", UUID(selected.agent_id)
        )
    )
    sender_did, sender_key = sender.stable_id, sender.did_key
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
                    registry_client=registry_client,
                )
            else:
                await authorize_message_delivery(
                    TransactionInfra(None, tx),
                    recipient_agent=recipient,
                    sender_did=sender_did,
                    sender_address=envelope.sender_address,
                    sender_verified_dids=[sender_did, sender_key],
                    registry_client=registry_client,
                )
    except ForbiddenError as exc:
        allowed = False
        assert exc.detail.endswith(
            "Ask the recipient to add your exact address as a contact or check their inbound policy."
        )
    except FederationAuthorityError as exc:
        allowed = False
        assert exc.reason == "recipient_policy_rejected"
        assert exc.http_status == 403
    assert allowed == active_sender


@pytest.mark.asyncio
async def test_federation_shared_team_membership_stays_locked_until_delivery_commits(
    privacy_app,
):
    """A retirement must wait for the policy decision's enclosing delivery TX."""
    import asyncio
    import asyncpg

    env = privacy_app
    manager = env.db
    registry_client = application_registry_client(env.app.state)
    sender = await admit_messaging_actor(env, alias="policy-sender", team_id=TEAM)
    bob = await admit_messaging_actor(env, alias="policy-recipient", team_id=TEAM)
    await set_messaging_inbound_mode(env, bob, "team_and_contacts")
    recipient = await manager.fetch_one(
        "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", UUID(bob.agent_id)
    )
    envelope = _envelope().model_copy(
        update={
            "sender_did_aw": sender.stable_id,
            "sender_current_did_key": sender.did_key,
        }
    )
    authorized, finish = asyncio.Event(), asyncio.Event()

    async def hold_delivery():
        async with manager.transaction() as tx:
            await _authorize_policy(
                tx,
                envelope=envelope,
                recipient=dict(recipient),
                stored_route_continuation=False,
                registry_client=registry_client,
            )
            authorized.set()
            await finish.wait()

    # Start outside either transaction so the tasks hold independent leases.
    delivery = asyncio.create_task(hold_delivery())
    try:
        await asyncio.wait_for(authorized.wait(), timeout=5)
        async with manager.transaction() as retiring:
            await retiring.execute("SET LOCAL lock_timeout = '200ms'")
            with pytest.raises(asyncpg.LockNotAvailableError):
                await archive_messaging_actor(
                    retiring,
                    env.redis,
                    team_id=sender.team_id,
                    agent_id=sender.agent_id,
                    registry_client=registry_client,
                )
    finally:
        finish.set()
        await delivery
    assert (
        await manager.fetch_value(
            "SELECT status FROM {{tables.agents}} WHERE agent_id=$1",
            UUID(sender.agent_id),
        )
        == "active"
    )
    await archive_messaging_actor(
        manager,
        env.redis,
        team_id=sender.team_id,
        agent_id=sender.agent_id,
        registry_client=registry_client,
    )
    with pytest.raises(FederationAuthorityError) as refused:
        async with manager.transaction() as tx:
            await _authorize_policy(
                tx,
                envelope=envelope,
                recipient=dict(recipient),
                stored_route_continuation=False,
                registry_client=registry_client,
            )
    assert refused.value.detail.endswith(
        "Ask the recipient to add your exact address as a contact or check their inbound policy."
    )
