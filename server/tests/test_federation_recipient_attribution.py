"""Identity residence retains local attribution without granting membership."""

import asyncio
import json
from uuid import UUID

import pytest
from nacl.signing import SigningKey
from awid.did import did_from_public_key

from aweb.application_state import application_registry_client
from aweb.lifecycle import LifecycleActor, LifecycleCascadeRequest, apply_lifecycle_cascade
from chat_pair_support import route_pair as route_pair
from messaging_actor_support import admit_messaging_actor, register_messaging_team
from test_messages_http import _federated_mail_payload, _registered_routing_pair

__all__ = ["route_pair"]


def _mail_to_resident(world, *, conversation_id=None):
    alice, bob = world.source.actor, world.target.actor
    return _federated_mail_payload(
        sender_sk=alice.signing_key, sender_did_key=alice.did_key,
        sender_did_aw=alice.stable_id, sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address, target_did_aw=bob.stable_id,
        target_did_key=bob.did_key, target_delivery_origin=world.target.node.origin,
        conversation_id=conversation_id,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["first-contact", "superseded-member"])
async def test_inbound_identity_keeps_local_attribution_and_delivers_its_event(route_pair, case):
    world = await _registered_routing_pair(route_pair)
    alice, bob = world.source.actor, world.target.actor
    target = world.target.node

    if case == "superseded-member":
        name, domain = bob.team_id.split(":", 1)
        controller = await target.registry.ensure_namespace(domain=domain)
        new_key = SigningKey.generate()
        new_did = did_from_public_key(bytes(new_key.verify_key))
        # Actual SDK acts use second precision, newer than native admission.
        await asyncio.sleep(1)
        await target.registry_client.rotate_team_key(
            domain, name, new_team_did_key=new_did,
            namespace_controller_signing_key=bytes(controller),
        )
        world.target.env.team_sk, world.target.env.team_did = bytes(new_key), new_did
        await admit_messaging_actor(
            world.target.env, alias="rotation-observer", team_id=bob.team_id, local=True,
        )
        row = await target.db.fetch_one(
            "SELECT a.accepted_team_did_key, t.team_did_key FROM {{tables.agents}} a "
            "JOIN {{tables.teams}} t ON t.team_id=a.team_id WHERE a.agent_id=$1",
            UUID(bob.agent_id),
        )
        assert row["accepted_team_did_key"] != row["team_did_key"]

    data = _mail_to_resident(world)
    envelope = data["envelope"]
    redis = target.server.app.state.redis
    async with redis.pubsub() as events:
        await events.subscribe("events:" + bob.agent_id)
        subscribed = await events.get_message(timeout=2)
        assert subscribed and subscribed["type"] == "subscribe"
        response = await target.client.post("/v1/federation/messages", json=data)
        assert response.status_code == 200, response.text
        observed = await events.get_message(ignore_subscribe_messages=True, timeout=1)

    message_id = UUID(envelope["message_id"])
    row = await target.db.fetch_one(
        "SELECT from_did, to_did, to_agent_id, team_id, signed_payload, signature "
        "FROM {{tables.messages}} WHERE message_id=$1", message_id,
    )
    participant = await target.db.fetch_one(
        "SELECT agent_id FROM {{tables.conversation_participants}} "
        "WHERE conversation_id=$1 AND did=$2",
        UUID(envelope["conversation_id"]), bob.stable_id,
    )
    outbox = await target.db.fetch_value(
        "SELECT payload_json FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1",
        message_id,
    )
    outbox = json.loads(outbox) if isinstance(outbox, str) else outbox
    event = json.loads(observed["data"]) if observed is not None else {}
    assert (row["from_did"], row["to_did"], row["signed_payload"], row["signature"]) == (
        alice.stable_id, bob.stable_id, envelope["signed_payload"], data["signature"],
    )
    assert (
        row["to_agent_id"], row["team_id"], participant["agent_id"],
        outbox["to_agent_id"], event.get("type"), event.get("message_id"),
    ) == (
        UUID(bob.agent_id), bob.team_id, UUID(bob.agent_id),
        bob.agent_id, "message.delivered", envelope["message_id"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("new_memberships", [1, 2], ids=["different-attribution", "no-attribution"])
async def test_continuation_keeps_original_participant_attribution(route_pair, new_memberships):
    world = await _registered_routing_pair(route_pair)
    bob = world.target.actor
    target = world.target.node
    sent = await target.client.post("/v1/federation/messages", json=_mail_to_resident(world))
    assert sent.status_code == 200, sent.text
    conversation_id = sent.json()["conversation_id"]

    def stored_reference():
        return target.db.fetch_value(
            "SELECT agent_id FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
            UUID(conversation_id), bob.stable_id,
        )

    assert await stored_reference() == UUID(bob.agent_id)
    domain = bob.team_id.split(":", 1)[1]
    replacements = []
    for index in range(new_memberships):
        team_id = f"replacement-{index}:{domain}"
        await register_messaging_team(world.target.env, team_id=team_id)
        replacements.append(await admit_messaging_actor(
            world.target.env, alias="replacement", team_id=team_id, existing_identity=bob,
        ))
    archived = await apply_lifecycle_cascade(
        target.db, target.server.app.state.redis,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(actor_id=None, actor_type="support", authority="operator"),
            team_id=bob.team_id,
            target_agent_id=bob.agent_id,
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
        registry_client=application_registry_client(target.server.app.state),
    )
    assert archived.errors == () and archived.identity_archived
    assert await stored_reference() == UUID(bob.agent_id)

    data = _mail_to_resident(world, conversation_id=conversation_id)
    continued = await target.client.post("/v1/federation/messages", json=data)
    assert continued.status_code == 200, continued.text
    assert continued.json()["conversation_id"] == conversation_id
    row = await target.db.fetch_one(
        "SELECT to_did, to_agent_id, team_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(continued.json()["message_id"]),
    )
    replacement = replacements[0] if new_memberships == 1 else None
    assert (row["to_did"], row["to_agent_id"], row["team_id"]) == (
        bob.stable_id, UUID(replacement.agent_id) if replacement else None,
        replacement.team_id if replacement else None,
    )
    assert await stored_reference() == UUID(bob.agent_id)
