"""The native SQL metadata reader agrees with the canonical row projection."""

import pytest
from aweb.identity_metadata import lookup_identity_metadata_by_agent_id
from aweb.member_team_key import read_member_projection
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app as privacy_app
from test_identity_binding_http import certificate, register, request


@pytest.mark.asyncio
async def test_empty_signing_key_and_empty_marker_cannot_attribute_global_metadata(
    privacy_app,
):
    # identity.md:569-585 and identity-messaging-contract.md:268-277:
    # marker equality needs an actual current key, not two empty strings.
    env = privacy_app
    actor = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable, address = await register(env, registry, actor)
        connected = await request(
            env,
            actor,
            "POST",
            "/v1/connect",
            {},
            certificate=certificate(env, actor, stable, address),
        )
        assert connected.status_code == 200, connected.text
        before = await lookup_identity_metadata_by_agent_id(env.infra, [str(actor.id)])
        assert before[str(actor.id)]["stable_id"] == stable
        assert before[str(actor.id)]["address"] == address
        # Explicit corrupt/legacy storage, not a supported identity mutation.
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_key='',did_aw_verified_key='',address=$2 "
            "WHERE agent_id=$1",
            actor.id,
            "identity.test/forged-claim",
        )
        row = await read_member_projection(env.db, agent_id=actor.id)
        assert row.verified_identity()["did_aw"] is None
        assert row.verified_identity()["address"] is None
        metadata = await lookup_identity_metadata_by_agent_id(env.infra, [str(actor.id)])
        assert not metadata[str(actor.id)].get("stable_id"), metadata
        assert not metadata[str(actor.id)].get("address"), metadata
