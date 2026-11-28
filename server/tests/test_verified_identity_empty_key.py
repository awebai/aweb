"""The native SQL metadata reader agrees with the canonical row projection."""

import pytest
from aweb.identity_metadata import lookup_identity_metadata_by_agent_id
from aweb.identity_binding import IdentityProjectionField, verified_identity_field_sql
from aweb.member_team_key import MemberProjection, read_member_projection
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app as privacy_app
from test_identity_binding_http import certificate, register, request

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_empty_signing_key_and_empty_marker_cannot_attribute_global_metadata(
    privacy_app,
):
    # identity.md:569-585 and Global And Local Identities
    # (docs/identity-messaging-contract.md:118-121):
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
        member = await read_member_projection(env.db, agent_id=actor.id)
        assert member is not None
        historical = MemberProjection.from_row(
            {
                **dict(member),
                "did_key": "",
                "did_aw_verified_key": "",
                "address": "identity.test/forged-claim",
            }
        )
        assert historical.verified_identity()["did_aw"] is None
        assert historical.verified_identity()["address"] is None

        # Exercise the exact SQL projection with the same historical values
        # without writing a row that current identity admission cannot create.
        projected = await env.db.fetch_one(
            f"""SELECT {verified_identity_field_sql(IdentityProjectionField.STABLE_DID)} AS did_aw,
                       {verified_identity_field_sql(IdentityProjectionField.ADDRESS)} AS address
                FROM (VALUES ($1::text, $2::text, $3::text, $4::text))
                   AS history(did_key, did_aw_verified_key, did_aw, address)""",
            historical["did_key"],
            historical["did_aw_verified_key"],
            historical["did_aw"],
            historical["address"],
        )
        assert dict(projected) == {"did_aw": None, "address": None}
