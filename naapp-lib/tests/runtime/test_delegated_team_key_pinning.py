"""Real member auth and pin storage under inherited DNS, through actual AWID."""

import base64
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest
from aweb_naapp_testing import Member
from nacl.signing import SigningKey
from pgdbm import AsyncMigrationManager

import aweb_naapp.runtime
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_key_pins import DatabaseTeamKeyPins
from tests.runtime.conftest import relying_app

world = runpy.run_path(
    str(Path(__file__).resolve().parents[3] / "awid/tests/team_key_delegation_support.py")
)["world"]


@pytest.fixture
async def awid_db_infra(registry):
    return registry.app.state.db


@pytest.mark.parametrize("delegated", [True, False])
async def test_member_request_uses_the_shared_child_controller_witness(
    world, test_db_factory, delegated
):
    db = await test_db_factory.create_db(suffix="delegated_pin")
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(aweb_naapp.runtime.__file__).parent / "migrations"),
        module_name="aweb_naapp",
    ).apply_pending_migrations()
    pins = DatabaseTeamKeyPins(lambda: db)
    team_id = "base:" + world.domain
    await pins.first_sight(team_id, world.parent[1])
    member = Member(
        team_id=team_id,
        team_key=SigningKey(world.team[0]),
        extra_cert_fields={"lifetime": "local", "identity_scope": "local"},
    )
    await world.sdk.register_team_certificate(
        world.domain,
        "base",
        team_controller_signing_key=world.team[0],
        certificate_id=member.certificate_id,
        member_did_key=member.did_key,
        member_did_aw=None,
        member_address=None,
        alias=member.alias,
        identity_scope="local",
        certificate=base64.b64encode(json.dumps(member.certificate()).encode()).decode(),
    )
    if not delegated:
        await world.db.execute(
            "UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL,parent_controller_key=NULL WHERE domain=$1",
            world.domain,
        )
    cache = AWIDTeamCache(
        registry_url=world.sdk.registry_url,
        ttl_seconds=60,
        transport=world.sdk.transport,
        team_key_pins=pins,
        txt_resolver=world.resolver,
        enforce_team_key_pins=True,
        namespace_evidence=world.sdk.namespace_evidence,
    )
    origin = "https://app.example.com"
    registry = SimpleNamespace(transport=world.sdk.transport)
    async with relying_app(registry, public_origin=origin, cache=cache) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=origin, method="GET", path="/v1/items")
        )
    if delegated:
        assert response.status_code == 200, response.text
        assert response.json()["team_did_key"] == world.team[1]
        assert (await pins.pin(team_id)).act_key == world.team[1]
    else:
        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "team_key_unverified"
        assert (await pins.pin(team_id)).team_did_key == world.parent[1]
