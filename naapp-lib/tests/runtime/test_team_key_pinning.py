"""A team key a naapp admitted is not replaced by an unsigned registry answer.

The registry operator is modelled by writing the registry's own tables: that
is exactly the power the threat gives it. Rotation goes through the real AWID
route. Two caches share the database pins, standing for the same app before
and after its in-memory facts expired or the process restarted. DNS, the root
the namespace controller is checked against, is the one answer the tests supply.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import Member, did_key
from awid.signing import canonical_json_bytes, sign_message
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, dns_naming
from nacl.signing import SigningKey
from pgdbm import AsyncMigrationManager

import aweb_naapp.runtime
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_key_pins import DatabaseTeamKeyPins
from tests.runtime.conftest import relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"
MIGRATIONS = Path(aweb_naapp.runtime.__file__).parent / "migrations"


@pytest.fixture
async def pins_db(test_db_factory):
    db = await test_db_factory.create_db(suffix="naapp_team_key_pins")
    await AsyncMigrationManager(db, migrations_path=str(MIGRATIONS), module_name="aweb_naapp").apply_pending_migrations()
    return db


@pytest.fixture
def namespace_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture(params=["certificate_status", "team_history"])
def team_cache(request, registry, pins_db, namespace_key):
    service_token = SERVICE_TOKEN if request.param == "team_history" else None

    def make() -> AWIDTeamCache:
        return AWIDTeamCache(
            registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport, service_token=service_token,
            team_key_pins=DatabaseTeamKeyPins(lambda: pins_db),
            txt_resolver=dns_naming("example.com", namespace_key),
        )

    return make


async def _register_namespace(registry, controller: str) -> None:
    await registry.db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
        "VALUES ('example.com', $1, 'verified')", controller,
    )


async def _rotate(registry, controller: SigningKey, new_team_did_key: str) -> None:
    timestamp = datetime.now(UTC).isoformat()
    claims = {"domain": "example.com", "operation": "rotate_team_key", "name": "backend",
              "new_team_did_key": new_team_did_key}
    signature = sign_message(bytes(controller), canonical_json_bytes({**claims, "timestamp": timestamp}))
    async with httpx.AsyncClient(transport=registry.transport, base_url=REGISTRY_URL) as client:
        response = await client.post(
            "/v1/namespaces/example.com/teams/backend/rotate",
            json={"new_team_did_key": new_team_did_key},
            headers={"Authorization": f"DIDKey {did_key(controller)} {signature}", "X-AWEB-Timestamp": timestamp},
        )
    assert response.status_code == 200, response.text


async def _get(registry, cache: AWIDTeamCache, member: Member):
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        return await client.get("/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items"))


async def _admitted(registry, team_cache) -> Member:
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key, visibility="public")
    await registry.add_certificate(member.certificate())
    admitted = await _get(registry, team_cache(), member)
    assert admitted.status_code == 200, admitted.text
    return member


async def test_substituted_registry_team_key_does_not_admit_a_forged_member(registry, team_cache, pins_db):
    member = await _admitted(registry, team_cache)
    forger = Member(team_id=TEAM_ID, alias="mallory", certificate_id="forged-mallory")
    await registry.rotate_team_key(TEAM_ID, forger.team_did_key)
    await registry.add_certificate(forger.certificate())

    forged = await _get(registry, team_cache(), forger)

    assert forged.status_code == 401, forged.text
    assert forged.json()["detail"] == "team_key_unverified"
    pinned = await pins_db.fetch_value("SELECT team_did_key FROM {{tables.team_key_pins}} WHERE team_id = $1", TEAM_ID)
    assert pinned == member.team_did_key


async def test_rotation_signed_by_the_dns_controller_moves_the_pin(registry, team_cache, pins_db, namespace_key):
    member = await _admitted(registry, team_cache)
    await _register_namespace(registry, did_key(namespace_key))
    rotated = Member(team_id=TEAM_ID, alias="dave", certificate_id="rotated-dave")
    await _rotate(registry, namespace_key, rotated.team_did_key)
    await registry.add_certificate(rotated.certificate())

    cache = team_cache()
    accepted = await _get(registry, cache, rotated)
    former = await _get(registry, cache, member)

    assert accepted.status_code == 200, accepted.text
    assert former.status_code == 401, former.text
    pin = await pins_db.fetch_one("SELECT * FROM {{tables.team_key_pins}} WHERE team_id = $1", TEAM_ID)
    assert pin["team_did_key"] == rotated.team_did_key
    assert pin["team_key_act_at"] is not None


async def test_rotation_by_a_controller_dns_does_not_name_is_refused(registry, team_cache, pins_db):
    member = await _admitted(registry, team_cache)
    registry_controller = SigningKey.generate()
    await _register_namespace(registry, did_key(registry_controller))
    forger = Member(team_id=TEAM_ID, alias="mallory", certificate_id="forged-mallory")
    await _rotate(registry, registry_controller, forger.team_did_key)
    await registry.add_certificate(forger.certificate())

    forged = await _get(registry, team_cache(), forger)

    assert forged.status_code == 401, forged.text
    assert forged.json()["detail"] == "team_key_unverified"
    pinned = await pins_db.fetch_value("SELECT team_did_key FROM {{tables.team_key_pins}} WHERE team_id = $1", TEAM_ID)
    assert pinned == member.team_did_key
