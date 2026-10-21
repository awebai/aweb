"""awid_service.testing: AWID's own routes on a test's database, for the tests
of the services that rely on AWID. Each test reaches it through the real
registry client or the real routes."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from awid.did import did_from_public_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import verify_team_server_record
from nacl.signing import SigningKey

from awid_service.main import create_app
from awid_service.testing import REGISTRY_URL, running_registry

TEAM_ID = "backend:example.com"


def _did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def _certificate(team_key: SigningKey, member_key: SigningKey, certificate_id: str) -> dict:
    cert = {
        "version": 1,
        "certificate_id": certificate_id,
        "team_id": TEAM_ID,
        "team_did_key": _did_key(team_key),
        "member_did_key": _did_key(member_key),
        "alias": "alice",
        "lifetime": "persistent",
        "issued_at": "2026-01-01T00:00:00Z",
    }
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))
    return cert


@pytest_asyncio.fixture
async def database_url(test_db_factory) -> str:
    return (await test_db_factory.create_db(suffix="awid_testing")).config.get_dsn()


@pytest.mark.asyncio
async def test_the_registry_serves_every_route_awid_serves(database_url) -> None:
    served = {route.path for route in create_app().routes}
    async with running_registry(database_url) as registry:
        assert {route.path for route in registry.app.routes} >= served - {"/", "/health", "/ops/health"}


@pytest.mark.asyncio
async def test_an_added_team_is_served_with_its_key(database_url) -> None:
    team_key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        assert await client.get_team_public_key("example.com", "backend") == _did_key(team_key)
        await registry.rotate_team_key(TEAM_ID, _did_key(rotated := SigningKey.generate()))
        assert await client.get_team_public_key("example.com", "backend") == _did_key(rotated)


@pytest.mark.asyncio
async def test_an_added_certificate_is_listed_until_revoked(database_url) -> None:
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        await registry.add_certificate(_certificate(team_key, member_key, "cert-1"))
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        listed = await client.list_team_certificates("example.com", "backend")
        assert [cert.certificate_id for cert in listed] == ["cert-1"]
        assert await client.get_team_revocations("example.com", "backend") == set()
        await registry.revoke("cert-1")
        assert await client.get_team_revocations("example.com", "backend") == {"cert-1"}


@pytest.mark.asyncio
async def test_a_did_registers_and_rotates_through_awid(database_url) -> None:
    key, rotated = SigningKey.generate(), SigningKey.generate()
    async with running_registry(database_url) as registry:
        did_aw = await registry.register_did(key)
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        assert (await client.resolve_key(did_aw)).current_did_key == _did_key(key)
        await registry.rotate_did(did_aw, key, rotated)
        assert (await client.resolve_key(did_aw)).current_did_key == _did_key(rotated)


@pytest.mark.asyncio
async def test_a_published_team_server_record_verifies_against_the_team_key(database_url) -> None:
    team_key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        await registry.publish_team_server(TEAM_ID, team_key, server_url="https://aweb.example")
        async with httpx.AsyncClient(transport=registry.transport, base_url=REGISTRY_URL) as client:
            body = (await client.get("/v1/namespaces/example.com/teams/backend/server")).json()
        record = verify_team_server_record(
            body["record"],
            body["signature"],
            team_id=TEAM_ID,
            current_team_did_key=_did_key(team_key),
            now=datetime.now(UTC),
        )
        assert record.server_url == "https://aweb.example"


@pytest.mark.asyncio
async def test_the_transport_records_requests_and_carries_faults(database_url) -> None:
    async with running_registry(database_url) as registry:
        async with httpx.AsyncClient(transport=registry.transport, base_url=REGISTRY_URL) as client:
            path = "/v1/namespaces/example.com/teams/backend"
            assert (await client.get(path)).status_code == 404
            assert [request.url.path for request in registry.transport.calls] == [path]

            registry.transport.fault = lambda request, response: httpx.Response(503)
            assert (await client.get(path)).status_code == 503

            registry.transport.fault = None
            registry.transport.down = True
            with pytest.raises(httpx.ConnectError):
                await client.get(path)
