"""awid_service.testing: AWID's own routes on a test's database, for the tests
of the services that rely on AWID. Each test reaches it through the real
registry client or the real routes."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import os

import httpx
import pytest
import pytest_asyncio
from awid.did import did_from_public_key, generate_keypair
from awid.registry import RegistryClient, RegistryError
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import verify_team_server_record
from nacl.signing import SigningKey
from redis.asyncio import Redis

from awid_service.main import create_app
from awid_service.testing import REGISTRY_URL, running_registry

TEAM_ID = "backend:example.com"


def _did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def _certificate(
    team_key: SigningKey, member_key: SigningKey, certificate_id: str
) -> dict:
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
        assert {route.path for route in registry.app.routes} >= served


@pytest.mark.asyncio
async def test_an_added_team_is_served_with_its_key(database_url) -> None:
    team_key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        assert await client.get_team_public_key("example.com", "backend") == _did_key(
            team_key
        )
        await registry.rotate_team_key(
            TEAM_ID, _did_key(rotated := SigningKey.generate())
        )
        assert await client.get_team_public_key("example.com", "backend") == _did_key(
            rotated
        )


@pytest.mark.asyncio
async def test_an_added_certificate_is_listed_until_revoked(database_url) -> None:
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        await registry.add_certificate(
            _certificate(team_key, member_key, "cert-1"), team_key=team_key
        )
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        listed = await client.list_team_certificates("example.com", "backend")
        assert [cert.certificate_id for cert in listed] == ["cert-1"]
        assert await client.get_team_revocations("example.com", "backend") == set()
        await registry.revoke("cert-1")
        assert await client.get_team_revocations("example.com", "backend") == {"cert-1"}


@pytest.mark.asyncio
async def test_fixture_setup_creates_a_namespace_before_its_team(database_url) -> None:
    team_key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        async with httpx.AsyncClient(
            transport=registry.transport, base_url=REGISTRY_URL
        ) as client:
            namespace = await client.get("/v1/namespaces/example.com")
        assert namespace.status_code == 200, (
            "fixture team has no registered namespace authority"
        )
        writes = [
            (request.method, request.url.path)
            for request in registry.transport.calls
            if request.method == "POST"
        ]
        assert writes == [
            ("POST", "/v1/namespaces"),
            ("POST", "/v1/namespaces/example.com/teams"),
        ]


@pytest.mark.asyncio
async def test_fixture_setup_stores_the_registered_signed_certificate(
    database_url,
) -> None:
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    certificate = _certificate(team_key, member_key, "cert-1")
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        await registry.add_certificate(certificate, team_key=team_key)
        stored = await registry.db.fetch_value(
            "SELECT certificate FROM {{tables.team_certificates}} WHERE certificate_id='cert-1'",
        )
        assert stored, "fixture certificate bypassed signed-blob registration"
        assert json.loads(base64.b64decode(stored)) == certificate


@pytest.mark.asyncio
async def test_fixture_setup_rejects_a_forged_certificate_without_writing(
    database_url,
) -> None:
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    certificate = _certificate(team_key, member_key, "cert-forged")
    certificate["signature"] = _certificate(
        SigningKey.generate(), member_key, "cert-forged"
    )["signature"]
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        with pytest.raises(RegistryError) as refused:
            await registry.add_certificate(certificate, team_key=team_key)
        assert (refused.value.status_code, refused.value.detail) == (
            422,
            "certificate signature verification failed",
        )
        assert (
            await registry.db.fetch_value(
                "SELECT count(*) FROM {{tables.team_certificates}}"
            )
            == 0
        )


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
async def test_a_published_team_server_record_verifies_against_the_team_key(
    database_url,
) -> None:
    team_key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, _did_key(team_key))
        await registry.publish_team_server(
            TEAM_ID, team_key, server_url="https://aweb.example"
        )
        async with httpx.AsyncClient(
            transport=registry.transport, base_url=REGISTRY_URL
        ) as client:
            body = (
                await client.get("/v1/namespaces/example.com/teams/backend/server")
            ).json()
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
        async with httpx.AsyncClient(
            transport=registry.transport, base_url=REGISTRY_URL
        ) as client:
            path = "/v1/namespaces/example.com/teams/backend"
            assert (await client.get(path)).status_code == 404
            assert [request.url.path for request in registry.transport.calls] == [path]

            registry.transport.fault = lambda request, response: httpx.Response(503)
            assert (await client.get(path)).status_code == 503

            registry.transport.fault = None
            registry.transport.down = True
            with pytest.raises(httpx.ConnectError):
                await client.get(path)


@pytest.mark.asyncio
async def test_the_registry_reports_its_health_with_the_redis_it_is_given(
    database_url,
) -> None:
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    ) as redis:
        async with running_registry(database_url, redis=redis) as registry:
            client = RegistryClient(
                registry_url=REGISTRY_URL, transport=registry.transport
            )
            health = await client.health()
    assert health["status"] == "ok"
    assert health["checks"]["redis"] == health["checks"]["database"] == "ok"


@pytest.mark.asyncio
async def test_the_registry_without_redis_is_live_and_not_ready(database_url) -> None:
    async with running_registry(database_url) as registry:
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        with pytest.raises(RegistryError) as unhealthy:
            await client.health()
        async with httpx.AsyncClient(
            transport=registry.transport, base_url=REGISTRY_URL
        ) as http:
            live = await http.get("/live")
    assert unhealthy.value.status_code == 503
    assert unhealthy.value.body["checks"] == {
        "redis": "error",
        "database": "ok",
        "schema": "awid",
        "rate_limiter": "NoOpRateLimiter",
    }
    assert (live.status_code, live.json()) == (200, {"status": "ok"})


@pytest.mark.asyncio
async def test_fixture_namespace_custody_cannot_silently_change(database_url):
    async with running_registry(database_url) as registry:
        original, public_key = generate_keypair()
        assert (
            await registry.ensure_namespace(domain="example.com", controller=original)
            is original
        )
        assert await registry.ensure_namespace(domain="example.com") is original
        other, _ = generate_keypair()
        with pytest.raises(ValueError) as refused:
            await registry.ensure_namespace(domain="example.com", controller=other)
        assert str(refused.value).endswith(
            "Pass its current signing key as controller=."
        )
        namespace = await RegistryClient(
            registry_url=REGISTRY_URL, transport=registry.transport
        ).get_namespace("example.com")
        assert namespace.controller_did == did_from_public_key(public_key)


@pytest.mark.asyncio
async def test_fixture_revoke_requires_registered_controller_custody(database_url):
    async with running_registry(database_url) as registry:
        with pytest.raises(ValueError) as refused:
            await registry.revoke("never-registered")
        assert str(refused.value).endswith(
            "Register it through add_certificate and select team_id= before revoking it."
        )
        assert not registry.transport.calls


@pytest.mark.asyncio
async def test_fixture_dns_requires_a_published_namespace_authority(database_url):
    from awid.dns_verify import DnsVerificationError

    async with running_registry(database_url) as registry:
        with pytest.raises(DnsVerificationError) as refused:
            await registry.namespace_authority("missing.example")
        assert str(refused.value).endswith(
            "Register the namespace through ensure_namespace first."
        )
        assert not registry.transport.calls


@pytest.mark.asyncio
async def test_fixture_attestation_publication_requires_a_supported_record(
    database_url,
):
    async with running_registry(database_url) as registry:
        with pytest.raises(ValueError) as refused:
            await registry.publish_signed_record(
                record={"team_id": TEAM_ID, "type": "unknown"},
                signature="",
                team_key=SigningKey.generate(),
            )
        assert str(refused.value).endswith(
            "Publish a team custodian, member custody or member person record."
        )
        assert not registry.transport.calls
