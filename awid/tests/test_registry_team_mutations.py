"""Real registry routes enforce the distinct visibility and deletion authorities."""

from __future__ import annotations

import json

import httpx
import pytest

from awid.did import generate_keypair
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from test_registry_client import FakeRedis
from test_team_visibility_enforcement import (
    SERVICE_TOKEN,
    _create_team,
    _register_member,
    _revoke_member,
    _setup_namespace,
    service_client,  # noqa: F401
)

DOMAIN = "visibility-client.example"
NAME = "ops"


async def _team(service_client, controller_identity):
    ns_key, ns_did = controller_identity
    await _setup_namespace(service_client, ns_key, ns_did, DOMAIN)
    return await _create_team(service_client, ns_key, ns_did, DOMAIN, NAME)


def _registry(service_client, *, cached=False, transport=None, **kwargs):
    service_client._transport.app.state.awid_public_origins = ("http://testserver",)
    options = {
        "registry_url": "http://testserver",
        "transport": transport or service_client._transport,
        "service_token": SERVICE_TOKEN,
        **kwargs,
    }
    if cached:
        return CachedRegistryClient(redis_client=FakeRedis(), **options)
    return RegistryClient(**options)


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True], ids=["client", "cached-client"])
async def test_registry_visibility_changes_anonymous_reads(service_client, controller_identity, cached):
    key, did, created = await _team(service_client, controller_identity)
    path = f"/v1/namespaces/{DOMAIN}/teams/{NAME}"
    assert (await service_client.get(path)).status_code == 403
    registry = _registry(service_client, cached=cached)
    try:
        # Warm the metadata cache with the old value before every mutation.
        assert (await registry.get_team(DOMAIN, NAME)).visibility == "private"
        for visibility in ("public", "public", "private"):
            updated = await registry.set_team_visibility(DOMAIN, NAME, visibility, key)
            assert updated.visibility == visibility
            assert updated.team_id == created["team_id"]
            assert updated.team_did_key == did
            assert updated.created_at == created["created_at"]
            response = await service_client.get(path)
            assert response.status_code == (200 if visibility == "public" else 403)
            if visibility == "public":
                assert response.json()["visibility"] == "public"
            else:
                assert response.json()["detail"]["code"] == "team_private"
            assert (await registry.get_team(DOMAIN, NAME)).visibility == visibility
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("signer", ["namespace", "member", "stranger"])
async def test_registry_visibility_requires_the_team_controller(
    service_client, controller_identity, awid_db_infra, signer,
):
    key, did, _ = await _team(service_client, controller_identity)
    if signer == "namespace":
        wrong_key = controller_identity[0]
    elif signer == "member":
        wrong_key, _, _ = await _register_member(service_client, key, did, DOMAIN, NAME, "alice")
    else:
        wrong_key, _ = generate_keypair()
    registry = _registry(service_client)
    try:
        # Even the valid service credential above buys no write authority.
        with pytest.raises(RegistryError) as refused:
            await registry.set_team_visibility(DOMAIN, NAME, "public", wrong_key)
        assert refused.value.status_code == 403
        row = await awid_db_infra.get_manager("aweb").fetch_one(
            "SELECT visibility FROM {{tables.teams}} WHERE domain = $1 AND name = $2", DOMAIN, NAME,
        )
        assert row["visibility"] == "private"
        assert (await registry.set_team_visibility(DOMAIN, NAME, "public", key)).visibility == "public"
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,visibility,status", [(NAME, "invalid", 422), ("missing", "public", 404)])
async def test_registry_visibility_preserves_route_refusals(
    service_client, controller_identity, name, visibility, status,
):
    key, _, _ = await _team(service_client, controller_identity)
    registry = _registry(service_client)
    try:
        with pytest.raises(RegistryError) as refused:
            await registry.set_team_visibility(DOMAIN, name, visibility, key)
        assert refused.value.status_code == status
        assert (await registry.set_team_visibility(DOMAIN, NAME, "public", key)).visibility == "public"
    finally:
        await registry.aclose()


class ForwardToService(httpx.AsyncBaseTransport):
    """Observe or alter the wire request, then use the real ASGI app and DB."""

    def __init__(self, service_client, *, tamper=False):
        self.inner = service_client._transport
        self.tamper = tamper
        self.hosts = []

    async def handle_async_request(self, request):
        self.hosts.append(request.url.host)
        if self.tamper:
            body = json.loads(request.content)
            body["visibility"] = "private"
            request = httpx.Request(request.method, request.url, headers=request.headers, json=body)
        return await self.inner.handle_async_request(request)


@pytest.mark.asyncio
async def test_registry_visibility_follows_the_domain_registry(service_client, controller_identity):
    key, _, _ = await _team(service_client, controller_identity)
    domains = []

    async def resolve(domain):
        domains.append(domain)
        return "http://testserver"

    transport = ForwardToService(service_client)
    registry = _registry(
        service_client, transport=transport, registry_url="http://home-registry.example",
        domain_registry_resolver=resolve,
    )
    try:
        assert (await registry.set_team_visibility(DOMAIN, NAME, "public", key)).visibility == "public"
        assert domains == [DOMAIN]
        assert transport.hosts == ["testserver"]
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_registry_visibility_signature_binds_the_new_value(service_client, controller_identity):
    key, _, _ = await _team(service_client, controller_identity)
    registry = _registry(service_client, transport=ForwardToService(service_client, tamper=True))
    try:
        with pytest.raises(RegistryError) as refused:
            await registry.set_team_visibility(DOMAIN, NAME, "public", key)
        assert refused.value.status_code == 401
    finally:
        await registry.aclose()
    # The same controller's unaltered neighboring request succeeds.
    registry = _registry(service_client)
    try:
        assert (await registry.set_team_visibility(DOMAIN, NAME, "public", key)).visibility == "public"
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True], ids=["client", "cached-client"])
async def test_registry_delete_requires_revocation_then_removes_team_and_cached_reads(
    service_client, controller_identity, awid_db_infra, cached,
):
    key, did, _ = await _team(service_client, controller_identity)
    _, _, cert_id = await _register_member(service_client, key, did, DOMAIN, NAME, "alice")
    registry = _registry(service_client, cached=cached)
    try:
        assert (await registry.get_team(DOMAIN, NAME)).team_did_key == did
        with pytest.raises(RegistryError) as refused:
            await registry.delete_team(DOMAIN, NAME, controller_identity[0])
        assert refused.value.status_code == 409
        assert await registry.get_team(DOMAIN, NAME) is not None
        assert len(await registry.list_team_certificates(DOMAIN, NAME)) == 1
        await _revoke_member(service_client, key, did, DOMAIN, NAME, cert_id)
        # Warm all cache tiers with the revoked certificate before deleting.
        assert (await registry.get_team(DOMAIN, NAME)).team_did_key == did
        for signing_key in (None, key):
            certificates = await registry.list_team_certificates(
                DOMAIN, NAME, active_only=False, signing_key=signing_key,
            )
            assert [certificate.certificate_id for certificate in certificates] == [cert_id]
        assert await registry.get_team_revocations(DOMAIN, NAME) == {cert_id}
        result = await registry.delete_team(DOMAIN, NAME, controller_identity[0])
        assert result == {"deleted": True, "team_id": f"{NAME}:{DOMAIN}", "domain": DOMAIN, "name": NAME}
        assert await registry.get_team(DOMAIN, NAME) is None
        for signing_key in (None, key):
            with pytest.raises(RegistryError) as missing:
                await registry.list_team_certificates(
                    DOMAIN, NAME, active_only=False, signing_key=signing_key,
                )
            assert missing.value.status_code == 404
        assert await registry.get_team_revocations(DOMAIN, NAME) == set()
        db = awid_db_infra.get_manager("aweb")
        row = await db.fetch_one(
            "SELECT team_uuid, deleted_at FROM {{tables.teams}} WHERE domain = $1 AND name = $2", DOMAIN, NAME,
        )
        assert row["deleted_at"] is not None
        assert await db.fetch_value(
            "SELECT count(*) FROM {{tables.team_certificates}} WHERE team_uuid = $1", row["team_uuid"],
        ) == 0
        with pytest.raises(RegistryError) as missing:
            await registry.delete_team(DOMAIN, NAME, controller_identity[0])
        assert missing.value.status_code == 404
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("signer", ["team", "member", "stranger"])
async def test_registry_delete_requires_namespace_controller(
    service_client, controller_identity, signer,
):
    key, did, _ = await _team(service_client, controller_identity)
    if signer == "team":
        wrong_key = key
    elif signer == "member":
        wrong_key, _, cert_id = await _register_member(service_client, key, did, DOMAIN, NAME, "alice")
        await _revoke_member(service_client, key, did, DOMAIN, NAME, cert_id)
    else:
        wrong_key, _ = generate_keypair()
    registry = _registry(service_client)
    try:
        # The service credential and the team's controller do not authorize deletion.
        with pytest.raises(RegistryError) as refused:
            await registry.delete_team(DOMAIN, NAME, wrong_key)
        assert refused.value.status_code == 403
        assert await registry.get_team(DOMAIN, NAME) is not None
        assert (await registry.delete_team(DOMAIN, NAME, controller_identity[0]))["deleted"] is True
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_registry_delete_follows_domain_registry(service_client, controller_identity):
    await _team(service_client, controller_identity)
    domains = []

    async def resolve(domain):
        domains.append(domain)
        return "http://testserver"

    transport = ForwardToService(service_client)
    registry = _registry(
        service_client, transport=transport, registry_url="http://home-registry.example",
        domain_registry_resolver=resolve,
    )
    try:
        assert (await registry.delete_team(DOMAIN, NAME, controller_identity[0]))["deleted"] is True
        assert domains == [DOMAIN]
        assert transport.hosts == ["testserver"]
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_registry_delete_signature_binds_team_name(service_client, controller_identity):
    await _team(service_client, controller_identity)
    ns_key, ns_did = controller_identity
    await _create_team(service_client, ns_key, ns_did, DOMAIN, "other")

    class RewrittenDelete(ForwardToService):
        async def handle_async_request(self, request):
            request.url = request.url.copy_with(path=f"/v1/namespaces/{DOMAIN}/teams/other")
            return await super().handle_async_request(request)

    registry = _registry(service_client, transport=RewrittenDelete(service_client))
    try:
        with pytest.raises(RegistryError) as refused:
            await registry.delete_team(DOMAIN, NAME, ns_key)
        assert refused.value.status_code == 401
    finally:
        await registry.aclose()
    registry = _registry(service_client)
    try:
        assert await registry.get_team(DOMAIN, "other") is not None
        assert await registry.get_team(DOMAIN, NAME) is not None
        assert (await registry.delete_team(DOMAIN, NAME, ns_key))["deleted"] is True
    finally:
        await registry.aclose()
