from __future__ import annotations

import json

import pytest
from httpx import MockTransport, Response

from awid.did import generate_keypair
from awid.registry import CachedRegistryClient, RegistryClient


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.values[key] = value

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.values.pop(key, None)


@pytest.mark.asyncio
async def test_registry_client_register_team_certificate_uses_public_method_contract():
    controller_key, _ = generate_keypair()
    seen: dict[str, object] = {}

    async def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["timestamp"] = request.headers.get("x-aweb-timestamp")
        seen["payload"] = json.loads(request.content.decode("utf-8"))
        return Response(201)

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        await registry.register_team_certificate(
            "example.com",
            "backend",
            team_controller_signing_key=controller_key,
            certificate_id="cert-1",
            member_did_key="did:key:z6MkMember",
            member_did_aw="did:aw:member",
            member_address="example.com/alice",
            alias="alice",
            identity_scope="global",
            certificate="signed-cert-json",
        )
    finally:
        await registry.aclose()

    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/namespaces/example.com/teams/backend/certificates"
    assert str(seen["auth"]).startswith("DIDKey ")
    assert seen["timestamp"]
    assert seen["payload"] == {
        "certificate_id": "cert-1",
        "member_did_key": "did:key:z6MkMember",
        "member_did_aw": "did:aw:member",
        "member_address": "example.com/alice",
        "alias": "alice",
        "identity_scope": "global",
        "certificate": "signed-cert-json",
    }


@pytest.mark.asyncio
async def test_registry_client_revoke_team_certificate_uses_public_method_contract():
    controller_key, _ = generate_keypair()
    seen: dict[str, object] = {}

    async def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["timestamp"] = request.headers.get("x-aweb-timestamp")
        seen["payload"] = json.loads(request.content.decode("utf-8"))
        return Response(204)

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        await registry.revoke_team_certificate(
            "example.com",
            "backend",
            team_controller_signing_key=controller_key,
            certificate_id="cert-1",
        )
    finally:
        await registry.aclose()

    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/namespaces/example.com/teams/backend/certificates/revoke"
    assert str(seen["auth"]).startswith("DIDKey ")
    assert seen["timestamp"]
    assert seen["payload"] == {"certificate_id": "cert-1"}


@pytest.mark.asyncio
async def test_registry_client_list_team_certificates_sends_active_only_false():
    seen: dict[str, object] = {}

    async def handler(request):
        seen["path"] = request.url.path
        seen["query"] = request.url.query.decode("utf-8")
        return Response(200, json={"certificates": []})

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        assert await registry.list_team_certificates("example.com", "backend", active_only=False) == []
    finally:
        await registry.aclose()

    assert seen["path"] == "/v1/namespaces/example.com/teams/backend/certificates"
    assert seen["query"] == "active_only=false"


@pytest.mark.asyncio
async def test_cached_registry_client_can_invalidate_team_certificate_reads():
    redis = FakeRedis()
    registry = CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(lambda _request: Response(500)),
    )
    active_key = registry._team_certificates_cache_key("example.com", "backend", active_only=True)
    all_key = registry._team_certificates_cache_key("example.com", "backend", active_only=False)
    revocations_key = registry._team_revocations_cache_key("example.com", "backend")
    redis.values.update(
        {
            active_key: "active",
            all_key: "all",
            revocations_key: "revocations",
            "unrelated": "keep",
        }
    )
    try:
        await registry.invalidate_team_certificate_cache("example.com", "backend")
    finally:
        await registry.aclose()

    assert active_key not in redis.values
    assert all_key not in redis.values
    assert revocations_key not in redis.values
    assert redis.values["unrelated"] == "keep"
