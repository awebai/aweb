from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from redis.exceptions import RedisError

import aweb.dns_verify as dns_verify_module
from aweb.awid import (
    AlreadyRegisteredError,
    CachedRegistryClient,
    RegistryError,
    RegistryClient,
    did_from_public_key,
    generate_keypair,
    stable_id_from_did_key,
    verify_did_key_signature,
)
import aweb.awid.registry as registry_module
from aweb.awid.log import log_entry_payload
from aweb.awid.signing import canonical_json_bytes


def _authorization_parts(header: str) -> tuple[str, str]:
    scheme, did_key, signature = header.split(" ")
    assert scheme == "DIDKey"
    return did_key, signature


class _FakeRedis:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.values: dict[str, str] = {}

    async def get(self, key: str):
        if self.fail:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def set(self, key: str, value: str, *, ex: int | None = None):
        if self.fail:
            raise RedisError("redis unavailable")
        self.values[key] = value
        return True

    async def delete(self, *keys: str):
        if self.fail:
            raise RedisError("redis unavailable")
        deleted = 0
        for key in keys:
            deleted += int(key in self.values)
            self.values.pop(key, None)
        return deleted


@pytest.mark.asyncio
async def test_register_did_posts_create_then_fetches_full_mapping():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST" and request.url.path == "/v1/did":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["did_aw"] == did_aw
            assert payload["did_key"] == did_key
            assert payload["authorized_by"] == did_key
            assert payload["server"] == "https://registry.example"
            verify_did_key_signature(
                did_key=payload["did_key"],
                payload=log_entry_payload(
                    did_aw=payload["did_aw"],
                    seq=payload["seq"],
                    operation="create",
                    previous_did_key=None,
                    new_did_key=payload["did_key"],
                    prev_entry_hash=payload["prev_entry_hash"],
                    state_hash=payload["state_hash"],
                    authorized_by=payload["authorized_by"],
                    timestamp=payload["timestamp"],
                ),
                signature_b64=payload["proof"],
            )
            return httpx.Response(200, json={"registered": True})
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/full":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == did_key
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=f"{timestamp}\nGET\n{request.url.path}".encode("utf-8"),
                signature_b64=signature,
            )
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "server": "https://registry.example",
                    "address": "",
                    "handle": None,
                    "created_at": "2026-04-03T00:00:00Z",
                    "updated_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    mapping = await client.register_did(did_key, signing_key, "https://registry.example")

    assert mapping.did_aw == did_aw
    assert mapping.current_did_key == did_key
    assert [request.url.path for request in requests] == ["/v1/did", f"/v1/did/{did_aw}/full"]


@pytest.mark.asyncio
async def test_register_did_raises_already_registered_error_with_existing_key():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/did":
            return httpx.Response(409, json={"detail": "did_aw already registered"})
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "log_head": None,
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(AlreadyRegisteredError) as exc_info:
        await client.register_did(did_key, signing_key, "https://registry.example")

    assert exc_info.value.did_aw == did_aw
    assert exc_info.value.existing_did_key == did_key


@pytest.mark.asyncio
async def test_register_address_resolves_current_key_before_posting():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET" and request.url.path == f"/v1/did/{subject_did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "log_head": None,
                },
            )
        if request.method == "POST" and request.url.path == "/v1/namespaces/acme.com/addresses":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload == {
                "name": "support",
                "did_aw": subject_did_aw,
                "current_did_key": subject_did_key,
                "reachability": "public",
            }
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == controller_did
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "acme.com",
                        "name": "support",
                        "operation": "register_address",
                        "timestamp": timestamp,
                    }
                ),
                signature_b64=signature,
            )
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": "support",
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    address = await client.register_address(
        "acme.com",
        "support",
        subject_did_aw,
        controller_signing_key,
        "public",
    )

    assert address.current_did_key == subject_did_key
    assert [request.url.path for request in requests] == [
        f"/v1/did/{subject_did_aw}/key",
        "/v1/namespaces/acme.com/addresses",
    ]


@pytest.mark.asyncio
async def test_get_namespace_returns_none_on_404():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/namespaces/missing.example"
        return httpx.Response(404, json={"detail": "Namespace not found"})

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    assert await client.get_namespace("missing.example") is None


@pytest.mark.asyncio
async def test_get_namespace_uses_discovered_registry_for_domain():
    async def _resolve_registry(domain: str) -> str:
        assert domain == "example.com"
        return "https://registry.example"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://registry.example/v1/namespaces/example.com")
        return httpx.Response(
            200,
            json={
                "namespace_id": "ns-1",
                "domain": "example.com",
                "controller_did": None,
                "verification_status": "verified",
                "last_verified_at": None,
                "created_at": "2026-04-04T00:00:00Z",
            },
        )

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
        domain_registry_resolver=_resolve_registry,
    )

    namespace = await client.get_namespace("example.com")

    assert namespace is not None
    assert namespace.domain == "example.com"


@pytest.mark.asyncio
async def test_registry_url_for_domain_uses_explicit_registry_url_by_default(monkeypatch):
    async def _no_override_lookup(domain: str):
        assert domain == "example.com"
        return None

    monkeypatch.setattr(dns_verify_module, "discover_registry_override", _no_override_lookup)

    client = RegistryClient(registry_url="https://registry.example")

    assert await client._registry_url_for_domain("example.com") == "https://registry.example"


@pytest.mark.asyncio
async def test_registry_url_for_domain_allows_dns_override_of_explicit_default(monkeypatch):
    async def _override_lookup(domain: str):
        assert domain == "example.com"
        return "https://override.example"

    monkeypatch.setattr(dns_verify_module, "discover_registry_override", _override_lookup)

    client = RegistryClient(registry_url="https://registry.example")

    assert await client._registry_url_for_domain("example.com") == "https://override.example"


@pytest.mark.asyncio
async def test_registry_url_for_domain_falls_back_to_configured_registry_when_dns_override_lookup_fails(
    monkeypatch,
):
    async def _failing_override_lookup(_domain: str):
        from aweb.dns_verify import DnsVerificationError

        raise DnsVerificationError("dns unavailable")

    monkeypatch.setattr(dns_verify_module, "discover_registry_override", _failing_override_lookup)

    client = RegistryClient(registry_url="https://registry.example")

    assert await client._registry_url_for_domain("example.com") == "https://registry.example"


@pytest.mark.asyncio
async def test_register_namespace_supports_parent_authorized_subdomains():
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)
    child_signing_key, child_public_key = generate_keypair()
    child_controller_did = did_from_public_key(child_public_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/namespaces"
        auth_did_key, signature = _authorization_parts(request.headers["authorization"])
        parent_did_key, parent_signature = _authorization_parts(
            request.headers["x-aweb-parent-authorization"]
        )
        timestamp = request.headers["x-aweb-timestamp"]
        parent_timestamp = request.headers["x-aweb-parent-timestamp"]
        assert auth_did_key == child_controller_did
        assert parent_did_key == parent_controller_did
        verify_did_key_signature(
            did_key=auth_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "project.aweb.ai",
                    "operation": "register",
                    "timestamp": timestamp,
                }
            ),
            signature_b64=signature,
        )
        verify_did_key_signature(
            did_key=parent_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "project.aweb.ai",
                    "child_domain": "project.aweb.ai",
                    "controller_did": child_controller_did,
                    "operation": "authorize_subdomain_registration",
                    "timestamp": parent_timestamp,
                }
            ),
            signature_b64=parent_signature,
        )
        payload = json.loads(request.content.decode("utf-8"))
        assert payload == {"domain": "project.aweb.ai", "controller_did": child_controller_did}
        return httpx.Response(
            200,
            json={
                "namespace_id": "ns-subdomain",
                "domain": "project.aweb.ai",
                "controller_did": child_controller_did,
                "verification_status": "verified",
                "last_verified_at": "2026-04-03T00:00:00Z",
                "created_at": "2026-04-03T00:00:00Z",
            },
        )

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    namespace = await client.register_namespace(
        "project.aweb.ai",
        child_controller_did,
        child_signing_key,
        parent_signing_key=parent_signing_key,
    )

    assert namespace.domain == "project.aweb.ai"
    assert namespace.controller_did == child_controller_did


@pytest.mark.asyncio
async def test_register_namespace_parent_authorization_binds_child_controller_did():
    parent_signing_key, parent_public_key = generate_keypair()
    child_signing_key, child_public_key = generate_keypair()
    child_controller_did = did_from_public_key(child_public_key)
    other_signing_key, other_public_key = generate_keypair()
    other_controller_did = did_from_public_key(other_public_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        auth_did_key, auth_signature = _authorization_parts(request.headers["authorization"])
        parent_did_key, parent_signature = _authorization_parts(
            request.headers["x-aweb-parent-authorization"]
        )
        timestamp = request.headers["x-aweb-timestamp"]
        parent_timestamp = request.headers["x-aweb-parent-timestamp"]
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["controller_did"] == other_controller_did
        assert auth_did_key == other_controller_did
        verify_did_key_signature(
            did_key=auth_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "project.aweb.ai",
                    "operation": "register",
                    "timestamp": timestamp,
                }
            ),
            signature_b64=auth_signature,
        )
        with pytest.raises(ValueError):
            verify_did_key_signature(
                did_key=parent_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "project.aweb.ai",
                        "child_domain": "project.aweb.ai",
                        "controller_did": child_controller_did,
                        "operation": "authorize_subdomain_registration",
                        "timestamp": parent_timestamp,
                    }
                ),
                signature_b64=parent_signature,
            )
        return httpx.Response(401, json={"detail": "Invalid signature"})

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(RegistryError):
        await client.register_namespace(
            "project.aweb.ai",
            other_controller_did,
            other_signing_key,
            parent_signing_key=parent_signing_key,
        )


@pytest.mark.asyncio
async def test_rotate_namespace_controller_signs_proof_with_new_controller_key():
    new_controller_signing_key, new_controller_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_controller_public_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == "/v1/namespaces/example.com"
        auth_did_key, signature = _authorization_parts(request.headers["authorization"])
        timestamp = request.headers["x-aweb-timestamp"]
        assert auth_did_key == new_controller_did
        payload = json.loads(request.content.decode("utf-8"))
        assert payload == {"new_controller_did": new_controller_did}
        verify_did_key_signature(
            did_key=auth_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "example.com",
                    "new_controller_did": new_controller_did,
                    "operation": "rotate_controller",
                    "timestamp": timestamp,
                }
            ),
            signature_b64=signature,
        )
        return httpx.Response(
            200,
            json={
                "namespace_id": "ns-1",
                "domain": "example.com",
                "controller_did": new_controller_did,
                "verification_status": "verified",
                "last_verified_at": "2026-04-03T00:00:00Z",
                "created_at": "2026-04-01T00:00:00Z",
            },
        )

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    namespace = await client.rotate_namespace_controller(
        "example.com",
        new_controller_did,
        new_controller_signing_key,
    )

    assert namespace.controller_did == new_controller_did


@pytest.mark.asyncio
async def test_rotate_namespace_controller_supports_parent_authorization_headers():
    new_controller_signing_key, new_controller_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_controller_public_key)
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        auth_did_key, auth_signature = _authorization_parts(request.headers["authorization"])
        parent_did_key, parent_signature = _authorization_parts(
            request.headers["x-aweb-parent-authorization"]
        )
        timestamp = request.headers["x-aweb-timestamp"]
        parent_timestamp = request.headers["x-aweb-parent-timestamp"]
        assert auth_did_key == new_controller_did
        assert parent_did_key == parent_controller_did
        verify_did_key_signature(
            did_key=auth_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "project.aweb.ai",
                    "new_controller_did": new_controller_did,
                    "operation": "rotate_controller",
                    "timestamp": timestamp,
                }
            ),
            signature_b64=auth_signature,
        )
        verify_did_key_signature(
            did_key=parent_did_key,
            payload=canonical_json_bytes(
                {
                    "domain": "project.aweb.ai",
                    "child_domain": "project.aweb.ai",
                    "new_controller_did": new_controller_did,
                    "operation": "authorize_subdomain_rotation",
                    "timestamp": parent_timestamp,
                }
            ),
            signature_b64=parent_signature,
        )
        return httpx.Response(
            200,
            json={
                "namespace_id": "ns-1",
                "domain": "project.aweb.ai",
                "controller_did": new_controller_did,
                "verification_status": "verified",
                "last_verified_at": "2026-04-03T00:00:00Z",
                "created_at": "2026-04-01T00:00:00Z",
            },
        )

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    namespace = await client.rotate_namespace_controller(
        "project.aweb.ai",
        new_controller_did,
        new_controller_signing_key,
        parent_signing_key=parent_signing_key,
    )

    assert namespace.controller_did == new_controller_did


@pytest.mark.asyncio
async def test_list_update_delete_and_reverse_lookup_address_methods():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses":
            return httpx.Response(
                200,
                json={
                    "addresses": [
                        {
                            "address_id": "addr-1",
                            "domain": "acme.com",
                            "name": "support",
                            "did_aw": subject_did_aw,
                            "current_did_key": subject_did_key,
                            "reachability": "private",
                            "created_at": "2026-04-03T00:00:00Z",
                        }
                    ]
                },
            )
        if request.method == "PUT" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == controller_did
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "acme.com",
                        "name": "support",
                        "operation": "update_address",
                        "timestamp": timestamp,
                    }
                ),
                signature_b64=signature,
            )
            payload = json.loads(request.content.decode("utf-8"))
            assert payload == {"reachability": "public"}
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": "support",
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "DELETE" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == controller_did
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "acme.com",
                        "name": "support",
                        "operation": "delete_address",
                        "timestamp": timestamp,
                    }
                ),
                signature_b64=signature,
            )
            return httpx.Response(200, json={"status": "deleted"})
        if request.method == "GET" and request.url.path == f"/v1/did/{subject_did_aw}/addresses":
            return httpx.Response(
                200,
                json={
                    "addresses": [
                        {
                            "address_id": "addr-1",
                            "domain": "acme.com",
                            "name": "support",
                            "did_aw": subject_did_aw,
                            "current_did_key": subject_did_key,
                            "reachability": "public",
                            "created_at": "2026-04-03T00:00:00Z",
                        }
                    ]
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    addresses = await client.list_addresses("acme.com")
    updated = await client.update_address(
        "acme.com",
        "support",
        controller_signing_key,
        "public",
    )
    await client.delete_address("acme.com", "support", controller_signing_key)
    reverse_lookup = await client.list_did_addresses(subject_did_aw)

    assert [address.name for address in addresses] == ["support"]
    assert updated.reachability == "public"
    assert [address.name for address in reverse_lookup] == ["support"]
    assert [request.url.path for request in requests] == [
        "/v1/namespaces/acme.com/addresses",
        "/v1/namespaces/acme.com/addresses/support",
        "/v1/namespaces/acme.com/addresses/support",
        f"/v1/did/{subject_did_aw}/addresses",
    ]


@pytest.mark.asyncio
async def test_resolve_address_uses_discovered_registry_for_domain():
    async def _resolve_registry(domain: str) -> str:
        assert domain == "acme.com"
        return "https://registry.acme.test"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(
            "https://registry.acme.test/v1/namespaces/acme.com/addresses/support"
        )
        return httpx.Response(
            200,
            json={
                "address_id": "addr-1",
                "domain": "acme.com",
                "name": "support",
                "did_aw": "did:aw:z6Mksubject",
                "current_did_key": "did:key:z6Mksubject",
                "reachability": "public",
                "created_at": "2026-04-04T00:00:00Z",
            },
        )

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
        domain_registry_resolver=_resolve_registry,
    )

    address = await client.resolve_address("acme.com", "support")

    assert address is not None
    assert address.name == "support"


@pytest.mark.asyncio
async def test_update_server_uses_current_key_and_signed_audit_payload():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    requests: list[httpx.Request] = []
    current_server = {"value": "https://old.example"}

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/full":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == did_key
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=f"{timestamp}\nGET\n{request.url.path}".encode("utf-8"),
                signature_b64=signature,
            )
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "server": current_server["value"],
                    "address": "",
                    "handle": None,
                    "created_at": "2026-04-03T00:00:00Z",
                    "updated_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "log_head": {
                        "seq": 3,
                        "operation": "rotate_key",
                        "previous_did_key": did_key,
                        "new_did_key": did_key,
                        "prev_entry_hash": "prev-prev",
                        "entry_hash": "head-3",
                        "state_hash": "state-3",
                        "authorized_by": did_key,
                        "signature": "sig",
                        "timestamp": "2026-04-03T00:00:00Z",
                    },
                },
            )
        if request.method == "PUT" and request.url.path == f"/v1/did/{did_aw}":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["operation"] == "update_server"
            assert payload["new_did_key"] == did_key
            assert payload["server"] == "https://new.example"
            verify_did_key_signature(
                did_key=did_key,
                payload=log_entry_payload(
                    did_aw=did_aw,
                    seq=payload["seq"],
                    operation="update_server",
                    previous_did_key=did_key,
                    new_did_key=did_key,
                    prev_entry_hash=payload["prev_entry_hash"],
                    state_hash=payload["state_hash"],
                    authorized_by=payload["authorized_by"],
                    timestamp=payload["timestamp"],
                ),
                signature_b64=payload["signature"],
            )
            current_server["value"] = payload["server"]
            return httpx.Response(200, json={"updated": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = RegistryClient(
        registry_url="https://api.awid.ai",
        transport=httpx.MockTransport(handler),
    )

    mapping = await client.update_server(did_aw, "https://new.example", signing_key)

    assert mapping.server == "https://new.example"
    assert [request.url.path for request in requests] == [
        f"/v1/did/{did_aw}/full",
        f"/v1/did/{did_aw}/key",
        f"/v1/did/{did_aw}",
        f"/v1/did/{did_aw}/full",
    ]


@pytest.mark.asyncio
async def test_base_url_override_requires_local_mode():
    client = RegistryClient(
        registry_url="https://api.awid.ai",
        base_url="http://override.test",
    )

    with pytest.raises(ValueError, match="base_url override is only allowed"):
        client._resolved_base_url()

    allowed = RegistryClient(
        registry_url="local",
        base_url="http://override.test",
    )

    assert allowed._resolved_base_url() == "http://override.test"


@pytest.mark.asyncio
async def test_local_registry_mode_uses_http_transport_when_provided():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("http://awid.local/v1/namespaces/example.com")
        return httpx.Response(
            200,
            json={
                "namespace_id": "ns-1",
                "domain": "example.com",
                "controller_did": None,
                "verification_status": "verified",
                "last_verified_at": None,
                "created_at": "2026-04-03T00:00:00Z",
            },
        )

    client = RegistryClient(registry_url="local", transport=httpx.MockTransport(handler))

    namespace = await client.get_namespace("example.com")

    assert namespace is not None
    assert namespace.domain == "example.com"


@pytest.mark.asyncio
async def test_cached_registry_client_reuses_cached_resolve_key():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    request_count = {"value": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"/v1/did/{did_aw}/key"
        request_count["value"] += 1
        return httpx.Response(
            200,
            json={
                "did_aw": did_aw,
                "current_did_key": did_key,
                "log_head": None,
            },
        )

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    first = await client.resolve_key(did_aw)
    second = await client.resolve_key(did_aw)

    assert first.current_did_key == did_key
    assert second.current_did_key == did_key
    assert request_count["value"] == 1


@pytest.mark.asyncio
async def test_cached_registry_client_serves_stale_then_refreshes_in_background(monkeypatch):
    signing_key, public_key = generate_keypair()
    old_did_key = did_from_public_key(public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_public_key)
    did_aw = stable_id_from_did_key(old_did_key)
    now = {"value": 0}
    current_key = {"value": old_did_key}

    monkeypatch.setattr(registry_module, "_cache_now", lambda: now["value"])

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"/v1/did/{did_aw}/key"
        return httpx.Response(
            200,
            json={
                "did_aw": did_aw,
                "current_did_key": current_key["value"],
                "log_head": None,
            },
        )

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    fresh = await client.resolve_key(did_aw)
    assert fresh.current_did_key == old_did_key

    current_key["value"] = new_did_key
    now["value"] = 301
    stale = await client.resolve_key(did_aw)
    assert stale.current_did_key == old_did_key

    for _ in range(3):
        await asyncio.sleep(0)

    refreshed = await client.resolve_key(did_aw)
    assert refreshed.current_did_key == new_did_key


@pytest.mark.asyncio
async def test_cached_registry_client_resolve_key_fresh_bypasses_stale_cache(monkeypatch):
    signing_key, public_key = generate_keypair()
    old_did_key = did_from_public_key(public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_public_key)
    did_aw = stable_id_from_did_key(old_did_key)
    now = {"value": 0}
    current_key = {"value": old_did_key}

    monkeypatch.setattr(registry_module, "_cache_now", lambda: now["value"])

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"/v1/did/{did_aw}/key"
        return httpx.Response(
            200,
            json={
                "did_aw": did_aw,
                "current_did_key": current_key["value"],
                "log_head": None,
            },
        )

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    fresh = await client.resolve_key(did_aw)
    assert fresh.current_did_key == old_did_key

    current_key["value"] = new_did_key
    now["value"] = 301

    force_fresh = await client.resolve_key_fresh(did_aw)

    assert force_fresh.current_did_key == new_did_key
    cached = await client.resolve_key(did_aw)
    assert cached.current_did_key == new_did_key
    assert new_signing_key != signing_key


@pytest.mark.asyncio
async def test_cached_registry_client_uses_address_ttl_for_list_addresses(monkeypatch):
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    now = {"value": 0}
    current_name = {"value": "support"}

    monkeypatch.setattr(registry_module, "_cache_now", lambda: now["value"])

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/namespaces/acme.com/addresses"
        return httpx.Response(
            200,
            json={
                "addresses": [
                    {
                        "address_id": "addr-1",
                        "domain": "acme.com",
                        "name": current_name["value"],
                        "did_aw": subject_did_aw,
                        "current_did_key": subject_did_key,
                        "reachability": "public",
                        "created_at": "2026-04-03T00:00:00Z",
                    }
                ]
            },
        )

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    fresh = await client.list_addresses("acme.com")
    assert [item.name for item in fresh] == ["support"]

    current_name["value"] = "ops"
    now["value"] = 301
    stale = await client.list_addresses("acme.com")
    assert [item.name for item in stale] == ["support"]

    for _ in range(3):
        await asyncio.sleep(0)

    refreshed = await client.list_addresses("acme.com")
    assert [item.name for item in refreshed] == ["ops"]


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_address_reads_on_update():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    reachability = {"value": "private"}
    request_counts: dict[str, int] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        request_counts[request.url.path] = request_counts.get(request.url.path, 0) + 1
        address_payload = {
            "address_id": "addr-1",
            "domain": "acme.com",
            "name": "support",
            "did_aw": subject_did_aw,
            "current_did_key": subject_did_key,
            "reachability": reachability["value"],
            "created_at": "2026-04-03T00:00:00Z",
        }
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            return httpx.Response(200, json=address_payload)
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses":
            return httpx.Response(200, json={"addresses": [address_payload]})
        if request.method == "GET" and request.url.path == f"/v1/did/{subject_did_aw}/addresses":
            return httpx.Response(200, json={"addresses": [address_payload]})
        if request.method == "PUT" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            reachability["value"] = "public"
            address_payload["reachability"] = "public"
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == controller_did
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "acme.com",
                        "name": "support",
                        "operation": "update_address",
                        "timestamp": timestamp,
                    }
                ),
                signature_b64=signature,
            )
            return httpx.Response(200, json=address_payload)
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    before_address = await client.resolve_address("acme.com", "support")
    before_domain = await client.list_addresses("acme.com")
    before_reverse = await client.list_did_addresses(subject_did_aw)
    updated = await client.update_address("acme.com", "support", controller_signing_key, "public")
    after_address = await client.resolve_address("acme.com", "support")
    after_domain = await client.list_addresses("acme.com")
    after_reverse = await client.list_did_addresses(subject_did_aw)

    assert before_address is not None
    assert before_address.reachability == "private"
    assert [item.reachability for item in before_domain] == ["private"]
    assert [item.reachability for item in before_reverse] == ["private"]
    assert updated.reachability == "public"
    assert after_address is not None
    assert after_address.reachability == "public"
    assert [item.reachability for item in after_domain] == ["public"]
    assert [item.reachability for item in after_reverse] == ["public"]
    assert request_counts["/v1/namespaces/acme.com/addresses/support"] == 3
    assert request_counts["/v1/namespaces/acme.com/addresses"] == 2
    assert request_counts[f"/v1/did/{subject_did_aw}/addresses"] == 2


@pytest.mark.asyncio
async def test_cached_registry_client_register_did_invalidates_stale_key_cache_on_conflict():
    stale_signing_key, stale_public_key = generate_keypair()
    stale_did_key = did_from_public_key(stale_public_key)
    current_signing_key, current_public_key = generate_keypair()
    current_did_key = did_from_public_key(current_public_key)
    did_aw = stable_id_from_did_key(current_did_key)
    redis = _FakeRedis()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/did":
            return httpx.Response(409, json={"detail": "did_aw already registered"})
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": current_did_key,
                    "log_head": None,
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=redis,
        transport=httpx.MockTransport(handler),
    )
    await client._write_cache_entry(
        client._did_key_cache_key(did_aw),
        value=registry_module.KeyResolution(did_aw=did_aw, current_did_key=stale_did_key, log_head=None),
        ttl_seconds=300,
        encode=registry_module._key_resolution_to_json,
    )

    with pytest.raises(AlreadyRegisteredError) as exc_info:
        await client.register_did(current_did_key, current_signing_key, "https://registry.example")

    assert exc_info.value.existing_did_key == current_did_key


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_namespace_cache_on_register():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    redis = _FakeRedis()
    current_controller = {"value": "did:key:zstale"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1/namespaces/example.com":
            return httpx.Response(
                200,
                json={
                    "namespace_id": "ns-1",
                    "domain": "example.com",
                    "controller_did": current_controller["value"],
                    "verification_status": "verified",
                    "last_verified_at": "2026-04-03T00:00:00Z",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "POST" and request.url.path == "/v1/namespaces":
            current_controller["value"] = controller_did
            return httpx.Response(
                200,
                json={
                    "namespace_id": "ns-1",
                    "domain": "example.com",
                    "controller_did": controller_did,
                    "verification_status": "verified",
                    "last_verified_at": "2026-04-03T00:00:00Z",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=redis,
        transport=httpx.MockTransport(handler),
    )

    stale = await client.get_namespace("example.com")
    created = await client.register_namespace("example.com", controller_did, controller_signing_key)
    refreshed = await client.get_namespace("example.com")

    assert stale is not None
    assert stale.controller_did == "did:key:zstale"
    assert created.controller_did == controller_did
    assert refreshed is not None
    assert refreshed.controller_did == controller_did


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_namespace_cache_on_rotate():
    stale_signing_key, stale_public_key = generate_keypair()
    stale_did = did_from_public_key(stale_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did = did_from_public_key(new_public_key)
    current_controller = {"value": stale_did}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1/namespaces/example.com":
            return httpx.Response(
                200,
                json={
                    "namespace_id": "ns-1",
                    "domain": "example.com",
                    "controller_did": current_controller["value"],
                    "verification_status": "verified",
                    "last_verified_at": "2026-04-03T00:00:00Z",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "PUT" and request.url.path == "/v1/namespaces/example.com":
            current_controller["value"] = new_did
            return httpx.Response(
                200,
                json={
                    "namespace_id": "ns-1",
                    "domain": "example.com",
                    "controller_did": new_did,
                    "verification_status": "verified",
                    "last_verified_at": "2026-04-03T00:00:00Z",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    stale = await client.get_namespace("example.com")
    rotated = await client.rotate_namespace_controller("example.com", new_did, new_signing_key)
    refreshed = await client.get_namespace("example.com")

    assert stale is not None
    assert stale.controller_did == stale_did
    assert rotated.controller_did == new_did
    assert refreshed is not None
    assert refreshed.controller_did == new_did


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_address_cache_on_register():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    address_name = {"value": "stale"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == f"/v1/did/{subject_did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "log_head": None,
                },
            )
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": address_name["value"],
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "POST" and request.url.path == "/v1/namespaces/acme.com/addresses":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["did_aw"] == subject_did_aw
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == controller_did
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=canonical_json_bytes(
                    {
                        "domain": "acme.com",
                        "name": "support",
                        "operation": "register_address",
                        "timestamp": timestamp,
                    }
                ),
                signature_b64=signature,
            )
            address_name["value"] = "support"
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": "support",
                    "did_aw": subject_did_aw,
                    "current_did_key": subject_did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )
    await client._write_cache_entry(
        client._address_cache_key("acme.com", "support", registry_url="https://api.awid.ai"),
        value=registry_module.Address(
            address_id="addr-1",
            domain="acme.com",
            name="stale",
            did_aw=subject_did_aw,
            current_did_key=subject_did_key,
            reachability="public",
            created_at="2026-04-03T00:00:00Z",
        ),
        ttl_seconds=300,
        encode=registry_module._address_to_json,
    )

    created = await client.register_address(
        "acme.com",
        "support",
        subject_did_aw,
        controller_signing_key,
        "public",
    )
    refreshed = await client.resolve_address("acme.com", "support")

    assert created.name == "support"
    assert refreshed is not None
    assert refreshed.name == "support"


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_did_cache_before_update_server():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    head = {"seq": 3, "entry_hash": "head-3"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "log_head": {
                        "seq": head["seq"],
                        "operation": "update_server",
                        "previous_did_key": did_key,
                        "new_did_key": did_key,
                        "prev_entry_hash": "prev",
                        "entry_hash": head["entry_hash"],
                        "state_hash": "state",
                        "authorized_by": did_key,
                        "signature": "sig",
                        "timestamp": "2026-04-03T00:00:00Z",
                    },
                },
            )
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/full":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            assert auth_did_key == did_key
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=f"{timestamp}\nGET\n{request.url.path}".encode("utf-8"),
                signature_b64=signature,
            )
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "server": "https://old.example",
                    "address": "",
                    "handle": None,
                    "created_at": "2026-04-03T00:00:00Z",
                    "updated_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "PUT" and request.url.path == f"/v1/did/{did_aw}":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["seq"] == 8
            assert payload["prev_entry_hash"] == "head-7"
            return httpx.Response(200, json={"updated": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    await client.resolve_key(did_aw)
    head["seq"] = 7
    head["entry_hash"] = "head-7"

    await client.update_server(did_aw, "https://new.example", signing_key)


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_did_cache_before_rotate_key():
    old_signing_key, old_public_key = generate_keypair()
    old_did_key = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_public_key)
    did_aw = stable_id_from_did_key(old_did_key)
    head = {"seq": 2, "entry_hash": "head-2"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": old_did_key,
                    "log_head": {
                        "seq": head["seq"],
                        "operation": "update_server",
                        "previous_did_key": old_did_key,
                        "new_did_key": old_did_key,
                        "prev_entry_hash": "prev",
                        "entry_hash": head["entry_hash"],
                        "state_hash": "state",
                        "authorized_by": old_did_key,
                        "signature": "sig",
                        "timestamp": "2026-04-03T00:00:00Z",
                    },
                },
            )
        if request.method == "GET" and request.url.path == f"/v1/did/{did_aw}/full":
            auth_did_key, signature = _authorization_parts(request.headers["authorization"])
            timestamp = request.headers["x-aweb-timestamp"]
            verify_did_key_signature(
                did_key=auth_did_key,
                payload=f"{timestamp}\nGET\n{request.url.path}".encode("utf-8"),
                signature_b64=signature,
            )
            response_did_key = new_did_key if auth_did_key == new_did_key else old_did_key
            return httpx.Response(
                200,
                json={
                    "did_aw": did_aw,
                    "current_did_key": response_did_key,
                    "server": "https://old.example",
                    "address": "",
                    "handle": None,
                    "created_at": "2026-04-03T00:00:00Z",
                    "updated_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "PUT" and request.url.path == f"/v1/did/{did_aw}":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["seq"] == 6
            assert payload["prev_entry_hash"] == "head-5"
            return httpx.Response(200, json={"updated": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    await client.resolve_key(did_aw)
    head["seq"] = 5
    head["entry_hash"] = "head-5"

    mapping = await client.rotate_key(did_aw, new_did_key, old_signing_key, new_signing_key)

    assert mapping.current_did_key == new_did_key


@pytest.mark.asyncio
async def test_cached_registry_client_delete_address_invalidates_reverse_lookup_from_cached_address():
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    subject_did_aw = stable_id_from_did_key(subject_did_key)
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    deleted = {"value": False}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            return httpx.Response(404, json={"detail": "Address not found"})
        if request.method == "DELETE" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            deleted["value"] = True
            return httpx.Response(200, json={"status": "deleted"})
        if request.method == "GET" and request.url.path == f"/v1/did/{subject_did_aw}/addresses":
            addresses = []
            if not deleted["value"]:
                addresses.append(
                    {
                        "address_id": "addr-1",
                        "domain": "acme.com",
                        "name": "support",
                        "did_aw": subject_did_aw,
                        "current_did_key": subject_did_key,
                        "reachability": "public",
                        "created_at": "2026-04-03T00:00:00Z",
                    }
                )
            return httpx.Response(200, json={"addresses": addresses})
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )
    await client._write_cache_entry(
        client._address_cache_key("acme.com", "support", registry_url="https://api.awid.ai"),
        value=registry_module.Address(
            address_id="addr-1",
            domain="acme.com",
            name="support",
            did_aw=subject_did_aw,
            current_did_key=subject_did_key,
            reachability="public",
            created_at="2026-04-03T00:00:00Z",
        ),
        ttl_seconds=300,
        encode=registry_module._address_to_json,
    )
    await client._write_cache_entry(
        client._did_addresses_cache_key(subject_did_aw),
        value=[
            registry_module.Address(
                address_id="addr-1",
                domain="acme.com",
                name="support",
                did_aw=subject_did_aw,
                current_did_key=subject_did_key,
                reachability="public",
                created_at="2026-04-03T00:00:00Z",
            )
        ],
        ttl_seconds=300,
        encode=lambda value: [registry_module._address_to_json(item) for item in value],
    )

    await client.delete_address("acme.com", "support", controller_signing_key)
    refreshed = await client.list_did_addresses(subject_did_aw)

    assert refreshed == []


@pytest.mark.asyncio
async def test_cached_registry_client_invalidates_reassign_address_caches():
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    old_subject_signing_key, old_subject_public_key = generate_keypair()
    old_did_key = did_from_public_key(old_subject_public_key)
    old_did_aw = stable_id_from_did_key(old_did_key)
    new_subject_signing_key, new_subject_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_subject_public_key)
    new_did_aw = stable_id_from_did_key(new_did_key)
    current_did_aw = {"value": old_did_aw}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1/namespaces/acme.com/addresses/support":
            did_aw = current_did_aw["value"]
            did_key = new_did_key if did_aw == new_did_aw else old_did_key
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": "support",
                    "did_aw": did_aw,
                    "current_did_key": did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        if request.method == "GET" and request.url.path == f"/v1/did/{new_did_aw}/key":
            return httpx.Response(
                200,
                json={
                    "did_aw": new_did_aw,
                    "current_did_key": new_did_key,
                    "log_head": None,
                },
            )
        if request.method == "GET" and request.url.path == f"/v1/did/{old_did_aw}/addresses":
            addresses = []
            if current_did_aw["value"] == old_did_aw:
                addresses.append(
                    {
                        "address_id": "addr-1",
                        "domain": "acme.com",
                        "name": "support",
                        "did_aw": old_did_aw,
                        "current_did_key": old_did_key,
                        "reachability": "public",
                        "created_at": "2026-04-03T00:00:00Z",
                    }
                )
            return httpx.Response(200, json={"addresses": addresses})
        if request.method == "GET" and request.url.path == f"/v1/did/{new_did_aw}/addresses":
            addresses = []
            if current_did_aw["value"] == new_did_aw:
                addresses.append(
                    {
                        "address_id": "addr-1",
                        "domain": "acme.com",
                        "name": "support",
                        "did_aw": new_did_aw,
                        "current_did_key": new_did_key,
                        "reachability": "public",
                        "created_at": "2026-04-03T00:00:00Z",
                    }
                )
            return httpx.Response(200, json={"addresses": addresses})
        if request.method == "POST" and request.url.path == "/v1/namespaces/acme.com/addresses/support/reassign":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["current_did_key"] == new_did_key
            current_did_aw["value"] = new_did_aw
            return httpx.Response(
                200,
                json={
                    "address_id": "addr-1",
                    "domain": "acme.com",
                    "name": "support",
                    "did_aw": new_did_aw,
                    "current_did_key": new_did_key,
                    "reachability": "public",
                    "created_at": "2026-04-03T00:00:00Z",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(),
        transport=httpx.MockTransport(handler),
    )

    before_old = await client.list_did_addresses(old_did_aw)
    reassigned = await client.reassign_address("acme.com", "support", new_did_aw, controller_signing_key)
    after_old = await client.list_did_addresses(old_did_aw)
    after_new = await client.list_did_addresses(new_did_aw)

    assert [item.did_aw for item in before_old] == [old_did_aw]
    assert reassigned.did_aw == new_did_aw
    assert after_old == []
    assert [item.did_aw for item in after_new] == [new_did_aw]


@pytest.mark.asyncio
async def test_cached_registry_client_passthrough_when_redis_is_down():
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    request_count = {"value": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"/v1/did/{did_aw}/key"
        request_count["value"] += 1
        return httpx.Response(
            200,
            json={
                "did_aw": did_aw,
                "current_did_key": did_key,
                "log_head": None,
            },
        )

    client = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_FakeRedis(fail=True),
        transport=httpx.MockTransport(handler),
    )

    await client.resolve_key(did_aw)
    await client.resolve_key(did_aw)

    assert request_count["value"] == 2
