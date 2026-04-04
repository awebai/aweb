from __future__ import annotations

import json

import httpx
import pytest

from aweb.awid import (
    AlreadyRegisteredError,
    RegistryError,
    RegistryClient,
    did_from_public_key,
    generate_keypair,
    stable_id_from_did_key,
    verify_did_key_signature,
)
from aweb.awid.log import log_entry_payload
from aweb.awid.signing import canonical_json_bytes


def _authorization_parts(header: str) -> tuple[str, str]:
    scheme, did_key, signature = header.split(" ")
    assert scheme == "DIDKey"
    return did_key, signature


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
