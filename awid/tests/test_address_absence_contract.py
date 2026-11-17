"""Only the address endpoint's typed absence permits alias fallback."""

import asyncio
import json
import os
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.external_http import PinnedRegistryHTTP
from awid.federation_errors import FederationAuthorityError
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError


@pytest_asyncio.fixture
async def response_server():
    state = {"status": 404, "body": {}, "requests": []}

    async def handle(reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        state["requests"].append(raw.split(b"\r\n", 1)[0])
        answer = state["responses"].pop(0) if state.get("responses") else state
        body = json.dumps(answer["body"]).encode()
        writer.write(
            f"HTTP/1.1 {answer['status']} Result\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    state["origin"] = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        yield state
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True], ids=["plain", "redis"])
@pytest.mark.parametrize(
    "kind", ["typed", "generic", "wrong-code", "wrong-status", "success"]
)
async def test_sdk_address_absence_is_coded_and_old_negative_cache_is_not_authority(
    response_server, cached, kind
):
    state = response_server
    domain = f"absence-{uuid4().hex}.example"
    state["body"] = {
        "detail": {"code": "address_not_found", "message": "Address not found"}
    }
    if kind == "generic":
        state["body"] = {"detail": "Address not found"}
    elif kind == "wrong-code":
        state["body"]["detail"]["code"] = "namespace_not_found"
    elif kind == "wrong-status":
        state["status"] = 503
    elif kind == "success":
        state["status"] = 200
        state["body"] = {
            "address_id": "present",
            "domain": domain,
            "name": "person",
            "did_aw": "did:aw:present",
            "current_did_key": "did:key:present",
            "created_at": "2026-11-17T00:00:00Z",
        }
    redis = Redis.from_url(os.environ["REDIS_URL"]) if cached else None
    client = (
        CachedRegistryClient(state["origin"], redis)
        if cached
        else RegistryClient(state["origin"])
    )
    key = legacy = None
    try:
        if redis is not None:
            key = client._address_cache_key(
                domain, "person", registry_url=state["origin"], caller_did_key=None
            )
            legacy = key.replace(":v3:address:", ":v2:address:")
            await client._write_cache_entry(
                legacy, value=None, ttl_seconds=60, encode=lambda value: value
            )
        for read in (client.resolve_address, client.resolve_address_fresh):
            if kind in ("typed", "success"):
                result = await read(domain, "person")
                if kind == "typed":
                    assert result is None
                else:
                    assert result.address_id == "present"
            else:
                with pytest.raises(RegistryError) as refused:
                    await read(domain, "person")
                assert refused.value.status_code == state["status"]
                if redis is not None:
                    assert await redis.get(key) is None
        assert len(state["requests"]) == 2
    finally:
        await client.aclose()
        if redis is not None:
            await redis.delete(key, legacy)
            await redis.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["address", "namespace", "key", "log"])
@pytest.mark.parametrize("typed", [True, False])
async def test_strict_absence_reason_means_typed_address_absence_only(
    response_server, endpoint, typed
):
    state = response_server
    state["body"] = (
        {"detail": {"code": "address_not_found"}}
        if typed
        else {"detail": "Address not found"}
    )
    path = {
        "address": "/v1/namespaces/example.com/addresses/person",
        "namespace": "/v1/namespaces/example.com",
        "key": "/v1/did/did%3Aaw%3Aperson/key",
        "log": "/v1/did/did%3Aaw%3Aperson/log",
    }[endpoint]
    client = PinnedRegistryHTTP(state["origin"], ("127.0.0.1",), 1)
    try:
        with pytest.raises(FederationAuthorityError) as refused:
            await client.get_json(path, not_found_reason="recipient_identity_not_found")
        assert refused.value.reason == (
            "recipient_identity_not_found"
            if typed and endpoint == "address"
            else "sender_registry_protocol_invalid"
        )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_real_address_route_codes_absence_but_missing_namespace_is_not_absence(
    client, controller_identity, fake_domain_verifier
):
    from test_team_visibility_enforcement import _setup_namespace

    key, did = controller_identity
    domain = f"absence-{uuid4().hex}.example"
    await _setup_namespace(client, key, did, domain)
    missing = await client.get(f"/v1/namespaces/{domain}/addresses/person")
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "address_not_found"
    namespace = await client.get(f"/v1/namespaces/not-{domain}/addresses/person")
    assert namespace.status_code == 404
    assert namespace.json()["detail"] != missing.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True], ids=["plain", "redis"])
@pytest.mark.parametrize("stage", ["first", "later", "empty", "revoked"])
async def test_revocation_scan_requires_a_complete_success_not_404(
    response_server, cached, stage
):
    state = response_server
    domain = f"revocations-{uuid4().hex}.example"
    state["status"] = 404
    state["body"] = {"detail": "Team not found"}
    if stage == "later":
        state["responses"] = [
            {
                "status": 200,
                "body": {
                    "revocations": [
                        {
                            "certificate_id": "withdrawn",
                            "revoked_at": "2026-11-17T00:00:00Z",
                        }
                    ],
                    "has_more": True,
                    "next_cursor": "next",
                },
            }
        ]
    elif stage in ("empty", "revoked"):
        state["status"] = 200
        state["body"] = {
            "revocations": (
                [{"certificate_id": "withdrawn"}] if stage == "revoked" else []
            ),
            "has_more": False,
        }
    redis = Redis.from_url(os.environ["REDIS_URL"]) if cached else None
    client = (
        CachedRegistryClient(state["origin"], redis)
        if cached
        else RegistryClient(state["origin"])
    )
    key = client._team_revocations_cache_key(domain, "ops") if cached else None
    legacy = (
        key.replace(":v2:team_revocations:", ":v1:team_revocations:")
        if cached
        else None
    )
    try:
        if cached:
            # An old client could stamp an uncoded 404 as a fresh empty set.
            await client._write_cache_entry(
                legacy, value=set(), ttl_seconds=60, encode=sorted
            )
        if stage in ("first", "later"):
            with pytest.raises(RegistryError) as refused:
                await client.get_team_revocations(domain, "ops")
            assert refused.value.status_code == 404
            if redis is not None:
                assert await redis.get(key) is None
        else:
            assert await client.get_team_revocations(domain, "ops") == (
                {"withdrawn"} if stage == "revoked" else set()
            )
        assert len(state["requests"]) == (2 if stage == "later" else 1)
    finally:
        await client.aclose()
        if redis is not None:
            await redis.delete(key, legacy)
            await redis.aclose()
