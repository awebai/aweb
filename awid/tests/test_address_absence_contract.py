"""Registry-owned absence and strict refusal compatibility over real HTTP."""

import asyncio
import json
import os
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.did import did_key_from_signing_key
from awid.external_http import PinnedRegistryHTTP
from awid.federation_errors import FederationAuthorityError
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError


@pytest_asyncio.fixture
async def response_server():
    state = {"status": 404, "body": {}, "requests": []}

    async def handle(reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        state["requests"].append(raw.split(b"\r\n", 1)[0])
        request_path = raw.split(b" ", 2)[1].split(b"?", 1)[0].decode()
        if state.get("team") and request_path.endswith("/teams/ops"):
            answer = state["team"]
        else:
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
    "kind",
    [
        "typed",
        "legacy",
        "namespace-legacy",
        "generic",
        "legacy-extra",
        "wrong-code",
        "wrong-status",
        "success",
    ],
)
async def test_sdk_address_absence_is_coded_and_old_negative_cache_is_not_authority(
    response_server, cached, kind, caplog
):
    state = response_server
    domain = f"absence-{uuid4().hex}.example"
    state["body"] = {"detail": {"code": "address_not_found", "message": "Address not found"}}
    if kind == "legacy":
        state["body"] = {"detail": "Address not found"}
    elif kind == "namespace-legacy":
        state["body"] = {"detail": "Namespace not found"}
    elif kind == "generic":
        state["body"] = {"detail": "Not Found"}
    elif kind == "legacy-extra":
        state["body"] = {"detail": "Address not found", "proxy": True}
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
        CachedRegistryClient(state["origin"], redis) if cached else RegistryClient(state["origin"])
    )
    key = legacy = None
    try:
        if redis is not None:
            key = client._address_cache_key(
                domain, "person", registry_url=state["origin"], caller_did_key=None
            )
            legacy = key.replace(":v4:address:", ":v3:address:")
            assert legacy != key
            await client._write_cache_entry(
                legacy, value=None, ttl_seconds=60, encode=lambda value: value
            )
        for read in (client.resolve_address, client.resolve_address_fresh):
            if kind in ("typed", "legacy", "namespace-legacy", "success"):
                result = await read(domain, "person")
                if kind in ("typed", "legacy", "namespace-legacy"):
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
        legacy_reads = [
            r for r in caplog.records if getattr(r, "event", "") == "awid_legacy_address_not_found"
        ]
        assert len(legacy_reads) == (2 if kind in ("legacy", "namespace-legacy") else 0)
    finally:
        await client.aclose()
        if redis is not None:
            await redis.delete(key, legacy)
            await redis.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["address", "namespace", "key", "log"])
@pytest.mark.parametrize("body_kind", ["typed", "legacy", "generic"])
@pytest.mark.parametrize(
    "not_found_reason", ["sender_identity_not_found", "recipient_identity_not_found"]
)
async def test_strict_404_retains_callers_refusal_reason(
    response_server, endpoint, body_kind, not_found_reason, caplog
):
    state = response_server
    state["body"] = (
        {"detail": {"code": "address_not_found"}}
        if body_kind == "typed"
        else {"detail": "Address not found" if body_kind == "legacy" else "Not Found"}
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
            await client.get_json(path, not_found_reason=not_found_reason)
        assert refused.value.reason == not_found_reason
        # Strict reads refuse; they do not use the SDK's absence classifier.
        assert not any(
            getattr(r, "event", "") == "awid_legacy_address_not_found" for r in caplog.records
        )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_strict_missing_namespace_preserves_sender_identity_not_found(
    response_server,
):
    state = response_server
    state["body"] = {"detail": "Namespace not found"}
    client = PinnedRegistryHTTP(state["origin"], ("127.0.0.1",), 1)
    try:
        with pytest.raises(FederationAuthorityError) as refused:
            await client.get_json(
                "/v1/namespaces/example.com",
                not_found_reason="sender_identity_not_found",
            )
        assert refused.value.reason == "sender_identity_not_found"
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
@pytest.mark.parametrize("stage", ["missing", "first", "later", "empty", "revoked"])
async def test_revocation_scan_requires_a_complete_success_not_404(
    response_server, cached, stage, caplog
):
    state = response_server
    domain = f"revocations-{uuid4().hex}.example"
    team_did_key = did_key_from_signing_key(bytes(32))
    state["status"] = 404
    state["body"] = {"detail": "Team not found"}
    if stage == "first":
        state["body"] = {"detail": "Not Found"}
        state["team"] = {
            "status": 200,
            "body": {
                "team_id": f"ops:{domain}",
                "domain": domain,
                "name": "ops",
                "team_did_key": team_did_key,
                "created_at": "2026-11-17T00:00:00Z",
            },
        }
    elif stage == "later":
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
            "revocations": ([{"certificate_id": "withdrawn"}] if stage == "revoked" else []),
            "has_more": False,
        }
    redis = Redis.from_url(os.environ["REDIS_URL"]) if cached else None
    client = (
        CachedRegistryClient(state["origin"], redis) if cached else RegistryClient(state["origin"])
    )
    key = client._team_revocations_cache_key(domain, "ops") if cached else None
    legacy = key.replace(":v3:team_revocations:", ":v2:team_revocations:") if cached else None
    try:
        if cached:
            assert legacy != key
            # An old client could stamp an uncoded 404 as a fresh empty set.
            await client._write_cache_entry(legacy, value=set(), ttl_seconds=60, encode=sorted)
        if stage == "first":
            assert await client.get_team_public_key(domain, "ops") == team_did_key
        if stage in ("first", "later"):
            with pytest.raises(RegistryError) as refused:
                await client.get_team_revocations(domain, "ops")
            assert refused.value.status_code == 404
            if redis is not None:
                assert await redis.get(key) is None
        elif stage == "missing":
            # Cloud consumes these exact SDK answers: no dependency exception,
            # then no team key, which its verifier maps to 401 rather than 503.
            assert await client.get_team_revocations(domain, "ops") == set()
            assert await client.get_team_public_key(domain, "ops") is None
        else:
            assert await client.get_team_revocations(domain, "ops") == (
                {"withdrawn"} if stage == "revoked" else set()
            )
        assert len(state["requests"]) == (2 if stage in ("missing", "first", "later") else 1)
        missing_reads = [
            r for r in caplog.records if getattr(r, "event", "") == "awid_legacy_team_not_found"
        ]
        assert len(missing_reads) == (1 if stage == "missing" else 0)
    finally:
        await client.aclose()
        if redis is not None:
            await redis.delete(key, legacy)
            await redis.aclose()
