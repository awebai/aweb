from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from httpx import MockTransport, Response

import awid.registry as registry_module
from awid.did import generate_keypair
from awid.registry import (
    MAX_REGISTRY_ERROR_BYTES,
    MAX_REGISTRY_RESPONSE_BYTES,
    CachedRegistryClient,
    RegistryClient,
    RegistryError,
)


def test_registry_http_bound_values_are_pinned():
    assert MAX_REGISTRY_RESPONSE_BYTES == 10 * 1024 * 1024
    assert MAX_REGISTRY_ERROR_BYTES == 64 * 1024


class UnreadEncodedStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.iterations = 0
        self.closed = 0

    async def __aiter__(self):
        self.iterations += 1
        raise AssertionError("encoded response was read before rejection")
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        self.closed += 1


@pytest.mark.asyncio
async def test_registry_client_rejects_encoding_before_stream_iteration():
    stream = UnreadEncodedStream()
    accept_encoding: list[str] = []

    def handler(request):
        accept_encoding.append(request.headers.get("accept-encoding", ""))
        return Response(200, stream=stream, headers={"Content-Encoding": "gzip"})

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        with pytest.raises(ValueError, match="(?i)content.encoding"):
            await registry.health()
    finally:
        await registry.aclose()
    assert accept_encoding == ["identity"]
    assert stream.iterations == 0
    assert stream.closed == 1


@pytest.mark.asyncio
async def test_registry_client_does_not_echo_control_bearing_content_encoding():
    stream = UnreadEncodedStream()
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(
            lambda _request: Response(
                200,
                stream=stream,
                headers={"Content-Encoding": "\x1b[31m"},
            )
        ),
    )
    try:
        with pytest.raises(ValueError) as caught:
            await registry.health()
    finally:
        await registry.aclose()
    assert str(caught.value) == "unsupported HTTP Content-Encoding"
    assert stream.iterations == 0
    assert stream.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("content_encoding", ["identity", " Identity "])
async def test_registry_client_accepts_identity_encoded_response(content_encoding: str):
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(
            lambda _request: Response(
                200,
                json={},
                headers={"Content-Encoding": content_encoding},
            )
        ),
    )
    try:
        assert await registry.health() == {}
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("header_name", ["accept-encoding", "aCcEpT-EnCoDiNg"])
async def test_registry_client_forces_identity_encoding_over_caller_header(
    header_name: str,
):
    seen: list[str] = []

    def handler(request):
        seen.append(request.headers["accept-encoding"])
        return Response(200, json={})

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        assert await registry._request_json(
            "GET",
            "/health",
            headers={header_name: "gzip"},
        ) == {}
    finally:
        await registry.aclose()
    assert seen == ["identity"]


@pytest.mark.asyncio
async def test_registry_client_redirect_target_receives_no_request():
    target_hits = 0

    def handler(request):
        nonlocal target_hits
        if request.url.host == "target.test":
            target_hits += 1
            return Response(200, json={})
        return Response(307, headers={"Location": "http://target.test/final"})

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        with pytest.raises(Exception):
            await registry.health()
    finally:
        await registry.aclose()
    assert target_hits == 0


class SlowResponseStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        while True:
            await asyncio.sleep(0.02)
            yield b" "


class ClosingErrorStream(httpx.AsyncByteStream):
    def __init__(self, closed: list[bool]) -> None:
        self.closed = closed

    async def __aiter__(self):
        yield b"{"
        raise httpx.ReadError("malicious response failed mid-stream")

    async def aclose(self) -> None:
        self.closed.append(True)


@pytest.mark.asyncio
async def test_registry_client_closes_every_repeated_failed_response():
    closed: list[bool] = []
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(
            lambda _request: Response(200, stream=ClosingErrorStream(closed))
        ),
    )
    try:
        for _attempt in range(16):
            with pytest.raises(httpx.ReadError):
                await registry.health()
    finally:
        await registry.aclose()
    assert len(closed) == 16


@pytest.mark.asyncio
async def test_registry_client_enforces_overall_deadline_on_slow_body():
    registry = RegistryClient(
        registry_url="http://registry.test",
        timeout_seconds=0.01,
        transport=MockTransport(lambda _request: Response(200, stream=SlowResponseStream())),
    )
    try:
        with pytest.raises(TimeoutError):
            await registry.health()
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_registry_client_explicitly_disables_redirects(monkeypatch):
    real_client = httpx.AsyncClient
    configured: list[bool] = []

    def client_factory(**kwargs):
        configured.append(kwargs.get("follow_redirects", True))
        kwargs.setdefault("follow_redirects", True)
        return real_client(**kwargs)

    monkeypatch.setattr(registry_module.httpx, "AsyncClient", client_factory)
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(lambda _request: Response(200, json={})),
    )
    try:
        await registry.health()
    finally:
        await registry.aclose()
    assert configured == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extra_bytes", "should_succeed"),
    [(0, True), (1, False)],
)
async def test_registry_client_enforces_response_limit(extra_bytes: int, should_succeed: bool):
    content = b"{}" + b" " * (MAX_REGISTRY_RESPONSE_BYTES - 2 + extra_bytes)
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(lambda _request: Response(200, content=content)),
    )
    try:
        if should_succeed:
            assert await registry.health() == {}
        else:
            with pytest.raises(ValueError, match="maximum|size|large|limit"):
                await registry.health()
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("suffix", "should_succeed"),
    [(b" \r\n\t", True), (b"\n{}", False)],
)
async def test_registry_client_requires_one_json_document(
    suffix: bytes,
    should_succeed: bool,
):
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(lambda _request: Response(200, content=b"{}" + suffix)),
    )
    try:
        if should_succeed:
            assert await registry.health() == {}
        else:
            with pytest.raises(json.JSONDecodeError):
                await registry.health()
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body_size", "should_succeed"),
    [(64 * 1024, True), (64 * 1024 + 1, False)],
)
async def test_registry_client_enforces_error_limit(body_size: int, should_succeed: bool):
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(lambda _request: Response(500, content=b"x" * body_size)),
    )
    try:
        if should_succeed:
            with pytest.raises(RegistryError) as caught:
                await registry.health()
            assert caught.value.detail == "x" * (64 * 1024)
        else:
            with pytest.raises(ValueError, match="maximum|size|large|limit"):
                await registry.health()
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_registry_client_sanitizes_error_controls():
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(
            lambda _request: Response(500, content=b"bad\x1b[31m\nnext\x00line")
        ),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await registry.health()
    finally:
        await registry.aclose()
    assert "\x1b" not in caught.value.detail
    assert "\n" not in caught.value.detail
    assert "\x00" not in caught.value.detail
    assert caught.value.detail == "bad [31m next line"


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
async def test_registry_client_publish_encryption_key_uses_awid_endpoint():
    assertion = {
        "operation": "publish_encryption_key",
        "version": "aweb-e2ee-key-v1",
        "identity_did": "did:key:z6MkIdentity",
        "custody": "hosted_custodial",
        "encryption_key_id": "sha256:key",
        "encryption_public_key": "public",
        "algorithm": "x25519",
        "created_at": "2026-05-27T00:00:00Z",
        "not_before": "2026-05-27T00:00:00Z",
        "expires_at": "2026-08-25T00:00:00Z",
        "signature": "signature",
    }
    seen: dict[str, object] = {}

    async def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["payload"] = json.loads(request.content.decode("utf-8"))
        return Response(200, json=assertion)

    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        result = await registry.publish_encryption_key("did:aw:abc", assertion)
    finally:
        await registry.aclose()

    assert result == assertion
    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/did/did:aw:abc/encryption-key"
    assert seen["payload"] == assertion


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
