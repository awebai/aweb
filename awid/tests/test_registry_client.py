from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from httpx import MockTransport, Response

import awid.registry as registry_module
from awid.ratelimit import AWID_SERVICE_TOKEN_HEADER
from awid.did import generate_keypair
from awid.registry import (
    MAX_REGISTRY_ERROR_BYTES,
    MAX_REGISTRY_RESPONSE_BYTES,
    CachedRegistryClient,
    RegistryClient,
    RegistryError,
)



async def _unused_domain_registry_resolver(domain: str) -> str:
    raise AssertionError("field-forwarding fixtures are never called")

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
        self.expirations: dict[str, int | None] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.values[key] = value
        self.expirations[key] = ex

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.values.pop(key, None)
            self.expirations.pop(key, None)


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


@pytest.mark.asyncio
async def test_cached_registry_client_carries_the_service_token():
    """CachedRegistryClient declares its own __init__, so every RegistryClient
    field has to be named there explicitly; a field the override forgets is not
    a missing value but a TypeError at construction."""
    seen: dict[str, object] = {}

    async def handler(request):
        seen["token"] = request.headers.get(AWID_SERVICE_TOKEN_HEADER)
        return Response(200, json={"status": "ok"})

    token = "trusted-service-token-with-at-least-32-bytes"
    registry = CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=FakeRedis(),  # type: ignore[arg-type]
        transport=MockTransport(handler),
        service_token=token,
    )
    try:
        assert registry.service_token == token
        assert await registry.health() == {"status": "ok"}
    finally:
        await registry.aclose()

    assert seen["token"] == token


def test_cached_registry_client_names_every_registry_client_field():
    """The override's signature and the parent's field list have to be kept in
    step by hand. Compare them so the next added field fails here rather than
    at server startup."""
    parent_fields = {
        field.name for field in dataclasses.fields(RegistryClient) if field.init
    }
    override_parameters = set(
        inspect.signature(CachedRegistryClient.__init__).parameters
    ) - {"self", "redis_client"}

    assert parent_fields - override_parameters == set()


# One distinguishable value per RegistryClient field, so a value that arrives on
# the wrong field, or does not arrive at all, is visible. Keyed by field name and
# checked for completeness by the test below rather than by whoever edits it.
DISTINGUISHABLE_REGISTRY_CLIENT_FIELDS = {
    "registry_url": "http://named-registry.test",
    "timeout_seconds": 12.5,
    "transport": MockTransport(lambda _request: Response(500)),
    "base_url": "http://named-base.test",
    "domain_registry_resolver": _unused_domain_registry_resolver,
    "service_token": "distinguishable-service-token-of-sufficient-length",
}


@pytest.mark.asyncio
async def test_cached_registry_client_forwards_every_field_it_names():
    """Naming a field in the override is half the work; forwarding it to super()
    is the other half, and the parity test above cannot see that half. Worse, it
    steers against it: when a newly added field makes parity fail, adding the
    NAME is the minimum edit that turns it green, and the forwarding is a second
    edit nothing then checks."""
    fields = {
        field.name for field in dataclasses.fields(RegistryClient) if field.init
    }
    assert fields == set(DISTINGUISHABLE_REGISTRY_CLIENT_FIELDS), (
        "give every RegistryClient field a distinguishable value here, or this "
        "test silently stops covering the ones it does not name"
    )

    registry = CachedRegistryClient(
        redis_client=FakeRedis(),  # type: ignore[arg-type]
        **DISTINGUISHABLE_REGISTRY_CLIENT_FIELDS,
    )
    try:
        for name, value in DISTINGUISHABLE_REGISTRY_CLIENT_FIELDS.items():
            assert getattr(registry, name) == value, name
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_get_team_revocations_pages_until_complete():
    """aweb-abfo: the client must not read one page as the complete set."""
    pages = [
        {"revocations": [{"certificate_id": "c1", "revoked_at": "2026-01-01T00:00:00+00:00"}],
         "has_more": True, "next_cursor": "cur-1"},
        {"revocations": [{"certificate_id": "c2", "revoked_at": "2026-01-01T00:00:00+00:00"}],
         "has_more": True, "next_cursor": "cur-2"},
        {"revocations": [{"certificate_id": "c3", "revoked_at": "2026-01-02T00:00:00+00:00"}],
         "has_more": False, "next_cursor": None},
    ]
    requests: list[str] = []

    def handler(request):
        requests.append(str(request.url))
        cursor = request.url.params.get("cursor")
        if cursor == "cur-1":
            return Response(200, json=pages[1])
        if cursor == "cur-2":
            return Response(200, json=pages[2])
        return Response(200, json=pages[0])

    registry = RegistryClient(registry_url="http://registry.test", transport=MockTransport(handler))
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert revoked == {"c1", "c2", "c3"}
    assert len(requests) == 3


@pytest.mark.asyncio
async def test_get_team_revocations_legacy_server_short_page_is_complete():
    """An old server sends no has_more; a page shorter than its hard limit is
    the whole set and must not trigger extra requests."""
    def handler(request):
        return Response(200, json={"revocations": [
            {"certificate_id": "c1", "revoked_at": "2026-01-01T00:00:00+00:00"},
        ]})

    registry = RegistryClient(registry_url="http://registry.test", transport=MockTransport(handler))
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert revoked == {"c1"}


@pytest.mark.asyncio
async def test_get_team_revocations_legacy_server_full_page_pages_by_since():
    """An old server returning its full 1000-row page must be paged with
    `since` rather than read as complete."""
    first_page = {"revocations": [
        {"certificate_id": f"old-{i}", "revoked_at": "2026-01-01T00:00:00+00:00"}
        for i in range(1000)
    ]}
    second_page = {"revocations": [
        {"certificate_id": "new-1", "revoked_at": "2026-01-02T00:00:00+00:00"},
    ]}

    def handler(request):
        if request.url.params.get("since"):
            return Response(200, json=second_page)
        return Response(200, json=first_page)

    registry = RegistryClient(registry_url="http://registry.test", transport=MockTransport(handler))
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert len(revoked) == 1001
    assert "new-1" in revoked


@pytest.mark.asyncio
async def test_get_team_revocations_missing_team_is_empty():
    def handler(request):
        return Response(404, json={"detail": "Team not found"})

    registry = RegistryClient(registry_url="http://registry.test", transport=MockTransport(handler))
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert revoked == set()


def _revocations_cache_payload(*, fetched_at: int, certificate_ids: list[str]) -> str:
    from awid.registry import _TEAM_REVOCATIONS_CACHE_TTL_SECONDS

    return json.dumps(
        {
            "fetched_at": fetched_at,
            "fresh_until": fetched_at + _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
            "value": sorted(certificate_ids),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _failing_registry(redis: FakeRedis, *, detail: str = "registry down") -> CachedRegistryClient:
    return CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(lambda _request: Response(500, json={"detail": detail})),
    )


def test_revocation_outage_grace_stays_within_the_adopted_bound():
    """The registry-outage grace for revocations is a constant, not a knob
    (adopted, Juan 2026-08-17; trust-model.md 'Registry availability posture').
    Serving a last-known-good revocation set is bounded at 15 minutes of data
    age; past that the enforcement path must fail closed. Raising this is a
    trust-model change and belongs next to the rulings in trust-model.md."""
    from awid.registry import _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS

    assert _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS <= 15 * 60


@pytest.mark.asyncio
async def test_cached_revocations_fresh_entry_served_without_fetch_or_warning(
    monkeypatch, caplog
):
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list[str] = []

    def handler(request):
        requests.append(str(request.url))
        return Response(500, json={"detail": "must not be called"})

    registry = CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(handler),
    )
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _revocations_cache_payload(fetched_at=now - 10, certificate_ids=["c1"])
    )
    try:
        with caplog.at_level(logging.WARNING):
            revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert revoked == {"c1"}
    assert requests == []
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.asyncio
async def test_cached_revocations_refresh_failure_within_grace_serves_stale_loudly(
    monkeypatch, caplog
):
    """Registry-outage grace: past the stale-while-revalidate window but within
    15 minutes of data age, a failed refresh serves the last-known-good set and
    logs at WARNING with the team, the served data's age, and the error."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _revocations_cache_payload(fetched_at=now - 300, certificate_ids=["c1", "c2"])
    )
    try:
        with caplog.at_level(logging.WARNING):
            revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()
    assert revoked == {"c1", "c2"}
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "acme.com/ops" in message
    assert "aged 300s" in message
    assert "registry down" in message


@pytest.mark.asyncio
async def test_cached_revocations_stale_window_refresh_failure_is_loud(
    monkeypatch, caplog
):
    """Inside the stale-while-revalidate window the stale set is still served
    with a background refresh, but a failed refresh is no longer a swallowed
    debug line: it warns with team, age, and error."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _revocations_cache_payload(fetched_at=now - 90, certificate_ids=["c1"])
    )
    try:
        with caplog.at_level(logging.WARNING):
            revoked = await registry.get_team_revocations("acme.com", "ops")
            refresh_tasks = list(registry._refresh_tasks.values())
            assert refresh_tasks, "stale read should schedule a background refresh"
            await asyncio.gather(*refresh_tasks, return_exceptions=True)
    finally:
        await registry.aclose()
    assert revoked == {"c1"}
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "acme.com/ops" in message
    assert "aged 90s" in message
    assert "registry down" in message


@pytest.mark.asyncio
async def test_cached_revocations_refresh_failure_beyond_grace_fails_closed(monkeypatch):
    """Past 15 minutes of data age the last-known-good set must NOT be served:
    the fetch failure propagates so the enforcement path returns 503."""
    from awid.registry import _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS

    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _revocations_cache_payload(
            fetched_at=now - (_TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS + 1),
            certificate_ids=["c1"],
        )
    )
    try:
        with pytest.raises(RegistryError):
            await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_grace_retention_applies_only_to_revocation_entries():
    """The grace lengthens Redis retention for the revocations tier only; a
    non-revocation cached read keeps the shared ttl * stale-multiplier."""
    from awid.registry import (
        _STALE_MULTIPLIER,
        _TEAM_METADATA_CACHE_TTL_SECONDS,
        _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
        _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
    )

    def handler(request):
        if request.url.path.endswith("/revocations"):
            return Response(200, json={"revocations": [], "has_more": False})
        return Response(
            200,
            json={
                "team_id": "team-1",
                "domain": "acme.com",
                "name": "ops",
                "display_name": "Ops",
                "team_did_key": "did:key:z6MkTeam",
                "visibility": "private",
                "created_at": "2026-01-01T00:00:00Z",
            },
        )

    redis = FakeRedis()
    registry = CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(handler),
    )
    try:
        await registry.get_team_revocations("acme.com", "ops")
        await registry.get_team("acme.com", "ops")
    finally:
        await registry.aclose()

    revocations_key = registry._team_revocations_cache_key("acme.com", "ops")
    team_key = registry._team_metadata_cache_key("acme.com", "ops")
    assert redis.expirations[revocations_key] == (
        _TEAM_REVOCATIONS_CACHE_TTL_SECONDS + _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
    )
    assert redis.expirations[team_key] == (
        _TEAM_METADATA_CACHE_TTL_SECONDS * _STALE_MULTIPLIER
    )


# ---------------------------------------------------------------------------
# Incremental revocation refresh (aweb-abfs.6)
#
# The revocation list grows monotonically with no ceiling, so a refresh reads
# only the tail — entries at/after a stored high-water mark — and unions it into
# the cached set. Every test below is about the same invariant: the increment is
# an optimisation, and losing it, corrupting it or outrunning it must cost
# bandwidth, never correctness.
# ---------------------------------------------------------------------------

_MARK = "2026-01-02T00:00:00+00:00"
_MARK_DT = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _incremental_revocations_cache_payload(
    *,
    fetched_at: int,
    certificate_ids: list[str],
    high_water_mark,
    full_sync_at,
) -> str:
    """A cached revocation entry that also carries incremental bookkeeping.

    Deliberately separate from _revocations_cache_payload: that helper builds
    the entry a client with no incremental support writes, and the pre-existing
    tests keep exercising exactly that shape.
    """
    from awid.registry import (
        _REVOCATIONS_SYNC_FIELD,
        _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
    )

    return json.dumps(
        {
            "fetched_at": fetched_at,
            "fresh_until": fetched_at + _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
            "value": sorted(certificate_ids),
            _REVOCATIONS_SYNC_FIELD: {
                "high_water_mark": high_water_mark,
                "full_sync_at": full_sync_at,
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _stored_revocations_entry(redis: FakeRedis, registry: CachedRegistryClient) -> dict:
    return json.loads(redis.values[registry._team_revocations_cache_key("acme.com", "ops")])


def _stored_sync_state(redis: FakeRedis, registry: CachedRegistryClient) -> dict:
    from awid.registry import _REVOCATIONS_SYNC_FIELD

    return _stored_revocations_entry(redis, registry)[_REVOCATIONS_SYNC_FIELD]


def _cached_registry(redis: FakeRedis, handler) -> CachedRegistryClient:
    return CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(handler),
    )


def _revocation_page(entries, *, has_more: bool | None = False, next_cursor=None) -> Response:
    body: dict = {
        "revocations": [
            {"certificate_id": cert_id, "revoked_at": revoked_at}
            for cert_id, revoked_at in entries
        ]
    }
    if has_more is not None:
        body["has_more"] = has_more
        body["next_cursor"] = next_cursor
    return Response(200, json=body)


def _since_honouring_handler(all_entries, requests: list, *, paginated: bool = True):
    """A server that applies the route's own `revoked_at > since` filter."""

    def handler(request):
        requests.append(request.url)
        since = request.url.params.get("since")
        entries = all_entries
        if since:
            cutoff = datetime.fromisoformat(since)
            entries = [e for e in all_entries if datetime.fromisoformat(e[1]) > cutoff]
        return _revocation_page(entries, has_more=False if paginated else None)

    return handler


def test_incremental_refresh_bounds_are_pinned():
    """Two relationships, not two magic numbers.

    The overlap must be at least one refresh interval, because it is what stops
    a `revoked_at > since` filter from skipping entries that share the mark's
    timestamp or that commit out of timestamp order. The full-resync bound must
    not exceed the outage grace: the grace is already the longest window in
    which this tier may act on data that is not current, so undetected drift
    must not be able to outlive it.
    """
    from awid.registry import (
        _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
        _TEAM_REVOCATIONS_FULL_RESYNC_SECONDS,
        _TEAM_REVOCATIONS_INCREMENTAL_OVERLAP_SECONDS,
        _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
    )

    assert (
        _TEAM_REVOCATIONS_INCREMENTAL_OVERLAP_SECONDS
        >= _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
    )
    assert (
        _TEAM_REVOCATIONS_FULL_RESYNC_SECONDS
        <= _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
    )


@pytest.mark.asyncio
async def test_incremental_revocation_refresh_scopes_by_since_and_unions(monkeypatch):
    """The refresh reads the tail, not the list, and adds it to what it had."""
    from awid.registry import _TEAM_REVOCATIONS_INCREMENTAL_OVERLAP_SECONDS

    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []

    def handler(request):
        requests.append(request.url)
        return _revocation_page([("c3", "2026-01-03T00:00:30+00:00")])

    registry = _cached_registry(redis, handler)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            # Older than the stale-while-revalidate window, so the refresh is
            # the synchronous one and its result is what the caller sees.
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2", "c3"}
    assert len(requests) == 1
    since = requests[0].params.get("since")
    assert since is not None
    assert datetime.fromisoformat(since) == _MARK_DT - timedelta(
        seconds=_TEAM_REVOCATIONS_INCREMENTAL_OVERLAP_SECONDS
    )

    stored = _stored_revocations_entry(redis, registry)
    assert set(stored["value"]) == {"c1", "c2", "c3"}
    # The union really is current as of now, so restamping the age is honest.
    assert stored["fetched_at"] == now
    sync = _stored_sync_state(redis, registry)
    assert datetime.fromisoformat(sync["high_water_mark"]) == datetime(
        2026, 1, 3, 0, 0, 30, tzinfo=timezone.utc
    )
    # An incremental refresh never restamps the full-sync clock.
    assert sync["full_sync_at"] == now - 60


@pytest.mark.asyncio
async def test_incremental_refresh_does_not_skip_entries_sharing_the_mark(monkeypatch):
    """A mass revocation stamps many rows with one revoked_at, and the route
    filters `revoked_at > since`. Asking at the mark would drop every sibling
    of the newest row we already saw — and the composite (revoked_at, id)
    cursor that would express "at the mark, after this row" cannot be built by
    a client, because the route does not return `id`. So the mark is rewound
    and the union absorbs the re-read."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []
    all_entries = [
        ("c1", "2026-01-01T00:00:00+00:00"),
        ("cA", _MARK),
        ("cB", _MARK),  # same revoked_at as the mark; committed after our read
        ("cC", "2026-01-02T00:00:01+00:00"),
    ]
    registry = _cached_registry(redis, _since_honouring_handler(all_entries, requests))
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "cA"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "cA", "cB", "cC"}
    since = requests[0].params.get("since")
    assert datetime.fromisoformat(since) < _MARK_DT, (
        "since must be strictly before the mark or siblings sharing it are skipped"
    )
    sync = _stored_sync_state(redis, registry)
    assert datetime.fromisoformat(sync["high_water_mark"]) == datetime(
        2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "high_water_mark, full_sync_at",
    [
        (None, 1_000_000 - 60),  # never stored
        ("not-a-timestamp", 1_000_000 - 60),  # corrupt
        (_MARK, None),  # full-sync clock lost
        (_MARK, "recently"),  # full-sync clock corrupt
    ],
)
async def test_lost_or_corrupt_mark_refetches_fully_and_never_shrinks(
    monkeypatch, high_water_mark, full_sync_at
):
    """A mark the client cannot trust costs one full read, not a shrunken set.

    The server here answers a `since`-scoped request with only the tail, so if
    the client had used the unusable mark the result would be missing c1/c2 —
    the failure this test exists to forbid.
    """
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []

    def handler(request):
        requests.append(request.url)
        if request.url.params.get("since"):
            return _revocation_page([("c9", "2026-01-04T00:00:00+00:00")])
        return _revocation_page(
            [
                ("c1", "2026-01-01T00:00:00+00:00"),
                ("c2", _MARK),
                ("c9", "2026-01-04T00:00:00+00:00"),
            ]
        )

    registry = _cached_registry(redis, handler)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=high_water_mark,
            full_sync_at=full_sync_at,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2", "c9"}
    assert requests[0].params.get("since") is None
    sync = _stored_sync_state(redis, registry)
    assert sync["full_sync_at"] == now
    assert datetime.fromisoformat(sync["high_water_mark"]) == datetime(
        2026, 1, 4, tzinfo=timezone.utc
    )


@pytest.mark.asyncio
async def test_entry_without_a_usable_timestamp_forces_a_full_resync(monkeypatch):
    """An entry we cannot place on the timeline cannot advance a mark, and a
    mark that did not advance would re-read that tail forever. Resync instead,
    and drop the mark so the next read is full too."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []

    def handler(request):
        requests.append(request.url)
        if request.url.params.get("since"):
            return Response(
                200,
                json={
                    "revocations": [{"certificate_id": "c3", "revoked_at": None}],
                    "has_more": False,
                },
            )
        return _revocation_page(
            [("c1", "2026-01-01T00:00:00+00:00"), ("c2", _MARK)]
        )

    registry = _cached_registry(redis, handler)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2"}
    assert requests[0].params.get("since") is not None
    assert requests[1].params.get("since") is None
    assert _stored_sync_state(redis, registry)["full_sync_at"] == now


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
async def test_periodic_full_resync_fires_at_its_bound(monkeypatch, expired: bool):
    """Incremental until the bound, full at it — so drift cannot accumulate
    silently no matter how well the increment appears to be working."""
    from awid.registry import _TEAM_REVOCATIONS_FULL_RESYNC_SECONDS

    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []
    age = _TEAM_REVOCATIONS_FULL_RESYNC_SECONDS + (0 if expired else -1)
    all_entries = [("c1", "2026-01-01T00:00:00+00:00"), ("c2", _MARK)]
    registry = _cached_registry(redis, _since_honouring_handler(all_entries, requests))
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - age,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2"}
    sync = _stored_sync_state(redis, registry)
    if expired:
        assert requests[0].params.get("since") is None
        assert sync["full_sync_at"] == now
    else:
        assert requests[0].params.get("since") is not None
        assert sync["full_sync_at"] == now - age


@pytest.mark.asyncio
async def test_failed_incremental_refresh_serves_stale_at_its_original_age(
    monkeypatch, caplog
):
    """The grace is decided on how old the data really is. A failed incremental
    refresh must not touch the entry, so the age keeps counting from the last
    genuinely-current fetch — 300s here, not 0s."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    cache_key = registry._team_revocations_cache_key("acme.com", "ops")
    payload = _incremental_revocations_cache_payload(
        fetched_at=now - 300,
        certificate_ids=["c1", "c2"],
        high_water_mark=_MARK,
        full_sync_at=now - 60,
    )
    redis.values[cache_key] = payload
    try:
        with caplog.at_level(logging.WARNING):
            revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2"}
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "aged 300s" in warnings[0].getMessage()
    assert redis.values[cache_key] == payload


@pytest.mark.asyncio
async def test_partly_read_incremental_refresh_does_not_look_current(
    monkeypatch, caplog
):
    """A page-through that dies half way has read a prefix of the tail, which is
    neither a complete increment nor grounds for a new mark. It must leave the
    entry — and therefore its age — exactly as it was."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []

    def handler(request):
        requests.append(request.url)
        if request.url.params.get("cursor"):
            return Response(500, json={"detail": "registry down"})
        return _revocation_page(
            [("c3", "2026-01-03T00:00:00+00:00")], has_more=True, next_cursor="cur-1"
        )

    registry = _cached_registry(redis, handler)
    cache_key = registry._team_revocations_cache_key("acme.com", "ops")
    payload = _incremental_revocations_cache_payload(
        fetched_at=now - 300,
        certificate_ids=["c1", "c2"],
        high_water_mark=_MARK,
        full_sync_at=now - 60,
    )
    redis.values[cache_key] = payload
    try:
        with caplog.at_level(logging.WARNING):
            revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert len(requests) == 2
    # c3 was read but is not adopted: a half-read tail proves nothing.
    assert revoked == {"c1", "c2"}
    assert redis.values[cache_key] == payload
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "aged 300s" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_failed_incremental_refresh_beyond_grace_still_fails_closed(monkeypatch):
    """Incremental refresh does not buy extra staleness: past 15 minutes of data
    age the failure propagates, mark or no mark."""
    from awid.registry import _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS

    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - (_TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS + 1),
            certificate_ids=["c1"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        with pytest.raises(RegistryError):
            await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_incremental_refresh_of_a_deleted_team_resyncs_fully(monkeypatch):
    """Deleting a team is the one path that removes revocation rows, and it
    leaves the route answering 404. Unioning onto the cached set would pin a
    dead team's revocations forever, so a 404 mid-increment resyncs."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []

    def handler(request):
        requests.append(request.url)
        return Response(404, json={"detail": "Team not found"})

    registry = _cached_registry(redis, handler)
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == set()
    assert requests[0].params.get("since") is not None
    assert requests[1].params.get("since") is None
    sync = _stored_sync_state(redis, registry)
    assert sync["high_water_mark"] is None
    assert sync["full_sync_at"] == now


@pytest.mark.asyncio
async def test_incremental_refresh_against_a_legacy_server(monkeypatch):
    """`since` predates pagination, so a server that sends no has_more still
    supports an incremental read; the union and the mark work unchanged."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []
    all_entries = [
        ("c1", "2026-01-01T00:00:00+00:00"),
        ("c2", _MARK),
        ("c3", "2026-01-03T00:00:00+00:00"),
    ]
    registry = _cached_registry(
        redis, _since_honouring_handler(all_entries, requests, paginated=False)
    )
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            fetched_at=now - 300,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2", "c3"}
    assert len(requests) == 1
    assert requests[0].params.get("since") is not None
    sync = _stored_sync_state(redis, registry)
    assert datetime.fromisoformat(sync["high_water_mark"]) == datetime(
        2026, 1, 3, tzinfo=timezone.utc
    )


@pytest.mark.asyncio
async def test_first_full_read_stores_the_mark_the_next_read_uses(monkeypatch):
    """End to end on a live cache: read once with nothing cached, then again
    after the TTL. Only the first read is a full page-through."""
    clock = {"now": 1_000_000}
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock["now"])
    redis = FakeRedis()
    requests: list = []
    all_entries = [("c1", "2026-01-01T00:00:00+00:00"), ("c2", _MARK)]
    handler = _since_honouring_handler(all_entries, requests)
    registry = _cached_registry(redis, handler)
    try:
        assert await registry.get_team_revocations("acme.com", "ops") == {"c1", "c2"}
        assert requests[0].params.get("since") is None
        first_sync = _stored_sync_state(redis, registry)
        assert datetime.fromisoformat(first_sync["high_water_mark"]) == _MARK_DT
        assert first_sync["full_sync_at"] == 1_000_000

        # Past the stale window so the refresh is synchronous, and a new
        # revocation has landed in the meantime.
        clock["now"] = 1_000_300
        all_entries.append(("c3", "2026-01-02T00:00:00.500000+00:00"))
        assert await registry.get_team_revocations("acme.com", "ops") == {
            "c1",
            "c2",
            "c3",
        }
    finally:
        await registry.aclose()

    assert requests[1].params.get("since") is not None
    second_sync = _stored_sync_state(redis, registry)
    assert datetime.fromisoformat(second_sync["high_water_mark"]) == datetime(
        2026, 1, 2, 0, 0, 0, 500000, tzinfo=timezone.utc
    )
    assert second_sync["full_sync_at"] == 1_000_000


@pytest.mark.asyncio
async def test_background_revalidation_refreshes_incrementally(monkeypatch):
    """The stale-while-revalidate path shares the one refresh routine, so it
    increments and advances the mark just like the synchronous path."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    requests: list = []
    all_entries = [
        ("c1", "2026-01-01T00:00:00+00:00"),
        ("c2", _MARK),
        ("c3", "2026-01-03T00:00:00+00:00"),
    ]
    registry = _cached_registry(redis, _since_honouring_handler(all_entries, requests))
    redis.values[registry._team_revocations_cache_key("acme.com", "ops")] = (
        _incremental_revocations_cache_payload(
            # Inside the stale window: served immediately, refreshed behind.
            fetched_at=now - 90,
            certificate_ids=["c1", "c2"],
            high_water_mark=_MARK,
            full_sync_at=now - 60,
        )
    )
    try:
        revoked = await registry.get_team_revocations("acme.com", "ops")
        refresh_tasks = list(registry._refresh_tasks.values())
        assert refresh_tasks
        await asyncio.gather(*refresh_tasks)
    finally:
        await registry.aclose()

    assert revoked == {"c1", "c2"}
    assert requests[0].params.get("since") is not None
    stored = _stored_revocations_entry(redis, registry)
    assert set(stored["value"]) == {"c1", "c2", "c3"}
    assert _stored_sync_state(redis, registry)["full_sync_at"] == now - 60


def _certificates_cache_payload(*, fetched_at: int, certificate_ids: list[str]) -> str:
    from awid.registry import _TEAM_CERTIFICATES_CACHE_TTL_SECONDS

    return json.dumps(
        {
            "fetched_at": fetched_at,
            "fresh_until": fetched_at + _TEAM_CERTIFICATES_CACHE_TTL_SECONDS,
            "value": [
                {
                    "certificate_id": certificate_id,
                    "member_did_key": "did:key:z6MkMember",
                    "member_did_aw": None,
                    "member_address": None,
                    "alias": "member",
                    "identity_scope": "local",
                    "issued_at": "2026-01-01T00:00:00Z",
                    "revoked_at": None,
                }
                for certificate_id in certificate_ids
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _team_cache_payload(*, fetched_at: int, ttl_seconds: int) -> str:
    return json.dumps(
        {
            "fetched_at": fetched_at,
            "fresh_until": fetched_at + ttl_seconds,
            "value": {
                "team_id": "team-1",
                "domain": "acme.com",
                "name": "ops",
                "display_name": "Ops",
                "team_did_key": "did:key:z6MkTeam",
                "visibility": "private",
                "created_at": "2026-01-01T00:00:00Z",
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    )


@pytest.mark.asyncio
async def test_cached_certificates_stale_refresh_failure_is_loud(monkeypatch, caplog):
    """The team-certificate tier gates every authenticated request once the
    staged existence check (AWEB_REQUIRE_REGISTERED_CERTIFICATES) is enabled, so
    a failed background refresh warns with the team, the served data's age and
    the error — the sibling of the revocation-refresh warning, not a swallowed
    debug line."""
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    cache_key = registry._team_certificates_cache_key("acme.com", "ops", active_only=True)
    redis.values[cache_key] = _certificates_cache_payload(
        fetched_at=now - 900, certificate_ids=["cert-1"]
    )
    try:
        with caplog.at_level(logging.DEBUG):
            certificates = await registry.list_team_certificates("acme.com", "ops")
            refresh_tasks = list(registry._refresh_tasks.values())
            assert refresh_tasks, "stale read should schedule a background refresh"
            await asyncio.gather(*refresh_tasks, return_exceptions=True)
    finally:
        await registry.aclose()

    assert [c.certificate_id for c in certificates] == ["cert-1"]
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "acme.com/ops" in message
    assert "aged 900s" in message
    assert "registry down" in message
    assert "AWID cache refresh failed" not in caplog.text


@pytest.mark.asyncio
async def test_cached_read_without_failure_hook_stays_silent(monkeypatch, caplog):
    """Tiers that pass no failure hook keep the pre-existing silent behavior: a
    failed background refresh logs at debug and never at warning."""
    from awid.registry import _TEAM_METADATA_CACHE_TTL_SECONDS

    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    redis = FakeRedis()
    registry = _failing_registry(redis)
    cache_key = registry._team_metadata_cache_key("acme.com", "ops")
    redis.values[cache_key] = _team_cache_payload(
        fetched_at=now - (_TEAM_METADATA_CACHE_TTL_SECONDS + 60),
        ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
    )
    try:
        with caplog.at_level(logging.DEBUG):
            team = await registry.get_team("acme.com", "ops")
            refresh_tasks = list(registry._refresh_tasks.values())
            assert refresh_tasks, "stale read should schedule a background refresh"
            await asyncio.gather(*refresh_tasks, return_exceptions=True)
    finally:
        await registry.aclose()

    assert team is not None and team.team_id == "team-1"
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    debugs = [
        r
        for r in caplog.records
        if r.levelno == logging.DEBUG and "AWID cache refresh failed" in r.getMessage()
    ]
    assert len(debugs) == 1


@pytest.mark.asyncio
async def test_certificate_cache_retention_is_unchanged_by_refresh_logging():
    """The certificates tier gets louder logging only: no outage grace and no
    widened retention. Its Redis expiry stays ttl * stale-multiplier."""
    from awid.registry import _STALE_MULTIPLIER, _TEAM_CERTIFICATES_CACHE_TTL_SECONDS

    redis = FakeRedis()
    registry = CachedRegistryClient(
        registry_url="http://registry.test",
        redis_client=redis,  # type: ignore[arg-type]
        transport=MockTransport(lambda _request: Response(200, json={"certificates": []})),
    )
    try:
        assert await registry.list_team_certificates("acme.com", "ops") == []
    finally:
        await registry.aclose()

    cache_key = registry._team_certificates_cache_key("acme.com", "ops", active_only=True)
    assert redis.expirations[cache_key] == (
        _TEAM_CERTIFICATES_CACHE_TTL_SECONDS * _STALE_MULTIPLIER
    )


def test_revocation_cache_ttl_stays_within_the_ruled_bound():
    """aweb-abfp: revocations are load-bearing for membership enforcement on
    every authenticated request (aweb-abfn), and this TTL is the client half of
    how fast a revocation takes effect. The hard worst case is twice this value
    (the stale-while-revalidate window), and the Redis-backed cache survives
    process restarts, so the constant is the only bound. 60 seconds matches the
    federation authority reuse ceiling. Raising it is a trust-model change and
    belongs next to the rulings in trust-model.md, not in a refactor."""
    from awid.registry import _STALE_MULTIPLIER, _TEAM_REVOCATIONS_CACHE_TTL_SECONDS

    assert _TEAM_REVOCATIONS_CACHE_TTL_SECONDS <= 60
    assert _TEAM_REVOCATIONS_CACHE_TTL_SECONDS * _STALE_MULTIPLIER <= 120
