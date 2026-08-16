from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from awid.registry import CachedRegistryClient, KeyResolution, RegistryError
from aweb import identity_auth_deps
from aweb.team_auth_deps import _get_revoked_certificates, _resolve_team_key


class _FailingTeamRegistry:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def get_team_public_key(self, domain: str, team_name: str) -> str:
        raise self.exc

    async def get_team_revocations(self, domain: str, team_name: str) -> set[str]:
        raise self.exc


class _CacheRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def set(self, key: str, value: str, *, ex: int | None = None):
        self.values[key] = value
        return True

    async def delete(self, *keys: str):
        for key in keys:
            self.values.pop(key, None)
        return len(keys)


class _RateLimitedFreshIdentityRegistry:
    async def resolve_key(self, did_aw: str):
        return KeyResolution(did_aw=did_aw, current_did_key="did:key:old")

    async def resolve_key_fresh(self, did_aw: str):
        raise RegistryError("rate limit exceeded", status_code=429)

    async def list_did_addresses(self, did_aw: str):
        raise AssertionError("a mismatching identity must fail before address resolution")


class _FailingIdentityRegistry:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def resolve_key(self, did_aw: str):
        raise self.exc


def _request_with_registry(registry_client):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(awid_registry_client=registry_client)),
        state=SimpleNamespace(),
        headers={
            "Authorization": "DIDKey did:key:alice sig",
            "X-AWEB-Timestamp": "2026-06-22T00:00:00Z",
            "X-AWEB-DID-AW": "did:aw:alice",
        },
    )


@pytest.mark.asyncio
async def test_team_key_resolution_unexpected_error_fails_closed():
    request = _request_with_registry(_FailingTeamRegistry(RuntimeError("boom")))

    with pytest.raises(HTTPException) as raised:
        await _resolve_team_key(request, "backend:acme.com")

    assert raised.value.status_code == 500
    assert "Unexpected AWID team key resolution dependency error (RuntimeError): boom" == raised.value.detail


@pytest.mark.asyncio
async def test_team_revocation_check_error_never_returns_empty_set():
    request = _request_with_registry(_FailingTeamRegistry(RuntimeError("revocation lookup exploded")))

    with pytest.raises(HTTPException) as raised:
        await _get_revoked_certificates(request, "backend:acme.com")

    assert raised.value.status_code == 500
    assert "Unexpected AWID team revocation check dependency error (RuntimeError)" in raised.value.detail


@pytest.mark.asyncio
async def test_team_revocation_check_upstream_failure_is_retryable_503_and_still_denies():
    request = _request_with_registry(_FailingTeamRegistry(httpx.ConnectError("connect refused")))

    with pytest.raises(HTTPException) as raised:
        await _get_revoked_certificates(request, "backend:acme.com")

    assert raised.value.status_code == 503
    assert "AWID team revocation check upstream unavailable (ConnectError): connect refused" == raised.value.detail


@pytest.mark.asyncio
async def test_identity_auth_warmed_key_and_address_cache_makes_zero_upstream_calls(monkeypatch):
    did_aw = "did:aw:alice"
    did_key = "did:key:alice"
    request_counts = {"key": 0, "addresses": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/did/{did_aw}/key":
            request_counts["key"] += 1
            return httpx.Response(
                200,
                json={"did_aw": did_aw, "current_did_key": did_key, "log_head": None},
            )
        if request.url.path == f"/v1/did/{did_aw}/addresses":
            request_counts["addresses"] += 1
            return httpx.Response(200, json={"addresses": []})
        raise AssertionError(f"unexpected request: {request.url}")

    registry = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=_CacheRedis(),
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(identity_auth_deps, "parse_didkey_auth", lambda header: (did_key, "sig"))
    monkeypatch.setattr(identity_auth_deps, "require_timestamp", lambda request: "2026-06-22T00:00:00Z")
    monkeypatch.setattr(identity_auth_deps, "enforce_timestamp_skew", lambda timestamp: None)
    monkeypatch.setattr(identity_auth_deps, "verify_did_key_signature", lambda **kwargs: None)
    request = _request_with_registry(registry)

    try:
        first = await identity_auth_deps.resolve_identity_auth(request)
        after_first = dict(request_counts)
        second = await identity_auth_deps.resolve_identity_auth(request)
    finally:
        await registry.aclose()

    assert first == second == identity_auth_deps.IdentityAuth(
        did_key=did_key, did_aw=did_aw, address=None
    )
    assert after_first == {"key": 1, "addresses": 1}
    assert request_counts == after_first


@pytest.mark.asyncio
async def test_identity_did_aw_stale_cache_never_accepts_a_different_key_on_429(monkeypatch):
    monkeypatch.setattr(identity_auth_deps, "parse_didkey_auth", lambda header: ("did:key:new", "sig"))
    monkeypatch.setattr(identity_auth_deps, "require_timestamp", lambda request: "2026-06-22T00:00:00Z")
    monkeypatch.setattr(identity_auth_deps, "enforce_timestamp_skew", lambda timestamp: None)
    monkeypatch.setattr(identity_auth_deps, "verify_did_key_signature", lambda **kwargs: None)
    request = _request_with_registry(_RateLimitedFreshIdentityRegistry())

    with pytest.raises(HTTPException) as raised:
        await identity_auth_deps.resolve_identity_auth(request)

    assert raised.value.status_code == 401
    assert raised.value.detail == "did:aw does not match Authorization did:key"


@pytest.mark.asyncio
async def test_identity_did_aw_resolution_error_fails_closed(monkeypatch):
    monkeypatch.setattr(identity_auth_deps, "parse_didkey_auth", lambda header: ("did:key:alice", "sig"))
    monkeypatch.setattr(identity_auth_deps, "require_timestamp", lambda request: "2026-06-22T00:00:00Z")
    monkeypatch.setattr(identity_auth_deps, "enforce_timestamp_skew", lambda timestamp: None)
    monkeypatch.setattr(identity_auth_deps, "verify_did_key_signature", lambda **kwargs: None)
    request = _request_with_registry(_FailingIdentityRegistry(RuntimeError("resolver bug")))

    with pytest.raises(HTTPException) as raised:
        await identity_auth_deps.resolve_identity_auth(request)

    assert raised.value.status_code == 500
    assert "Unexpected AWID did:aw resolution dependency error (RuntimeError): resolver bug" == raised.value.detail


@pytest.mark.asyncio
async def test_identity_did_aw_resolution_upstream_failure_is_retryable_503_and_still_denies(monkeypatch):
    monkeypatch.setattr(identity_auth_deps, "parse_didkey_auth", lambda header: ("did:key:alice", "sig"))
    monkeypatch.setattr(identity_auth_deps, "require_timestamp", lambda request: "2026-06-22T00:00:00Z")
    monkeypatch.setattr(identity_auth_deps, "enforce_timestamp_skew", lambda timestamp: None)
    monkeypatch.setattr(identity_auth_deps, "verify_did_key_signature", lambda **kwargs: None)
    request = _request_with_registry(_FailingIdentityRegistry(httpx.ReadTimeout("read timed out")))

    with pytest.raises(HTTPException) as raised:
        await identity_auth_deps.resolve_identity_auth(request)

    assert raised.value.status_code == 503
    assert "AWID did:aw resolution upstream unavailable (ReadTimeout): read timed out" == raised.value.detail
