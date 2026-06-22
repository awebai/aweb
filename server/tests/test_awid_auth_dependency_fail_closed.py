from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from aweb import identity_auth_deps
from aweb.team_auth_deps import _get_revoked_certificates, _resolve_team_key


class _FailingTeamRegistry:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def get_team_public_key(self, domain: str, team_name: str) -> str:
        raise self.exc

    async def get_team_revocations(self, domain: str, team_name: str) -> set[str]:
        raise self.exc


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
