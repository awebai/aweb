"""Staged existence-required certificate verification (hosted anchoring).

An unregistered certificate is unrevocable: the registry's revocation set
can never name it, so a certificate that verifies cryptographically would
verify forever. With AWEB_REQUIRE_REGISTERED_CERTIFICATES on (default OFF
— the activation is gated on the anchoring backfill's failure enumeration
being empty or individually remediated), a presented or recorded team
certificate must additionally EXIST at the AWID registry:

- presented-certificate path (verify_request_certificate: HTTP team routes,
  messaging cert branch, /v1/connect, MCP cert branch) → 403 with a verdict
  distinct from both signature failure (401) and revocation;
- identity-only paths (_enforce_current_membership: HTTP and MCP) → team
  context stripped, same remedy as revocation there;
- registry unavailable → same fail-closed 503 posture as the revocation
  check, honoring the cached client's internal staleness/grace semantics.

When OFF the behavior is byte-identical to today and zero existence reads
are made.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from awid.did import did_from_public_key
from awid.registry import RegistryError
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import _enforce_current_membership
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.team_auth_deps import verify_request_certificate
from aweb.team_auth_envelope import compact_team_auth_payload

TEAM_ID = "backend:acme.com"

FLAG = "AWEB_REQUIRE_REGISTERED_CERTIFICATES"


class _FakeRegistry:
    """Local fake of the cached AWID registry client's read surface."""

    def __init__(
        self,
        *,
        team_did_key: str = "did:key:zTeam",
        revoked: set[str] | None = None,
        certificate_ids: list[str] | None = None,
        revocations_error: Exception | None = None,
        list_error: Exception | None = None,
    ) -> None:
        self.team_did_key = team_did_key
        self.revoked = revoked or set()
        self.certificate_ids = certificate_ids or []
        self.revocations_error = revocations_error
        self.list_error = list_error
        self.list_calls = 0
        self.last_active_only: bool | None = None

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        return self.team_did_key

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        if self.revocations_error is not None:
            raise self.revocations_error
        return set(self.revoked)

    async def list_team_certificates(self, domain: str, name: str, *, active_only: bool = True):
        self.list_calls += 1
        self.last_active_only = active_only
        if self.list_error is not None:
            raise self.list_error
        return [SimpleNamespace(certificate_id=cert_id) for cert_id in self.certificate_ids]


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return bytes(sk), did_from_public_key(pk)


def _make_certificate(team_sk, team_did_key, member_did_key, certificate_id="cert-001"):
    cert = {
        "version": 1,
        "certificate_id": certificate_id,
        "team_id": TEAM_ID,
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": "alice",
        "identity_scope": "global",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    return cert


def _signed_cert_request(registry: _FakeRegistry, certificate_id: str = "cert-001") -> Request:
    """A request carrying a cryptographically valid certificate + signature
    (legacy compact envelope), whose app state holds the fake registry."""
    team_sk, team_did_key = _make_keypair()
    registry.team_did_key = team_did_key
    member_sk, member_did_key = _make_keypair()
    cert = _make_certificate(team_sk, team_did_key, member_did_key, certificate_id=certificate_id)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    body_sha256 = hashlib.sha256(b"").hexdigest()
    signature = sign_message(
        member_sk,
        compact_team_auth_payload(team_id=TEAM_ID, timestamp=timestamp, body_sha256=body_sha256),
    )
    headers = {
        "Authorization": f"DIDKey {member_did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
    }
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/tasks",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
            "app": SimpleNamespace(
                state=SimpleNamespace(awid_registry_client=registry, public_origin="")
            ),
        }
    )


def _identity_request(registry: _FakeRegistry):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(awid_registry_client=registry)))


# ---------------------------------------------------------------------------
# Presented-certificate path (verify_request_certificate)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flag_off_unregistered_certificate_verifies_with_no_existence_read(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    registry = _FakeRegistry(certificate_ids=[])  # registry has never seen the cert
    request = _signed_cert_request(registry)

    cert_info = await verify_request_certificate(request, db=object())

    assert cert_info["certificate_id"] == "cert-001"
    assert cert_info["team_id"] == TEAM_ID
    # OFF path adds zero registry existence reads.
    assert registry.list_calls == 0


@pytest.mark.asyncio
async def test_flag_on_unregistered_certificate_fails_with_distinct_verdict(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(certificate_ids=["cert-other"])
    request = _signed_cert_request(registry)

    with pytest.raises(HTTPException) as excinfo:
        await verify_request_certificate(request, db=object())

    # Distinct from signature failure (401) and from revocation ("revoked").
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == "Certificate not registered: cert-001"
    assert "revoked" not in excinfo.value.detail
    # The existence read went through the cached listing with active_only
    # False: existence means "the registry has seen it", independent of
    # revocation state (which is checked separately, first).
    assert registry.list_calls == 1
    assert registry.last_active_only is False


@pytest.mark.asyncio
async def test_flag_on_registered_certificate_passes(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(certificate_ids=["cert-001", "cert-other"])
    request = _signed_cert_request(registry)

    cert_info = await verify_request_certificate(request, db=object())

    assert cert_info["certificate_id"] == "cert-001"
    assert registry.list_calls == 1


@pytest.mark.asyncio
async def test_flag_on_revoked_certificate_keeps_revocation_verdict(monkeypatch):
    """Ordering preserved: revocation is checked before existence, so a
    revoked certificate keeps its revocation verdict even when it would
    also fail the existence check."""
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(revoked={"cert-001"}, certificate_ids=[])
    request = _signed_cert_request(registry)

    with pytest.raises(HTTPException) as excinfo:
        await verify_request_certificate(request, db=object())

    assert excinfo.value.status_code == 401
    assert "revoked" in excinfo.value.detail
    assert "not registered" not in excinfo.value.detail
    assert registry.list_calls == 0


@pytest.mark.asyncio
async def test_flag_on_registry_unavailable_fails_closed(monkeypatch):
    """Same availability posture as the revocation check: when the cached
    client cannot serve (its internal freshness/grace exhausted, surfaced
    to us as the read raising), the existence check fails closed with 503 —
    it must not silently fail open."""
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(list_error=httpx.ConnectError("registry down"))
    request = _signed_cert_request(registry)

    with pytest.raises(HTTPException) as excinfo:
        await verify_request_certificate(request, db=object())

    assert excinfo.value.status_code == 503


@pytest.mark.asyncio
async def test_flag_on_team_unknown_to_registry_means_not_registered(monkeypatch):
    """A definitive registry 404 for the team's certificate listing is an
    answer (nothing is registered), not an outage — mirrors the revocation
    read's 404-means-empty behavior."""
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(
        list_error=RegistryError("team not found", status_code=404)
    )
    request = _signed_cert_request(registry)

    with pytest.raises(HTTPException) as excinfo:
        await verify_request_certificate(request, db=object())

    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == "Certificate not registered: cert-001"


# ---------------------------------------------------------------------------
# Identity-only paths (_enforce_current_membership: HTTP and MCP branches)
# ---------------------------------------------------------------------------

_ROW = {
    "agent_id": "agent-1",
    "team_id": TEAM_ID,
    "alias": "alice",
    "did_aw": "did:aw:alice",
    "address": "acme.com/alice",
    "identity_scope": "global",
    "certificate_id": "cert-9",
}


@pytest.mark.asyncio
async def test_identity_flag_off_unregistered_recorded_certificate_keeps_context(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    registry = _FakeRegistry(certificate_ids=[])
    out = await _enforce_current_membership(_identity_request(registry), dict(_ROW))
    assert out["team_id"] == TEAM_ID
    assert out["alias"] == "alice"
    assert registry.list_calls == 0


@pytest.mark.asyncio
async def test_identity_flag_on_unregistered_recorded_certificate_strips_context(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(certificate_ids=["cert-other"])
    out = await _enforce_current_membership(_identity_request(registry), dict(_ROW))
    assert out["team_id"] is None
    assert out["alias"] is None
    assert out["agent_id"] is None
    # Existence ends membership, not the identity — same remedy as revocation.
    assert out["did_aw"] == "did:aw:alice"
    assert out["address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_identity_flag_on_registered_recorded_certificate_keeps_context(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(certificate_ids=["cert-9"])
    out = await _enforce_current_membership(_identity_request(registry), dict(_ROW))
    assert out["team_id"] == TEAM_ID
    assert out["agent_id"] == "agent-1"


@pytest.mark.asyncio
async def test_identity_flag_on_revoked_certificate_still_strips_as_revoked(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(revoked={"cert-9"}, certificate_ids=[])
    out = await _enforce_current_membership(_identity_request(registry), dict(_ROW))
    assert out["team_id"] is None
    # Revocation verdict decided before the existence read is ever made.
    assert registry.list_calls == 0


@pytest.mark.asyncio
async def test_identity_flag_on_registry_unavailable_fails_closed(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(list_error=httpx.ConnectError("registry down"))
    with pytest.raises(HTTPException) as excinfo:
        await _enforce_current_membership(_identity_request(registry), dict(_ROW))
    assert excinfo.value.status_code == 503


@pytest.mark.asyncio
async def test_identity_flag_on_row_without_recorded_certificate_passes_without_reads(monkeypatch):
    """Pre-migration-017 rows have no recorded certificate; they pass
    unchanged (and heal at the next certificate-authenticated request),
    with no registry reads at all."""
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry()
    row = {"team_id": TEAM_ID, "alias": "alice", "agent_id": "a", "certificate_id": None}
    out = await _enforce_current_membership(_identity_request(registry), row)
    assert out is row
    assert registry.list_calls == 0


# ---------------------------------------------------------------------------
# MCP certificate branch (delegates to verify_request_certificate)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_certificate_branch_flag_on_rejects_unregistered_certificate(monkeypatch):
    monkeypatch.setenv(FLAG, "true")
    registry = _FakeRegistry(certificate_ids=[])
    request = _signed_cert_request(registry)

    middleware = MCPAuthMiddleware(app=lambda *_a, **_k: None, db_infra=object())
    with pytest.raises(HTTPException) as excinfo:
        await middleware._resolve_auth(request)

    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == "Certificate not registered: cert-001"
