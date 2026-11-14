"""Actual SDK/authentication with HTTP doubles; no DB, Redis or sockets."""

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException

from aweb.hook_bindings import OwnerActTeamKeyUnavailable, core_owner_act_verifier
from aweb.team_auth_deps import verify_request_certificate
from awid.protected_membership import certificate_digest
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from team_facts_fixtures import legacy_registry, legacy_team_response
from test_team_auth_deps import (
    _encode_certificate, _make_certificate, _make_keypair, _request_with_app_state,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("projection", ["legacy", "missing", "malformed", "down", "protected-rotated"])
async def test_valid_certificate_requires_explicit_current_protection(monkeypatch, projection):
    monkeypatch.delenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", raising=False)
    team, _, team_did = _make_keypair()
    member, _, member_did = _make_keypair()
    cert = _make_certificate(team, team_did, member_did)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes({
        "team_id": cert["team_id"], "timestamp": timestamp,
        "body_sha256": hashlib.sha256(b"").hexdigest(),
    })
    request = _request_with_app_state({
        "Authorization": f"DIDKey {member_did} {sign_message(member, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": _encode_certificate(cert),
    })
    reads = []

    async def handler(req):
        reads.append(req.url.path)
        if req.url.path.endswith("/revocations"):
            return httpx.Response(200, json={"revocations": [], "has_more": False})
        if req.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"certificates": [
                {**cert, "certificate_sha256": certificate_digest(cert), "revoked_at": None},
            ], "has_more": False})
        value = legacy_team_response("acme.com", "backend", team_did_key=team_did)
        # The first read supplies the existing controller-key verifier. The
        # second supplies the mandatory current protection observation.
        if len(reads) > 1:
            if projection == "missing":
                value.pop("protection")
            elif projection == "malformed":
                value["protection"] = {"mode": "unknown"}
            elif projection == "down":
                return httpx.Response(503)
            elif projection == "protected-rotated":
                value["team_did_key"] = _make_keypair()[2]
                value["protection"] = {
                    "mode": "protected", "service_id": "isolated-signer",
                    "service_did_key": team_did,
                    "history_id": "cadb7acb-7116-4842-adc7-f95972894e72", "generation": 1,
                }
        return httpx.Response(200, json=value)

    async with RegistryClient("https://registry.test", transport=httpx.MockTransport(handler)) as registry:
        request.app.state.awid_registry_client = registry
        if projection == "legacy":
            assert (await verify_request_certificate(request, db=object()))["alias"] == cert["alias"]
        else:
            with pytest.raises(HTTPException) as caught:
                await verify_request_certificate(request, db=object())
            if projection == "protected-rotated":
                assert caught.value.status_code == 401
            else:
                assert caught.value.status_code == 503
                assert caught.value.detail == {"code": "protected_state_unavailable"}


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [None, {"mode": "unknown"}, OSError("outage")])
async def test_complete_legacy_fake_never_overwrites_explicit_missing_or_failed_evidence(answer):
    registry = AsyncMock()
    if isinstance(answer, Exception):
        registry.get_team_fresh.side_effect = answer
    else:
        registry.get_team_fresh.return_value = answer
    assert legacy_registry(registry) is registry
    if isinstance(answer, Exception):
        with pytest.raises(OSError):
            await registry.get_team_fresh("acme.com", "backend")
    else:
        assert await registry.get_team_fresh("acme.com", "backend") == answer


@pytest.mark.asyncio
async def test_owner_act_authority_failure_keeps_registry_cause():
    async def handler(req):
        return httpx.Response(403, json={"detail": {"code": "team_private", "message": "private"}})

    async with RegistryClient("https://registry.test", transport=httpx.MockTransport(handler)) as registry:
        verifier = core_owner_act_verifier(audience="https://aweb.test", registry_client=registry)
        # Authority is observed before artifact parsing; no effect or DB is entered.
        with pytest.raises(OwnerActTeamKeyUnavailable) as caught:
            await verifier.prepare(b"", "", team_id="backend:acme.com")
        assert caught.value.dependency_error.code == "team_private"
