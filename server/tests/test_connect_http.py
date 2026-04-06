"""HTTP-level test for POST /v1/connect through the full ASGI stack."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb.awid.did import did_from_public_key
from aweb.awid.signing import canonical_json_bytes, sign_message
from aweb.routes.connect import router as connect_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(team_sk, team_did_key, member_did_key, **kwargs):
    cert = {
        "version": 1,
        "certificate_id": kwargs.get("certificate_id", "cert-001"),
        "team": kwargs.get("team_address", "acme.com/backend"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "permanent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    sig = sign_message(team_sk, payload)
    cert["signature"] = sig
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _build_test_app(aweb_db, team_did_key):
    """Build a minimal FastAPI app with connect router and mocked awid registry."""
    app = FastAPI()
    app.include_router(connect_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    import hashlib as _hashlib

    @app.middleware("http")
    async def cache_body(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = _hashlib.sha256(body).hexdigest()

        async def _receive():
            return {"type": "http.request", "body": body}

        request._receive = _receive
        return await call_next(request)

    app.state.db = _DbShim()
    app.state.redis = None
    app.state.rate_limiter = None

    # Mock the awid registry client to return the team key
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    return app


def _signed_request(agent_sk, agent_did_key, team_address, body_bytes=b""):
    """Build signed headers. Signs {body_sha256, team, timestamp}."""
    import hashlib
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team": team_address,
        "timestamp": timestamp,
    })
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


@pytest.mark.asyncio
async def test_connect_http_first_time(aweb_cloud_db):
    """First-time connection: no agent exists yet. The endpoint auto-provisions
    team + agent + workspace and returns 200."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_address="acme.com/backend",
        alias="alice",
        lifetime="permanent",
    )
    cert_header = _encode_certificate(cert)

    body = {
        "hostname": "Mac.local",
        "workspace_path": "/Users/alice/project",
        "repo_origin": "",
        "role": "developer",
        "human_name": "Alice",
        "agent_type": "agent",
    }

    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["team_address"] == "acme.com/backend"
    assert data["alias"] == "alice"
    assert data["agent_id"]
    assert data["workspace_id"]
    assert data["role"] == "developer"


@pytest.mark.asyncio
async def test_connect_http_idempotent(aweb_cloud_db):
    """Reconnecting returns the same agent_id."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_address="acme.com/backend",
        alias="bob",
    )
    cert_header = _encode_certificate(cert)

    body = {"hostname": "Mac.local", "workspace_path": "/project"}
    body_bytes = json.dumps(body).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        headers1 = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
        headers1["X-AWID-Team-Certificate"] = cert_header
        resp1 = await client.post("/v1/connect", content=body_bytes, headers={**headers1, "Content-Type": "application/json"})

        headers2 = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
        headers2["X-AWID-Team-Certificate"] = cert_header
        resp2 = await client.post("/v1/connect", content=body_bytes, headers={**headers2, "Content-Type": "application/json"})

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json()["agent_id"] == resp2.json()["agent_id"]


@pytest.mark.asyncio
async def test_connect_http_missing_cert_returns_401(aweb_cloud_db):
    """Request without certificate header returns 401."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
    # No X-AWID-Team-Certificate header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_connect_http_invalid_signature_returns_401(aweb_cloud_db):
    """Request with wrong signature returns 401."""
    team_sk, _, team_did_key = _make_keypair()
    _, _, agent_did_key = _make_keypair()
    other_sk, _, _ = _make_keypair()  # sign with wrong key

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_address="acme.com/backend",
        alias="eve",
    )
    cert_header = _encode_certificate(cert)

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(other_sk, agent_did_key, "acme.com/backend", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 401
