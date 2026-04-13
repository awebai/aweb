"""HTTP-level test for POST /v1/connect through the full ASGI stack."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
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
        "team_id": kwargs.get("team_id", "backend:acme.com"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "persistent"),
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
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            request.state.cached_body = b""
            request.state.body_sha256 = _hashlib.sha256(b"").hexdigest()
            return await call_next(request)

        original_receive = request._receive
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = _hashlib.sha256(body).hexdigest()
        replayed = False

        async def _receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            while True:
                message = await original_receive()
                if message["type"] == "http.disconnect":
                    return message
                if message["type"] == "http.request" and not message.get("more_body", False):
                    continue
                return message

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


def _signed_request(agent_sk, agent_did_key, team_id, body_bytes=b""):
    """Build signed headers. Signs {body_sha256, team_id, timestamp}."""
    import hashlib
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team_id": team_id,
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
        team_id="backend:acme.com",
        alias="alice",
        lifetime="persistent",
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
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["team_id"] == "backend:acme.com"
    assert data["alias"] == "alice"
    assert data["agent_id"]
    assert data["workspace_id"]
    assert data["role"] == "developer"


@pytest.mark.asyncio
async def test_connect_http_missing_role_stays_empty(aweb_cloud_db):
    """Missing role should not fall back to the certificate alias."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        lifetime="persistent",
    )
    cert_header = _encode_certificate(cert)

    body = {
        "hostname": "Mac.local",
        "workspace_path": "/Users/alice/project",
        "repo_origin": "",
        "human_name": "Alice",
        "agent_type": "agent",
    }

    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/connect",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["alias"] == "alice"
    assert data["role"] == ""

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT role FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        "backend:acme.com",
        agent_did_key,
    )
    assert row is not None
    assert row["role"] == ""


@pytest.mark.asyncio
async def test_connect_http_idempotent(aweb_cloud_db):
    """Reconnecting returns the same agent_id."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="bob",
    )
    cert_header = _encode_certificate(cert)

    body = {"hostname": "Mac.local", "workspace_path": "/project"}
    body_bytes = json.dumps(body).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        headers1 = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
        headers1["X-AWID-Team-Certificate"] = cert_header
        resp1 = await client.post("/v1/connect", content=body_bytes, headers={**headers1, "Content-Type": "application/json"})

        headers2 = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
        headers2["X-AWID-Team-Certificate"] = cert_header
        resp2 = await client.post("/v1/connect", content=body_bytes, headers={**headers2, "Content-Type": "application/json"})

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json()["agent_id"] == resp2.json()["agent_id"]


@pytest.mark.asyncio
async def test_connect_http_ephemeral_agents_store_no_stable_identity(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    alice_cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="default:local",
        alias="alice",
        lifetime="ephemeral",
    )
    bob_cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="default:local",
        alias="bob",
        lifetime="ephemeral",
    )
    body = {"hostname": "Mac.local", "workspace_path": "/tmp/repo"}
    body_bytes = json.dumps(body).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        alice_headers = _signed_request(alice_sk, alice_did_key, "default:local", body_bytes)
        alice_headers["X-AWID-Team-Certificate"] = _encode_certificate(alice_cert)
        alice_resp = await client.post(
            "/v1/connect",
            content=body_bytes,
            headers={**alice_headers, "Content-Type": "application/json"},
        )

        bob_headers = _signed_request(bob_sk, bob_did_key, "default:local", body_bytes)
        bob_headers["X-AWID-Team-Certificate"] = _encode_certificate(bob_cert)
        bob_resp = await client.post(
            "/v1/connect",
            content=body_bytes,
            headers={**bob_headers, "Content-Type": "application/json"},
        )

    assert alice_resp.status_code == 200, alice_resp.text
    assert bob_resp.status_code == 200, bob_resp.text

    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT alias, did_key, did_aw, address, lifetime
        FROM {{tables.agents}}
        WHERE team_id = 'default:local'
        ORDER BY alias
        """
    )
    assert [row["alias"] for row in rows] == ["alice", "bob"]
    assert rows[0]["did_key"] == alice_did_key
    assert rows[1]["did_key"] == bob_did_key
    assert all(row["did_aw"] is None for row in rows)
    assert all(row["address"] is None for row in rows)
    assert all(row["lifetime"] == "ephemeral" for row in rows)


@pytest.mark.asyncio
async def test_connect_http_reuses_existing_agent_for_same_alias(aweb_cloud_db):
    """An existing active agent may reconnect with the same alias and update mutable fields."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    existing_cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        lifetime="persistent",
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )
    existing_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, human_name, agent_type, role, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'persistent', 'Old Name', 'old-type', 'old-role', 'retired')
        """,
        existing_agent_id,
        "backend:acme.com",
        agent_did_key,
        "did:aw:old",
        "acme.com/alice",
        "alice",
    )

    body = {
        "hostname": "Mac.local",
        "workspace_path": "/new-path",
        "role": "developer",
        "human_name": "Alice Updated",
        "agent_type": "codex",
    }
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(existing_cert)

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 200
    assert resp.json()["agent_id"] == str(existing_agent_id)

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT did_aw, address, human_name, agent_type, role, status
        FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        existing_agent_id,
    )
    assert row["did_aw"] is None
    assert row["address"] is None
    assert row["human_name"] == "Alice Updated"
    assert row["agent_type"] == "codex"
    assert row["role"] == "developer"
    assert row["status"] == "active"


@pytest.mark.asyncio
async def test_connect_http_missing_cert_returns_401(aweb_cloud_db):
    """Request without certificate header returns 401."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
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
        team_id="backend:acme.com",
        alias="eve",
    )
    cert_header = _encode_certificate(cert)

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(other_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_connect_http_rejects_alias_collision_for_different_agent(aweb_cloud_db):
    """A second agent may not take over an existing active workspace alias."""
    team_sk, _, team_did_key = _make_keypair()
    first_sk, _, first_did_key = _make_keypair()
    second_sk, _, second_did_key = _make_keypair()

    existing_cert = _make_certificate(
        team_sk, team_did_key, first_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    new_cert = _make_certificate(
        team_sk, team_did_key, second_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )
    first_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, 'persistent', 'active')
        """,
        first_agent_id,
        "backend:acme.com",
        first_did_key,
        "alice",
    )
    existing_workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type, workspace_path)
        VALUES ($1, $2, $3, $4, 'agent', $5)
        """,
        existing_workspace_id,
        "backend:acme.com",
        first_agent_id,
        "alice",
        "/existing",
    )

    body = {"hostname": "Mac.local", "workspace_path": "/new-path"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(second_sk, second_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(new_cert)

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 409
    assert "already in use by another active agent" in resp.text

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT agent_id, workspace_path FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        existing_workspace_id,
    )
    assert str(row["agent_id"]) == str(first_agent_id)
    assert row["workspace_path"] == "/existing"


@pytest.mark.asyncio
async def test_connect_http_rejects_alias_change_for_same_agent(aweb_cloud_db):
    """A reconnect may not silently change the alias already bound to a did:key."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    new_cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="bob",
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )
    existing_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, 'persistent', 'active')
        """,
        existing_agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )
    existing_workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type, workspace_path)
        VALUES ($1, $2, $3, $4, 'agent', $5)
        """,
        existing_workspace_id,
        "backend:acme.com",
        existing_agent_id,
        "alice",
        "/existing",
    )

    body = {"hostname": "Mac.local", "workspace_path": "/new-path"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(new_cert)

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 409
    assert "did_key is already bound to alias" in resp.text

    workspace_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT alias, workspace_path FROM {{tables.workspaces}}
        WHERE team_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        "backend:acme.com",
    )
    assert len(workspace_rows) == 1
    assert workspace_rows[0]["alias"] == "alice"
    assert workspace_rows[0]["workspace_path"] == "/existing"


@pytest.mark.asyncio
async def test_connect_http_allows_rejoin_after_soft_deleted_agent(aweb_cloud_db):
    """Soft-deleted agents release alias and did_key for clean rejoin."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        lifetime="persistent",
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )
    deleted_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, lifetime, status, deleted_at)
        VALUES ($1, $2, $3, $4, 'persistent', 'deleted', NOW())
        """,
        deleted_agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    body = {"hostname": "Mac.local", "workspace_path": "/new-path"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/connect",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    new_agent_id = resp.json()["agent_id"]
    assert new_agent_id != str(deleted_agent_id)

    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT agent_id, alias, did_key, status, deleted_at
        FROM {{tables.agents}}
        WHERE team_id = $1
        ORDER BY deleted_at NULLS FIRST, created_at
        """,
        "backend:acme.com",
    )
    assert len(rows) == 2
    assert str(rows[0]["agent_id"]) == new_agent_id
    assert rows[0]["alias"] == "alice"
    assert rows[0]["did_key"] == agent_did_key
    assert rows[0]["status"] == "active"
    assert rows[0]["deleted_at"] is None
    assert str(rows[1]["agent_id"]) == str(deleted_agent_id)
    assert rows[1]["deleted_at"] is not None
