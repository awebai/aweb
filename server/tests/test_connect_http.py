"""Connect lifecycle through actual aweb HTTP, AWID, PostgreSQL and Redis."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from aweb.presence import clear_workspace_presence
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app  # noqa: F401


@pytest_asyncio.fixture
async def connect_app(privacy_app):
    try:
        yield privacy_app
    finally:
        # Only this disposable database's connect workspaces can own these
        # presence keys. Never flush the host's shared Redis.
        rows = await privacy_app.db.fetch_all(
            "SELECT workspace_id FROM {{tables.workspaces}} WHERE team_id = ANY($1::text[])",
            ["backend:acme.com", "default:local"],
        )
        for row in rows:
            workspace = str(row["workspace_id"])
            if await privacy_app.redis.exists(f"presence_coordinates:{workspace}"):
                await clear_workspace_presence(privacy_app.redis, [workspace])


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
        "identity_scope": kwargs.get("identity_scope", "global"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    sig = sign_message(team_sk, payload)
    cert["signature"] = sig
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


async def _register_controller(env, team_did_key, team_id="backend:acme.com"):
    """Publish the controller in the real registry used by the actual app."""
    name, domain = team_id.split(":", 1)
    await env.registry_db.execute(
        """INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility)
           VALUES ($1, $2, $3, 'public')""",
        domain, name, team_did_key,
    )


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
async def test_connect_http_first_time(connect_app):
    """First-time connection: no agent exists yet. The endpoint auto-provisions
    team + agent + workspace and returns 200."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
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

    await _register_controller(connect_app, team_did_key)

    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["team_id"] == "backend:acme.com"
    assert data["alias"] == "alice"
    assert data["agent_id"]
    assert data["workspace_id"]
    assert data["role"] == "developer"


@pytest.mark.asyncio
async def test_connect_http_invalid_repo_origin_returns_422(connect_app):
    """Invalid repo_origin is user input and must not surface as a 500."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
    )
    cert_header = _encode_certificate(cert)

    body = {
        "hostname": "Mac.local",
        "workspace_path": "/Users/alice/project",
        "repo_origin": "/tmp/local-path-origin",
        "role": "developer",
        "human_name": "Alice",
        "agent_type": "agent",
    }

    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    await _register_controller(connect_app, team_did_key)

    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_connect_http_missing_role_stays_empty(connect_app):
    """Missing role should not fall back to the certificate alias."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
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

    await _register_controller(connect_app, team_did_key)

    client = connect_app.client
    resp = await client.post(
        "/v1/connect",
        content=body_bytes,
        headers={**headers, "Content-Type": "application/json"},
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["alias"] == "alice"
    assert data["role"] == ""

    row = await connect_app.db.fetch_one(
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
async def test_connect_http_idempotent(connect_app):
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

    await _register_controller(connect_app, team_did_key)

    client = connect_app.client
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
async def test_connect_http_ephemeral_agents_store_no_stable_identity(connect_app):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    alice_cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="default:local",
        alias="alice",
        identity_scope="local",
    )
    bob_cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="default:local",
        alias="bob",
        identity_scope="local",
    )
    body = {"hostname": "Mac.local", "workspace_path": "/tmp/repo"}
    body_bytes = json.dumps(body).encode()

    await _register_controller(connect_app, team_did_key, "default:local")
    client = connect_app.client
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

    rows = await connect_app.db.fetch_all(
        """
        SELECT alias, did_key, did_aw, address, identity_scope
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
    assert all(row["identity_scope"] == "local" for row in rows)


@pytest.mark.asyncio
async def test_connect_http_reuses_existing_agent_for_same_alias(connect_app):
    """An existing active agent may reconnect with the same alias and update mutable fields."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    existing_cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
    )

    await connect_app.db.execute(
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
    await connect_app.db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, human_name, agent_type, role, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'global', 'Old Name', 'old-type', 'old-role', 'retired')
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

    await _register_controller(connect_app, team_did_key)
    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 200
    assert resp.json()["agent_id"] == str(existing_agent_id)

    row = await connect_app.db.fetch_one(
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
async def test_connect_http_missing_cert_returns_401(connect_app):
    """Request without certificate header returns 401."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    # No X-AWID-Team-Certificate header

    await _register_controller(connect_app, team_did_key)

    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["request_signer", "registered_controller"])
async def test_connect_http_invalid_signature_returns_401(connect_app, mismatch):
    """Request with wrong signature returns 401."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    other_sk, _, other_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="eve",
    )
    cert_header = _encode_certificate(cert)

    body = {"hostname": "Mac.local"}
    body_bytes = json.dumps(body).encode()
    headers = _signed_request(other_sk if mismatch == "request_signer" else agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    await _register_controller(connect_app, team_did_key if mismatch == "request_signer" else other_did_key)

    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_connect_http_rejects_alias_collision_for_different_agent(connect_app):
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

    await connect_app.db.execute(
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
    await connect_app.db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'global', 'active')
        """,
        first_agent_id,
        "backend:acme.com",
        first_did_key,
        "alice",
    )
    existing_workspace_id = uuid4()
    await connect_app.db.execute(
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

    await _register_controller(connect_app, team_did_key)
    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 409
    assert resp.json() == {
        "detail": {
            "code": "alias_active",
            "message": "alias 'alice' is already in use by another active agent in team backend:acme.com",
        }
    }, resp.text

    row = await connect_app.db.fetch_one(
        """
        SELECT agent_id, workspace_path FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        existing_workspace_id,
    )
    assert str(row["agent_id"]) == str(first_agent_id)
    assert row["workspace_path"] == "/existing"


@pytest.mark.asyncio
async def test_connect_http_rejects_alias_change_for_same_agent(connect_app):
    """A reconnect may not silently change the alias already bound to a did:key."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    new_cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="bob",
    )

    await connect_app.db.execute(
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
    await connect_app.db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'global', 'active')
        """,
        existing_agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )
    existing_workspace_id = uuid4()
    await connect_app.db.execute(
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

    await _register_controller(connect_app, team_did_key)
    client = connect_app.client
    resp = await client.post("/v1/connect", content=body_bytes, headers={**headers, "Content-Type": "application/json"})

    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "alias_mismatch", resp.text
    assert "already bound to alias 'alice'" in resp.json()["detail"]["message"], resp.text

    workspace_rows = await connect_app.db.fetch_all(
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
async def test_connect_http_allows_rejoin_after_soft_deleted_agent(connect_app):
    """Soft-deleted agents release alias and did_key for clean rejoin."""
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk, team_did_key, agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
    )

    await connect_app.db.execute(
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
    await connect_app.db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status, deleted_at)
        VALUES ($1, $2, $3, $4, 'global', 'deleted', NOW())
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

    await _register_controller(connect_app, team_did_key)
    client = connect_app.client
    resp = await client.post(
        "/v1/connect",
        content=body_bytes,
        headers={**headers, "Content-Type": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    new_agent_id = resp.json()["agent_id"]
    assert new_agent_id != str(deleted_agent_id)

    rows = await connect_app.db.fetch_all(
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
