"""HTTP-level regression tests for DELETE /v1/workspaces/{workspace_id}."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.coordination.routes.workspaces import router as workspaces_router


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
        "alias": kwargs.get("alias", "bob"),
        "lifetime": kwargs.get("lifetime", "ephemeral"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_request(agent_sk, agent_did_key, team_address, body_bytes=b""):
    import hashlib

    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes(
        {
            "body_sha256": body_sha256,
            "team": team_address,
            "timestamp": timestamp,
        }
    )
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, team_did_key):
    app = FastAPI()
    app.include_router(workspaces_router)

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

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry
    return app


@pytest.mark.asyncio
async def test_delete_workspace_soft_deletes_stale_ephemeral_identity(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_address = "acme.com/backend"
    workspace_id = uuid4()
    agent_id = uuid4()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_address=team_address,
        alias="bob",
        lifetime="ephemeral",
    )
    headers = _signed_request(agent_sk, agent_did_key, team_address)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        "acme.com",
        "backend",
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, role)
        VALUES ($1, $2, $3, $4, 'ephemeral', 'developer')
        """,
        agent_id,
        team_address,
        agent_did_key,
        "bob",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_address, agent_id, alias, workspace_path, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        workspace_id,
        team_address,
        agent_id,
        "bob",
        "/tmp/gone-worktree",
        datetime.now(timezone.utc) - timedelta(hours=1),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_address, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        team_address,
        workspace_id,
        "bob",
        "",
        "backend-1",
        datetime.now(timezone.utc),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.delete(f"/v1/workspaces/{workspace_id}", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workspace_id"] == str(workspace_id)
    assert body["alias"] == "bob"
    assert body["identity_deleted"] is True

    workspace_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )
    agent_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at, status FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        agent_id,
    )
    claims_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*) AS count FROM {{tables.task_claims}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )

    assert workspace_row["deleted_at"] is not None
    assert agent_row["deleted_at"] is not None
    assert agent_row["status"] == "deleted"
    assert claims_row["count"] == 0


@pytest.mark.asyncio
async def test_delete_workspace_rejects_persistent_identity(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_address = "acme.com/backend"
    workspace_id = uuid4()
    agent_id = uuid4()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_address=team_address,
        alias="maintainer",
        lifetime="persistent",
    )
    headers = _signed_request(agent_sk, agent_did_key, team_address)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        "acme.com",
        "backend",
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, role)
        VALUES ($1, $2, $3, $4, 'persistent', 'developer')
        """,
        agent_id,
        team_address,
        agent_did_key,
        "maintainer",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_address, agent_id, alias, workspace_path, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        workspace_id,
        team_address,
        agent_id,
        "maintainer",
        "/tmp/gone-worktree",
        datetime.now(timezone.utc) - timedelta(hours=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.delete(f"/v1/workspaces/{workspace_id}", headers=headers)

    assert resp.status_code == 409
    assert "ephemeral identities" in resp.text


@pytest.mark.asyncio
async def test_delete_workspace_rejects_recent_ephemeral_workspace(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_address = "acme.com/backend"
    workspace_id = uuid4()
    agent_id = uuid4()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_address=team_address,
        alias="bot",
        lifetime="ephemeral",
    )
    headers = _signed_request(agent_sk, agent_did_key, team_address)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        "acme.com",
        "backend",
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, role)
        VALUES ($1, $2, $3, $4, 'ephemeral', 'developer')
        """,
        agent_id,
        team_address,
        agent_did_key,
        "bot",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_address, agent_id, alias, workspace_path, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        workspace_id,
        team_address,
        agent_id,
        "bot",
        "/tmp/recent-worktree",
        datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.delete(f"/v1/workspaces/{workspace_id}", headers=headers)

    assert resp.status_code == 409
    assert "still active" in resp.text

    workspace_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )
    agent_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        agent_id,
    )
    assert workspace_row["deleted_at"] is None
    assert agent_row["deleted_at"] is None
