"""HTTP-level tests for /v1/agents routes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.routes.agents import router as agents_router


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
        "member_did_aw": kwargs.get("member_did_aw", ""),
        "member_address": kwargs.get("member_address", ""),
        "alias": kwargs.get("alias", "alice"),
        "identity_scope": kwargs.get("identity_scope", "local"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    cert["signature"] = sign_message(team_sk, payload)
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _raw_standard_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _encryption_key_id(raw_public_key: bytes) -> str:
    digest = hashlib.sha256(b"aweb-e2ee-v2 encryption-key\n" + raw_public_key).digest()
    return "sha256:" + _raw_standard_b64(digest)


def _make_encryption_assertion(
    signing_key: bytes,
    *,
    did_key: str,
    stable_id: str | None = None,
    raw_public_key: bytes = b"\x01" * 32,
    created_at: str = "2026-05-25T12:00:00Z",
    not_before: str = "2026-05-25T11:59:00Z",
    expires_at: str = "2126-05-26T12:00:00Z",
    custody: str | None = None,
) -> dict:
    payload = {
        "operation": "publish_encryption_key",
        "version": "aweb-e2ee-key-v1",
        "identity_did": did_key,
        "encryption_key_id": _encryption_key_id(raw_public_key),
        "encryption_public_key": _raw_standard_b64(raw_public_key),
        "algorithm": "x25519",
        "created_at": created_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }
    if stable_id:
        payload["identity_stable_id"] = stable_id
    if custody is not None:
        payload["custody"] = custody
    payload["signature"] = sign_message(signing_key, canonical_json_bytes(payload))
    return payload


def _signed_request(agent_sk, agent_did_key, team_id, body_bytes=b""):
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


class _PauseAfterWorkspaceRead:
    def __init__(self, manager) -> None:
        self._manager = manager
        self.workspace_read = asyncio.Event()
        self.resume = asyncio.Event()

    def __getattr__(self, name):
        return getattr(self._manager, name)

    async def fetch_one(self, query, *args):
        row = await self._manager.fetch_one(query, *args)
        if "SELECT w.workspace_id, w.hostname" in query:
            self.workspace_read.set()
            await asyncio.wait_for(self.resume.wait(), timeout=5)
        return row


def _build_test_app(aweb_db, team_did_key):
    app = FastAPI()
    app.include_router(agents_router)

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

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    return app


async def _insert_team(aweb_db, team_id: str, team_did_key: str) -> None:
    team_name, namespace = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        namespace,
        team_name,
        team_did_key,
    )


@pytest.mark.asyncio
async def test_suggest_alias_prefix_returns_next_available_name(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    alice_agent_id = uuid4()
    bob_agent_id = uuid4()
    alice01_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES
            ($1, $2, $3, $4, 'local', 'active'),
            ($5, $2, $6, 'bob', 'local', 'active'),
            ($7, $2, $8, 'alice-01', 'local', 'active')
        """,
        alice_agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
        bob_agent_id,
        "did:key:z6Mkbob",
        alice01_agent_id,
        "did:key:z6Mkalice01",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES
            ($1, $2, $3, 'alice', 'agent'),
            ($4, $2, $5, 'bob', 'agent'),
            ($6, $2, $7, 'alice-01', 'agent')
        """,
        uuid4(),
        "backend:acme.com",
        alice_agent_id,
        uuid4(),
        bob_agent_id,
        uuid4(),
        alice01_agent_id,
    )

    body_bytes = b"{}"
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_id": "backend:acme.com",
        "name_prefix": "charlie",
        "names": [{"name": "charlie"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_no_body_keeps_legacy_response_shape(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    body_bytes = b""
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers=headers,
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_id": "backend:acme.com",
        "name_prefix": "bob",
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_uses_agent_aliases_without_workspace_rows(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    body_bytes = b"{}"
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_id": "backend:acme.com",
        "name_prefix": "bob",
        "names": [{"name": "bob"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_count_and_exclude_are_ordered(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES
            ($1, $2, $3, 'alice', 'local', 'active'),
            ($4, $2, $5, 'bob', 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        uuid4(),
        "did:key:z6Mkbob",
    )

    body_bytes = json.dumps({"scope": "local", "exclude": ["charlie"], "count": 3}, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_id": "backend:acme.com",
        "name_prefix": "dave",
        "names": [{"name": "dave"}, {"name": "eve"}, {"name": "frank"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_global_uses_namespace_names_and_user_prefix(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    other_team_sk, _, other_team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="maria",
        identity_scope="global",
        member_address="acme.com/maria",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await _insert_team(aweb_cloud_db.aweb_db, "frontend:acme.com", other_team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, status)
        VALUES
            ($1, $2, $3, 'did:aw:maria', 'acme.com/maria', 'maria', 'global', 'active'),
            ($4, $2, $5, 'did:aw:mariaalice', 'acme.com/maria-alice', 'maria-alice', 'global', 'active'),
            ($6, $7, $8, 'did:aw:mariabob', 'acme.com/maria-bob', 'maria-bob', 'global', 'active'),
            ($9, $7, $10, 'did:aw:otheralice', 'acme.com/other-alice', 'other-alice', 'global', 'active'),
            ($11, $7, $12, 'did:aw:otherns', 'other.com/maria-charlie', 'maria-charlie', 'global', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        uuid4(),
        "did:key:z6Mkmariaalice",
        uuid4(),
        "frontend:acme.com",
        "did:key:z6Mkmariabob",
        uuid4(),
        "did:key:z6Mkotheralice",
        uuid4(),
        "did:key:z6Mkotherns",
    )

    body_bytes = json.dumps(
        {"scope": "global", "exclude": ["maria-charlie"], "count": 2},
        separators=(",", ":"),
    ).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    app.state.awid_registry_client.list_addresses = AsyncMock(
        return_value=[
            SimpleNamespace(domain="acme.com", name="maria"),
            SimpleNamespace(domain="acme.com", name="maria-alice"),
            SimpleNamespace(domain="acme.com", name="maria-bob"),
            SimpleNamespace(domain="acme.com", name="other-alice"),
            SimpleNamespace(domain="other.com", name="maria-charlie"),
        ]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_id": "backend:acme.com",
        "name_prefix": "maria-dave",
        "names": [{"name": "maria-dave"}, {"name": "maria-eve"}],
    }


@pytest.mark.asyncio
async def test_patch_agent_workspace_accepts_canonical_role_name(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, role, workspace_type)
        VALUES ($1, $2, $3, 'alice', 'developer', 'manual')
        """,
        workspace_id,
        "backend:acme.com",
        agent_id,
    )

    body_bytes = json.dumps({"role_name": "Reviewer"}, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(
            "/v1/agents/me",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["role_name"] == "reviewer"
    assert data["role"] == "reviewer"

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT role, workspace_type
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )
    assert row["role"] == "reviewer"
    assert row["workspace_type"] == "manual"


@pytest.mark.asyncio
async def test_patch_agent_workspace_omission_preserves_concurrent_repo_binding(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, 'alice', 'local', 'active')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, role, workspace_type)
        VALUES ($1, $2, $3, 'alice', 'developer', 'manual')
        """,
        workspace_id,
        "backend:acme.com",
        agent_id,
    )

    role_body = json.dumps({"role_name": "Reviewer"}, separators=(",", ":")).encode()
    role_headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", role_body)
    role_headers["X-AWID-Team-Certificate"] = cert_header
    repair_body = json.dumps(
        {"repo_origin": "https://github.com/acme/backend.git"},
        separators=(",", ":"),
    ).encode()
    repair_headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", repair_body)
    repair_headers["X-AWID-Team-Certificate"] = cert_header

    paused_db = _PauseAfterWorkspaceRead(aweb_cloud_db.aweb_db)
    role_app = _build_test_app(paused_db, team_did_key)
    repair_app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with (
        AsyncClient(transport=ASGITransport(app=role_app), base_url="http://test") as role_client,
        AsyncClient(transport=ASGITransport(app=repair_app), base_url="http://test") as repair_client,
    ):
        role_request = asyncio.create_task(
            role_client.patch(
                "/v1/agents/me",
                content=role_body,
                headers={**role_headers, "Content-Type": "application/json"},
            )
        )
        await asyncio.wait_for(paused_db.workspace_read.wait(), timeout=5)
        repair = await repair_client.patch(
            "/v1/agents/me",
            content=repair_body,
            headers={**repair_headers, "Content-Type": "application/json"},
        )
        paused_db.resume.set()
        role = await role_request

    assert repair.status_code == 200, repair.text
    assert role.status_code == 200, role.text

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT w.role, w.repo_id, w.workspace_type, r.canonical_origin
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.repos}} r ON r.id = w.repo_id
        WHERE w.workspace_id = $1
        """,
        workspace_id,
    )
    assert row["role"] == "reviewer"
    assert str(row["repo_id"]) == repair.json()["repo_id"]
    assert row["workspace_type"] == "agent"
    assert row["canonical_origin"] == "github.com/acme/backend"


@pytest.mark.asyncio
async def test_patch_agent_workspace_repairs_ssh_over_443_repo_binding(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES ($1, $2, $3, 'alice', 'manual')
        """,
        workspace_id,
        "backend:acme.com",
        agent_id,
    )

    body = {"repo_origin": "ssh://git@ssh.github.com:443/acme/backend.git"}
    body_bytes = json.dumps(body, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.patch(
            "/v1/agents/me",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )
        second = await client.patch(
            "/v1/agents/me",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["canonical_origin"] == "github.com/acme/backend"
    assert second.json()["repo_id"] == first.json()["repo_id"]

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT w.repo_id, w.workspace_type, r.canonical_origin
        FROM {{tables.workspaces}} w
        JOIN {{tables.repos}} r ON r.id = w.repo_id
        WHERE w.workspace_id = $1
        """,
        workspace_id,
    )
    assert str(row["repo_id"]) == first.json()["repo_id"]
    assert row["canonical_origin"] == "github.com/acme/backend"
    assert row["workspace_type"] == "agent"


@pytest.mark.asyncio
async def test_get_my_inbound_mode_returns_current_global_agent_policy(aweb_cloud_db):
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
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status, inbound_mode)
        VALUES ($1, $2, $3, $4, 'global', 'active', 'team_and_contacts')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com")
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/agents/me/inbound-mode", headers=headers)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "agent_id": str(agent_id),
        "team_id": "backend:acme.com",
        "alias": "alice",
        "identity_scope": "global",
        "inbound_mode": "team_and_contacts",
        "configurable": True,
    }


@pytest.mark.asyncio
async def test_patch_my_inbound_mode_updates_global_agent_policy(aweb_cloud_db):
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
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status, inbound_mode)
        VALUES ($1, $2, $3, $4, 'global', 'active', 'open')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    body_bytes = json.dumps({"inbound_mode": "team_and_contacts"}, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(
            "/v1/agents/me/inbound-mode",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["inbound_mode"] == "team_and_contacts"
    stored = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    assert stored == "team_and_contacts"


@pytest.mark.asyncio
async def test_patch_my_inbound_mode_rejects_local_agent(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status, inbound_mode)
        VALUES ($1, $2, $3, $4, 'local', 'active', 'open')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    body_bytes = json.dumps({"inbound_mode": "team_and_contacts"}, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(
            "/v1/agents/me/inbound-mode",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 409, resp.text
    assert "global" in resp.text


@pytest.mark.asyncio
async def test_publish_my_encryption_key_for_local_agent_and_list_returns_verified_key(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    assertion = _make_encryption_assertion(agent_sk, did_key=agent_did_key)
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        publish = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )
        listed = await client.get("/v1/agents", headers={
            **_signed_request(agent_sk, agent_did_key, "backend:acme.com"),
            "X-AWID-Team-Certificate": cert_header,
        })

    assert publish.status_code == 200, publish.text
    assert publish.json()["encryption_key"]["encryption_key_id"] == assertion["encryption_key_id"]
    assert "identity_stable_id" not in publish.json()["encryption_key"]
    assert listed.status_code == 200, listed.text
    [agent] = listed.json()["agents"]
    assert agent["agent_id"] == str(agent_id)
    assert agent["repo"] is None
    assert agent["encryption_key"]["encryption_key_id"] == assertion["encryption_key_id"]
    assert "identity_stable_id" not in agent["encryption_key"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_preserves_signed_custody(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)

    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        agent_id,
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    assertion = _make_encryption_assertion(agent_sk, did_key=agent_did_key, custody="self")
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        publish = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )
        listed = await client.get("/v1/agents", headers={
            **_signed_request(agent_sk, agent_did_key, "backend:acme.com"),
            "X-AWID-Team-Certificate": cert_header,
        })

    assert publish.status_code == 200, publish.text
    assert publish.json()["encryption_key"]["custody"] == "self"
    assert listed.status_code == 200, listed.text
    [agent] = listed.json()["agents"]
    assert agent["agent_id"] == str(agent_id)
    assert agent["encryption_key"]["custody"] == "self"


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_unsigned_custody_mutation(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    assertion = _make_encryption_assertion(agent_sk, did_key=agent_did_key)
    assertion["custody"] = "self"
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 422, resp.text
    assert "invalid signature" in resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_replayed_older_local_encryption_key_does_not_roll_back_listed_key(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    older = _make_encryption_assertion(
        agent_sk,
        did_key=agent_did_key,
        raw_public_key=b"\x01" * 32,
        created_at="2026-05-25T12:00:00Z",
        not_before="2026-05-25T12:00:00Z",
    )
    newer = _make_encryption_assertion(
        agent_sk,
        did_key=agent_did_key,
        raw_public_key=b"\x02" * 32,
        created_at="2026-05-25T12:01:00Z",
        not_before="2026-05-25T12:01:00Z",
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for assertion in (older, newer, older):
            body = json.dumps(assertion, separators=(",", ":")).encode()
            headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body)
            headers["X-AWID-Team-Certificate"] = cert_header
            resp = await client.put(
                "/v1/agents/me/encryption-key",
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
            assert resp.status_code == 200, resp.text

        listed = await client.get("/v1/agents", headers={
            **_signed_request(agent_sk, agent_did_key, "backend:acme.com"),
            "X-AWID-Team-Certificate": cert_header,
        })

    assert listed.status_code == 200, listed.text
    [agent] = listed.json()["agents"]
    assert agent["encryption_key"]["encryption_key_id"] == newer["encryption_key_id"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_team_controller_substitution(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    assertion = _make_encryption_assertion(team_sk, did_key=agent_did_key)
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "invalid_encryption_key_assertion"
    assert "invalid signature" in resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_empty_local_stable_id_field(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="local",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        "alice",
    )

    assertion = _make_encryption_assertion(agent_sk, did_key=agent_did_key)
    assertion["identity_stable_id"] = ""
    assertion["signature"] = sign_message(
        agent_sk,
        canonical_json_bytes({k: v for k, v in assertion.items() if k != "signature"}),
    )
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 422, resp.text
    assert "omit identity_stable_id" in resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_requires_global_stable_id(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    stable_id = "did:aw:2exampleglobal"

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id="backend:acme.com",
        alias="alice",
        identity_scope="global",
    )
    cert["member_did_aw"] = stable_id
    cert["signature"] = sign_message(
        team_sk,
        canonical_json_bytes({k: v for k, v in cert.items() if k != "signature"}),
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com", team_did_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, $5, 'global', 'active')
        """,
        uuid4(),
        "backend:acme.com",
        agent_did_key,
        stable_id,
        "alice",
    )

    assertion = _make_encryption_assertion(agent_sk, did_key=agent_did_key)
    body_bytes = json.dumps(assertion, separators=(",", ":")).encode()
    headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        missing = await client.put(
            "/v1/agents/me/encryption-key",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

        good_assertion = _make_encryption_assertion(
            agent_sk,
            did_key=agent_did_key,
            stable_id=stable_id,
            raw_public_key=b"\x02" * 32,
        )
        good_body = json.dumps(good_assertion, separators=(",", ":")).encode()
        good_headers = _signed_request(agent_sk, agent_did_key, "backend:acme.com", good_body)
        good_headers["X-AWID-Team-Certificate"] = cert_header
        ok = await client.put(
            "/v1/agents/me/encryption-key",
            content=good_body,
            headers={**good_headers, "Content-Type": "application/json"},
        )

    assert missing.status_code == 422, missing.text
    assert "identity_stable_id" in missing.json()["detail"]["message"]
    assert ok.status_code == 200, ok.text
    assert ok.json()["encryption_key"]["identity_stable_id"] == stable_id
