from __future__ import annotations

import json
import os
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.awid.custody import encrypt_signing_key, reset_custody_key_cache
from aweb.awid.did import did_from_public_key, encode_public_key, generate_keypair
from aweb.awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.db import get_db_infra
from aweb.mcp.auth import AuthContext, _auth_context
from aweb.mcp.tools.signing import sign as mcp_sign
from aweb.ratelimit import MemoryFixedWindowRateLimiter
from aweb.redis_client import get_redis
from aweb.routes.custody_sign import router as custody_sign_router
from aweb.routes.init import bootstrap_router


class _FakeRedis:
    async def eval(self, _script: str, _num_keys: int, _key: str, _window_seconds: int) -> int:
        return 1


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db, server_db):
        self._aweb_db = aweb_db
        self._server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        if name == "server":
            return self._server_db
        raise KeyError(name)


def _build_app(*, aweb_db, server_db) -> FastAPI:
    app = FastAPI(title="aweb custody sign test")
    app.include_router(bootstrap_router)
    app.include_router(custody_sign_router)
    app.state.db = _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.state.rate_limiter = MemoryFixedWindowRateLimiter()
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture(autouse=True)
def _reset_custody_env():
    original = os.environ.get("AWEB_CUSTODY_KEY")
    reset_custody_key_cache()
    yield
    if original is None:
        os.environ.pop("AWEB_CUSTODY_KEY", None)
    else:
        os.environ["AWEB_CUSTODY_KEY"] = original
    reset_custody_key_cache()


async def _create_project(client: AsyncClient, *, slug: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/create-project",
        json={
            "project_slug": slug,
            "namespace_slug": slug,
            "alias": "alice",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _set_agent_custody(aweb_db, *, agent_id: str, custody: str, signing_key_enc, did: str, public_key: str) -> None:
    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET custody = $2,
            signing_key_enc = $3,
            did = $4,
            public_key = $5
        WHERE agent_id = $1
        """,
        uuid.UUID(agent_id),
        custody,
        signing_key_enc,
        did,
        public_key,
    )


@pytest.mark.asyncio
async def test_custody_sign_route_signs_arbitrary_payload(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    master_key = bytes.fromhex("22" * 32)
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    encrypted = encrypt_signing_key(signing_key, master_key)
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    reset_custody_key_cache()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await _create_project(client, slug=f"custody-sign-{uuid.uuid4().hex[:8]}")
        await _set_agent_custody(
            aweb_cloud_db.aweb_db,
            agent_id=created["agent_id"],
            custody="custodial",
            signing_key_enc=encrypted,
            did=did_key,
            public_key=encode_public_key(public_key),
        )

        payload = {
            "domain": "registry.example",
            "key": "did:aw:example",
            "operation": "register_address",
        }
        response = await client.post(
            "/v1/custody/sign",
            headers=_auth_headers(created["api_key"]),
            json={"sign_payload": payload},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["did_key"] == did_key
    assert data["signature"]
    assert data["timestamp"]

    verify_did_key_signature(
        did_key=data["did_key"],
        payload=canonical_json_bytes({**payload, "timestamp": data["timestamp"]}),
        signature_b64=data["signature"],
    )


@pytest.mark.asyncio
async def test_custody_sign_route_rejects_self_custodial_agent(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await _create_project(client, slug=f"custody-self-{uuid.uuid4().hex[:8]}")
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET custody = 'self',
                signing_key_enc = NULL
            WHERE agent_id = $1
            """,
            uuid.UUID(created["agent_id"]),
        )
        response = await client.post(
            "/v1/custody/sign",
            headers=_auth_headers(created["api_key"]),
            json={"sign_payload": {"domain": "registry.example", "operation": "lookup"}},
        )

    assert response.status_code == 400, response.text
    assert response.json() == {"detail": "Only custodial agents may use this endpoint"}


@pytest.mark.asyncio
async def test_custody_sign_route_requires_authentication(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/custody/sign",
            json={"sign_payload": {"domain": "registry.example", "operation": "lookup"}},
        )

    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Authentication required"}


@pytest.mark.asyncio
async def test_custody_sign_route_returns_503_when_custody_key_missing(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    master_key = bytes.fromhex("55" * 32)
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    encrypted = encrypt_signing_key(signing_key, master_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await _create_project(client, slug=f"custody-missing-key-{uuid.uuid4().hex[:8]}")
        await _set_agent_custody(
            aweb_cloud_db.aweb_db,
            agent_id=created["agent_id"],
            custody="custodial",
            signing_key_enc=encrypted,
            did=did_key,
            public_key=encode_public_key(public_key),
        )
        os.environ.pop("AWEB_CUSTODY_KEY", None)
        reset_custody_key_cache()
        response = await client.post(
            "/v1/custody/sign",
            headers=_auth_headers(created["api_key"]),
            json={"sign_payload": {"domain": "registry.example", "operation": "lookup"}},
        )

    assert response.status_code == 503, response.text
    assert "AWEB_CUSTODY_KEY not set" in response.json()["detail"]


@pytest.mark.asyncio
async def test_custody_sign_route_returns_503_when_did_missing(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    master_key = bytes.fromhex("44" * 32)
    signing_key, public_key = generate_keypair()
    encrypted = encrypt_signing_key(signing_key, master_key)
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    reset_custody_key_cache()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await _create_project(client, slug=f"custody-missing-did-{uuid.uuid4().hex[:8]}")
        await _set_agent_custody(
            aweb_cloud_db.aweb_db,
            agent_id=created["agent_id"],
            custody="custodial",
            signing_key_enc=encrypted,
            did="",
            public_key=encode_public_key(public_key),
        )
        response = await client.post(
            "/v1/custody/sign",
            headers=_auth_headers(created["api_key"]),
            json={"sign_payload": {"domain": "registry.example", "operation": "lookup"}},
        )

    assert response.status_code == 503, response.text
    assert "has no did:key configured" in response.json()["detail"]


@pytest.mark.asyncio
async def test_custody_sign_route_rate_limits_per_agent(aweb_cloud_db):
    app = _build_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    master_key = bytes.fromhex("66" * 32)
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    encrypted = encrypt_signing_key(signing_key, master_key)
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    reset_custody_key_cache()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await _create_project(client, slug=f"custody-rate-limit-{uuid.uuid4().hex[:8]}")
        await _set_agent_custody(
            aweb_cloud_db.aweb_db,
            agent_id=created["agent_id"],
            custody="custodial",
            signing_key_enc=encrypted,
            did=did_key,
            public_key=encode_public_key(public_key),
        )
        headers = _auth_headers(created["api_key"])
        for i in range(60):
            response = await client.post(
                "/v1/custody/sign",
                headers=headers,
                json={"sign_payload": {"operation": "lookup", "attempt": i}},
            )
            assert response.status_code == 200, response.text

        limited = await client.post(
            "/v1/custody/sign",
            headers=headers,
            json={"sign_payload": {"operation": "lookup", "attempt": 61}},
        )

    assert limited.status_code == 429, limited.text
    assert limited.json() == {"detail": "rate limit exceeded"}
    assert limited.headers["X-RateLimit-Limit"] == "60"
    assert limited.headers["Retry-After"]


@pytest.mark.asyncio
async def test_mcp_sign_tool_returns_signed_payload_components(aweb_cloud_db):
    db_infra = _DbInfra(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    master_key = bytes.fromhex("33" * 32)
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    encrypted = encrypt_signing_key(signing_key, master_key)
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    reset_custody_key_cache()

    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        f"mcp-sign-{project_id.hex[:8]}",
        "MCP Sign Test",
    )
    await aweb_cloud_db.oss_db.execute(
        """
        INSERT INTO {{tables.projects}} (id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        f"mcp-sign-{project_id.hex[:8]}",
        "MCP Sign Test",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, custody, did, public_key,
             signing_key_enc, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        "alice",
        "Alice",
        "agent",
        "custodial",
        did_key,
        encode_public_key(public_key),
        encrypted,
        "persistent",
    )

    token = _auth_context.set(AuthContext(project_id=str(project_id), agent_id=str(agent_id)))
    try:
        result = json.loads(
            await mcp_sign(
                db_infra,
                sign_payload={"domain": "registry.example", "key": "did:aw:example"},
            )
        )
    finally:
        _auth_context.reset(token)

    assert result["did_key"] == did_key
    assert result["signature"]
    assert result["timestamp"]
    verify_did_key_signature(
        did_key=result["did_key"],
        payload=canonical_json_bytes(
            {
                "domain": "registry.example",
                "key": "did:aw:example",
                "timestamp": result["timestamp"],
            }
        ),
        signature_b64=result["signature"],
    )


@pytest.mark.asyncio
async def test_mcp_sign_tool_returns_error_for_self_custodial_agent(aweb_cloud_db):
    db_infra = _DbInfra(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        f"mcp-self-{project_id.hex[:8]}",
        "MCP Self Test",
    )
    await aweb_cloud_db.oss_db.execute(
        """
        INSERT INTO {{tables.projects}} (id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        f"mcp-self-{project_id.hex[:8]}",
        "MCP Self Test",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        agent_id,
        project_id,
        "alice",
        "Alice",
        "agent",
        "self",
        "ephemeral",
    )

    token = _auth_context.set(AuthContext(project_id=str(project_id), agent_id=str(agent_id)))
    try:
        result = json.loads(await mcp_sign(db_infra, sign_payload={"domain": "registry.example"}))
    finally:
        _auth_context.reset(token)

    assert result == {"error": "Only custodial agents may use this tool"}
