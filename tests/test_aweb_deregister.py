"""Tests for DELETE /v1/agents/me — ephemeral agent self-deregistration (aweb-fj2.15)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.custody import encrypt_signing_key
from aweb.did import did_from_public_key, encode_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_ephemeral_agent(aweb_db, *, project_slug: str, alias: str, master_key: bytes):
    """Create a project with an ephemeral custodial agent (with encrypted signing key)."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    encrypted_key = encrypt_signing_key(private_key, master_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        project_slug,
        f"Project {project_slug}",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, signing_key_enc, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        agent_id,
        project_id,
        alias,
        f"Human {alias}",
        "agent",
        did,
        encode_public_key(public_key),
        "custodial",
        encrypted_key,
        "ephemeral",
        "active",
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "did": did,
        "api_key": api_key,
    }


async def _seed_persistent_agent_with_key(aweb_db, *, project_slug: str):
    """Create a persistent self-custodial agent with its own API key."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        project_slug,
        f"Project {project_slug}",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        "persistent-agent",
        "Persistent Agent",
        "agent",
        did,
        encode_public_key(public_key),
        "self",
        "persistent",
        "active",
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    return {"agent_id": str(agent_id), "api_key": api_key}


@pytest.mark.asyncio
async def test_deregister_ephemeral_agent(aweb_db_infra, monkeypatch):
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(
        aweb_db, project_slug="dereg-test", alias="alice", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["agent_id"]
            assert body["status"] == "deregistered"


@pytest.mark.asyncio
async def test_deregister_clears_signing_key(aweb_db_infra, monkeypatch):
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(
        aweb_db, project_slug="key-clear", alias="bob", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200

    # Verify signing key is destroyed and agent is soft-deleted
    row = await aweb_db.fetch_one(
        "SELECT signing_key_enc, status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )
    assert row["signing_key_enc"] is None
    assert row["status"] == "deregistered"
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_deregister_creates_log_entry(aweb_db_infra, monkeypatch):
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(
        aweb_db, project_slug="log-test", alias="charlie", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )

    log = await aweb_db.fetch_one(
        "SELECT operation, old_did FROM {{tables.agent_log}} WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )
    assert log is not None
    assert log["operation"] == "deregister"
    assert log["old_did"] == seed["did"]


@pytest.mark.asyncio
async def test_deregister_rejects_persistent_agent(aweb_db_infra, monkeypatch):
    """A persistent agent trying to self-deregister gets 400."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    persistent = await _seed_persistent_agent_with_key(aweb_db, project_slug="persist-test")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(persistent["api_key"]),
            )
            assert resp.status_code == 400
            assert (
                "persistent" in resp.json()["detail"].lower()
                or "retire" in resp.json()["detail"].lower()
            )


@pytest.mark.asyncio
async def test_deregister_alias_reusable_after(aweb_db_infra, monkeypatch):
    """After deregistration, the alias should be reusable for a new agent."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(
        aweb_db, project_slug="reuse-test", alias="alice", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200

    # Create a new agent with the same alias — should succeed
    new_agent_id = uuid.uuid4()
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        new_agent_id,
        uuid.UUID(seed["project_id"]),
        "alice",
        "New Alice",
        "agent",
        did,
        encode_public_key(public_key),
        "custodial",
        "ephemeral",
    )
    row = await aweb_db.fetch_one(
        "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1",
        new_agent_id,
    )
    assert row["alias"] == "alice"


@pytest.mark.asyncio
async def test_deregister_twice_returns_404(aweb_db_infra, monkeypatch):
    """Deregistering the same agent twice should return 404 the second time."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(
        aweb_db, project_slug="double-dereg", alias="agent", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp1 = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp1.status_code == 200

            resp2 = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_deregister_requires_auth(aweb_db_infra, monkeypatch):
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete("/v1/agents/me")
            assert resp.status_code in (401, 403)
