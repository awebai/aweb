"""Tests for DELETE /v1/agents/{agent_id} — ephemeral agent deregistration (aweb-fj2.15)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.custody import encrypt_signing_key
from aweb.did import did_from_public_key, generate_keypair


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
        public_key.hex(),
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


async def _seed_persistent_agent(aweb_db, *, project_id: uuid.UUID):
    """Add a persistent agent to an existing project."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    agent_id = uuid.uuid4()

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
        public_key.hex(),
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
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="dereg-test", alias="alice", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['agent_id']}",
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
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="key-clear", alias="bob", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['agent_id']}",
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
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="log-test", alias="charlie", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.delete(
                f"/v1/agents/{seed['agent_id']}",
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
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create project + ephemeral agent for auth
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="persist-test", alias="temp", master_key=master_key)
    # Add a persistent agent to the same project
    persistent = await _seed_persistent_agent(aweb_db, project_id=uuid.UUID(seed["project_id"]))

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{persistent['agent_id']}",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 400
            assert "persistent" in resp.json()["detail"].lower() or "retire" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_deregister_404_unknown_agent(aweb_db_infra, monkeypatch):
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="unknown-test", alias="agent", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{uuid.uuid4()}",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_deregister_cross_project_forbidden(aweb_db_infra, monkeypatch):
    """An agent in project A cannot deregister an agent in project B."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")

    seed_a = await _seed_ephemeral_agent(aweb_db, project_slug="proj-a", alias="alice", master_key=master_key)
    seed_b = await _seed_ephemeral_agent(aweb_db, project_slug="proj-b", alias="bob", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Agent in project A tries to deregister agent in project B
            resp = await c.delete(
                f"/v1/agents/{seed_b['agent_id']}",
                headers=_auth(seed_a["api_key"]),
            )
            assert resp.status_code == 404  # Should look like not found (don't leak cross-project info)


@pytest.mark.asyncio
async def test_deregister_alias_reusable_after(aweb_db_infra, monkeypatch):
    """After deregistration, the alias should be reusable for a new agent."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_agent(aweb_db, project_slug="reuse-test", alias="alice", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['agent_id']}",
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
        public_key.hex(),
        "custodial",
        "ephemeral",
    )
    row = await aweb_db.fetch_one(
        "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1",
        new_agent_id,
    )
    assert row["alias"] == "alice"


@pytest.mark.asyncio
async def test_deregister_requires_auth(aweb_db_infra, monkeypatch):
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(f"/v1/agents/{uuid.uuid4()}")
            assert resp.status_code in (401, 403)
