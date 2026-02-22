"""Tests for GET /v1/agents/resolve/{namespace}/{alias} — cross-project agent resolution (aweb-fj2.9)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.did import did_from_public_key, encode_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_project_with_identity(aweb_db, *, slug: str, alias: str, custody: str = "self"):
    """Create a project with one agent that has DID/identity fields populated."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        f"Project {slug}",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        agent_id,
        project_id,
        alias,
        f"Human {alias}",
        "agent",
        did,
        encode_public_key(public_key),
        custody,
        "persistent",
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
        "slug": slug,
        "alias": alias,
        "did": did,
        "public_key": encode_public_key(public_key),
        "custody": custody,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_resolve_returns_agent_identity(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_identity(aweb_db, slug="mycompany", alias="researcher")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/mycompany/researcher",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["did"] == seed["did"]
            assert body["address"] == "mycompany/researcher"
            assert body["agent_id"] == seed["agent_id"]
            assert body["human_name"] == "Human researcher"
            assert body["public_key"] == seed["public_key"]
            assert body["server"] == "https://app.claweb.ai"
            assert body["custody"] == "self"
            assert body["lifetime"] == "persistent"
            assert body["status"] == "active"


@pytest.mark.asyncio
async def test_resolve_cross_project(aweb_db_infra, monkeypatch):
    """An agent in project A can resolve an agent in project B."""
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Project A
    seed_a = await _seed_project_with_identity(aweb_db, slug="org-alpha", alias="alice")
    # Project B
    seed_b = await _seed_project_with_identity(aweb_db, slug="org-beta", alias="bob")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Agent in project A resolves agent in project B
            resp = await c.get(
                "/v1/agents/resolve/org-beta/bob",
                headers=_auth(seed_a["api_key"]),
            )
            assert resp.status_code == 200
            assert resp.json()["did"] == seed_b["did"]
            assert resp.json()["address"] == "org-beta/bob"


@pytest.mark.asyncio
async def test_resolve_404_unknown_namespace(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_identity(aweb_db, slug="exists", alias="agent")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/nonexistent/agent",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resolve_404_unknown_alias(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_identity(aweb_db, slug="mycompany", alias="researcher")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/mycompany/unknown",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resolve_excludes_deleted_agents(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_identity(aweb_db, slug="deleteme", alias="gone")

    # Soft-delete the agent
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET deleted_at = NOW() WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )

    # Need a live agent to authenticate with
    seed2 = await _seed_project_with_identity(aweb_db, slug="alive", alias="here")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/deleteme/gone",
                headers=_auth(seed2["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resolve_requires_auth(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/agents/resolve/mycompany/researcher")
            assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_resolve_custodial_ephemeral_agent(aweb_db_infra, monkeypatch):
    """Resolve an ephemeral custodial agent — should return correct lifetime and custody."""
    monkeypatch.setenv("AWEB_SERVER_URL", "https://app.claweb.ai")
    aweb_db = aweb_db_infra.get_manager("aweb")

    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "beadhub-proj",
        "BeadHub",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        agent_id,
        project_id,
        "alice",
        "Alice",
        "agent",
        did,
        encode_public_key(public_key),
        "custodial",
        "ephemeral",
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

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/beadhub-proj/alice",
                headers=_auth(api_key),
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["custody"] == "custodial"
            assert body["lifetime"] == "ephemeral"
            assert body["did"] == did


@pytest.mark.asyncio
async def test_resolve_server_url_defaults_to_empty(aweb_db_infra, monkeypatch):
    """When AWEB_SERVER_URL is not set, server field should be empty string."""
    monkeypatch.delenv("AWEB_SERVER_URL", raising=False)
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_identity(aweb_db, slug="no-server", alias="agent")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/resolve/no-server/agent",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200
            assert resp.json()["server"] == ""
