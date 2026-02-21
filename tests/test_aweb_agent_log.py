"""Tests for GET /v1/agents/{agent_id}/log — lifecycle audit trail (aweb-fj2.16)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_agent_with_log(aweb_db, *, slug: str = "log-proj", alias: str = "agent"):
    """Create a project + agent + API key + log entries."""
    _, public_key = generate_keypair()
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
        public_key.hex(),
        "self",
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

    # Add log entries
    await aweb_db.execute(
        "INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, new_did) VALUES ($1, $2, $3, $4)",
        agent_id,
        project_id,
        "create",
        did,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did, new_did, signed_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        agent_id,
        project_id,
        "rotate",
        did,
        "did:key:zNewKey",
        did,
    )

    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "slug": slug,
        "alias": alias,
        "did": did,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_agent_log_returns_entries(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_agent_with_log(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                f"/v1/agents/{seed['agent_id']}/log",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["agent_id"]
            assert body["address"] == f"{seed['slug']}/{seed['alias']}"
            assert len(body["log"]) == 2

            # Ordered by created_at ASC
            assert body["log"][0]["operation"] == "create"
            assert body["log"][0]["new_did"] == seed["did"]
            assert body["log"][1]["operation"] == "rotate"
            assert body["log"][1]["old_did"] == seed["did"]
            assert body["log"][1]["new_did"] == "did:key:zNewKey"
            assert body["log"][1]["signed_by"] == seed["did"]


@pytest.mark.asyncio
async def test_agent_log_empty_for_no_entries(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create agent without adding log entries
    _, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "empty-log",
        "Empty Log",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        agent_id,
        project_id,
        "no-log-agent",
        "No Log",
        "agent",
        did,
        public_key.hex(),
        "self",
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

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                f"/v1/agents/{agent_id}/log",
                headers=_auth(api_key),
            )
            assert resp.status_code == 200
            assert resp.json()["log"] == []


@pytest.mark.asyncio
async def test_agent_log_404_unknown_agent(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_agent_with_log(aweb_db, slug="unknown-log")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                f"/v1/agents/{uuid.uuid4()}/log",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_agent_log_cross_project_forbidden(aweb_db_infra):
    """An agent in project A cannot read logs for an agent in project B."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_a = await _seed_agent_with_log(aweb_db, slug="log-proj-a", alias="alice")

    # Create a separate project B with its own agent
    _, pub_b = generate_keypair()
    did_b = did_from_public_key(pub_b)
    proj_b_id = uuid.uuid4()
    agent_b_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        proj_b_id,
        "log-proj-b",
        "Project B",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        agent_b_id,
        proj_b_id,
        "bob",
        "Bob",
        "agent",
        did_b,
        pub_b.hex(),
        "self",
        "persistent",
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Agent A tries to read agent B's log
            resp = await c.get(
                f"/v1/agents/{agent_b_id}/log",
                headers=_auth(seed_a["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_agent_log_includes_all_fields(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_agent_with_log(aweb_db, slug="full-fields")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                f"/v1/agents/{seed['agent_id']}/log",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200
            entry = resp.json()["log"][0]
            # All expected fields present
            assert "log_id" in entry
            assert "operation" in entry
            assert "old_did" in entry
            assert "new_did" in entry
            assert "signed_by" in entry
            assert "entry_signature" in entry
            assert "metadata" in entry
            assert "created_at" in entry


@pytest.mark.asyncio
async def test_agent_log_requires_auth(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/v1/agents/{uuid.uuid4()}/log")
            assert resp.status_code in (401, 403)
