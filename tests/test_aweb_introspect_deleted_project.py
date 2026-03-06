"""Tests: introspect must not return agent data for soft-deleted projects (aweb-c91, aweb-rt7)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra


async def _setup_agent_with_key(aweb_db) -> dict:
    """Create project + agent + active API key directly in the DB."""
    namespace_id = uuid.uuid4()
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    slug = f"test/delproj-{uuid.uuid4().hex[:6]}"

    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_id,
        "test-ns",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        slug,
        "Deleted Project Test",
        namespace_id,
    )
    await aweb_db.execute(
        """INSERT INTO {{tables.agents}}
           (agent_id, project_id, alias, human_name, agent_type, lifetime, namespace_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        agent_id,
        project_id,
        "agent-x",
        "Agent X",
        "agent",
        "persistent",
        namespace_id,
    )
    key = f"aw_sk_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    await aweb_db.execute(
        """INSERT INTO {{tables.api_keys}}
           (project_id, agent_id, key_prefix, key_hash, is_active)
           VALUES ($1, $2, $3, $4, true)""",
        project_id,
        agent_id,
        key[:12],
        hash_api_key(key),
    )
    return {
        "project_id": project_id,
        "agent_id": agent_id,
        "slug": slug,
        "namespace_slug": "test-ns",
        "api_key": key,
    }


@pytest.mark.asyncio
async def test_introspect_excludes_deleted_project(aweb_db_infra):
    """Introspect should not return namespace_slug/address/alias for a soft-deleted project."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent_with_key(aweb_db)

    # Soft-delete the project
    await aweb_db.execute(
        "UPDATE {{tables.projects}} SET deleted_at = NOW() WHERE project_id = $1",
        env["project_id"],
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {env['api_key']}"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            # Agent data should NOT be present when project is deleted
            assert "namespace_slug" not in body
            assert "address" not in body
            assert "alias" not in body


@pytest.mark.asyncio
async def test_introspect_includes_live_project(aweb_db_infra):
    """Introspect returns namespace_slug/address/alias for a live project (positive case)."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent_with_key(aweb_db)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {env['api_key']}"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == env["namespace_slug"]
            assert body["address"] == f"{env['namespace_slug']}/agent-x"
            assert body["alias"] == "agent-x"


@pytest.mark.asyncio
async def test_list_agents_excludes_deleted_project(aweb_db_infra):
    """GET /v1/agents should 404 when project is soft-deleted."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent_with_key(aweb_db)

    # Soft-delete the project
    await aweb_db.execute(
        "UPDATE {{tables.projects}} SET deleted_at = NOW() WHERE project_id = $1",
        env["project_id"],
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents",
                headers={"Authorization": f"Bearer {env['api_key']}"},
            )
            assert resp.status_code == 404
