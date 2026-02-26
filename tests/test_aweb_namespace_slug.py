"""Tests for namespace_slug and address fields in introspect and agents-list (aweb-0s4)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


async def _init_project(client: AsyncClient, slug: str, alias: str) -> dict:
    """Bootstrap a project + agent + API key via /v1/init."""
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": slug,
            "project_name": f"Project {slug}",
            "alias": alias,
            "human_name": f"Human {alias}",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_introspect_returns_namespace_slug_and_address(aweb_db_infra):
    """GET /v1/auth/introspect includes namespace_slug and address."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            data = await _init_project(c, "test/ns-introspect", "alice")
            resp = await c.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {data['api_key']}"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == "test/ns-introspect"
            assert body["address"] == "test/ns-introspect/alice"
            assert body["access_mode"] == "open"


@pytest.mark.asyncio
async def test_introspect_no_namespace_slug_for_cross_project(aweb_db_infra):
    """Introspect must not return namespace_slug when agent doesn't match project."""
    # This test reuses the cross-project scoping logic from test_aweb_introspect_scoping.
    # When agent_id doesn't match an agent in the authenticated project,
    # namespace_slug and address should not be present.
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_a = uuid.uuid4()
    project_b = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_a,
        "ns-cross-a",
        "Project A",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_b,
        "ns-cross-b",
        "Project B",
    )

    victim_agent_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type)
        VALUES ($1, $2, $3, $4, $5)
        """,
        victim_agent_id,
        project_b,
        "victim",
        "Victim",
        "agent",
    )

    token = "aw_sk_" + uuid.uuid4().hex + uuid.uuid4().hex
    key_prefix = token[:12]
    await aweb_db.execute(
        """
        INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active)
        VALUES ($1, $2, $3, $4, true)
        """,
        project_a,
        victim_agent_id,
        key_prefix,
        hash_api_key(token),
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            res = await c.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200, res.text
            payload = res.json()
            assert "namespace_slug" not in payload
            assert "address" not in payload


@pytest.mark.asyncio
async def test_list_agents_returns_namespace_slug(aweb_db_infra):
    """GET /v1/agents response includes namespace_slug."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            data = await _init_project(c, "test/ns-agents", "bob")
            resp = await c.get(
                "/v1/agents",
                headers={"Authorization": f"Bearer {data['api_key']}"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == "test/ns-agents"
