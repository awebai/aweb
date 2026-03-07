"""Tests for agent profile fields: role, program, context."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_init_with_role_and_program(aweb_db_infra):
    """POST /v1/init accepts role and program, returned in introspect."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "profile-test",
                    "alias": "alice",
                    "role": "coordinator",
                    "program": "claude-code",
                },
            )
            assert resp.status_code == 200, resp.text

            api_key = resp.json()["api_key"]
            intro = await c.get("/v1/auth/introspect", headers=auth(api_key))
            assert intro.status_code == 200, intro.text
            body = intro.json()
            assert body["role"] == "coordinator"
            assert body["program"] == "claude-code"


@pytest.mark.asyncio
async def test_init_with_context_json(aweb_db_infra):
    """POST /v1/init accepts context JSONB, returned in introspect."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    ctx = {"repo": "github.com/org/repo", "branch": "main"}
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "ctx-test",
                    "alias": "bob",
                    "context": ctx,
                },
            )
            assert resp.status_code == 200, resp.text

            api_key = resp.json()["api_key"]
            intro = await c.get("/v1/auth/introspect", headers=auth(api_key))
            assert intro.status_code == 200, intro.text
            body = intro.json()
            assert body["context"] == ctx


@pytest.mark.asyncio
async def test_patch_agent_role_and_program(aweb_db_infra):
    """PATCH /v1/agents/me updates role and program."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={"project_slug": "patch-profile", "alias": "carol"},
            )
            api_key = resp.json()["api_key"]

            patch = await c.patch(
                "/v1/agents/me",
                headers=auth(api_key),
                json={"role": "developer", "program": "cursor"},
            )
            assert patch.status_code == 200, patch.text
            body = patch.json()
            assert body["role"] == "developer"
            assert body["program"] == "cursor"


@pytest.mark.asyncio
async def test_patch_agent_context(aweb_db_infra):
    """PATCH /v1/agents/me updates context JSONB."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    ctx = {"repo": "github.com/org/new-repo", "branch": "feature"}
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={"project_slug": "patch-ctx", "alias": "dave"},
            )
            api_key = resp.json()["api_key"]

            patch = await c.patch(
                "/v1/agents/me",
                headers=auth(api_key),
                json={"context": ctx},
            )
            assert patch.status_code == 200, patch.text
            assert patch.json()["context"] == ctx

            # Verify persisted via introspect
            intro = await c.get("/v1/auth/introspect", headers=auth(api_key))
            assert intro.json()["context"] == ctx


@pytest.mark.asyncio
async def test_list_agents_includes_profile_fields(aweb_db_infra):
    """GET /v1/agents includes role, program, context."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "list-profile",
                    "alias": "eve",
                    "role": "reviewer",
                    "program": "aider",
                    "context": {"team": "backend"},
                },
            )
            api_key = resp.json()["api_key"]

            agents = await c.get("/v1/agents", headers=auth(api_key))
            assert agents.status_code == 200, agents.text
            items = agents.json()["agents"]
            assert len(items) >= 1
            eve = next(a for a in items if a["alias"] == "eve")
            assert eve["role"] == "reviewer"
            assert eve["program"] == "aider"
            assert eve["context"] == {"team": "backend"}


@pytest.mark.asyncio
async def test_profile_fields_default_to_none(aweb_db_infra):
    """Profile fields are None when not set."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={"project_slug": "no-profile", "alias": "frank"},
            )
            api_key = resp.json()["api_key"]

            intro = await c.get("/v1/auth/introspect", headers=auth(api_key))
            body = intro.json()
            assert body.get("role") is None
            assert body.get("program") is None
            assert body.get("context") is None
