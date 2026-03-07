"""Tests for policies CRUD: create, list, get, activate."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _init_project(c: AsyncClient, slug: str = "pol-test", alias: str = "alice") -> str:
    """Bootstrap a project and return the API key."""
    resp = await c.post("/v1/init", json={"project_slug": slug, "alias": alias})
    assert resp.status_code == 200, resp.text
    return resp.json()["api_key"]


@pytest.mark.asyncio
async def test_create_policy(aweb_db_infra):
    """POST /v1/policies creates a versioned policy."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            resp = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"rules": ["be nice"]}},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["version"] == 1
            assert "policy_id" in body
            assert body["content"] == {"rules": ["be nice"]}


@pytest.mark.asyncio
async def test_create_increments_version(aweb_db_infra):
    """Each POST /v1/policies increments the version number."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            r1 = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"v": 1}},
            )
            r2 = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"v": 2}},
            )
            assert r1.json()["version"] == 1
            assert r2.json()["version"] == 2


@pytest.mark.asyncio
async def test_list_policies(aweb_db_infra):
    """GET /v1/policies returns all versions, newest first."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            await c.post("/v1/policies", headers=auth(api_key), json={"content": {"v": 1}})
            await c.post("/v1/policies", headers=auth(api_key), json={"content": {"v": 2}})

            resp = await c.get("/v1/policies", headers=auth(api_key))
            assert resp.status_code == 200, resp.text
            items = resp.json()["policies"]
            assert len(items) == 2
            # Newest first
            assert items[0]["version"] == 2
            assert items[1]["version"] == 1


@pytest.mark.asyncio
async def test_get_policy_by_id(aweb_db_infra):
    """GET /v1/policies/{policy_id} returns full policy with content."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            created = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"greeting": "hello"}},
            )
            policy_id = created.json()["policy_id"]

            resp = await c.get(f"/v1/policies/{policy_id}", headers=auth(api_key))
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["policy_id"] == policy_id
            assert body["version"] == 1
            assert body["content"] == {"greeting": "hello"}


@pytest.mark.asyncio
async def test_get_policy_not_found(aweb_db_infra):
    """GET /v1/policies/{bad_id} returns 404."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            resp = await c.get(
                "/v1/policies/00000000-0000-0000-0000-000000000000",
                headers=auth(api_key),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_activate_policy(aweb_db_infra):
    """POST /v1/policies/{policy_id}/activate sets the active policy."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            created = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"v": 1}},
            )
            policy_id = created.json()["policy_id"]

            resp = await c.post(
                f"/v1/policies/{policy_id}/activate",
                headers=auth(api_key),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["activated"] is True
            assert body["active_policy_id"] == policy_id


@pytest.mark.asyncio
async def test_get_active_policy(aweb_db_infra):
    """GET /v1/policies/active returns the activated policy."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            created = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"active": True}},
            )
            policy_id = created.json()["policy_id"]
            await c.post(f"/v1/policies/{policy_id}/activate", headers=auth(api_key))

            resp = await c.get("/v1/policies/active", headers=auth(api_key))
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["policy_id"] == policy_id
            assert body["content"] == {"active": True}


@pytest.mark.asyncio
async def test_get_active_policy_none(aweb_db_infra):
    """GET /v1/policies/active returns 404 when no policy is active."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_key = await _init_project(c)
            resp = await c.get("/v1/policies/active", headers=auth(api_key))
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_activate_wrong_project(aweb_db_infra):
    """Cannot activate a policy from another project."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            key_a = await _init_project(c, slug="proj-a", alias="alice")
            key_b = await _init_project(c, slug="proj-b", alias="bob")

            created = await c.post(
                "/v1/policies",
                headers=auth(key_a),
                json={"content": {"owner": "a"}},
            )
            policy_id = created.json()["policy_id"]

            # Try to activate project A's policy using project B's key
            resp = await c.post(
                f"/v1/policies/{policy_id}/activate",
                headers=auth(key_b),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_policies_scoped_to_project(aweb_db_infra):
    """Policies from other projects are not visible."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            key_a = await _init_project(c, slug="scope-a", alias="alice")
            key_b = await _init_project(c, slug="scope-b", alias="bob")

            await c.post("/v1/policies", headers=auth(key_a), json={"content": {"a": 1}})
            await c.post("/v1/policies", headers=auth(key_b), json={"content": {"b": 1}})

            resp_a = await c.get("/v1/policies", headers=auth(key_a))
            resp_b = await c.get("/v1/policies", headers=auth(key_b))

            assert len(resp_a.json()["policies"]) == 1
            assert len(resp_b.json()["policies"]) == 1
            assert resp_a.json()["policies"][0]["policy_id"] != resp_b.json()["policies"][0]["policy_id"]
