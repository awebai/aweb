"""Tests for contacts CRUD endpoints."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


async def _init_project(client: AsyncClient, slug: str, alias: str) -> dict:
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


def _headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_create_contact(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-create", "alice")
            headers = _headers(data["api_key"])

            resp = await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "other-org/bob", "label": "Bob"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["contact_address"] == "other-org/bob"
            assert body["label"] == "Bob"
            assert "contact_id" in body
            assert "created_at" in body


@pytest.mark.asyncio
async def test_create_contact_duplicate_conflict(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-dup", "alice")
            headers = _headers(data["api_key"])

            await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "other-org/bob"},
            )
            resp = await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "other-org/bob"},
            )
            assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_contact_self_rejected(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-self", "alice")
            headers = _headers(data["api_key"])

            resp = await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "test/contacts-self/alice"},
            )
            assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_contact_self_rejected_org_level(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-self-org", "alice")
            headers = _headers(data["api_key"])

            resp = await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "test/contacts-self-org"},
            )
            assert resp.status_code == 400


@pytest.mark.asyncio
async def test_list_contacts(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-list", "alice")
            headers = _headers(data["api_key"])

            await c.post("/v1/contacts", headers=headers, json={"contact_address": "org-a/bob"})
            await c.post("/v1/contacts", headers=headers, json={"contact_address": "org-b/carol"})

            resp = await c.get("/v1/contacts", headers=headers)
            assert resp.status_code == 200, resp.text
            contacts = resp.json()["contacts"]
            assert len(contacts) == 2
            addresses = {ct["contact_address"] for ct in contacts}
            assert addresses == {"org-a/bob", "org-b/carol"}


@pytest.mark.asyncio
async def test_list_contacts_empty(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-empty", "alice")
            headers = _headers(data["api_key"])

            resp = await c.get("/v1/contacts", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["contacts"] == []


@pytest.mark.asyncio
async def test_list_contacts_project_isolated(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            proj_a = await _init_project(c, "test/contacts-iso-a", "alice")
            proj_b = await _init_project(c, "test/contacts-iso-b", "bob")

            await c.post(
                "/v1/contacts",
                headers=_headers(proj_a["api_key"]),
                json={"contact_address": "external/x"},
            )
            await c.post(
                "/v1/contacts",
                headers=_headers(proj_b["api_key"]),
                json={"contact_address": "external/y"},
            )

            resp_a = await c.get("/v1/contacts", headers=_headers(proj_a["api_key"]))
            assert len(resp_a.json()["contacts"]) == 1
            assert resp_a.json()["contacts"][0]["contact_address"] == "external/x"

            resp_b = await c.get("/v1/contacts", headers=_headers(proj_b["api_key"]))
            assert len(resp_b.json()["contacts"]) == 1
            assert resp_b.json()["contacts"][0]["contact_address"] == "external/y"


@pytest.mark.asyncio
async def test_delete_contact(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-del", "alice")
            headers = _headers(data["api_key"])

            create_resp = await c.post(
                "/v1/contacts",
                headers=headers,
                json={"contact_address": "other/bob"},
            )
            contact_id = create_resp.json()["contact_id"]

            resp = await c.delete(f"/v1/contacts/{contact_id}", headers=headers)
            assert resp.status_code == 200

            list_resp = await c.get("/v1/contacts", headers=headers)
            assert list_resp.json()["contacts"] == []


@pytest.mark.asyncio
async def test_delete_contact_idempotent(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/contacts-del-idem", "alice")
            headers = _headers(data["api_key"])

            fake_id = str(uuid.uuid4())
            resp = await c.delete(f"/v1/contacts/{fake_id}", headers=headers)
            assert resp.status_code == 200


@pytest.mark.asyncio
async def test_delete_contact_cross_project(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            proj_a = await _init_project(c, "test/contacts-cross-a", "alice")
            proj_b = await _init_project(c, "test/contacts-cross-b", "bob")

            create_resp = await c.post(
                "/v1/contacts",
                headers=_headers(proj_a["api_key"]),
                json={"contact_address": "external/x"},
            )
            contact_id = create_resp.json()["contact_id"]

            # Project B tries to delete project A's contact
            resp = await c.delete(
                f"/v1/contacts/{contact_id}",
                headers=_headers(proj_b["api_key"]),
            )
            assert resp.status_code == 200  # Idempotent

            # Project A's contact should still exist
            list_resp = await c.get("/v1/contacts", headers=_headers(proj_a["api_key"]))
            assert len(list_resp.json()["contacts"]) == 1
