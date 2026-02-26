"""Tests for is_contact field on inbox messages and chat events (aweb-n5c)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


async def _setup_two_agents(aweb_db):
    """Create a project with two agents and API keys directly in the DB."""
    project_id = uuid.uuid4()
    agent_a_id = uuid.uuid4()
    agent_b_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        f"test/iscontact-{uuid.uuid4().hex[:6]}",
        "Is-Contact Test",
    )
    slug_row = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1", project_id
    )
    slug = slug_row["slug"]

    for aid, alias in [(agent_a_id, "alice"), (agent_b_id, "bob")]:
        await aweb_db.execute(
            """INSERT INTO {{tables.agents}}
               (agent_id, project_id, alias, human_name, agent_type)
               VALUES ($1, $2, $3, $4, $5)""",
            aid,
            project_id,
            alias,
            alias.title(),
            "agent",
        )

    key_a = f"aw_sk_{uuid.uuid4().hex}"
    key_b = f"aw_sk_{uuid.uuid4().hex}"
    for aid, key in [(agent_a_id, key_a), (agent_b_id, key_b)]:
        await aweb_db.execute(
            """INSERT INTO {{tables.api_keys}}
               (project_id, agent_id, key_prefix, key_hash, is_active)
               VALUES ($1, $2, $3, $4, true)""",
            project_id,
            aid,
            key[:12],
            hash_api_key(key),
        )

    return {
        "project_id": project_id,
        "slug": slug,
        "alice_id": agent_a_id,
        "bob_id": agent_b_id,
        "alice_key": key_a,
        "bob_key": key_b,
    }


async def _add_contact(aweb_db, project_id, address):
    """Insert a contact row directly."""
    await aweb_db.execute(
        "INSERT INTO {{tables.contacts}} (project_id, contact_address) VALUES ($1, $2)",
        project_id,
        address,
    )


async def _send_message(client, from_key, to_alias):
    """Send a message within the same project."""
    resp = await client.post(
        "/v1/messages",
        json={"to_alias": to_alias, "subject": "test", "body": "hello"},
        headers=_auth(from_key),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_inbox_is_contact_true(aweb_db_infra):
    """Inbox messages from a contact have is_contact=True."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_two_agents(aweb_db)

    # bob adds alice's address as a contact
    await _add_contact(aweb_db, env["project_id"], f"{env['slug']}/alice")

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            # alice sends to bob
            await _send_message(c, env["alice_key"], "bob")

            # bob checks inbox
            resp = await c.get("/v1/messages/inbox", headers=_auth(env["bob_key"]))
            assert resp.status_code == 200, resp.text
            msgs = resp.json()["messages"]
            assert len(msgs) >= 1
            assert msgs[0]["is_contact"] is True


@pytest.mark.asyncio
async def test_inbox_is_contact_false(aweb_db_infra):
    """Inbox messages from a non-contact have is_contact=False."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_two_agents(aweb_db)

    # No contact added
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            await _send_message(c, env["alice_key"], "bob")

            resp = await c.get("/v1/messages/inbox", headers=_auth(env["bob_key"]))
            assert resp.status_code == 200, resp.text
            msgs = resp.json()["messages"]
            assert len(msgs) >= 1
            assert msgs[0]["is_contact"] is False


@pytest.mark.asyncio
async def test_inbox_is_contact_org_level(aweb_db_infra):
    """Org-level contact matches any agent in that namespace."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_two_agents(aweb_db)

    # bob adds alice's org (not specific alias) as contact
    await _add_contact(aweb_db, env["project_id"], env["slug"])

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            await _send_message(c, env["alice_key"], "bob")

            resp = await c.get("/v1/messages/inbox", headers=_auth(env["bob_key"]))
            assert resp.status_code == 200, resp.text
            msgs = resp.json()["messages"]
            assert len(msgs) >= 1
            assert msgs[0]["is_contact"] is True


@pytest.mark.asyncio
async def test_chat_history_is_contact(aweb_db_infra, async_redis):
    """Chat history messages include is_contact field."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_two_agents(aweb_db)

    # alice adds bob as contact
    await _add_contact(aweb_db, env["project_id"], f"{env['slug']}/bob")

    app = create_app(db_infra=aweb_db_infra, redis=async_redis)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            # Create a chat session (alice → bob, with initial message)
            resp = await c.post(
                "/v1/chat/sessions",
                json={"to_aliases": ["bob"], "message": "hello from alice"},
                headers=_auth(env["alice_key"]),
            )
            assert resp.status_code in (200, 201), resp.text
            session_id = resp.json()["session_id"]

            # bob sends a reply
            resp = await c.post(
                f"/v1/chat/sessions/{session_id}/messages",
                json={"body": "hello from bob"},
                headers=_auth(env["bob_key"]),
            )
            assert resp.status_code in (200, 201), resp.text

            # alice reads history — bob is a contact
            resp = await c.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(env["alice_key"]),
            )
            assert resp.status_code == 200, resp.text
            msgs = resp.json()["messages"]
            assert len(msgs) >= 1
            bob_msg = [m for m in msgs if m["from_agent"] == "bob"][0]
            assert bob_msg["is_contact"] is True


@pytest.mark.asyncio
async def test_chat_history_is_contact_false(aweb_db_infra, async_redis):
    """Chat history messages from non-contacts have is_contact=False."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_two_agents(aweb_db)

    # No contact added
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/v1/chat/sessions",
                json={"to_aliases": ["bob"], "message": "hello from alice"},
                headers=_auth(env["alice_key"]),
            )
            assert resp.status_code in (200, 201), resp.text
            session_id = resp.json()["session_id"]

            resp = await c.post(
                f"/v1/chat/sessions/{session_id}/messages",
                json={"body": "hello from bob"},
                headers=_auth(env["bob_key"]),
            )
            assert resp.status_code in (200, 201), resp.text

            resp = await c.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(env["alice_key"]),
            )
            assert resp.status_code == 200, resp.text
            msgs = resp.json()["messages"]
            assert len(msgs) >= 1
            bob_msg = [m for m in msgs if m["from_agent"] == "bob"][0]
            assert bob_msg["is_contact"] is False
