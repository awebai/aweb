"""Tests for the unified conversations listing endpoint."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


def _headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_two_agents(aweb_db_infra):
    """Seed a project with two agents and API keys."""
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "test-conv",
        "Test Conv",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
        "VALUES ($1, $2, $3, $4, $5)",
        agent_1_id,
        project_id,
        "agent-1",
        "Agent One",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
        "VALUES ($1, $2, $3, $4, $5)",
        agent_2_id,
        project_id,
        "agent-2",
        "Agent Two",
        "agent",
    )

    api_key_1 = f"aw_sk_{uuid.uuid4().hex}"
    api_key_2 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_1_id,
        api_key_1[:12],
        hash_api_key(api_key_1),
        True,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_2_id,
        api_key_2[:12],
        hash_api_key(api_key_2),
        True,
    )

    return {
        "project_id": str(project_id),
        "agent_1_id": str(agent_1_id),
        "agent_2_id": str(agent_2_id),
        "api_key_1": api_key_1,
        "api_key_2": api_key_2,
    }


@pytest.mark.asyncio
async def test_conversations_empty(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_1"]))
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["conversations"] == []
            assert body["next_cursor"] is None


@pytest.mark.asyncio
async def test_conversations_mail_standalone(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Send a standalone mail (no thread_id)
            resp = await c.post(
                "/v1/messages",
                headers=_headers(seeded["api_key_1"]),
                json={
                    "to_agent_id": seeded["agent_2_id"],
                    "subject": "Hello",
                    "body": "Hi there!",
                },
            )
            assert resp.status_code == 200, resp.text

            # Agent-2 should see it as a conversation
            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            assert resp.status_code == 200, resp.text
            convs = resp.json()["conversations"]
            assert len(convs) == 1
            assert convs[0]["conversation_type"] == "mail"
            assert convs[0]["subject"] == "Hello"
            assert "agent-1" in convs[0]["participants"]
            assert convs[0]["last_message_preview"] == "Hi there!"
            assert convs[0]["unread_count"] == 1


@pytest.mark.asyncio
async def test_conversations_mail_threaded(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Send first message to create a thread
            r1 = await c.post(
                "/v1/messages",
                headers=_headers(seeded["api_key_1"]),
                json={
                    "to_agent_id": seeded["agent_2_id"],
                    "subject": "Thread topic",
                    "body": "First message",
                },
            )
            assert r1.status_code == 200, r1.text
            thread_id = r1.json()["message_id"]

            # Send a reply in the same thread
            r2 = await c.post(
                "/v1/messages",
                headers=_headers(seeded["api_key_2"]),
                json={
                    "to_agent_id": seeded["agent_1_id"],
                    "subject": "Re: Thread topic",
                    "body": "Reply message",
                    "thread_id": thread_id,
                },
            )
            assert r2.status_code == 200, r2.text

            # Agent-1 sees one conversation (the thread) with the reply as last
            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_1"]))
            assert resp.status_code == 200, resp.text
            convs = resp.json()["conversations"]
            # Should be 1 conversation for the thread
            thread_convs = [cv for cv in convs if cv["conversation_id"] == thread_id]
            assert len(thread_convs) == 1
            assert thread_convs[0]["last_message_preview"] == "Reply message"


@pytest.mark.asyncio
async def test_conversations_chat(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Create a chat session
            r = await c.post(
                "/v1/chat/sessions",
                headers=_headers(seeded["api_key_1"]),
                json={"to_aliases": ["agent-2"], "message": "Hey chat!", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Agent-2 should see the chat as a conversation
            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            assert resp.status_code == 200, resp.text
            convs = resp.json()["conversations"]
            chat_convs = [cv for cv in convs if cv["conversation_type"] == "chat"]
            assert len(chat_convs) == 1
            assert chat_convs[0]["conversation_id"] == session_id
            assert "agent-1" in chat_convs[0]["participants"]
            assert "agent-2" in chat_convs[0]["participants"]
            assert chat_convs[0]["subject"] == ""
            assert chat_convs[0]["last_message_preview"] == "Hey chat!"


@pytest.mark.asyncio
async def test_conversations_mixed_sorted(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Send a mail first
            await c.post(
                "/v1/messages",
                headers=_headers(seeded["api_key_1"]),
                json={
                    "to_agent_id": seeded["agent_2_id"],
                    "subject": "Mail first",
                    "body": "Mail body",
                },
            )

            # Small delay to ensure ordering
            await asyncio.sleep(0.05)

            # Then a chat
            await c.post(
                "/v1/chat/sessions",
                headers=_headers(seeded["api_key_1"]),
                json={"to_aliases": ["agent-2"], "message": "Chat later", "leaving": False},
            )

            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            assert resp.status_code == 200, resp.text
            convs = resp.json()["conversations"]
            assert len(convs) == 2
            # Chat is more recent, should be first
            assert convs[0]["conversation_type"] == "chat"
            assert convs[1]["conversation_type"] == "mail"


@pytest.mark.asyncio
async def test_conversations_cursor_pagination(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Create 3 mail conversations
            for i in range(3):
                await c.post(
                    "/v1/messages",
                    headers=_headers(seeded["api_key_1"]),
                    json={
                        "to_agent_id": seeded["agent_2_id"],
                        "subject": f"Mail {i}",
                        "body": f"Body {i}",
                    },
                )
                await asyncio.sleep(0.05)

            # Fetch with limit=2
            resp = await c.get(
                "/v1/conversations",
                headers=_headers(seeded["api_key_2"]),
                params={"limit": 2},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert len(body["conversations"]) == 2
            assert body["next_cursor"] is not None

            # Fetch next page
            resp2 = await c.get(
                "/v1/conversations",
                headers=_headers(seeded["api_key_2"]),
                params={"limit": 2, "cursor": body["next_cursor"]},
            )
            assert resp2.status_code == 200, resp2.text
            body2 = resp2.json()
            assert len(body2["conversations"]) == 1
            assert body2["next_cursor"] is None


@pytest.mark.asyncio
async def test_conversations_unread_count_mail(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            thread_id = None
            for i in range(3):
                r = await c.post(
                    "/v1/messages",
                    headers=_headers(seeded["api_key_1"]),
                    json={
                        "to_agent_id": seeded["agent_2_id"],
                        "subject": "Thread",
                        "body": f"Message {i}",
                        "thread_id": thread_id,
                    },
                )
                assert r.status_code == 200, r.text
                if thread_id is None:
                    thread_id = r.json()["message_id"]

            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            convs = resp.json()["conversations"]
            thread_conv = [cv for cv in convs if cv["conversation_id"] == thread_id]
            assert len(thread_conv) == 1
            assert thread_conv[0]["unread_count"] == 3


@pytest.mark.asyncio
async def test_conversations_unread_count_chat(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Create chat and send 2 messages
            r = await c.post(
                "/v1/chat/sessions",
                headers=_headers(seeded["api_key_1"]),
                json={"to_aliases": ["agent-2"], "message": "First", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            await c.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_headers(seeded["api_key_1"]),
                json={"body": "Second"},
            )

            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            convs = resp.json()["conversations"]
            chat_conv = [cv for cv in convs if cv["conversation_id"] == session_id]
            assert len(chat_conv) == 1
            assert chat_conv[0]["unread_count"] == 2


@pytest.mark.asyncio
async def test_conversations_project_isolation(aweb_db_infra):
    """Two projects should not see each other's conversations."""
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Project A
    proj_a_id = uuid.uuid4()
    agent_a1 = uuid.uuid4()
    agent_a2 = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        proj_a_id,
        "proj-iso-a",
        "Proj A",
    )
    for aid, alias in [(agent_a1, "a1"), (agent_a2, "a2")]:
        await aweb_db.execute(
            "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
            "VALUES ($1, $2, $3, $4, $5)",
            aid,
            proj_a_id,
            alias,
            alias,
            "agent",
        )
    key_a1 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        proj_a_id,
        agent_a1,
        key_a1[:12],
        hash_api_key(key_a1),
        True,
    )

    # Project B
    proj_b_id = uuid.uuid4()
    agent_b1 = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        proj_b_id,
        "proj-iso-b",
        "Proj B",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
        "VALUES ($1, $2, $3, $4, $5)",
        agent_b1,
        proj_b_id,
        "b1",
        "b1",
        "agent",
    )
    key_b1 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        proj_b_id,
        agent_b1,
        key_b1[:12],
        hash_api_key(key_b1),
        True,
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Send a mail in project A
            await c.post(
                "/v1/messages",
                headers=_headers(key_a1),
                json={
                    "to_agent_id": str(agent_a2),
                    "subject": "Project A mail",
                    "body": "Hello A",
                },
            )

            # Project B should see nothing
            resp = await c.get("/v1/conversations", headers=_headers(key_b1))
            assert resp.status_code == 200, resp.text
            assert resp.json()["conversations"] == []


@pytest.mark.asyncio
async def test_conversations_preview_truncated(aweb_db_infra):
    seeded = await _seed_two_agents(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            long_body = "x" * 200
            await c.post(
                "/v1/messages",
                headers=_headers(seeded["api_key_1"]),
                json={
                    "to_agent_id": seeded["agent_2_id"],
                    "subject": "Long",
                    "body": long_body,
                },
            )

            resp = await c.get("/v1/conversations", headers=_headers(seeded["api_key_2"]))
            convs = resp.json()["conversations"]
            assert len(convs) == 1
            assert len(convs[0]["last_message_preview"]) == 100
