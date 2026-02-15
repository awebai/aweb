"""Tests for mutation hooks (app.state.on_mutation callback)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed(aweb_db_infra: DatabaseInfra):
    """Create a project with two agents and return (project_id, a1_id, a2_id, key1, key2)."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    project_id = uuid.uuid4()
    a1_id = uuid.uuid4()
    a2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "hooks-test",
        "Hooks Test",
    )
    for aid, alias, name in [(a1_id, "alice", "Alice"), (a2_id, "bob", "Bob")]:
        await aweb_db.execute(
            "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
            "VALUES ($1, $2, $3, $4, $5)",
            aid,
            project_id,
            alias,
            name,
            "agent",
        )

    key1 = f"aw_sk_{uuid.uuid4().hex}"
    key2 = f"aw_sk_{uuid.uuid4().hex}"
    for aid, key in [(a1_id, key1), (a2_id, key2)]:
        await aweb_db.execute(
            "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
            "VALUES ($1, $2, $3, $4, $5)",
            project_id,
            aid,
            key[:12],
            hash_api_key(key),
            True,
        )

    return project_id, a1_id, a2_id, key1, key2


@pytest.mark.asyncio
async def test_message_sent_hook(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/messages",
                headers=_auth(key1),
                json={"to_agent_id": str(a2_id), "subject": "hi", "body": "hello"},
            )
            assert resp.status_code == 200, resp.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "message.sent"
    assert ctx["from_agent_id"] == str(a1_id)
    assert ctx["to_agent_id"] == str(a2_id)
    assert ctx["subject"] == "hi"
    assert "message_id" in ctx


@pytest.mark.asyncio
async def test_message_acknowledged_hook(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            send = await c.post(
                "/v1/messages",
                headers=_auth(key1),
                json={"to_agent_id": str(a2_id), "subject": "hi", "body": "hello"},
            )
            message_id = send.json()["message_id"]

            events.clear()
            ack = await c.post(
                f"/v1/messages/{message_id}/ack",
                headers=_auth(key2),
            )
            assert ack.status_code == 200, ack.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "message.acknowledged"
    assert ctx["message_id"] == message_id
    assert ctx["agent_id"] == str(a2_id)


@pytest.mark.asyncio
async def test_chat_message_sent_hook_create_session(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/chat/sessions",
                headers=_auth(key1),
                json={"to_aliases": ["bob"], "message": "hey bob"},
            )
            assert resp.status_code == 200, resp.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "chat.message_sent"
    assert ctx["from_agent_id"] == str(a1_id)
    assert "session_id" in ctx
    assert "message_id" in ctx


@pytest.mark.asyncio
async def test_chat_message_sent_hook_existing_session(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Create session first
            create = await c.post(
                "/v1/chat/sessions",
                headers=_auth(key1),
                json={"to_aliases": ["bob"], "message": "hey"},
            )
            session_id = create.json()["session_id"]

            events.clear()
            # Send in existing session
            resp = await c.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(key2),
                json={"body": "hi alice"},
            )
            assert resp.status_code == 200, resp.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "chat.message_sent"
    assert ctx["session_id"] == session_id
    assert ctx["from_agent_id"] == str(a2_id)
    assert "message_id" in ctx


@pytest.mark.asyncio
async def test_reservation_acquired_hook(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/reservations",
                headers=_auth(key1),
                json={"resource_key": "src/main.py", "ttl_seconds": 120},
            )
            assert resp.status_code == 200, resp.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "reservation.acquired"
    assert ctx["resource_key"] == "src/main.py"
    assert ctx["holder_agent_id"] == str(a1_id)
    assert ctx["ttl_seconds"] == 120


@pytest.mark.asyncio
async def test_reservation_released_hook(aweb_db_infra):
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/v1/reservations",
                headers=_auth(key1),
                json={"resource_key": "src/main.py", "ttl_seconds": 120},
            )

            events.clear()
            resp = await c.post(
                "/v1/reservations/release",
                headers=_auth(key1),
                json={"resource_key": "src/main.py"},
            )
            assert resp.status_code == 200, resp.text

    assert len(events) == 1
    etype, ctx = events[0]
    assert etype == "reservation.released"
    assert ctx["resource_key"] == "src/main.py"
    assert ctx["holder_agent_id"] == str(a1_id)


@pytest.mark.asyncio
async def test_hook_failure_does_not_break_route(aweb_db_infra):
    """A broken callback must not affect the route's response."""
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)

    async def broken_hook(event_type: str, context: dict) -> None:
        raise RuntimeError("callback exploded")

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = broken_hook

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/messages",
                headers=_auth(key1),
                json={"to_agent_id": str(a2_id), "subject": "hi", "body": "hello"},
            )
            assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_no_hook_set_works_fine(aweb_db_infra):
    """Routes work normally when no on_mutation callback is registered."""
    project_id, a1_id, a2_id, key1, key2 = await _seed(aweb_db_infra)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    # Explicitly don't set app.state.on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/messages",
                headers=_auth(key1),
                json={"to_agent_id": str(a2_id), "subject": "hi", "body": "hello"},
            )
            assert resp.status_code == 200, resp.text
