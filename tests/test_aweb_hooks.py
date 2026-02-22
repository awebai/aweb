"""Tests for mutation hooks (app.state.on_mutation callback)."""

from __future__ import annotations

import base64
import json
import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.custody import encrypt_signing_key
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, encode_public_key, generate_keypair


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


# --- Identity lifecycle hooks ---


@pytest.mark.asyncio
async def test_agent_created_hook(aweb_db_infra):
    """agent.created fires when /v1/init creates a new agent."""
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={"project_slug": "hook-created-test", "alias": "newagent"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["created"] is True

    created_events = [(e, ctx) for e, ctx in events if e == "agent.created"]
    assert len(created_events) == 1
    _, ctx = created_events[0]
    assert ctx["agent_id"] == data["agent_id"]
    assert ctx["project_id"] == data["project_id"]
    assert ctx["alias"] == "newagent"
    assert "did" in ctx
    assert "custody" in ctx
    assert ctx["lifetime"] == "persistent"


@pytest.mark.asyncio
async def test_agent_created_hook_not_fired_on_reconnect(aweb_db_infra):
    """agent.created does NOT fire when /v1/init reconnects an existing agent."""
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # First call creates
            resp1 = await c.post(
                "/v1/init",
                json={"project_slug": "hook-reconnect-test", "alias": "existingagent"},
            )
            assert resp1.status_code == 200
            assert resp1.json()["created"] is True

            events.clear()
            # Second call reconnects
            resp2 = await c.post(
                "/v1/init",
                json={"project_slug": "hook-reconnect-test", "alias": "existingagent"},
            )
            assert resp2.status_code == 200
            assert resp2.json()["created"] is False

    created_events = [(e, ctx) for e, ctx in events if e == "agent.created"]
    assert len(created_events) == 0


def _make_rotation_signature(
    old_private_key: bytes, old_did: str, new_did: str, timestamp: str
) -> str:
    payload = json.dumps(
        {"new_did": new_did, "old_did": old_did, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(old_private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


async def _seed_for_rotate(aweb_db_infra):
    """Seed a persistent self-custodial agent for rotation testing."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "hook-rotate",
        "Hook Rotate",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        "rotator",
        "Rotator",
        "agent",
        did,
        encode_public_key(public_key),
        "self",
        "persistent",
        "active",
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
        "private_key": private_key,
        "public_key": public_key,
        "did": did,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_agent_key_rotated_hook(aweb_db_infra):
    """agent.key_rotated fires on PUT /v1/agents/me/rotate."""
    seed = await _seed_for_rotate(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    new_private_key, new_public_key = generate_keypair()
    new_did = did_from_public_key(new_public_key)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_signature(seed["private_key"], seed["did"], new_did, timestamp)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": encode_public_key(new_public_key),
                    "custody": "self",
                    "timestamp": timestamp,
                    "rotation_signature": proof,
                },
            )
            assert resp.status_code == 200, resp.text

    rotated_events = [(e, ctx) for e, ctx in events if e == "agent.key_rotated"]
    assert len(rotated_events) == 1
    _, ctx = rotated_events[0]
    assert ctx["agent_id"] == seed["agent_id"]
    assert ctx["project_id"] == seed["project_id"]
    assert ctx["old_did"] == seed["did"]
    assert ctx["new_did"] == new_did
    assert ctx["custody"] == "self"


async def _seed_for_deregister(aweb_db_infra):
    """Seed an ephemeral custodial agent for deregistration testing."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    master_key = secrets.token_bytes(32)
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    encrypted_key = encrypt_signing_key(private_key, master_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "hook-dereg",
        "Hook Dereg",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, signing_key_enc, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        agent_id,
        project_id,
        "ephemeral-a",
        "Ephemeral A",
        "agent",
        did,
        encode_public_key(public_key),
        "custodial",
        encrypted_key,
        "ephemeral",
        "active",
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
        "did": did,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_agent_deregistered_hook(aweb_db_infra):
    """agent.deregistered fires on DELETE /v1/agents/me."""
    seed = await _seed_for_deregister(aweb_db_infra)
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text

    dereg_events = [(e, ctx) for e, ctx in events if e == "agent.deregistered"]
    assert len(dereg_events) == 1
    _, ctx = dereg_events[0]
    assert ctx["agent_id"] == seed["agent_id"]
    assert ctx["project_id"] == seed["project_id"]
    assert ctx["did"] == seed["did"]


async def _seed_for_retire(aweb_db_infra):
    """Seed a persistent custodial agent + successor for retirement testing."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    master_key = secrets.token_bytes(32)
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    encrypted_key = encrypt_signing_key(private_key, master_key)
    _, succ_pub = generate_keypair()
    succ_did = did_from_public_key(succ_pub)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    successor_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "hook-retire",
        "Hook Retire",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, signing_key_enc, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        agent_id,
        project_id,
        "retiree",
        "Retiree",
        "agent",
        did,
        encode_public_key(public_key),
        "custodial",
        encrypted_key,
        "persistent",
        "active",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        successor_id, project_id, "successor", "Successor", "agent",
        succ_did, encode_public_key(succ_pub), "persistent", "active",
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
        "successor_id": str(successor_id),
        "did": did,
        "api_key": api_key,
        "master_key": master_key,
    }


@pytest.mark.asyncio
async def test_agent_retired_hook(aweb_db_infra, monkeypatch):
    """agent.retired fires on PUT /v1/agents/me/retire."""
    seed = await _seed_for_retire(aweb_db_infra)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", seed["master_key"].hex())
    events: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/retire",
                headers=_auth(seed["api_key"]),
                json={"successor_agent_id": seed["successor_id"]},
            )
            assert resp.status_code == 200, resp.text

    retired_events = [(e, ctx) for e, ctx in events if e == "agent.retired"]
    assert len(retired_events) == 1
    _, ctx = retired_events[0]
    assert ctx["agent_id"] == seed["agent_id"]
    assert ctx["project_id"] == seed["project_id"]
    assert ctx["did"] == seed["did"]
    assert ctx["successor_agent_id"] == seed["successor_id"]
