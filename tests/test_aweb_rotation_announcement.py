"""Tests for rotation announcement storage and per-peer injection (aweb-fj2.12)."""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _make_rotation_signature(
    old_private_key: bytes, old_did: str, new_did: str, timestamp: str
) -> str:
    """Sign the canonical rotation payload with the old key."""
    payload = json.dumps(
        {"new_did": new_did, "old_did": old_did, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(old_private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


async def _seed_two_agents(aweb_db, *, slug: str = "ann-proj"):
    """Create a project with two persistent self-custodial agents."""
    project_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        f"Project {slug}",
    )

    agents = []
    for alias in ("alice", "bob"):
        private_key, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        agent_id = uuid.uuid4()
        await aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, project_id, alias, human_name, agent_type,
                 did, public_key, custody, lifetime, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        agents.append(
            {
                "project_id": str(project_id),
                "agent_id": str(agent_id),
                "private_key": private_key,
                "public_key": public_key,
                "did": did,
                "api_key": api_key,
                "alias": alias,
            }
        )

    return agents


@pytest.mark.asyncio
async def test_rotation_stores_announcement(aweb_db_infra):
    """After key rotation, a rotation_announcement row should be stored."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    agents = await _seed_two_agents(aweb_db, slug="ann-store")
    alice = agents[0]

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_signature(alice["private_key"], alice["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(alice["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_signature": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200

    row = await aweb_db.fetch_one(
        "SELECT old_did, new_did, rotation_timestamp, old_key_signature "
        "FROM {{tables.rotation_announcements}} WHERE agent_id = $1",
        uuid.UUID(alice["agent_id"]),
    )
    assert row is not None
    assert row["old_did"] == alice["did"]
    assert row["new_did"] == new_did
    assert row["rotation_timestamp"] == timestamp
    assert row["old_key_signature"] == proof


@pytest.mark.asyncio
async def test_inbox_includes_rotation_announcement(aweb_db_infra):
    """When Alice rotates her key and sends a message to Bob,
    Bob's inbox should include the rotation_announcement on that message."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    agents = await _seed_two_agents(aweb_db, slug="ann-inbox")
    alice, bob = agents[0], agents[1]

    # Rotate Alice's key
    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_signature(alice["private_key"], alice["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Rotate
            resp = await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(alice["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_signature": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200

            # Alice sends Bob a message
            resp = await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={
                    "to_alias": "bob",
                    "subject": "hello",
                    "body": "test message",
                },
            )
            assert resp.status_code == 200

            # Bob checks inbox
            resp = await c.get(
                "/v1/messages/inbox",
                headers=_auth(bob["api_key"]),
            )
            assert resp.status_code == 200
            messages = resp.json()["messages"]
            assert len(messages) == 1

            msg = messages[0]
            assert "rotation_announcement" in msg
            ann = msg["rotation_announcement"]
            assert ann["old_did"] == alice["did"]
            assert ann["new_did"] == new_did
            assert ann["timestamp"] == timestamp
            assert ann["old_key_signature"] == proof


@pytest.mark.asyncio
async def test_announcement_stops_after_peer_responds(aweb_db_infra):
    """After Bob sends a message to Alice (acknowledging the rotation),
    subsequent messages from Alice should NOT include the announcement."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    agents = await _seed_two_agents(aweb_db, slug="ann-ack")
    alice, bob = agents[0], agents[1]

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_signature(alice["private_key"], alice["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Rotate Alice's key
            await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(alice["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_signature": proof,
                    "timestamp": timestamp,
                },
            )

            # Alice sends Bob a message (first message after rotation)
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "msg1", "body": "first"},
            )

            # Bob sends Alice a message (acknowledges the rotation)
            await c.post(
                "/v1/messages",
                headers=_auth(bob["api_key"]),
                json={"to_alias": "alice", "subject": "reply", "body": "got it"},
            )

            # Alice sends Bob another message
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "msg2", "body": "second"},
            )

            # Bob checks inbox — the second message should NOT have announcement
            resp = await c.get(
                "/v1/messages/inbox",
                headers=_auth(bob["api_key"]),
            )
            assert resp.status_code == 200
            messages = resp.json()["messages"]
            # Messages ordered DESC by created_at
            msg2 = next(m for m in messages if m["subject"] == "msg2")
            assert msg2.get("rotation_announcement") is None


@pytest.mark.asyncio
async def test_announcement_per_peer_independent(aweb_db_infra):
    """Announcement delivery is per-peer: Bob acknowledging doesn't affect
    a third agent who hasn't seen the announcement yet."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    # Create project with 3 agents
    project_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "ann-3peer",
        "Three Peer",
    )

    agents = []
    for alias in ("alice", "bob", "carol"):
        private_key, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        agent_id = uuid.uuid4()
        await aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, project_id, alias, human_name, agent_type,
                 did, public_key, custody, lifetime, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        agents.append(
            {
                "agent_id": str(agent_id),
                "private_key": private_key,
                "public_key": public_key,
                "did": did,
                "api_key": api_key,
                "alias": alias,
            }
        )

    alice, bob, carol = agents

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_signature(alice["private_key"], alice["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Rotate Alice's key
            await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(alice["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_signature": proof,
                    "timestamp": timestamp,
                },
            )

            # Alice sends Bob a message
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "hi bob", "body": "test"},
            )
            # Alice sends Carol a message
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "carol", "subject": "hi carol", "body": "test"},
            )

            # Bob acknowledges (replies to Alice)
            await c.post(
                "/v1/messages",
                headers=_auth(bob["api_key"]),
                json={"to_alias": "alice", "subject": "ack", "body": "got it"},
            )

            # Alice sends both another message
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "msg2 bob", "body": "test"},
            )
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "carol", "subject": "msg2 carol", "body": "test"},
            )

            # Bob's second message should NOT have announcement (he acknowledged)
            resp = await c.get("/v1/messages/inbox", headers=_auth(bob["api_key"]))
            bob_msgs = resp.json()["messages"]
            msg2_bob = next(m for m in bob_msgs if m["subject"] == "msg2 bob")
            assert msg2_bob.get("rotation_announcement") is None

            # Carol's second message SHOULD still have announcement (she hasn't replied)
            resp = await c.get("/v1/messages/inbox", headers=_auth(carol["api_key"]))
            carol_msgs = resp.json()["messages"]
            msg2_carol = next(m for m in carol_msgs if m["subject"] == "msg2 carol")
            assert msg2_carol.get("rotation_announcement") is not None
            assert msg2_carol["rotation_announcement"]["old_did"] == alice["did"]


@pytest.mark.asyncio
async def test_no_announcement_without_rotation(aweb_db_infra):
    """Messages from agents who haven't rotated should NOT have announcements."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    agents = await _seed_two_agents(aweb_db, slug="ann-none")
    alice, bob = agents[0], agents[1]

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "hi", "body": "no rotation"},
            )

            resp = await c.get("/v1/messages/inbox", headers=_auth(bob["api_key"]))
            messages = resp.json()["messages"]
            assert len(messages) == 1
            assert messages[0].get("rotation_announcement") is None


@pytest.mark.asyncio
async def test_announcement_expires_after_24h(aweb_db_infra):
    """Announcements older than 24 hours should not be attached."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    agents = await _seed_two_agents(aweb_db, slug="ann-expiry")
    alice, bob = agents[0], agents[1]

    new_private_key, new_public_key = generate_keypair()
    new_did = did_from_public_key(new_public_key)
    timestamp = "2026-02-20T12:00:00Z"
    proof = _make_rotation_signature(alice["private_key"], alice["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Alice rotates
            resp = await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(alice["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public_key.hex(),
                    "custody": "self",
                    "timestamp": timestamp,
                    "rotation_signature": proof,
                },
            )
            assert resp.status_code == 200, resp.text

            # Backdate the announcement to 25 hours ago
            await aweb_db.execute(
                """
                UPDATE {{tables.rotation_announcements}}
                SET created_at = NOW() - INTERVAL '25 hours'
                WHERE agent_id = $1
                """,
                uuid.UUID(alice["agent_id"]),
            )

            # Alice sends a message to Bob
            await c.post(
                "/v1/messages",
                headers=_auth(alice["api_key"]),
                json={"to_alias": "bob", "subject": "late", "body": "expired announcement"},
            )

            # Bob's inbox should NOT have the announcement (expired)
            resp = await c.get("/v1/messages/inbox", headers=_auth(bob["api_key"]))
            messages = resp.json()["messages"]
            assert len(messages) == 1
            assert messages[0].get("rotation_announcement") is None
