"""Tests for DID/signature fields on message and chat endpoints (aweb-fj2.10)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_project_and_agents(aweb_db):
    """Create a project with two agents and API keys. Returns IDs and keys."""
    project_id = uuid.uuid4()
    a1_id = uuid.uuid4()
    a2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        f"proj-{uuid.uuid4().hex[:8]}",
        "Test Project",
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
async def test_mail_with_signature_fields(aweb_db_infra):
    """Send a message with DID/signature fields — they should be stored and returned in inbox."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    _, _, _, key1, key2 = await _seed_project_and_agents(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Send with signature fields
            resp = await client.post(
                "/v1/messages",
                headers=_auth(key1),
                json={
                    "to_alias": "bob",
                    "subject": "signed msg",
                    "body": "hello",
                    "from_did": "did:key:zSenderDid",
                    "to_did": "did:key:zRecipientDid",
                    "signature": "base64sig",
                    "signing_key_id": "did:key:zSignerDid",
                },
            )
            assert resp.status_code == 200, resp.text

            # Check inbox returns the fields
            resp = await client.get("/v1/messages/inbox", headers=_auth(key2))
            assert resp.status_code == 200
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            msg = msgs[0]
            assert msg["from_did"] == "did:key:zSenderDid"
            assert msg["to_did"] == "did:key:zRecipientDid"
            assert msg["signature"] == "base64sig"
            assert msg["signing_key_id"] == "did:key:zSignerDid"


@pytest.mark.asyncio
async def test_mail_without_signature_fields(aweb_db_infra):
    """Send a message without DID/signature fields — backward compat, fields should be null."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    _, _, _, key1, key2 = await _seed_project_and_agents(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(key1),
                json={"to_alias": "bob", "subject": "unsigned", "body": "hi"},
            )
            assert resp.status_code == 200

            resp = await client.get("/v1/messages/inbox", headers=_auth(key2))
            assert resp.status_code == 200
            msg = resp.json()["messages"][0]
            assert msg["from_did"] is None
            assert msg["to_did"] is None
            assert msg["signature"] is None
            assert msg["signing_key_id"] is None


@pytest.mark.asyncio
async def test_chat_with_signature_fields(aweb_db_infra):
    """Chat message with DID/signature fields — stored and returned in history."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    _, _, _, key1, key2 = await _seed_project_and_agents(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create session with signature fields
            resp = await client.post(
                "/v1/chat/sessions",
                headers=_auth(key1),
                json={
                    "to_aliases": ["bob"],
                    "message": "signed chat",
                    "from_did": "did:key:zAliceDid",
                    "to_did": "did:key:zBobDid",
                    "signature": "chatsig",
                    "signing_key_id": "did:key:zAliceDid",
                },
            )
            assert resp.status_code == 200, resp.text
            session_id = resp.json()["session_id"]

            # Check history returns the fields
            resp = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(key2),
            )
            assert resp.status_code == 200
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            assert msgs[0]["from_did"] == "did:key:zAliceDid"
            assert msgs[0]["to_did"] == "did:key:zBobDid"
            assert msgs[0]["signature"] == "chatsig"
            assert msgs[0]["signing_key_id"] == "did:key:zAliceDid"

            # Send another message in existing session with signature
            resp = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(key2),
                json={
                    "body": "reply",
                    "from_did": "did:key:zBobDid",
                    "to_did": "did:key:zAliceDid",
                    "signature": "replysig",
                    "signing_key_id": "did:key:zBobDid",
                },
            )
            assert resp.status_code == 200

            # Verify both in history
            resp = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(key1),
            )
            msgs = resp.json()["messages"]
            assert len(msgs) == 2
            assert msgs[1]["from_did"] == "did:key:zBobDid"
            assert msgs[1]["signature"] == "replysig"


@pytest.mark.asyncio
async def test_chat_without_signature_fields(aweb_db_infra):
    """Chat message without DID/signature — backward compat."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    _, _, _, key1, key2 = await _seed_project_and_agents(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/chat/sessions",
                headers=_auth(key1),
                json={"to_aliases": ["bob"], "message": "unsigned chat"},
            )
            assert resp.status_code == 200
            session_id = resp.json()["session_id"]

            resp = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(key2),
            )
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            assert msgs[0]["from_did"] is None
            assert msgs[0]["to_did"] is None
            assert msgs[0]["signature"] is None
            assert msgs[0]["signing_key_id"] is None


async def _collect_sse_text(
    *, client: AsyncClient, url: str, params: dict[str, str], headers: dict[str, str]
) -> str:
    resp = await client.get(url, params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.text


@pytest.mark.asyncio
async def test_chat_sse_stream_includes_identity_fields(aweb_db_infra):
    """SSE stream replay and live messages should include identity fields."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    _, _, _, key1, key2 = await _seed_project_and_agents(aweb_db)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Send a signed message to create session
            resp = await client.post(
                "/v1/chat/sessions",
                headers=_auth(key1),
                json={
                    "to_aliases": ["bob"],
                    "message": "sse signed",
                    "from_did": "did:key:zAliceDid",
                    "to_did": "did:key:zBobDid",
                    "signature": "ssesig",
                    "signing_key_id": "did:key:zAliceDid",
                },
            )
            assert resp.status_code == 200, resp.text
            session_id = resp.json()["session_id"]

            # Collect SSE replay (use 'after' in the past to get replay)
            past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            deadline = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
            sse_text = await _collect_sse_text(
                client=client,
                url=f"/v1/chat/sessions/{session_id}/stream",
                params={"deadline": deadline, "after": past},
                headers=_auth(key2),
            )

            # Parse SSE events — find message events
            events = []
            for line in sse_text.split("\n"):
                if line.startswith("data: "):
                    events.append(json.loads(line[len("data: ") :]))

            assert len(events) >= 1
            msg_event = events[0]
            assert msg_event["from_did"] == "did:key:zAliceDid"
            assert msg_event["to_did"] == "did:key:zBobDid"
            assert msg_event["signature"] == "ssesig"
            assert msg_event["signing_key_id"] == "did:key:zAliceDid"
