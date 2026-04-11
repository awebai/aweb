from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import Address, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER, MessagingAuth, get_messaging_auth
from aweb.routes import chat as chat_routes
from aweb.routes.chat import router as chat_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _signed_identity_headers(agent_sk, agent_did_key, did_aw: str, body_bytes=b""):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "did_aw": did_aw,
            "timestamp": timestamp,
        }
    )
    sig = sign_message(agent_sk, payload)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        IDENTITY_DID_AW_HEADER: did_aw,
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, registry):
    app = FastAPI()
    app.include_router(chat_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    @app.middleware("http")
    async def cache_body(request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            request.state.cached_body = b""
            request.state.body_sha256 = hashlib.sha256(b"").hexdigest()
            return await call_next(request)

        original_receive = request._receive
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        replayed = False

        async def _receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            while True:
                message = await original_receive()
                if message["type"] == "http.disconnect":
                    return message
                if message["type"] == "http.request" and not message.get("more_body", False):
                    continue
                return message

        request._receive = _receive
        return await call_next(request)

    app.state.db = _DbShim()
    app.state.redis = None
    app.state.rate_limiter = None
    app.state.awid_registry_client = registry
    return app


@pytest.mark.asyncio
async def test_create_chat_session_accepts_identity_auth_and_to_did(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'everyone')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(
        return_value=[
            Address(
                address_id="addr-1",
                domain="acme.com",
                name="alice",
                did_aw="did:aw:alice",
                current_did_key=alice_did_key,
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        ]
    )
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_dids": ["did:aw:bob"], "message": "hello bob"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["session_id"]
    assert {participant["did"] for participant in payload["participants"]} == {"did:aw:alice", "did:aw:bob"}
    assert {participant["address"] for participant in payload["participants"]} == {"acme.com/alice", "otherco.com/bob"}


@pytest.mark.asyncio
async def test_create_chat_session_returns_403_for_policy_violation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'nobody')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_dids": ["did:aw:bob"], "message": "blocked"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_accepts_signed_from_did_key_for_team_context(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _team_auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _team_auth_override

    payload = {
        "to_aliases": ["bob"],
        "message": "hello bob",
        "from_did": alice_did_key,
        "signature": "sig",
        "message_id": "11111111-1111-4111-8111-111111111111",
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"]
    assert {participant["alias"] for participant in body["participants"]} == {"alice", "bob"}


@pytest.mark.asyncio
async def test_chat_send_message_accepts_signed_from_did_key_for_team_context(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    session_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.chat_sessions}} (team_id, created_by)
        VALUES ('backend:acme.com', 'alice')
        RETURNING session_id
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    registry = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _team_auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _team_auth_override

    payload = {
        "body": "follow-up",
        "from_did": alice_did_key,
        "signature": "sig",
        "message_id": "22222222-2222-4222-8222-222222222222",
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["delivered"] is True


@pytest.mark.asyncio
async def test_chat_pending_matches_unread_mail_and_sessions_across_actor_dids(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES
            ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice'),
            ($2, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob')
        """,
        uuid4(),
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:aw:bob', 'bob', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at)
        VALUES ($1, 'did:aw:bob', 'did:key:z6MkAliceCurrent', 'bob', 'alice', 'hi', 'mail body', 'normal', $2)
        """,
        uuid4(),
        created_at + timedelta(minutes=2),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["messages_waiting"] == 1
    assert len(body["pending"]) == 1
    assert body["pending"][0]["session_id"] == str(session_id)
    assert body["pending"][0]["last_message"] == "ping"
    assert body["pending"][0]["last_from_address"] == "acme.com/bob"
    assert body["pending"][0]["participant_addresses"] == ["acme.com/bob"]


@pytest.mark.asyncio
async def test_chat_pending_excludes_all_actor_dids_from_waiting_lookup(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:aw:bob', 'bob', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    captured: dict[str, list[str]] = {}

    async def _fake_waiting_by_session(_redis, wanted):
        captured.update(wanted)
        return {key: [] for key in wanted}

    app.dependency_overrides[get_messaging_auth] = _auth_override
    monkeypatch.setattr(chat_routes, "get_waiting_agents_by_session", _fake_waiting_by_session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    assert captured == {str(session_id): ["did:aw:bob"]}


@pytest.mark.asyncio
async def test_chat_pending_preserves_last_from_did_without_address_mapping(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', '')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:aw:bob', '', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["pending"]) == 1
    assert body["pending"][0]["last_from_address"] == ""
    assert body["pending"][0]["last_from_did"] == "did:aw:bob"
    assert body["pending"][0]["participant_dids"] == ["did:aw:bob"]


@pytest.mark.asyncio
async def test_chat_pending_includes_last_from_stable_id_for_current_sender_key(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at)
        VALUES ($1, 'backend:acme.com', 'did:key:z6MkAliceCurrent', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', '')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:key:z6MkAliceCurrent', '', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkBobCurrent",
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["pending"]) == 1
    assert body["pending"][0]["last_from_did"] == "did:key:z6MkAliceCurrent"
    assert body["pending"][0]["last_from_stable_id"] == "did:aw:alice"
    assert body["pending"][0]["last_from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_chat_send_message_accepts_alternate_session_participant_did(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob')
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    payload = {"body": "follow-up"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 200, resp.text
    assert resp.json()["delivered"] is True


@pytest.mark.asyncio
async def test_chat_history_and_read_accept_alternate_session_participant_did(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    message_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:aw:bob', 'bob', 'hello', $3)
        """,
        message_id,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    monkeypatch.setattr(chat_routes, "publish_chat_session_signal", AsyncMock(return_value=1))

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        read = await client.post(
            f"/v1/chat/sessions/{session_id}/read",
            json={"up_to_message_id": str(message_id)},
        )

    assert history.status_code == 200, history.text
    assert [item["body"] for item in history.json()["messages"]] == ["hello"]
    assert read.status_code == 200, read.text
    assert read.json()["messages_marked"] == 1


@pytest.mark.asyncio
async def test_chat_stream_accepts_alternate_session_participant_did(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    seen: dict[str, str] = {}

    async def _fake_sse_events(*, viewer_did: str, contact_owner_dids: list[str], **kwargs):
        seen["viewer_did"] = viewer_did
        seen["contact_owner_dids"] = contact_owner_dids
        yield ": keepalive\n\n"

    monkeypatch.setattr(chat_routes, "_sse_events", _fake_sse_events)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=5.0) as client:
        resp = await client.get(f"/v1/chat/sessions/{session_id}/stream", params={"deadline": deadline})

    assert resp.status_code == 200, resp.text
    assert "keepalive" in resp.text
    assert seen == {
        "viewer_did": "did:key:z6MkAliceCurrent",
        "contact_owner_dids": ["did:aw:alice", "did:key:z6MkAliceCurrent"],
    }


@pytest.mark.asyncio
async def test_chat_session_list_accepts_alternate_session_participant_did(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob')
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/chat/sessions")

    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions"] == [
        {
            "session_id": str(session_id),
            "participants": ["bob"],
            "participant_dids": ["did:aw:bob"],
            "participant_addresses": ["acme.com/bob"],
            "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sender_waiting": False,
        }
    ]
