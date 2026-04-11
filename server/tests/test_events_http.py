"""HTTP-level regression tests for GET /v1/events/stream."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
import aweb.routes.events as events_module
from aweb.routes.events import router as events_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(team_sk, team_did_key, member_did_key, **kwargs):
    cert = {
        "version": 1,
        "certificate_id": kwargs.get("certificate_id", "cert-001"),
        "team_id": kwargs.get("team_id", "backend:acme.com"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": kwargs.get("member_did_aw", ""),
        "member_address": kwargs.get("member_address", ""),
        "alias": kwargs.get("alias", "bob"),
        "lifetime": kwargs.get("lifetime", "persistent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    cert["signature"] = sign_message(team_sk, payload)
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_request(agent_sk, agent_did_key, team_id, body_bytes=b""):
    import hashlib

    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team_id": team_id,
        "timestamp": timestamp,
    })
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, team_did_key):
    app = FastAPI()
    app.include_router(events_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    import hashlib as _hashlib
    from unittest.mock import AsyncMock

    @app.middleware("http")
    async def cache_body(request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            request.state.cached_body = b""
            request.state.body_sha256 = _hashlib.sha256(b"").hexdigest()
            return await call_next(request)

        original_receive = request._receive
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = _hashlib.sha256(body).hexdigest()
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

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry
    return app


@pytest.mark.asyncio
async def test_events_stream_includes_existing_unread_mail(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="backend:acme.com",
        alias="bob",
        lifetime="persistent",
        member_did_aw="did:aw:bob",
    )
    cert_header = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )

    alice = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, address, lifetime, role)
        VALUES ($1, $2, 'alice', 'acme.com/alice', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        alice_did_key,
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'bob', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        bob_did_key,
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (from_did, to_did, from_alias, to_alias, subject, body, team_id, from_agent_id, to_agent_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        alice_did_key,
        bob_did_key,
        "alice",
        "bob",
        "",
        "hello from alice",
        "backend:acme.com",
        alice["agent_id"],
        bob["agent_id"],
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    headers = _signed_request(bob_sk, bob_did_key, "backend:acme.com")
    headers["X-AWID-Team-Certificate"] = cert_header

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/events/stream", params={"deadline": deadline}, headers=headers)

    assert resp.status_code == 200
    assert "event: connected" in resp.text
    assert '"team_id": "backend:acme.com"' in resp.text
    assert "event: actionable_mail" in resp.text
    assert '"from_alias": "alice"' in resp.text
    assert f'"from_did": "{alice_did_key}"' in resp.text
    assert '"from_address": "acme.com/alice"' in resp.text


@pytest.mark.asyncio
async def test_events_stream_matches_unread_mail_across_viewer_dids(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="backend:acme.com",
        alias="bob",
        lifetime="persistent",
        member_did_aw="did:aw:bob",
    )
    cert_header = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )

    alice = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, address, lifetime, role)
        VALUES ($1, $2, $3, 'alice', 'acme.com/alice', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        alice_did_key,
        "did:aw:alice",
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'bob', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        bob_did_key,
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (from_did, to_did, from_alias, to_alias, subject, body, team_id, from_agent_id, to_agent_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        "did:aw:alice",
        "did:aw:bob",
        "alice",
        "bob",
        "",
        "hello stable bob",
        "backend:acme.com",
        alice["agent_id"],
        bob["agent_id"],
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    headers = _signed_request(bob_sk, bob_did_key, "backend:acme.com")
    headers["X-AWID-Team-Certificate"] = cert_header

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/events/stream", params={"deadline": deadline}, headers=headers)

    assert resp.status_code == 200
    assert "event: actionable_mail" in resp.text
    assert '"from_alias": "alice"' in resp.text
    assert '"from_address": "acme.com/alice"' in resp.text


@pytest.mark.asyncio
async def test_current_actionable_mail_includes_from_stable_id_for_current_sender_key(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, subject, body, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        """,
        uuid4(),
        "did:key:z6MkAliceCurrent",
        "did:aw:bob",
        "",
        "hello",
        "body",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )

    actionable = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob", "did:key:z6MkBobCurrent"],
    )

    assert len(actionable) == 1
    assert actionable[0]["from_did"] == "did:key:z6MkAliceCurrent"
    assert actionable[0]["from_stable_id"] == "did:aw:alice"
    assert actionable[0]["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_events_stream_matches_pending_chat_across_viewer_dids(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="backend:acme.com",
        alias="bob",
        lifetime="persistent",
        member_did_aw="did:aw:bob",
    )
    cert_header = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )

    alice = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, address, lifetime, role)
        VALUES ($1, $2, $3, 'alice', 'acme.com/alice', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        alice_did_key,
        "did:aw:alice",
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'bob', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        bob_did_key,
    )
    session = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_sessions}} (team_id, created_by)
        VALUES ($1, $2)
        RETURNING session_id
        """,
        "backend:acme.com",
        "did:aw:alice",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES
            ($1, $2, $3, 'alice'),
            ($1, $4, $5, 'bob')
        """,
        session["session_id"],
        "did:aw:alice",
        alice["agent_id"],
        "did:aw:bob",
        bob["agent_id"],
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_agent_id, from_did, from_alias, body)
        VALUES ($1, $2, $3, $4, $5)
        """,
        session["session_id"],
        alice["agent_id"],
        "did:aw:alice",
        "alice",
        "hello stable bob",
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    headers = _signed_request(bob_sk, bob_did_key, "backend:acme.com")
    headers["X-AWID-Team-Certificate"] = cert_header

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/events/stream", params={"deadline": deadline}, headers=headers)

    assert resp.status_code == 200
    assert "event: actionable_chat" in resp.text
    assert '"from_alias": "alice"' in resp.text
    assert '"from_did": "did:aw:alice"' in resp.text
    assert '"from_address": "acme.com/alice"' in resp.text


@pytest.mark.asyncio
async def test_current_actionable_chat_uses_per_session_participant_lists(aweb_cloud_db, monkeypatch):
    class _DbShim:
        def __init__(self, aweb_db):
            self._aweb_db = aweb_db

        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return self._aweb_db

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'backend:acme.com', 'did:aw:alice'),
            ('22222222-2222-4222-8222-222222222222', 'backend:acme.com', 'did:aw:carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'did:aw:bob', 'bob'),
            ('11111111-1111-4111-8111-111111111111', 'did:aw:alice', 'alice'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:bob', 'bob'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:carol', 'carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'did:aw:alice', 'alice', 'hello from alice'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:carol', 'carol', 'hello from carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES
            ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAlice', 'alice', 'acme.com/alice'),
            ($2, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob'),
            ($3, 'backend:acme.com', 'did:aw:carol', 'did:key:z6MkCarol', 'carol', 'otherco/carol')
        """,
        uuid4(),
        uuid4(),
        uuid4(),
    )

    seen: dict[str, list[str]] = {}

    async def _fake_get_waiting_agents(_redis, session_id: str, participant_dids: list[str]):
        seen[session_id] = list(participant_dids)
        return list(participant_dids)

    monkeypatch.setattr(events_module, "get_waiting_agents", _fake_get_waiting_agents)

    actionable = await events_module._current_actionable_chat(
        _DbShim(aweb_cloud_db.aweb_db),
        None,
        participant_dids=["did:aw:bob", "did:key:bob"],
        participant_agent_id=None,
    )

    assert seen["11111111-1111-4111-8111-111111111111"] == ["did:aw:alice"]
    assert seen["22222222-2222-4222-8222-222222222222"] == ["did:aw:carol"]
    assert {item["session_id"] for item in actionable} == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    assert all(item["sender_waiting"] is True for item in actionable)
    by_session = {item["session_id"]: item for item in actionable}
    assert by_session["11111111-1111-4111-8111-111111111111"]["from_address"] == "acme.com/alice"
    assert by_session["11111111-1111-4111-8111-111111111111"]["participant_addresses"] == [
        "acme.com/alice"
    ]


@pytest.mark.asyncio
async def test_current_actionable_chat_includes_from_stable_id_for_current_sender_key(aweb_cloud_db, monkeypatch):
    class _DbShim:
        def __init__(self, aweb_db):
            self._aweb_db = aweb_db

        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return self._aweb_db

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ('33333333-3333-4333-8333-333333333333', 'backend:acme.com', 'did:key:z6MkAliceCurrent')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ('33333333-3333-4333-8333-333333333333', 'did:aw:bob', 'bob'),
            ('33333333-3333-4333-8333-333333333333', 'did:key:z6MkAliceCurrent', 'alice')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
        VALUES ('33333333-3333-4333-8333-333333333333', 'did:key:z6MkAliceCurrent', '', 'hello from current key')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )

    async def _fake_get_waiting_agents(_redis, _session_id: str, participant_dids: list[str]):
        return list(participant_dids)

    monkeypatch.setattr(events_module, "get_waiting_agents", _fake_get_waiting_agents)

    actionable = await events_module._current_actionable_chat(
        _DbShim(aweb_cloud_db.aweb_db),
        None,
        participant_dids=["did:aw:bob", "did:key:z6MkBobCurrent"],
        participant_agent_id=None,
    )

    assert len(actionable) == 1
    assert actionable[0]["from_did"] == "did:key:z6MkAliceCurrent"
    assert actionable[0]["from_stable_id"] == "did:aw:alice"
    assert actionable[0]["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_current_actionable_mail_keeps_newest_unread_in_diff_window(aweb_cloud_db):
    created_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAlice', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )
    for i in range(50):
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.messages}}
                (message_id, from_did, to_did, from_alias, to_alias, subject, body, created_at)
            VALUES ($1, 'did:aw:alice', 'did:aw:bob', 'alice', 'bob', $2, $3, $4)
            """,
            f"00000000-0000-4000-8000-{i + 1:012d}",
            f"old-{i}",
            f"old-body-{i}",
            created_at + timedelta(minutes=i),
        )

    previous = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob"],
    )
    assert len(previous) == 50

    newest_message_id = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body, created_at)
        VALUES ($1, 'did:aw:alice', 'did:aw:bob', 'alice', 'bob', 'newest', 'newest-body', $2)
        """,
        newest_message_id,
        created_at + timedelta(hours=2),
    )

    current = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob"],
    )
    changed = events_module._new_or_changed_events(
        current,
        events_module._index_events(previous, key_field="message_id"),
        key_field="message_id",
    )

    assert newest_message_id in {item["message_id"] for item in current}
    assert newest_message_id in {item["message_id"] for item in changed}
