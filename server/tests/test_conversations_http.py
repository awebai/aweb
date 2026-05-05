from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import Address, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER, MessagingAuth, get_messaging_auth
from aweb.routes.conversations import router as conversations_router


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
    app.include_router(conversations_router)

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
async def test_conversations_lists_identity_scoped_mail_by_current_did(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES (
            '11111111-1111-1111-1111-111111111111',
            'did:aw:alice',
            $1,
            'alice',
            'bob',
            'hello',
            'hi',
            'normal',
            NOW()
        )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(
        return_value=[
            Address(
                address_id="addr-1",
                domain="acme.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key=bob_did_key,
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        ]
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert len(conversations) == 1
    assert conversations[0]["conversation_type"] == "mail"
    assert conversations[0]["conversation_id"] is None
    assert conversations[0]["legacy_message_id"] == "11111111-1111-1111-1111-111111111111"
    assert conversations[0]["last_message_from"] == "alice"


@pytest.mark.asyncio
async def test_conversations_groups_mail_by_conversation_id(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, created_by_did, created_at, updated_at
        )
        VALUES (
            '55555555-5555-4555-8555-555555555555',
            'mail',
            'did:aw:alice',
            NOW() - INTERVAL '2 minutes',
            NOW()
        )
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, alias, address, transport_hint, role
        )
        VALUES
            ('55555555-5555-4555-8555-555555555555', 'did:aw:alice', 'alice', 'acme.com/alice', 'mail', 'initiator'),
            ('55555555-5555-4555-8555-555555555555', $1, 'bob', 'acme.com/bob', 'mail', 'participant')
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, conversation_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES
            (
                '11111111-1111-1111-1111-111111111111',
                '55555555-5555-4555-8555-555555555555',
                'did:aw:alice',
                $1,
                'alice',
                'bob',
                'first',
                'one',
                'normal',
                NOW() - INTERVAL '1 minute'
            ),
            (
                '44444444-4444-4444-4444-444444444444',
                '55555555-5555-4555-8555-555555555555',
                'did:aw:alice',
                $1,
                'alice',
                'bob',
                'second',
                'two',
                'normal',
                NOW()
            )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(
        return_value=[
            Address(
                address_id="addr-1",
                domain="acme.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key=bob_did_key,
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        ]
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert len(conversations) == 1
    assert conversations[0]["conversation_id"] == "55555555-5555-4555-8555-555555555555"
    assert conversations[0]["subject"] == "second"
    assert conversations[0]["last_message_preview"] == "two"
    assert conversations[0]["unread_count"] == 2
    assert conversations[0]["participants"] == ["alice", "bob"]


@pytest.mark.asyncio
async def test_conversations_lists_legacy_mail_messages_without_conversation_id_separately(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES
            (
                '11111111-1111-1111-1111-111111111111',
                'did:aw:alice',
                $1,
                'alice',
                'bob',
                'first',
                'one',
                'normal',
                NOW() - INTERVAL '1 minute'
            ),
            (
                '44444444-4444-4444-4444-444444444444',
                'did:aw:alice',
                $1,
                'alice',
                'bob',
                'second',
                'two',
                'normal',
                NOW()
            )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(
        return_value=[
            Address(
                address_id="addr-1",
                domain="acme.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key=bob_did_key,
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        ]
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert [item["legacy_message_id"] for item in conversations] == [
        "44444444-4444-4444-4444-444444444444",
        "11111111-1111-1111-1111-111111111111",
    ]
    assert [item.get("conversation_id") for item in conversations] == [None, None]
    assert [item["subject"] for item in conversations] == ["second", "first"]


@pytest.mark.asyncio
async def test_conversations_lists_mail_for_sender_identity(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, created_by_did, created_at, updated_at
        )
        VALUES (
            '55555555-5555-4555-8555-555555555555',
            'mail',
            $1,
            NOW() - INTERVAL '2 minutes',
            NOW()
        )
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, alias, address, transport_hint, role
        )
        VALUES
            ('55555555-5555-4555-8555-555555555555', $1, 'alice', 'acme.com/alice', 'mail', 'initiator'),
            ('55555555-5555-4555-8555-555555555555', 'did:aw:bob', 'bob', 'acme.com/bob', 'mail', 'participant')
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, conversation_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES (
            '11111111-1111-1111-1111-111111111111',
            '55555555-5555-4555-8555-555555555555',
            $1,
            'did:aw:bob',
            'alice',
            'bob',
            'sender-visible',
            'hello from alice',
            'normal',
            NOW()
        )
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
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert len(conversations) == 1
    assert conversations[0]["conversation_id"] == "55555555-5555-4555-8555-555555555555"
    assert "legacy_message_id" not in conversations[0] or conversations[0]["legacy_message_id"] is None
    assert conversations[0]["subject"] == "sender-visible"


@pytest.mark.asyncio
async def test_conversations_lists_mail_by_authoritative_participant(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            (
                'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'ops:acme.com',
                'did:key:alice-current',
                'did:aw:alice',
                'acme.com/alice',
                'alice',
                'persistent',
                'developer',
                'everyone'
            ),
            (
                'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                'ops:acme.com',
                'did:key:bob-current',
                'did:aw:bob',
                'acme.com/bob',
                'bob',
                'persistent',
                'developer',
                'everyone'
            )
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, created_by_did, created_at, updated_at
        )
        VALUES (
            '55555555-5555-4555-8555-555555555555',
            'mail',
            'did:aw:alice',
            NOW() - INTERVAL '2 minutes',
            NOW()
        )
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, transport_hint, role
        )
        VALUES
            (
                '55555555-5555-4555-8555-555555555555',
                'did:aw:alice',
                'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'alice',
                'acme.com/alice',
                'sender',
                'initiator'
            ),
            (
                '55555555-5555-4555-8555-555555555555',
                'did:aw:bob',
                'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                'bob',
                'acme.com/bob',
                'to_alias',
                'participant'
            )
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, conversation_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES (
            '11111111-1111-1111-1111-111111111111',
            '55555555-5555-4555-8555-555555555555',
            'did:key:alice-current',
            'did:key:bob-current',
            'alice',
            'bob',
            'participant-visible',
            'hello from alice',
            'normal',
            NOW()
        )
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:alice-current",
            did_aw=None,
            address="acme.com/alice",
            team_id="ops:acme.com",
            alias="alice",
            agent_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations")

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert len(conversations) == 1
    assert conversations[0]["conversation_id"] == "55555555-5555-4555-8555-555555555555"
    assert conversations[0]["participant_dids"] == ["did:aw:alice", "did:aw:bob"]
    assert conversations[0]["participant_addresses"] == ["acme.com/alice", "acme.com/bob"]
    assert conversations[0]["subject"] == "participant-visible"


@pytest.mark.asyncio
async def test_conversations_mail_isolation_excludes_other_identities(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    carol_sk, _, carol_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES (
            '11111111-1111-1111-1111-111111111111',
            'did:aw:alice',
            $1,
            'alice',
            'bob',
            'hello',
            'hi',
            'normal',
            NOW()
        )
        """,
        bob_did_key,
    )

    registry = AsyncMock()

    async def resolve_key(did_aw: str):
        if did_aw == "did:aw:bob":
            return KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key)
        if did_aw == "did:aw:carol":
            return KeyResolution(did_aw="did:aw:carol", current_did_key=carol_did_key)
        raise AssertionError(f"unexpected did_aw {did_aw}")

    async def list_did_addresses(did_aw: str):
        if did_aw == "did:aw:bob":
            return [
                Address(
                    address_id="addr-1",
                    domain="acme.com",
                    name="bob",
                    did_aw="did:aw:bob",
                    current_did_key=bob_did_key,
                    reachability="public",
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            ]
        if did_aw == "did:aw:carol":
            return [
                Address(
                    address_id="addr-2",
                    domain="acme.com",
                    name="carol",
                    did_aw="did:aw:carol",
                    current_did_key=carol_did_key,
                    reachability="public",
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            ]
        raise AssertionError(f"unexpected did_aw {did_aw}")

    registry.resolve_key = AsyncMock(side_effect=resolve_key)
    registry.list_did_addresses = AsyncMock(side_effect=list_did_addresses)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(carol_sk, carol_did_key, "did:aw:carol")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["conversations"] == []


@pytest.mark.asyncio
async def test_conversations_lists_identity_scoped_chat_by_participant_did(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at)
        VALUES ('22222222-2222-2222-2222-222222222222', NULL, 'alice', NOW())
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ('22222222-2222-2222-2222-222222222222', 'did:aw:alice', 'alice'),
            ('22222222-2222-2222-2222-222222222222', $1, 'bob')
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (
            message_id, session_id, from_did, from_alias, body, created_at
        )
        VALUES (
            '33333333-3333-3333-3333-333333333333',
            '22222222-2222-2222-2222-222222222222',
            'did:aw:alice',
            'alice',
            'hello from chat',
            NOW()
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(
        return_value=[
            Address(
                address_id="addr-1",
                domain="acme.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key=bob_did_key,
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        ]
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/conversations", headers=headers)

    assert resp.status_code == 200, resp.text
    conversations = resp.json()["conversations"]
    assert len(conversations) == 1
    assert conversations[0]["conversation_type"] == "chat"
    assert conversations[0]["conversation_id"] == "22222222-2222-2222-2222-222222222222"
    assert conversations[0]["last_message_from"] == "alice"
