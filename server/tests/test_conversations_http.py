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
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER
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
    assert conversations[0]["conversation_id"] == "11111111-1111-1111-1111-111111111111"
    assert conversations[0]["last_message_from"] == "alice"


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
