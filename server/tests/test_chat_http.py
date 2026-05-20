from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import httpx
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import Address, AddressDelivery, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.envelope import verify_federation_envelope
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER, MessagingAuth, get_messaging_auth
from aweb.identity_metadata import routable_chat_address
from aweb.routes import chat as chat_routes
from aweb.routes.chat import router as chat_router
from aweb.routes.federation import router as federation_router


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
    app.include_router(federation_router)

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


def test_routable_chat_address_policy():
    assert (
        routable_chat_address(
            {"team_id": "ops:acme.com", "alias": "gsk"},
            "ops:acme.com",
            "gsk",
        )
        == "gsk"
    )
    assert (
        routable_chat_address(
            {"team_id": "ops:acme.com", "alias": "gsk"},
            "support:acme.com",
            "gsk",
        )
        == "ops~gsk"
    )
    assert (
        routable_chat_address(
            {"team_id": "ops:otherco.com", "alias": "gsk"},
            "support:acme.com",
            "gsk",
        )
        == "gsk"
    )
    assert (
        routable_chat_address(
            {"team_id": "ops:otherco.com", "alias": "gsk", "address": "otherco.com/gsk"},
            "support:acme.com",
            "gsk",
        )
        == "otherco.com/gsk"
    )


@pytest.mark.asyncio
async def test_chat_to_external_address_posts_federated_chat_and_projects_locally(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://remote.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        data = json.loads(request.content)
        envelope = data["envelope"]
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "session_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    session_id = str(uuid4())
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello remote chat",
            "conversation_id": session_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
            "wait_seconds": 30,
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/sessions",
            json={
                "session_id": session_id,
                "to_addresses": ["otherco.com/bob"],
                "message": "hello remote chat",
                "wait_seconds": 30,
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_with("otherco.com", "bob", did_key=alice_did_key)
    assert resp.json()["session_id"] == session_id
    assert resp.json()["message_id"] == message_id
    assert len(remote_requests) == 1
    remote_body = json.loads(remote_requests[0].content)
    assert str(remote_requests[0].url) == "https://remote.example/v1/federation/messages"
    assert remote_body["envelope"]["type"] == "chat"
    assert remote_body["envelope"]["sender_delivery_origin"] == "https://local.example"
    assert remote_body["envelope"]["target_delivery_origin"] == "https://remote.example"
    for deprecated_field in (
        "sender_active_team_id",
        "sender_team_certificate",
        "target_address_lookup_authorization",
        "target_address_lookup_timestamp",
    ):
        assert deprecated_field not in remote_body["envelope"]
    assert remote_body["envelope"]["wait_seconds"] == 30
    participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = 'did:aw:bob'
        """,
        UUID(session_id),
    )
    assert participant["delivery_origin"] == "https://remote.example"
    assert participant["current_did_key"] == "did:key:bob"
    conversation_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = 'did:aw:bob'
        """,
        UUID(session_id),
    )
    assert conversation_participant["current_did_key"] == "did:key:bob"
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT contact_address, label, reference_type, status
        FROM {{tables.contacts}}
        WHERE owner_did = 'did:aw:alice'
          AND contact_address = 'otherco.com/bob'
        """
    )
    assert dict(contact) == {
        "contact_address": "otherco.com/bob",
        "label": "bob",
        "reference_type": "identity",
        "status": "active",
    }


@pytest.mark.asyncio
async def test_chat_to_external_address_remote_failure_does_not_create_contact(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat-failure",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://remote.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    app.state.federation_chat_transport = httpx.MockTransport(
        lambda request: httpx.Response(503, json={"detail": "remote unavailable"})
    )

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    session_id = str(uuid4())
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "remote failure chat",
            "conversation_id": session_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/sessions",
            json={
                "session_id": session_id,
                "to_addresses": ["otherco.com/bob"],
                "message": "remote failure chat",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 502, resp.text
    contact_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.contacts}}
        WHERE owner_did = 'did:aw:alice'
          AND contact_address = 'otherco.com/bob'
        """
    )
    assert contact_count == 0


@pytest.mark.asyncio
async def test_chat_continuation_to_remote_participant_uses_stored_delivery_origin(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin, current_did_key)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:bob')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:acme.com', 'did:aw:alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3, 'chat', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:bob', 'chat', 'participant')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(side_effect=AssertionError("chat continuation must use stored current did:key"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://remote.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        body = json.loads(request.content)
        envelope = body["envelope"]
        verify_federation_envelope(envelope, body["signature"])
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "session_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "continuing remote chat",
            "conversation_id": str(session_id),
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "continuing remote chat",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["conversation_id"] == str(session_id)
    assert len(remote_requests) == 1
    envelope = json.loads(remote_requests[0].content)["envelope"]
    assert envelope["type"] == "chat"
    assert envelope["conversation_id"] == str(session_id)
    assert envelope["target_current_did_key"] == "did:key:bob"
    assert envelope["target_delivery_origin"] == "https://remote.example"
    registry.resolve_key.assert_not_called()

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.chat_participants}}
        SET current_did_key = NULL
        WHERE session_id = $1 AND did = 'did:aw:bob'
        """,
        session_id,
    )
    second_message_id = str(uuid4())
    second_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    second_signed_payload = canonical_json_bytes(
        {
            "body": "missing stored key",
            "conversation_id": str(session_id),
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": second_message_id,
            "timestamp": second_timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        missing_key = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "missing stored key",
                "from_did": alice_did_key,
                "message_id": second_message_id,
                "timestamp": second_timestamp,
                "signature": sign_message(alice_sk, second_signed_payload.encode()),
                "signed_payload": second_signed_payload,
            },
        )

    assert missing_key.status_code == 424, missing_key.text
    assert missing_key.json()["detail"] == "Remote chat recipient stored route is missing current did:key"
    assert len(remote_requests) == 1


@pytest.mark.asyncio
async def test_chat_continuation_refreshes_stale_delivery_origin_once(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin, current_did_key)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://old.example', 'did:key:bob')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:acme.com', 'did:aw:alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3, 'chat', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://old.example', 'did:key:bob', 'chat', 'participant')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://new.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        envelope = json.loads(request.content)["envelope"]
        if str(request.url).startswith("https://old.example/"):
            return httpx.Response(421, json={"detail": "moved"})
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "session_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "continuing after move",
            "conversation_id": str(session_id),
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "continuing after move",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 200, resp.text
    assert [str(request.url) for request in remote_requests] == [
        "https://old.example/v1/federation/messages",
        "https://new.example/v1/federation/messages",
    ]
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    chat_participant = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT delivery_origin FROM {{tables.chat_participants}} WHERE session_id = $1 AND did = 'did:aw:bob'",
        session_id,
    )
    conversation_participant = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT delivery_origin FROM {{tables.conversation_participants}} WHERE conversation_id = $1 AND did = 'did:aw:bob'",
        session_id,
    )
    assert chat_participant["delivery_origin"] == "https://new.example"
    assert conversation_participant["delivery_origin"] == "https://new.example"


@pytest.mark.asyncio
async def test_chat_continuation_does_not_retry_when_refresh_keeps_same_origin(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin, current_did_key)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://old.example', 'did:key:bob')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:acme.com', 'did:aw:alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3, 'chat', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://old.example', 'did:key:bob', 'chat', 'participant')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://old.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        return httpx.Response(421, json={"detail": "still wrong origin"})

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "same origin failure",
            "conversation_id": str(session_id),
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "same origin failure",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 421, resp.text
    assert len(remote_requests) == 1
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    chat_participant = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT delivery_origin FROM {{tables.chat_participants}} WHERE session_id = $1 AND did = 'did:aw:bob'",
        session_id,
    )
    assert chat_participant["delivery_origin"] == "https://old.example"


def _deprecated_federation_v1_fields() -> dict:
    return {
        "sender_active_team_id": "backend:alpha.example",
        "sender_team_certificate": {
            "team_id": "backend:alpha.example",
            "member_did": "did:aw:alice",
            "signature": "deprecated-and-ignored",
        },
        "target_address_lookup_authorization": "Bearer deprecated-private-lookup-token",
        "target_address_lookup_timestamp": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def _federated_chat_payload(
    *,
    sender_sk,
    sender_did_key: str,
    sender_did_aw: str = "did:aw:alice",
    sender_address: str = "alpha.example/alice",
    sender_delivery_origin: str = "https://sender.example",
    target_address: str = "beta.example/bob",
    target_did_aw: str = "did:aw:bob",
    target_did_key: str = "did:key:bob",
    target_delivery_origin: str = "https://recipient.example",
    body: str = "hello from another server",
    message_id: str | None = None,
    conversation_id: str | None = None,
):
    message_id = message_id or str(uuid4())
    conversation_id = conversation_id or str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": body,
            "conversation_id": conversation_id,
            "from": sender_address,
            "from_did": sender_did_key,
            "from_stable_id": sender_did_aw,
            "message_id": message_id,
            "timestamp": timestamp,
            "to": target_address,
            "to_did": target_did_key,
            "to_stable_id": target_did_aw,
            "type": "chat",
        }
    ).decode()
    envelope = {
        "version": 1,
        "type": "chat",
        "sender_did_aw": sender_did_aw,
        "sender_current_did_key": sender_did_key,
        "sender_address": sender_address,
        "sender_delivery_origin": sender_delivery_origin,
        "target_address": target_address,
        "target_did_aw": target_did_aw,
        "target_current_did_key": target_did_key,
        "target_delivery_origin": target_delivery_origin,
        "body": body,
        "message_id": message_id,
        "timestamp": timestamp,
        "signed_payload": signed_payload,
        "conversation_id": conversation_id,
    }
    return {
        "envelope": envelope,
        "signature": sign_message(sender_sk, signed_payload.encode()),
    }


@pytest.mark.asyncio
async def test_receive_old_v1_federated_chat_ignores_deprecated_fields_and_delivers(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    bob_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', 'bob', $1, 'did:aw:bob', 'beta.example/bob', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        bob_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-local-chat",
            domain="beta.example",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://recipient.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
    )
    payload["envelope"].update(_deprecated_federation_v1_fields())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_with("beta.example", "bob")
    session_id = resp.json()["session_id"]
    assert session_id == payload["envelope"]["conversation_id"]
    message = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, body, signature, signed_payload FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert message["from_did"] == "did:aw:alice"
    assert message["body"] == payload["envelope"]["body"]
    assert message["signature"] == payload["signature"]
    assert message["signed_payload"] == payload["envelope"]["signed_payload"]
    participants = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT did, agent_id, address, delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        ORDER BY did
        """,
        UUID(session_id),
    )
    by_did = {row["did"]: row for row in participants}
    assert by_did["did:aw:alice"]["delivery_origin"] == "https://sender.example"
    assert by_did["did:aw:alice"]["current_did_key"] == alice_did_key
    assert by_did["did:aw:bob"]["agent_id"] == bob_agent_id
    assert by_did["did:aw:bob"]["delivery_origin"] is None
    assert by_did["did:aw:bob"]["current_did_key"] == bob_did_key

    registry.resolve_address = AsyncMock(side_effect=AssertionError("reply must not resolve sender address"))
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        body = json.loads(request.content)
        envelope = body["envelope"]
        verify_federation_envelope(envelope, body["signature"])
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "session_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="beta.example/bob",
            team_id="backend:beta.example",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    reply_message_id = str(uuid4())
    reply_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "reply over stored route",
            "conversation_id": session_id,
            "from": "beta.example/bob",
            "from_did": bob_did_key,
            "from_stable_id": "did:aw:bob",
            "message_id": reply_message_id,
            "timestamp": reply_timestamp,
            "to": "did:aw:alice",
            "to_did": "did:aw:alice",
            "to_stable_id": "did:aw:alice",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "reply over stored route",
                "from_did": bob_did_key,
                "message_id": reply_message_id,
                "timestamp": reply_timestamp,
                "signature": sign_message(bob_sk, reply_signed_payload.encode()),
                "signed_payload": reply_signed_payload,
            },
        )

    assert reply.status_code == 200, reply.text
    assert len(remote_requests) == 1
    remote_envelope = json.loads(remote_requests[0].content)["envelope"]
    assert str(remote_requests[0].url) == "https://sender.example/v1/federation/messages"
    assert remote_envelope["target_address"] == "alpha.example/alice"
    assert remote_envelope["target_delivery_origin"] == "https://sender.example"
    registry.resolve_key.assert_not_awaited()



@pytest.mark.asyncio
async def test_receive_federated_chat_existing_local_didkey_first_contact_fails_closed(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, local_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', $1, 'local', 'ephemeral', 'developer', 'open')
        """,
        local_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin="https://recipient.example",
        body="first contact local chat",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 404, resp.text
    assert "Local did:key target requires an existing session" in resp.text
    assert await aweb_cloud_db.aweb_db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
async def test_receive_federated_chat_existing_local_didkey_reply_succeeds(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    local_sk, _, local_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    local_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', $1, 'local', 'ephemeral', 'developer', 'open')
        RETURNING agent_id
        """,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:beta.example', $2)
        """,
        session_id,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role)
        VALUES
            ($1, $2, $3, 'local', $2, NULL, 'local', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'remote.example/bob', 'https://remote.example', 'federation:https://remote.example', 'participant')
        """,
        session_id,
        local_did_key,
        local_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:beta.example', $2)
        """,
        session_id,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin)
        VALUES ($1, $2, $3, 'local', $2, NULL), ($1, 'did:aw:bob', NULL, 'bob', 'remote.example/bob', 'https://remote.example')
        """,
        session_id,
        local_did_key,
        local_agent_id,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw="did:aw:bob",
        sender_address="remote.example/bob",
        sender_delivery_origin="https://remote.example",
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin="https://recipient.example",
        body="learned chat reply",
        conversation_id=str(session_id),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, body FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert row["from_did"] == "did:aw:bob"
    assert row["body"] == "learned chat reply"
    session_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = 'did:aw:bob'
        """,
        session_id,
    )
    assert session_participant["current_did_key"] == bob_did_key
    conversation_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = 'did:aw:bob'
        """,
        session_id,
    )
    assert conversation_participant["current_did_key"] == bob_did_key

    registry.resolve_key = AsyncMock(side_effect=AssertionError("chat continuation must use backfilled current did:key"))
    registry.resolve_address = AsyncMock(side_effect=AssertionError("chat continuation must not rediscover address"))
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        envelope = json.loads(request.content)["envelope"]
        assert envelope["target_current_did_key"] == bob_did_key
        assert envelope["target_delivery_origin"] == "https://remote.example"
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "session_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_chat_transport = httpx.MockTransport(_remote_handler)

    async def _local_auth():
        return MessagingAuth(
            did_key=local_did_key,
            did_aw="",
            address="",
            team_id="backend:beta.example",
            alias="local",
            agent_id=local_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _local_auth
    reply_message_id = str(uuid4())
    reply_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "local chat continuation after backfill",
            "conversation_id": str(session_id),
            "from": "beta.example/local",
            "from_did": local_did_key,
            "message_id": reply_message_id,
            "timestamp": reply_timestamp,
            "to": "remote.example/bob",
            "to_did": bob_did_key,
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "local chat continuation after backfill",
                "from_did": local_did_key,
                "message_id": reply_message_id,
                "timestamp": reply_timestamp,
                "signature": sign_message(local_sk, reply_signed_payload.encode()),
                "signed_payload": reply_signed_payload,
            },
        )

    assert reply.status_code == 200, reply.text
    assert len(remote_requests) == 1
    registry.resolve_key.assert_not_called()
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_receive_federated_chat_local_didkey_missing_session_target_fails_closed(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    _, _, local_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    local_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', $1, 'local', 'ephemeral', 'developer', 'open')
        RETURNING agent_id
        """,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:beta.example', $2)
        """,
        session_id,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role)
        VALUES
            ($1, $2, $3, 'local', $2, NULL, 'local', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'remote.example/bob', 'https://remote.example', 'federation:https://remote.example', 'participant')
        """,
        session_id,
        local_did_key,
        local_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:beta.example', $2)
        """,
        session_id,
        local_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias, address)
        VALUES ($1, 'did:aw:bob', 'bob', 'remote.example/bob')
        """,
        session_id,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw="did:aw:bob",
        sender_address="remote.example/bob",
        sender_delivery_origin="https://remote.example",
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin="https://recipient.example",
        body="stale session",
        conversation_id=str(session_id),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 403, resp.text
    assert "Federation chat session participants mismatch" in resp.text
    assert await aweb_cloud_db.aweb_db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
async def test_receive_federated_chat_duplicate_message_id_is_idempotent(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', 'bob', $1, 'did:aw:bob', 'beta.example/bob', 'persistent', 'developer', 'open')
        """,
        bob_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-local-chat",
            domain="beta.example",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://recipient.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/federation/messages", json=payload)
        second = await client.post("/v1/federation/messages", json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["message_id"] == payload["envelope"]["message_id"]
    message_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    delivery_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.federated_message_deliveries}}
        WHERE message_type = 'chat' AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert message_count == 1
    assert delivery_count == 1


@pytest.mark.asyncio
async def test_receive_federated_chat_rejects_closed_or_mismatched_conversation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    closed_conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:beta.example', 'bob', $1, 'did:aw:bob', 'beta.example/bob', 'persistent', 'developer', 'open')
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, status, team_id, created_by_did)
        VALUES ($1, 'chat', 'closed', 'backend:beta.example', 'did:aw:someone-else')
        """,
        closed_conversation_id,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-local-chat",
            domain="beta.example",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://recipient.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        conversation_id=str(closed_conversation_id),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        closed = await client.post("/v1/federation/messages", json=payload)

    assert closed.status_code == 403, closed.text
    assert "not active" in closed.json()["detail"]
    delivery_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.federated_message_deliveries}}
        WHERE message_type = 'chat' AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert delivery_count == 0

    mismatched_conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, status, team_id, created_by_did)
        VALUES ($1, 'chat', 'active', 'backend:beta.example', 'did:aw:alice')
        """,
        mismatched_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', NULL, 'alice', 'alpha.example/alice', 'chat', 'initiator'),
            ($1, 'did:aw:carol', NULL, 'carol', 'beta.example/carol', 'chat', 'participant')
        """,
        mismatched_conversation_id,
    )
    mismatched_payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        conversation_id=str(mismatched_conversation_id),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        mismatched = await client.post("/v1/federation/messages", json=mismatched_payload)

    assert mismatched.status_code == 403, mismatched.text
    assert "participants mismatch" in mismatched.json()["detail"]
    mismatch_delivery_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.federated_message_deliveries}}
        WHERE message_type = 'chat' AND message_id = $1
        """,
        UUID(mismatched_payload["envelope"]["message_id"]),
    )
    assert mismatch_delivery_count == 0


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
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
async def test_create_chat_session_accepts_cross_team_to_address(aweb_cloud_db):
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
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

    payload = {"to_addresses": ["otherco.com/bob"], "message": "hello bob"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"]
    assert {participant["did"] for participant in body["participants"]} == {"did:aw:alice", "did:aw:bob"}
    assert {participant["address"] for participant in body["participants"]} == {"acme.com/alice", "otherco.com/bob"}
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)


@pytest.mark.asyncio
async def test_create_chat_session_external_address_without_delivery_origin_fails_closed(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
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

    payload = {"to_addresses": ["otherco.com/bob"], "message": "hello external bob"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 424, resp.text
    assert "no federated delivery origin" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_chat_session_hosted_handle_without_delivery_origin_fails_closed(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-c3po",
            domain="jane.aweb.ai",
            name="c3po",
            did_aw="did:aw:c3po",
            current_did_key="did:key:c3po",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
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

    payload = {"to_aliases": ["@jane/c3po"], "message": "hello c3po"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 424, resp.text
    assert "no federated delivery origin" in resp.json()["detail"]
    registry.resolve_address.assert_awaited_once_with("jane.aweb.ai", "c3po", did_key=alice_did_key)


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_existing_session_without_binding(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
        bob_did_key,
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, None)

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/chat/sessions",
            json={"to_addresses": ["acme.com/bob"], "message": "first"},
        )
    assert first.status_code == 200, first.text
    session_id = first.json()["session_id"]

    message_id = str(uuid4())
    timestamp = "2026-04-17T12:00:00Z"
    signed_payload = json.dumps(
        {
            "type": "chat",
            "from": "bob",
            "to": "acme.com/alice",
            "body": "signed reply",
            "from_did": bob_did_key,
            "message_id": message_id,
            "timestamp": timestamp,
        }
    )
    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/chat/sessions",
            json={
                "to_addresses": ["acme.com/alice"],
                "message": "signed reply",
                "from_did": bob_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": "test-signature",
                "signed_payload": signed_payload,
            },
        )

    assert reply.status_code == 409, reply.text
    assert reply.json()["detail"] == "Signed chat message must bind the existing session_id"
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*)::int AS count
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
        """,
        UUID(session_id),
    )
    assert row["count"] == 1


@pytest.mark.asyncio
async def test_create_chat_session_rejects_to_address_self_chat(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-1",
            domain="acme.com",
            name="alice",
            did_aw="did:aw:alice",
            current_did_key=alice_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_addresses": ["acme.com/alice"], "message": "self"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 400, resp.text
    assert "Self-chat is not supported" in resp.text


@pytest.mark.asyncio
async def test_create_chat_session_to_external_did_resolves_global_route_before_requiring_signature(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        side_effect=lambda did_aw: KeyResolution(
            did_aw=did_aw,
            current_did_key="did:key:bob" if did_aw == "did:aw:bob" else alice_did_key,
            delivery_origin="https://remote.example" if did_aw == "did:aw:bob" else None,
        )
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_dids": ["did:aw:bob"], "message": "raw did"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "Federated chat delivery requires session_id" in resp.text
    registry.resolve_key.assert_any_await("did:aw:bob")
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_create_chat_session_resolves_tilde_alias_cross_team(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:team-ops'),
            ('eng:acme.com', 'acme.com', 'eng', 'did:key:team-eng')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('eng:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    message_id = str(uuid4())
    timestamp = "2026-04-17T12:00:00Z"
    signed_payload = json.dumps(
        {
            "type": "chat",
            "from": "alice",
            "to": "eng~bob",
            "body": "hello eng",
            "from_did": alice_did_key,
            "message_id": message_id,
            "timestamp": timestamp,
        }
    )
    payload = {
        "to_aliases": ["eng~bob"],
        "message": "hello eng",
        "from_did": alice_did_key,
        "signature": "test-signature",
        "message_id": message_id,
        "timestamp": timestamp,
        "signed_payload": signed_payload,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"]
    assert {participant["did"] for participant in body["participants"]} == {"did:aw:alice", "did:aw:bob"}
    assert {participant["address"] for participant in body["participants"]} == {"acme.com/alice", "acme.com/bob"}
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected_status"),
    [
        ("missing~bob", 404),
        ("eng~missing", 404),
        ("~bob", 422),
        ("eng~", 422),
        ("eng~team~bob", 422),
    ],
)
async def test_create_chat_session_rejects_invalid_tilde_alias_targets(
    aweb_cloud_db,
    target,
    expected_status,
):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:team-ops'),
            ('eng:acme.com', 'acme.com', 'eng', 'did:key:team-eng')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json={"to_aliases": [target], "message": "hello"})

    assert resp.status_code == expected_status, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_mutation_context_includes_from_did_aw(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    captured: dict[str, dict] = {}

    async def _capture(event_type: str, context: dict) -> None:
        captured["event_type"] = event_type
        captured["context"] = dict(context)

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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
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
    app.state.on_mutation = _capture

    payload = {"to_dids": ["did:aw:bob"], "message": "hello bob"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    assert captured["event_type"] == "chat.message_sent"
    assert captured["context"]["from_did_aw"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_create_chat_session_global_recipient_allows_explicit_inbound_mode_open(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_dids": ["did:aw:bob"], "message": "allowed"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    contact_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.contacts}}
        WHERE owner_did = 'did:aw:alice'
          AND contact_address = 'otherco.com/bob'
          AND reference_type = 'identity'
          AND status = 'active'
        """
    )
    assert contact_count == 1


@pytest.mark.asyncio
async def test_create_chat_session_to_global_address_allows_explicit_inbound_mode_open(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_addresses": ["otherco.com/bob"], "message": "allowed"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_global_recipient_null_inbound_mode_fails_migration_required(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob-migration', 'did:aw:bob-migration', 'otherco.com/bob-migration', 'bob-migration', 'persistent', 'developer', NULL)
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_dids": ["did:aw:bob-migration"], "message": "blocked"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 403, resp.text
    assert "inbound_mode migration required" in resp.text
    contact_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.contacts}}
        WHERE owner_did = 'did:aw:alice'
          AND contact_address = 'otherco.com/bob-migration'
        """
    )
    assert contact_count == 0


@pytest.mark.asyncio
async def test_create_chat_session_to_address_falls_back_to_local_ephemeral_agent(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', NULL, NULL, 'bob', 'ephemeral', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_addresses": ["otherco.com/bob"], "message": "blocked"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 403, resp.text
    assert "Local recipient only accepts" in resp.text


@pytest.mark.asyncio
async def test_create_chat_session_to_address_does_not_fall_back_to_local_persistent_agent_when_awid_misses(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_addresses": ["otherco.com/bob"], "message": "hidden"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)


@pytest.mark.parametrize("recipient_lifetime", ["persistent", "ephemeral"])
@pytest.mark.asyncio
async def test_create_chat_session_to_address_uses_same_team_local_recipient_when_awid_misses(
    aweb_cloud_db,
    recipient_lifetime,
):
    # The persistent branch is guarded by requires_registry_address_binding();
    # the ephemeral branch bypasses that predicate. Keep these as twins so
    # address routing cannot be accidentally covered with only one lifetime.
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', $1, 'developer', 'open')
        """,
        recipient_lifetime,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=None)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="otherco.com/alice",
            team_id="ops:otherco.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    payload = {"to_addresses": ["otherco.com/bob"], "message": f"same team hidden {recipient_lifetime}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT did, alias FROM {{tables.chat_participants}} WHERE alias = 'bob'"
    )
    assert len(rows) == 1
    assert rows[0]["did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_create_chat_session_to_address_rejects_cross_team_local_persistent_when_awid_misses(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=None)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    payload = {"to_addresses": ["otherco.com/bob"], "message": "cross team hidden"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)


@pytest.mark.asyncio
async def test_create_chat_session_to_did_and_address_uses_local_persistent_when_registry_unconfigured(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, None)

    async def _auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    payload = {
        "to_dids": ["did:aw:bob"],
        "to_addresses": ["otherco.com/bob"],
        "message": "local bound",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT did, alias FROM {{tables.chat_participants}} WHERE alias = 'bob'"
    )
    assert len(rows) == 1
    assert rows[0]["did"] == "did:aw:bob"


@pytest.mark.parametrize("recipient_lifetime", ["persistent", "ephemeral"])
@pytest.mark.asyncio
async def test_create_chat_session_to_private_address_uses_client_recipient_binding(
    aweb_cloud_db,
    recipient_lifetime,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', $1, 'developer', 'open')
        """,
        recipient_lifetime,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "body": "private chat",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    )
    payload = {
        "to_addresses": ["otherco.com/bob"],
        "message": "private chat",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    body_json = resp.json()
    assert {participant["did"] for participant in body_json["participants"]} == {"did:aw:alice", "did:aw:bob"}
    assert {participant["address"] for participant in body_json["participants"]} == {"otherco.com/bob", None}


@pytest.mark.asyncio
async def test_create_chat_session_to_private_address_rejects_unverified_client_recipient_binding(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-2')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'persistent', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "body": "private chat",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    )
    payload = {
        "to_addresses": ["otherco.com/bob"],
        "message": "private chat",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": "not-a-valid-signature",
        "signed_payload": signed_payload.decode(),
    }
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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
async def test_create_chat_session_rejects_signed_payload_body_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    session_id = "11111111-aaaa-4aaa-8aaa-111111111111"
    message_id = "11111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "conversation_id": str(session_id),
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "session_id": session_id,
        "to_aliases": ["bob"],
        "message": "tampered hello",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload body must match the chat message"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_leaving_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "12111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob"],
        "message": "signed hello",
        "leaving": True,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload sender_leaving must match the chat message"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_wait_seconds_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "13111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob"],
        "message": "signed hello",
        "wait_seconds": 120,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload wait_seconds must match the chat message"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_recipient_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "14111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "mallory",
            "to_did": "did:aw:mallory",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob"],
        "message": "signed hello",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload recipient must match the chat target"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_partial_signed_recipient_binding_for_group_chat(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:carol', 'did:aw:carol', 'acme.com/carol', 'carol', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "17111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob,carol",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob", "carol"],
        "message": "signed hello",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload recipient must match the chat target"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_from_stable_id_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "15111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:mallory",
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob"],
        "message": "signed hello",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload from_stable_id must match the authenticated sender"


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_from_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "16111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hello",
            "from": "mallory",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "type": "chat",
        }
    )
    payload = {
        "to_aliases": ["bob"],
        "message": "signed hello",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload from must match the authenticated sender"


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
async def test_chat_send_message_rejects_legacy_bound_session_continuation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    session_id = uuid4()
    message_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open')
        """,
        alice_did_key,
        bob_did_key,
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'alice'"
    )
    bob_agent_id = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'bob'"
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob')
        """,
        session_id,
        alice_agent_id,
        bob_agent_id,
    )
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "legacy chat",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": str(message_id),
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "did:aw:bob",
            "type": "chat",
        }
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, signature, signed_payload, created_at)
        VALUES ($1, $2, 'did:aw:alice', 'alice', 'legacy chat', $3, $4, NOW())
        """,
        message_id,
        session_id,
        sign_message(alice_sk, signed_payload),
        signed_payload.decode(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _bob_auth_override():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json={"body": "blocked"})
        create_or_send_resp = await client.post(
            "/v1/chat/sessions",
            json={"to_aliases": ["alice"], "message": "also blocked"},
        )

    assert resp.status_code == 403, resp.text
    assert "conversation_id" in resp.json()["detail"]
    assert create_or_send_resp.status_code == 403, create_or_send_resp.text
    assert "conversation_id" in create_or_send_resp.json()["detail"]


@pytest.mark.asyncio
async def test_chat_create_with_signed_fresh_session_bypasses_legacy_bound_session(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team-1')
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        alice_did_key,
    )
    bob_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, lifetime, role, inbound_mode)
        VALUES ('backend:acme.com', 'bob', $1, 'did:aw:bob', 'acme.com/bob', 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        bob_did_key,
    )
    legacy_session_id = uuid4()
    legacy_message_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        legacy_session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob')
        """,
        legacy_session_id,
        alice_agent_id,
        bob_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'chat', 'backend:acme.com', 'did:aw:alice')
        """,
        legacy_session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', 'chat', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob', 'chat', 'participant')
        """,
        legacy_session_id,
        alice_agent_id,
        bob_agent_id,
    )
    legacy_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    legacy_signed_payload = canonical_json_bytes(
        {
            "body": "legacy chat",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": str(legacy_message_id),
            "timestamp": legacy_timestamp,
            "to": "bob",
            "to_did": "did:aw:bob",
            "type": "chat",
        }
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, signature, signed_payload, created_at)
        VALUES ($1, $2, 'did:aw:alice', 'alice', 'legacy chat', $3, $4, NOW())
        """,
        legacy_message_id,
        legacy_session_id,
        sign_message(alice_sk, legacy_signed_payload),
        legacy_signed_payload.decode(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _bob_auth_override():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth_override

    fresh_session_id = uuid4()
    fresh_message_id = uuid4()
    fresh_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    fresh_signed_payload = canonical_json_bytes(
        {
            "body": "fresh chat",
            "conversation_id": str(fresh_session_id),
            "from": "bob",
            "from_did": bob_did_key,
            "message_id": str(fresh_message_id),
            "timestamp": fresh_timestamp,
            "to": "alice",
            "to_did": "did:aw:alice",
            "type": "chat",
        }
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/sessions",
            json={
                "session_id": str(fresh_session_id),
                "to_aliases": ["alice"],
                "message": "fresh chat",
                "from_did": bob_did_key,
                "message_id": str(fresh_message_id),
                "timestamp": fresh_timestamp,
                "signature": sign_message(bob_sk, fresh_signed_payload),
                "signed_payload": fresh_signed_payload.decode(),
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"] == str(fresh_session_id)
    assert body["message_id"] == str(fresh_message_id)
    legacy_status = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT status FROM {{tables.conversations}} WHERE conversation_id = $1",
        legacy_session_id,
    )
    assert legacy_status == "closed"


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_body_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "22222222-2222-4222-8222-222222222222"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed reply",
            "conversation_id": str(session_id),
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "body": "tampered reply",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload body must match the chat message"


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_hang_on_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "23222222-2222-4222-8222-222222222222"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed reply",
            "conversation_id": str(session_id),
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "body": "signed reply",
        "hang_on": True,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload hang_on must match the chat message"


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_leaving_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "24222222-2222-4222-8222-222222222222"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed reply",
            "conversation_id": str(session_id),
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "bob",
            "to_did": "",
            "type": "chat",
        }
    )
    payload = {
        "body": "signed reply",
        "leaving": True,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload sender_leaving must match the chat message"


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_recipient_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "24222222-2222-4222-8222-222222222222"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed reply",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "mallory",
            "to_did": "did:aw:mallory",
            "type": "chat",
        }
    )
    payload = {
        "body": "signed reply",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload recipient must match the chat target"


@pytest.mark.asyncio
async def test_chat_send_message_rejects_partial_signed_recipient_binding_for_group_chat(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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
            ($1, 'did:aw:bob', 'bob'),
            ($1, 'did:aw:carol', 'carol')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'open'),
            ('backend:acme.com', 'did:key:carol', 'did:aw:carol', 'acme.com/carol', 'carol', 'persistent', 'developer', 'open')
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "25222222-2222-4222-8222-222222222222"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed reply",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": "",
            "timestamp": timestamp,
            "to": "acme.com/bob,acme.com/carol",
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    )
    payload = {
        "body": "signed reply",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/v1/chat/sessions/{session_id}/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "signed_payload recipient must match the chat target"


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
async def test_chat_routes_use_team_alias_for_same_namespace_sender_without_public_address(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:team-ops'),
            ('support:acme.com', 'acme.com', 'support', 'did:key:team-support')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES
            ($1, 'ops:acme.com', 'did:aw:gsk', 'did:key:gsk', 'gsk', NULL),
            ($2, 'support:acme.com', 'did:aw:amy', 'did:key:amy', 'amy', NULL)
        """,
        uuid4(),
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at)
        VALUES ($1, 'ops:acme.com', 'gsk', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:aw:gsk', 'gsk'),
            ($1, 'did:aw:amy', 'amy')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:aw:gsk', 'gsk', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:amy",
            did_aw="did:aw:amy",
            address="",
            team_id="support:acme.com",
            alias="amy",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        pending = await client.get("/v1/chat/pending")
        sessions = await client.get("/v1/chat/sessions")

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["from_address"] == "ops~gsk"
    assert pending.status_code == 200, pending.text
    assert pending.json()["pending"][0]["last_from_address"] == "ops~gsk"
    assert pending.json()["pending"][0]["participant_addresses"] == ["ops~gsk"]
    assert sessions.status_code == 200, sessions.text
    assert sessions.json()["sessions"][0]["participant_addresses"] == ["ops~gsk"]


@pytest.mark.asyncio
async def test_cross_org_chat_create_persists_sender_address_without_local_metadata(aweb_cloud_db, monkeypatch):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-ops'),
            ('support:juan.aweb.ai', 'juan.aweb.ai', 'support', 'did:key:team-support')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ('support:juan.aweb.ai', 'did:key:amy', 'did:aw:amy', 'juan.aweb.ai/amy', 'amy', 'persistent', 'developer', 'open')
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _sender_auth():
        return MessagingAuth(
            did_key="did:key:gsk",
            did_aw="did:aw:gsk",
            address="otherco.com/gsk",
            team_id="ops:otherco.com",
            alias="gsk",
        )

    app.dependency_overrides[get_messaging_auth] = _sender_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/v1/chat/sessions", json={"to_dids": ["did:aw:amy"], "message": "hello"})

    assert created.status_code == 200, created.text
    session_id = created.json()["session_id"]
    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.chat_messages}} WHERE session_id = $1",
        UUID(session_id),
    )
    assert stored == "otherco.com/gsk"

    async def _amy_auth():
        return MessagingAuth(
            did_key="did:key:amy",
            did_aw="did:aw:amy",
            address="juan.aweb.ai/amy",
            team_id="support:juan.aweb.ai",
            alias="amy",
        )

    class _FakePubSub:
        async def subscribe(self, *_args, **_kwargs):
            return None

        async def get_message(self, *_args, **_kwargs):
            return None

        async def close(self):
            return None

        async def aclose(self):
            return None

    class _FakeRedis:
        def pubsub(self):
            return _FakePubSub()

    app.state.redis = _FakeRedis()
    app.dependency_overrides[get_messaging_auth] = _amy_auth
    monkeypatch.setattr(chat_routes, "register_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "unregister_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "get_waiting_agents", AsyncMock(return_value=[]))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=5.0) as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        pending = await client.get("/v1/chat/pending")
        stream = await client.get(
            f"/v1/chat/sessions/{session_id}/stream",
            params={
                "deadline": (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
                "after": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            },
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["from_address"] == "otherco.com/gsk"
    assert pending.status_code == 200, pending.text
    assert pending.json()["pending"][0]["last_from_address"] == "otherco.com/gsk"
    assert stream.status_code == 200, stream.text
    assert '"from_address": "otherco.com/gsk"' in stream.text


@pytest.mark.asyncio
async def test_chat_create_derives_ephemeral_sender_address_from_team_namespace(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team-ops')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES
            ('ops:acme.com', 'did:key:alice', NULL, NULL, 'alice', 'ephemeral', 'developer', 'open'),
            ('ops:acme.com', 'did:key:bob', NULL, NULL, 'bob', 'ephemeral', 'developer', 'open')
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key="did:key:alice",
            did_aw="",
            address="",
            team_id="ops:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/v1/chat/sessions", json={"to_aliases": ["bob"], "message": "hello"})

    assert created.status_code == 200, created.text
    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(created.json()["message_id"]),
    )
    assert stored == "acme.com/alice"
    participant_address = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT address
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = 'did:key:alice'
        """,
        UUID(created.json()["session_id"]),
    )
    assert participant_address == "acme.com/alice"


@pytest.mark.asyncio
async def test_cross_org_chat_reply_persists_sender_address_without_local_metadata(aweb_cloud_db):
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-ops'),
            ('support:juan.aweb.ai', 'juan.aweb.ai', 'support', 'did:key:team-support')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'ops:otherco.com', 'gsk')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:aw:gsk', 'gsk'),
            ($1, 'did:aw:amy', 'amy')
        """,
        session_id,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _amy_auth():
        return MessagingAuth(
            did_key="did:key:amy",
            did_aw="did:aw:amy",
            address="juan.aweb.ai/amy",
            team_id="support:juan.aweb.ai",
            alias="amy",
        )

    app.dependency_overrides[get_messaging_auth] = _amy_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        sent = await client.post(f"/v1/chat/sessions/{session_id}/messages", json={"body": "reply"})

    assert sent.status_code == 200, sent.text
    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.chat_messages}} WHERE session_id = $1",
        session_id,
    )
    assert stored == "juan.aweb.ai/amy"

    async def _gsk_auth():
        return MessagingAuth(
            did_key="did:key:gsk",
            did_aw="did:aw:gsk",
            address="otherco.com/gsk",
            team_id="ops:otherco.com",
            alias="gsk",
        )

    app.dependency_overrides[get_messaging_auth] = _gsk_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["from_address"] == "juan.aweb.ai/amy"


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
    assert history.json()["messages"][0]["conversation_id"] == str(session_id)
    assert [item["body"] for item in history.json()["messages"]] == ["hello"]
    assert read.status_code == 200, read.text
    assert read.json()["messages_marked"] == 1


@pytest.mark.asyncio
async def test_chat_history_includes_sender_stable_identity_for_current_key(aweb_cloud_db):
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
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:key:z6MkAliceCurrent', 'alice', 'hello', $3)
        """,
        message_id,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkBob",
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")

    assert history.status_code == 200, history.text
    body = history.json()
    assert body["messages"][0]["conversation_id"] == str(session_id)
    assert body["messages"][0]["from_did"] == "did:key:z6MkAliceCurrent"
    assert body["messages"][0]["from_stable_id"] == "did:aw:alice"
    assert body["messages"][0]["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_chat_history_filters_by_message_id(aweb_cloud_db):
    session_id = uuid4()
    first_message_id = uuid4()
    second_message_id = uuid4()
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
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES
            ($1, $2, 'did:aw:alice', 'alice', 'first', $3),
            ($4, $2, 'did:aw:bob', 'bob', 'second', $5)
        """,
        first_message_id,
        session_id,
        created_at + timedelta(minutes=1),
        second_message_id,
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
        history = await client.get(
            f"/v1/chat/sessions/{session_id}/messages?unread_only=true&message_id={second_message_id}"
        )

    assert history.status_code == 200, history.text
    body = history.json()
    assert [item["message_id"] for item in body["messages"]] == [str(second_message_id)]
    assert [item["conversation_id"] for item in body["messages"]] == [str(session_id)]
    assert [item["body"] for item in body["messages"]] == ["second"]


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
async def test_chat_stream_replay_includes_sender_stable_identity_for_current_key(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    message_id = uuid4()
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
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice')
        """,
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:key:z6MkAliceCurrent', 'alice', 'hello', $3)
        """,
        message_id,
        session_id,
        created_at + timedelta(seconds=30),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    class _FakePubSub:
        async def subscribe(self, *_args, **_kwargs):
            return None

        async def get_message(self, *_args, **_kwargs):
            return None

        async def close(self):
            return None

    class _FakeRedis:
        def pubsub(self):
            return _FakePubSub()

    app.state.redis = _FakeRedis()

    async def _auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkBob",
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override
    monkeypatch.setattr(chat_routes, "register_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "unregister_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "get_waiting_agents", AsyncMock(return_value=[]))

    deadline = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    after = created_at.isoformat()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=5.0) as client:
        resp = await client.get(
            f"/v1/chat/sessions/{session_id}/stream",
            params={"deadline": deadline, "after": after},
        )

    assert resp.status_code == 200, resp.text
    assert '"from_did": "did:key:z6MkAliceCurrent"' in resp.text
    assert '"from_stable_id": "did:aw:alice"' in resp.text
    assert '"from_address": "acme.com/alice"' in resp.text


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
                "conversation_id": str(session_id),
                "team_id": "",
                "participants": ["bob"],
            "participant_dids": ["did:aw:bob"],
            "participant_addresses": ["acme.com/bob"],
            "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_activity": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sender_waiting": False,
        }
    ]
