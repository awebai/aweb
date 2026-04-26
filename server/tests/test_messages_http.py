from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import Address, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import (
    IDENTITY_DID_AW_HEADER,
    IdentityAuth,
    MessagingAuth,
    get_identity_auth,
    get_messaging_auth,
)
from aweb.routes.messages import router as messages_router


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
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "persistent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    cert["signature"] = sign_message(team_sk, payload)
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


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


def _signed_team_headers(agent_sk, agent_did_key, team_id: str, cert_header: str, body_bytes=b""):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )
    sig = sign_message(agent_sk, payload)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": cert_header,
    }


def _build_test_app(aweb_db, registry):
    app = FastAPI()
    app.include_router(messages_router)

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


def _cert(certificate_id: str, member_did_aw: str, member_did_key: str, alias: str = "alice"):
    return {
        "certificate_id": certificate_id,
        "member_did_aw": member_did_aw,
        "member_did_key": member_did_key,
        "member_address": "",
        "alias": alias,
        "lifetime": "persistent",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.mark.asyncio
async def test_messages_inbox_accepts_identity_auth(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
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

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES ('did:aw:bob', 'did:aw:alice', 'bob', 'alice', 'hi', 'hello', 'normal')
        """
    )

    headers = _signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["messages"]) == 1
    assert body["messages"][0]["to_did"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_messages_inbox_includes_sender_stable_identity_for_current_key(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    _, _, alice_current_did = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice',
            'persistent', 'developer', 'everyone'
        )
        """,
        alice_current_did,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:acme.com', $1, 'did:aw:bob', 'acme.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES ($1, 'did:aw:bob', 'alice', 'bob', 'stable sender', 'hello', 'normal')
        """,
        alice_current_did,
    )

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["messages"][0]["from_did"] == alice_current_did
    assert body["messages"][0]["from_stable_id"] == "did:aw:alice"
    assert body["messages"][0]["from_address"] == "acme.com/alice"
    assert body["messages"][0]["to_did"] == "did:aw:bob"
    assert body["messages"][0]["to_stable_id"] == "did:aw:bob"
    assert body["messages"][0]["to_address"] == "acme.com/bob"


@pytest.mark.asyncio
async def test_messages_inbox_prefers_stored_sender_address_without_local_metadata(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:acme.com', $1, 'did:aw:bob', 'acme.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            from_did, to_did, from_alias, from_address, to_alias, subject, body, priority
        )
        VALUES ('did:aw:gsk', 'did:aw:bob', 'gsk', 'otherco.com/gsk', 'bob', 'external', 'hello', 'normal')
        """
    )

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["messages"][0]["from_alias"] == "gsk"
    assert body["messages"][0]["from_address"] == "otherco.com/gsk"


@pytest.mark.asyncio
async def test_messages_inbox_filters_by_message_id(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES
            ('11111111-1111-1111-1111-111111111111', 'did:aw:bob', 'did:aw:alice', 'bob', 'alice', 'first', 'one', 'normal'),
            ('22222222-2222-2222-2222-222222222222', 'did:aw:carol', 'did:aw:alice', 'carol', 'alice', 'second', 'two', 'normal')
        """
    )

    headers = _signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/messages/inbox?unread_only=true&message_id=22222222-2222-2222-2222-222222222222",
            headers=headers,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [item["message_id"] for item in body["messages"]] == ["22222222-2222-2222-2222-222222222222"]


@pytest.mark.asyncio
async def test_send_message_mutation_context_includes_from_did_aw(aweb_cloud_db):
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
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.on_mutation = _capture

    payload = {"to_did": "did:aw:bob", "subject": "hello", "body": "hi"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", headers=headers, content=body)

    assert resp.status_code == 200, resp.text
    assert captured["event_type"] == "message.sent"
    assert captured["context"]["from_did_aw"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_messages_inbox_rejects_invalid_identity_signature(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    other_sk, _, _ = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(other_sk, alice_did_key, "did:aw:alice")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 401
    assert "Invalid DIDKey signature" in resp.text


@pytest.mark.asyncio
async def test_messages_inbox_requires_timestamp(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice")
    headers.pop("X-AWEB-Timestamp")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_send_message_accepts_identity_auth(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'contacts'
        )
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:bob', 'acme.com/alice', 'Alice')
        """
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

    payload = {"to_did": "did:aw:bob", "subject": "hello", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, from_address, to_did FROM {{tables.messages}} WHERE subject = 'hello'"
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["from_address"] == "acme.com/alice"
    assert row["to_did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_send_message_accepts_external_to_address_without_local_agent(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice',
            'persistent', 'developer', 'everyone'
        )
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

    payload = {"to_address": "otherco.com/bob", "subject": "external", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT from_did, to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'external'
        """
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "bob"

    async def _bob_auth():
        return MessagingAuth(
            did_key="did:key:bob",
            did_aw="did:aw:bob",
            address="otherco.com/bob",
            team_id="ops:otherco.com",
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    inbox = inbox_resp.json()
    assert inbox["messages"][0]["to_did"] == "did:aw:bob"
    assert inbox["messages"][0]["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_identity_scoped_send_by_address_allows_persistent_multi_membership(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:team-ops'),
            ('dev:acme.com', 'acme.com', 'dev', 'did:key:team-dev')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('dev:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone')
        """,
        alice_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-bob",
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
                address_id="addr-alice",
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

    payload = {"to_address": "otherco.com/bob", "subject": "multi membership external", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT team_id, from_agent_id, from_alias, from_did, from_address, to_did, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'multi membership external'
        """
    )
    assert row["team_id"] is None
    assert row["from_agent_id"] is None
    assert row["from_alias"] == "acme.com/alice"
    assert row["from_did"] == "did:aw:alice"
    assert row["from_address"] == "acme.com/alice"
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_team_auth_alias_send_resolves_active_team_with_persistent_multi_membership(aweb_cloud_db):
    ops_team_sk, _, ops_team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', $1),
            ('dev:acme.com', 'acme.com', 'dev', 'did:key:team-dev')
        """,
        ops_team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('dev:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('ops:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone')
        """,
        alice_did_key,
        bob_did_key,
    )
    alice_ops_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT agent_id
        FROM {{tables.agents}}
        WHERE team_id = 'ops:acme.com' AND alias = 'alice'
        """
    )
    assert alice_ops_row is not None

    cert = _make_certificate(
        ops_team_sk,
        ops_team_did_key,
        alice_did_key,
        team_id="ops:acme.com",
        alias="alice",
        member_did_aw="did:aw:alice",
        member_address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=ops_team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_alias": "bob", "subject": "multi membership team auth", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice_sk,
            alice_did_key,
            "ops:acme.com",
            _encode_certificate(cert),
            body_bytes,
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT team_id, from_agent_id, from_alias, from_did, from_address, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'multi membership team auth'
        """
    )
    assert row["team_id"] == "ops:acme.com"
    assert row["from_agent_id"] == alice_ops_row["agent_id"]
    assert row["from_alias"] == "alice"
    assert row["from_did"] == "did:aw:alice"
    assert row["from_address"] == "acme.com/alice"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_stable_id_transport_routes_stable_and_accepts_current_binding(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """,
        bob_did_key,
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

    payload = {
        "to_did": bob_did_key,
        "to_stable_id": "did:aw:bob",
        "subject": "hello stable transport",
        "body": "hi",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did FROM {{tables.messages}} WHERE subject = 'hello stable transport'"
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_send_message_to_current_did_remains_visible_after_recipient_rotation(aweb_cloud_db):
    _, _, bob_old_did_key = _make_keypair()
    _, _, bob_new_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """,
        bob_old_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {"to_did": bob_old_did_key, "subject": "hello current did", "body": "hi"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_resp = await client.post("/v1/messages", json=payload)
    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE subject = 'hello current did'"
    )
    assert row["to_did"] == "did:aw:bob"

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did_key = $1
        WHERE did_aw = 'did:aw:bob'
        """,
        bob_new_did_key,
    )

    async def _inbox_auth_override():
        return IdentityAuth(
            did_key=bob_new_did_key,
            did_aw="did:aw:bob",
            address="otherco.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _inbox_auth_override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    body = inbox_resp.json()
    assert [item["subject"] for item in body["messages"]] == ["hello current did"]


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_did_and_to_stable_id(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_did": bob_did_key,
        "to_stable_id": "did:aw:carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_did" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_address_and_to_stable_id(aweb_cloud_db):
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', $1, 'did:aw:carol', 'otherco.com/carol', 'carol',
            'persistent', 'developer', 'everyone'
        )
        """,
        carol_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-1",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key="did:key:bob-current",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_address": "otherco.com/bob",
        "to_stable_id": "did:aw:carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_address" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_agent_id_and_to_stable_id(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE did_aw = 'did:aw:bob'"
    )
    assert bob is not None

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_agent_id": str(bob["agent_id"]),
        "to_stable_id": "did:aw:carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_agent_id" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_alias_and_to_stable_id(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:otherco.com",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_alias": "bob",
        "to_stable_id": "did:aw:carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_alias" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_address_and_to_did(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-1",
            domain="otherco.com",
            name="carol",
            did_aw="did:aw:carol",
            current_did_key="did:key:carol-current",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_did": "did:aw:bob",
        "to_address": "otherco.com/carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_address" in resp.text


@pytest.mark.asyncio
async def test_send_message_accepts_local_to_address_binding_when_awid_misses(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:test.local', 'test.local', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk',
            'ephemeral', 'developer', 'everyone'
        )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=None)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "body": "hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "priority": "normal",
            "subject": "local address binding",
            "timestamp": timestamp,
            "to": "test.local/gsk",
            "to_did": "did:aw:bob",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "to_address": "test.local/gsk",
        "subject": "local address binding",
        "body": "hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": "test-signature",
        "signed_payload": signed_payload.decode(),
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("test.local", "gsk", did_key="did:key:z6MkAliceCurrent")
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'local address binding'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is not None
    assert row["to_alias"] == "gsk"


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_local_to_address_binding_when_awid_misses(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:test.local', 'test.local', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk',
             'ephemeral', 'developer', 'everyone'),
            ('ops:test.local', $2, 'did:aw:carol', 'test.local/carol', 'carol',
             'ephemeral', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=None)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_did": "did:aw:carol",
        "to_address": "test.local/gsk",
        "subject": "local address mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_address" in resp.text
    registry.resolve_address.assert_awaited_once_with("test.local", "gsk", did_key="did:key:z6MkAliceCurrent")


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_agent_id_and_to_did(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )
    carol = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE did_aw = 'did:aw:carol'"
    )
    assert carol is not None

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_did": "did:aw:bob",
        "to_agent_id": str(carol["agent_id"]),
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_agent_id" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_alias_and_to_did(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:otherco.com",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_did": "did:aw:bob",
        "to_alias": "carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_alias" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_agent_id_and_to_address(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )
    carol = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE did_aw = 'did:aw:carol'"
    )
    assert carol is not None

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-1",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_address": "otherco.com/bob",
        "to_agent_id": str(carol["agent_id"]),
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_agent_id" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_alias_and_to_address(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-1",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:otherco.com",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_address": "otherco.com/bob",
        "to_alias": "carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_alias" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_to_alias_and_to_agent_id(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
             'persistent', 'developer', 'everyone'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol',
             'persistent', 'developer', 'everyone')
        """,
        bob_did_key,
        carol_did_key,
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE did_aw = 'did:aw:bob'"
    )
    assert bob is not None

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="ops:otherco.com",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {
        "to_agent_id": str(bob["agent_id"]),
        "to_alias": "carol",
        "subject": "mismatch",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_alias" in resp.text


@pytest.mark.asyncio
async def test_send_message_contacts_policy_accepts_equivalent_owner_did(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'contacts'
        )
        """,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, 'acme.com/alice', 'Alice')
        """,
        bob_did_key,
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

    payload = {"to_did": "did:aw:bob", "subject": "hello via legacy owner", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did FROM {{tables.messages}} WHERE subject = 'hello via legacy owner'"
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_send_message_accepts_team_auth(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()
    del bob_sk

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', $1)
        """,
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone')
        """,
        alice_did_key,
        bob_did_key,
    )

    cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="backend:acme.com",
        alias="alice",
        member_did_aw="did:aw:alice",
        member_address="acme.com/alice",
    )
    cert_header = _encode_certificate(cert)
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    registry.list_team_certificates = AsyncMock(
        return_value=[_cert("cert-1", "did:aw:alice", alice_did_key, "alice")]
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_alias": "bob", "subject": "hello", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(alice_sk, alice_did_key, "backend:acme.com", cert_header, body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_send_message_resolves_tilde_alias_cross_team(aweb_cloud_db):
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
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('eng:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone')
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
            "type": "mail",
            "from": "alice",
            "to": "eng~bob",
            "priority": "normal",
            "subject": "hello eng",
            "body": "hi",
            "from_did": alice_did_key,
            "message_id": message_id,
            "timestamp": timestamp,
        }
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "to_alias": "eng~bob",
                "subject": "hello eng",
                "body": "hi",
                "from_did": alice_did_key,
                "signature": "test-signature",
                "message_id": message_id,
                "timestamp": timestamp,
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = 'hello eng'"
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"
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
async def test_send_message_rejects_invalid_tilde_alias_targets(
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
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone')
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
        resp = await client.post(
            "/v1/messages",
            json={"to_alias": target, "subject": "hello", "body": "hi"},
        )

    assert resp.status_code == expected_status, resp.text


@pytest.mark.asyncio
async def test_ephemeral_team_auth_mail_routes_by_did_key_and_inboxes_by_identity_did_key(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('default:local', 'local', 'default', $1)
        """,
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('default:local', $1, NULL, NULL, 'alice', 'ephemeral', 'developer', 'everyone'),
            ('default:local', $2, NULL, NULL, 'bob', 'ephemeral', 'developer', 'everyone')
        """,
        alice_did_key,
        bob_did_key,
    )

    alice_cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="default:local",
        alias="alice",
        lifetime="ephemeral",
    )
    bob_cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="default:local",
        alias="bob",
        lifetime="ephemeral",
    )
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    alice_payload = {"to_alias": "bob", "subject": "local to bob", "body": "hello bob"}
    alice_body = json.dumps(alice_payload).encode()
    alice_headers = {
        **_signed_team_headers(
            alice_sk,
            alice_did_key,
            "default:local",
            _encode_certificate(alice_cert),
            alice_body,
        ),
        "Content-Type": "application/json",
    }

    bob_payload = {"to_alias": "alice", "subject": "local to alice", "body": "hello alice"}
    bob_body = json.dumps(bob_payload).encode()
    bob_headers = {
        **_signed_team_headers(
            bob_sk,
            bob_did_key,
            "default:local",
            _encode_certificate(bob_cert),
            bob_body,
        ),
        "Content-Type": "application/json",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        alice_send = await client.post("/v1/messages", content=alice_body, headers=alice_headers)
        bob_send = await client.post("/v1/messages", content=bob_body, headers=bob_headers)

        alice_inbox = await client.get(
            "/v1/messages/inbox",
            headers=_signed_identity_headers(alice_sk, alice_did_key, ""),
        )
        bob_inbox = await client.get(
            "/v1/messages/inbox",
            headers=_signed_identity_headers(bob_sk, bob_did_key, ""),
        )

    assert alice_send.status_code == 200, alice_send.text
    assert bob_send.status_code == 200, bob_send.text
    assert alice_inbox.status_code == 200, alice_inbox.text
    assert bob_inbox.status_code == 200, bob_inbox.text

    messages = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT from_did, from_address, to_did, subject
        FROM {{tables.messages}}
        WHERE subject IN ('local to bob', 'local to alice')
        ORDER BY subject
        """
    )
    assert [row["subject"] for row in messages] == ["local to alice", "local to bob"]
    assert messages[0]["from_did"] == bob_did_key
    assert messages[0]["from_address"] == "local/bob"
    assert messages[0]["to_did"] == alice_did_key
    assert messages[1]["from_did"] == alice_did_key
    assert messages[1]["from_address"] == "local/alice"
    assert messages[1]["to_did"] == bob_did_key

    alice_body_json = alice_inbox.json()
    bob_body_json = bob_inbox.json()
    assert [item["subject"] for item in alice_body_json["messages"]] == ["local to alice"]
    assert [item["subject"] for item in bob_body_json["messages"]] == ["local to bob"]
    assert alice_body_json["messages"][0]["to_did"] == alice_did_key
    assert alice_body_json["messages"][0]["to_stable_id"] is None
    assert bob_body_json["messages"][0]["to_did"] == bob_did_key
    assert bob_body_json["messages"][0]["to_stable_id"] is None


@pytest.mark.asyncio
async def test_identity_auth_mail_derives_sender_address_from_agent_row(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:gsk.aweb.ai', 'gsk.aweb.ai', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('ops:gsk.aweb.ai', $1, NULL, NULL, 'gsk', 'ephemeral', 'developer', 'everyone'),
            ('ops:gsk.aweb.ai', $2, NULL, NULL, 'amy', 'ephemeral', 'developer', 'everyone')
        """,
        alice_did_key,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_did": bob_did_key, "subject": "identity sender", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT from_did, from_alias, from_address, to_did
        FROM {{tables.messages}}
        WHERE subject = 'identity sender'
        """
    )
    assert row["from_did"] == alice_did_key
    assert row["from_alias"] == "gsk"
    assert row["from_address"] == "gsk.aweb.ai/gsk"
    assert row["to_did"] == bob_did_key


@pytest.mark.asyncio
async def test_send_message_team_auth_uses_cert_identity_when_agent_row_is_partial(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', $1)
        """,
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, NULL, NULL, 'alice', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'contacts')
        """,
        alice_did_key,
        bob_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:bob', 'acme.com/alice', 'Alice')
        """
    )
    alice_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT agent_id
        FROM {{tables.agents}}
        WHERE team_id = 'backend:acme.com' AND alias = 'alice'
        """
    )
    assert alice_row is not None

    cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="backend:acme.com",
        alias="alice",
        member_did_aw="did:aw:alice",
        member_address="acme.com/alice",
    )
    cert_header = _encode_certificate(cert)
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_alias": "bob", "subject": "hello partial", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(alice_sk, alice_did_key, "backend:acme.com", cert_header, body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_agent_id, from_did FROM {{tables.messages}} WHERE subject = 'hello partial'"
    )
    assert row["from_agent_id"] == alice_row["agent_id"]
    assert row["from_did"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_inbox_matches_stable_and_current_identity_dids(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES (
            '11111111-1111-1111-1111-111111111111',
            'did:aw:alice',
            $1,
            'alice',
            'bob',
            'hello',
            'hi',
            'normal'
        )
        """,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 200, resp.text
    messages = resp.json()["messages"]
    assert len(messages) == 1
    assert messages[0]["body"] == "hi"


@pytest.mark.asyncio
async def test_messages_inbox_and_ack_accept_persistent_cert_auth(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', $1)
        """,
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice',
            'persistent', 'developer', 'everyone'
        )
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES (
            '33333333-3333-3333-3333-333333333333',
            'did:aw:bob',
            'did:aw:alice',
            'bob',
            'alice',
            'persistent cert inbox',
            'hello',
            'normal'
        )
        """
    )

    cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="backend:acme.com",
        alias="alice",
        member_did_aw="did:aw:alice",
        member_address="acme.com/alice",
    )
    cert_header = _encode_certificate(cert)
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_team_headers(alice_sk, alice_did_key, "backend:acme.com", cert_header)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox", headers=headers)
        ack_resp = await client.post("/v1/messages/33333333-3333-3333-3333-333333333333/ack", headers=headers)

    assert inbox_resp.status_code == 200, inbox_resp.text
    assert [item["subject"] for item in inbox_resp.json()["messages"]] == ["persistent cert inbox"]
    assert ack_resp.status_code == 200, ack_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT read_at FROM {{tables.messages}} WHERE message_id = '33333333-3333-3333-3333-333333333333'"
    )
    assert row["read_at"] is not None


@pytest.mark.asyncio
async def test_messages_inbox_and_ack_accept_ephemeral_cert_auth(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('default:local', 'local', 'default', $1)
        """,
        team_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'default:local', $1, NULL, NULL, 'alice',
            'ephemeral', 'developer', 'everyone'
        )
        """,
        alice_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority
        )
        VALUES (
            '44444444-4444-4444-4444-444444444444',
            'did:key:bob',
            $1,
            'bob',
            'alice',
            'ephemeral cert inbox',
            'hello',
            'normal'
        )
        """,
        alice_did_key,
    )

    cert = _make_certificate(
        team_sk,
        team_did_key,
        alice_did_key,
        team_id="default:local",
        alias="alice",
        lifetime="ephemeral",
    )
    cert_header = _encode_certificate(cert)
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_team_headers(alice_sk, alice_did_key, "default:local", cert_header)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox", headers=headers)
        ack_resp = await client.post("/v1/messages/44444444-4444-4444-4444-444444444444/ack", headers=headers)

    assert inbox_resp.status_code == 200, inbox_resp.text
    assert [item["subject"] for item in inbox_resp.json()["messages"]] == ["ephemeral cert inbox"]
    assert inbox_resp.json()["messages"][0]["to_did"] == alice_did_key
    assert ack_resp.status_code == 200, ack_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT read_at FROM {{tables.messages}} WHERE message_id = '44444444-4444-4444-4444-444444444444'"
    )
    assert row["read_at"] is not None


@pytest.mark.asyncio
async def test_send_message_requires_timestamp_when_signature_is_provided(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed",
        "body": "hi",
        "from_did": "did:aw:alice",
        "message_id": "11111111-1111-4111-8111-111111111111",
        "signature": "sig",
        "signed_payload": "{}",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "message_id and timestamp are required" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_body_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    timestamp = "2026-04-10T00:00:00Z"
    message_id = "11111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "subject": "signed subject",
            "timestamp": timestamp,
            "to": "did:aw:bob",
            "to_did": "",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed subject",
        "body": "tampered hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "signed_payload body must match the mail body" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_priority_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    timestamp = "2026-04-10T00:00:00Z"
    message_id = "12111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "subject": "signed subject",
            "timestamp": timestamp,
            "to": "did:aw:bob",
            "to_did": "",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed subject",
        "body": "signed hi",
        "priority": "urgent",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "signed_payload priority must match the mail message" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_recipient_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    timestamp = "2026-04-10T00:00:00Z"
    message_id = "14111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "subject": "signed subject",
            "timestamp": timestamp,
            "to": "did:aw:mallory",
            "to_did": "did:aw:mallory",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed subject",
        "body": "signed hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "signed_payload recipient must match the mail recipient" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_from_stable_id_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    timestamp = "2026-04-10T00:00:00Z"
    message_id = "15111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "from_stable_id": "did:aw:mallory",
            "message_id": message_id,
            "subject": "signed subject",
            "timestamp": timestamp,
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed subject",
        "body": "signed hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "signed_payload from_stable_id must match the authenticated sender" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_from_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    timestamp = "2026-04-10T00:00:00Z"
    message_id = "16111111-1111-4111-8111-111111111111"
    signed_payload = canonical_json_bytes(
        {
            "body": "signed hi",
            "from": "otherco.com/mallory",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "subject": "signed subject",
            "timestamp": timestamp,
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed subject",
        "body": "signed hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "signed_payload from must match the authenticated sender" in resp.text


@pytest.mark.asyncio
async def test_send_message_rejects_signed_from_did_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'everyone'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {
        "to_did": "did:aw:bob",
        "subject": "signed",
        "body": "hi",
        "from_did": "did:aw:mallory",
        "message_id": "11111111-1111-4111-8111-111111111111",
        "timestamp": "2026-04-10T00:00:00Z",
        "signature": "sig",
        "signed_payload": "{}",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 422, resp.text
    assert "from_did must match the authenticated sender" in resp.text


@pytest.mark.asyncio
async def test_send_message_returns_403_for_policy_violation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'nobody'
        )
        """
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

    payload = {"to_did": "did:aw:bob", "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_send_message_to_address_enforces_local_recipient_policy(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob',
            'persistent', 'developer', 'nobody'
        )
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

    payload = {"to_address": "otherco.com/bob", "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_send_message_to_address_falls_back_to_local_ephemeral_agent(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES (
            'ops:otherco.com', 'did:key:bob', NULL, NULL, 'bob',
            'ephemeral', 'developer', 'nobody'
        )
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_address": "otherco.com/bob", "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 403, resp.text
    assert "Recipient does not accept messages" in resp.text
