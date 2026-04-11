from __future__ import annotations

import base64
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
        "SELECT from_did, to_did FROM {{tables.messages}} WHERE subject = 'hello'"
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"


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

    app.dependency_overrides[get_identity_auth] = _inbox_auth_override
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
        "SELECT from_did FROM {{tables.messages}} WHERE subject = 'hello partial'"
    )
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
