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
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER
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
