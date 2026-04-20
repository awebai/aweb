from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import Address, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER, MessagingAuth, get_messaging_auth
from aweb.identity_metadata import routable_chat_address
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


def test_routable_chat_address_policy():
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

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    message_id = "11111111-1111-4111-8111-111111111111"
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
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', 'did:key:carol', 'did:aw:carol', 'acme.com/carol', 'carol', 'persistent', 'developer', 'everyone')
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
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone'),
            ('backend:acme.com', 'did:key:carol', 'did:aw:carol', 'acme.com/carol', 'carol', 'persistent', 'developer', 'everyone')
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
            "participants": ["bob"],
            "participant_dids": ["did:aw:bob"],
            "participant_addresses": ["acme.com/bob"],
            "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sender_waiting": False,
        }
    ]
