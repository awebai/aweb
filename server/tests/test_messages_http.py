from __future__ import annotations

import base64
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

from awid.did import did_from_public_key, stable_id_from_public_key
from awid.registry import Address, AddressDelivery, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import E2EE_SUITE, _envelope_map, _hash_canonical, _key_wrap_map
from aweb.federation.envelope import verify_federation_envelope
from aweb.identity_auth_deps import (
    IDENTITY_DID_AW_HEADER,
    IdentityAuth,
    MessagingAuth,
    get_messaging_auth,
)
from aweb.routes.federation import router as federation_router
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
        "identity_scope": kwargs.get("identity_scope", "global"),
        "issued_at": kwargs.get("issued_at", datetime.now(timezone.utc).isoformat()),
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


def _raw_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _sha256_b64(data: bytes) -> str:
    return "sha256:" + _raw_b64(hashlib.sha256(data).digest())


def _encrypted_mail_envelope(
    *,
    sender_sk: bytes,
    sender_did: str,
    sender_stable_id: str,
    recipient_did: str,
    recipient_stable_id: str,
    message_id: str,
    conversation_id: str,
    sender_address: str = "acme.com/alice",
    recipient_address: str = "acme.com/bob",
    ciphertext: bytes = b"opaque-ciphertext-with-tag",
):
    signing_key = SigningKey(sender_sk)
    delivery_wrap = {
        "wrap_id": _sha256_b64(b"wrap-binding"),
        "recipient_stable_id": recipient_stable_id,
        "recipient_did": recipient_did,
        "recipient_address": recipient_address,
        "recipient_encryption_key_id": "sha256:" + _raw_b64(b"r" * 32),
        "sender_encryption_key_id": "sha256:" + _raw_b64(b"s" * 32),
        "sender_did": sender_did,
        "sender_stable_id": sender_stable_id,
        "wrap_purpose": "delivery",
        "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
        "encapsulated_key": _raw_b64(b"e" * 32),
        "wrapped_cek": _raw_b64(b"w" * 48),
    }
    sender_copy_wrap = {
        "wrap_id": _sha256_b64(b"sender-copy-wrap-binding"),
        "recipient_stable_id": sender_stable_id,
        "recipient_did": sender_did,
        "recipient_address": sender_address,
        "recipient_encryption_key_id": "sha256:" + _raw_b64(b"s" * 32),
        "sender_encryption_key_id": "sha256:" + _raw_b64(b"s" * 32),
        "sender_did": sender_did,
        "sender_stable_id": sender_stable_id,
        "wrap_purpose": "sender_copy",
        "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
        "encapsulated_key": _raw_b64(b"E" * 32),
        "wrapped_cek": _raw_b64(b"W" * 48),
    }
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = created_at + timedelta(minutes=5)
    envelope = {
        "message_version": 2,
        "envelope_type": "aweb.e2ee.message",
        "kind": "mail",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "from": {
            "address": sender_address,
            "did": sender_did,
            "stable_id": sender_stable_id,
            "encryption_key_id": "sha256:" + _raw_b64(b"s" * 32),
        },
        "recipients": [
            {
                "address": recipient_address,
                "did": recipient_did,
                "stable_id": recipient_stable_id,
                "encryption_key_id": "sha256:" + _raw_b64(b"r" * 32),
                "wrap_id": delivery_wrap["wrap_id"],
            }
        ],
        "routing": {
            "to": recipient_address,
            "to_did": recipient_did,
            "to_stable_id": recipient_stable_id,
            "sender_observed_inbound_mode": "open",
        },
        "policy": {"requires_e2ee": True, "legacy_plaintext_allowed": False},
        "crypto": {
            "suite": E2EE_SUITE,
            "content_nonce": _raw_b64(b"n" * 12),
            "ciphertext_hash": _sha256_b64(ciphertext),
            "ciphertext_size": len(ciphertext),
            "inner_header_hash": _sha256_b64(b"inner-header"),
            "key_wraps_hash": _hash_canonical(
                "key_wraps",
                [_key_wrap_map(delivery_wrap), _key_wrap_map(sender_copy_wrap)],
            ),
        },
        "key_wraps": [delivery_wrap, sender_copy_wrap],
        "ciphertext": _raw_b64(ciphertext),
        "signing_key_id": sender_did,
    }
    payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    envelope["signature"] = _raw_b64(signing_key.sign(payload).signature)
    return envelope


def _build_test_app(aweb_db, registry):
    app = FastAPI()
    app.include_router(federation_router)
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
    app.state.public_origin = "http://test"
    return app


def _cert(certificate_id: str, member_did_aw: str, member_did_key: str, alias: str = "alice"):
    return {
        "certificate_id": certificate_id,
        "member_did_aw": member_did_aw,
        "member_did_key": member_did_key,
        "member_address": "",
        "alias": alias,
        "identity_scope": "global",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


async def _insert_team(aweb_db, team_id: str):
    team_name, namespace = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        """,
        team_id,
        namespace,
        team_name,
    )


async def _insert_agent(
    aweb_db,
    *,
    team_id: str,
    alias: str,
    did_key: str,
    did_aw: str,
    address: str,
    inbound_mode: str | None = "open",
):
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ($1, $2, $3, $4, $5, 'global', 'developer', $6)
        RETURNING agent_id
        """,
        team_id,
        did_key,
        did_aw,
        address,
        alias,
        inbound_mode,
    )
    return str(row["agent_id"])


async def _conversation_participants(aweb_db, conversation_id: str):
    rows = await aweb_db.fetch_all(
        """
        SELECT did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        ORDER BY role, alias
        """,
        UUID(conversation_id),
    )
    return [dict(row) for row in rows]


@pytest.mark.asyncio
async def test_send_message_to_local_alias_creates_conversation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

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
    payload = {"to_alias": "bob", "subject": "conversation local", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    conversation_id = resp.json()["conversation_id"]
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT message_id, conversation_id
        FROM {{tables.messages}}
        WHERE subject = 'conversation local'
        """
    )
    assert str(row["conversation_id"]) == conversation_id

    participants = await _conversation_participants(aweb_cloud_db.aweb_db, conversation_id)
    by_did = {row["did"]: row for row in participants}
    assert by_did["did:aw:alice"]["role"] == "initiator"
    assert str(by_did["did:aw:alice"]["agent_id"]) == alice_agent_id
    assert by_did["did:aw:bob"]["role"] == "participant"
    assert str(by_did["did:aw:bob"]["agent_id"]) == bob_agent_id
    assert by_did["did:aw:bob"]["transport_hint"] == "to_alias"

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    assert inbox_resp.json()["messages"][0]["conversation_id"] == conversation_id


@pytest.mark.asyncio
async def test_send_encrypted_message_stores_opaque_envelope_only(aweb_cloud_db):
    alice_sk, alice_pk, alice_did_key = _make_keypair()
    _, bob_pk, bob_did_key = _make_keypair()
    alice_stable = stable_id_from_public_key(alice_pk)
    bob_stable = stable_id_from_public_key(bob_pk)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw=alice_stable,
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw=bob_stable,
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw=alice_stable,
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    message_id = "33333333-3333-4333-8333-333333333333"
    conversation_id = "44444444-4444-4444-8444-444444444444"
    envelope = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice_stable,
        recipient_did=bob_did_key,
        recipient_stable_id=bob_stable,
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = {
        "to_alias": "bob",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": envelope,
        "priority": "normal",
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    app.dependency_overrides[get_messaging_auth] = _auth
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice_stable, body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        replay_resp = await client.post(
            "/v1/messages",
            content=body_bytes,
            headers={
                **_signed_identity_headers(alice_sk, alice_did_key, alice_stable, body_bytes),
                "Content-Type": "application/json",
            },
        )
    assert replay_resp.status_code == 200, replay_resp.text

    different_envelope = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice_stable,
        recipient_did=bob_did_key,
        recipient_stable_id=bob_stable,
        message_id=message_id,
        conversation_id=conversation_id,
        ciphertext=b"different-ciphertext-with-tag",
    )
    different_payload = {**payload, "encrypted_envelope": different_envelope}
    different_body = json.dumps(different_payload, separators=(",", ":")).encode()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        mutation_resp = await client.post(
            "/v1/messages",
            content=different_body,
            headers={
                **_signed_identity_headers(alice_sk, alice_did_key, alice_stable, different_body),
                "Content-Type": "application/json",
            },
        )
    assert mutation_resp.status_code == 409, mutation_resp.text

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT subject, body, content_mode, message_version, encrypted_envelope,
               encrypted_ciphertext_hash, encrypted_ciphertext_size, encrypted_key_wraps_hash,
               encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id,
               signed_envelope_hash
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        UUID(message_id),
    )
    assert row["subject"] == ""
    assert row["body"] == ""
    assert row["content_mode"] == "encrypted_v2"
    assert row["message_version"] == 2
    assert "secret" not in json.dumps(row["encrypted_envelope"])
    assert row["encrypted_ciphertext_hash"] == envelope["crypto"]["ciphertext_hash"]
    assert row["encrypted_ciphertext_size"] == envelope["crypto"]["ciphertext_size"]
    assert row["encrypted_key_wraps_hash"] == envelope["crypto"]["key_wraps_hash"]
    assert row["encrypted_inner_header_hash"] == envelope["crypto"]["inner_header_hash"]
    assert row["encrypted_suite"] == envelope["crypto"]["suite"]
    assert row["encrypted_signing_key_id"] == envelope["signing_key_id"]
    assert str(row["signed_envelope_hash"]).startswith("sha256:")
    count = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert count == 1

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw=bob_stable,
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    message = inbox_resp.json()["messages"][0]
    assert message["content_mode"] == "encrypted_v2"
    assert message["message_version"] == 2
    assert "encrypted_envelope" in message
    assert "subject" not in message
    assert "body" not in message


@pytest.mark.asyncio
async def test_send_encrypted_message_to_local_alias_without_address(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="",
        address="",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    message_id = "55555555-5555-4555-8555-555555555555"
    conversation_id = "66666666-6666-4666-8666-666666666666"
    envelope = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id="did:aw:alice",
        recipient_did=bob_did_key,
        recipient_stable_id="",
        recipient_address="",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = {
        "to_alias": "bob",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": envelope,
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    app.dependency_overrides[get_messaging_auth] = _auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/messages",
            content=body_bytes,
            headers={
                **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 200, resp.text
    participants = await _conversation_participants(aweb_cloud_db.aweb_db, conversation_id)
    assert [row["alias"] for row in participants] == ["alice", "bob"]
    assert participants[1]["address"] == "acme.com/bob"
    assert participants[1]["current_did_key"] == bob_did_key
    assert bob_agent_id


@pytest.mark.asyncio
async def test_send_message_to_address_reuses_alias_thread(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_alias": "bob", "subject": "initial alias thread", "body": "hello"},
        )
        assert first.status_code == 200, first.text
        conversation_id = first.json()["conversation_id"]
        message_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        signed_payload = canonical_json_bytes(
            {
                "body": "hello again",
                "conversation_id": conversation_id,
                "from": "acme.com/alice",
                "from_did": alice_did_key,
                "from_stable_id": "did:aw:alice",
                "message_id": message_id,
                "priority": "normal",
                "subject": "address reuses alias thread",
                "timestamp": timestamp,
                "to": "acme.com/bob",
                "to_did": bob_did_key,
                "to_stable_id": "did:aw:bob",
                "type": "mail",
            }
        )
        second = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_address": "acme.com/bob",
                "to_did": bob_did_key,
                "to_stable_id": "did:aw:bob",
                "subject": "address reuses alias thread",
                "body": "hello again",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload),
                "signed_payload": signed_payload.decode(),
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] == conversation_id
    messages = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT conversation_id, to_agent_id, to_did
        FROM {{tables.messages}}
        WHERE subject IN ('initial alias thread', 'address reuses alias thread')
        ORDER BY created_at
        """
    )
    assert [str(row["conversation_id"]) for row in messages] == [conversation_id, conversation_id]
    assert str(messages[1]["to_agent_id"]) == bob_agent_id
    assert messages[1]["to_did"] == "did:aw:bob"
    app.state.awid_registry_client.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_send_message_to_cross_team_did_creates_conversation(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

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
    payload = {"to_did": "did:aw:bob", "subject": "conversation to did", "body": "hello"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    conversation_id = resp.json()["conversation_id"]
    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT team_id FROM {{tables.conversations}} WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    message = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT conversation_id, to_did FROM {{tables.messages}} WHERE subject = 'conversation to did'"
    )
    participants = await _conversation_participants(aweb_cloud_db.aweb_db, conversation_id)
    by_did = {row["did"]: row for row in participants}

    assert conversation["team_id"] == "backend:acme.com"
    assert str(message["conversation_id"]) == conversation_id
    assert message["to_did"] == "did:aw:bob"
    assert str(by_did["did:aw:bob"]["agent_id"]) == bob_agent_id
    assert by_did["did:aw:bob"]["address"] == "otherco.com/bob"
    assert by_did["did:aw:bob"]["transport_hint"] == "to_did"


@pytest.mark.asyncio
async def test_send_message_to_external_address_posts_federated_mail_and_projects_locally(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
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
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

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
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "subject": "conversation address",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": "otherco.com/bob",
        "subject": "conversation address",
        "body": "hello",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_with("otherco.com", "bob", did_key=alice_did_key)
    assert resp.json()["conversation_id"] == conversation_id
    assert resp.json()["message_id"] == message_id
    assert len(remote_requests) == 1
    assert str(remote_requests[0].url) == "https://remote.example/v1/federation/messages"
    remote_body = json.loads(remote_requests[0].content)
    assert remote_body["signature"] == payload["signature"]
    assert remote_body["envelope"]["signed_payload"] == signed_payload
    assert remote_body["envelope"]["target_delivery_origin"] == "https://remote.example"
    for deprecated_field in (
        "sender_active_team_id",
        "sender_team_certificate",
        "target_address_lookup_authorization",
        "target_address_lookup_timestamp",
    ):
        assert deprecated_field not in remote_body["envelope"]
    assert remote_body["envelope"]["sender_did_aw"] == "did:aw:alice"
    assert remote_body["envelope"]["sender_current_did_key"] == alice_did_key
    assert remote_body["envelope"]["target_did_aw"] == "did:aw:bob"
    assert remote_body["envelope"]["target_current_did_key"] == "did:key:bob"
    participants = await _conversation_participants(aweb_cloud_db.aweb_db, conversation_id)
    by_did = {row["did"]: row for row in participants}
    message = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, to_agent_id, to_did
        FROM {{tables.messages}}
        WHERE subject = 'conversation address'
        """
    )

    assert str(message["conversation_id"]) == conversation_id
    assert message["to_agent_id"] is None
    assert message["to_did"] == "did:aw:bob"
    assert by_did["did:aw:bob"]["agent_id"] is None
    assert by_did["did:aw:bob"]["address"] == "otherco.com/bob"
    assert by_did["did:aw:bob"]["current_did_key"] == "did:key:bob"
    assert by_did["did:aw:bob"]["transport_hint"] == "to_address"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        retry = await client.post("/v1/messages", json=payload)

    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == message_id
    assert registry.resolve_address.await_count == 1
    assert len(remote_requests) == 2
    projected_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert projected_count == 1


@pytest.mark.asyncio
async def test_send_encrypted_message_to_external_address_posts_ciphertext_only(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key="did:key:bob"))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
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
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        data = json.loads(request.content)
        envelope = data["envelope"]
        verify_federation_envelope(envelope, data["signature"])
        assert envelope["content_mode"] == "encrypted_v2"
        assert envelope["message_version"] == 2
        assert envelope["subject"] == ""
        assert envelope["body"] == ""
        assert "signed_payload" not in envelope
        assert "sealed body" not in json.dumps(envelope)
        assert data["signature"] == envelope["encrypted_envelope"]["signature"]
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

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
    conversation_id = str(uuid4())
    envelope = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id="did:aw:alice",
        recipient_did="did:key:bob",
        recipient_stable_id="did:aw:bob",
        recipient_address="otherco.com/bob",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = {
        "to_address": "otherco.com/bob",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": envelope,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    assert len(remote_requests) == 1
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT subject, body, content_mode, message_version, signature, signed_payload, encrypted_envelope
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        UUID(message_id),
    )
    assert row["subject"] == ""
    assert row["body"] == ""
    assert row["content_mode"] == "encrypted_v2"
    assert row["message_version"] == 2
    assert row["signature"] is None
    assert row["signed_payload"] is None
    assert "sealed body" not in json.dumps(row["encrypted_envelope"])


@pytest.mark.asyncio
async def test_send_message_from_local_didkey_to_global_did_first_contact_fails_closed(aweb_cloud_db):
    local_sk, _, local_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    local_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=local_did_key,
        did_aw="",
        address="",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(side_effect=AssertionError("bare did:aw first-contact must not resolve by key"))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        envelope = json.loads(request.content)["envelope"]
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=local_did_key,
            did_aw=None,
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=local_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "local to global",
            "conversation_id": conversation_id,
            "from": "acme.com/alice",
            "from_did": local_did_key,
            "message_id": message_id,
            "subject": "local outbound",
            "timestamp": timestamp,
            "to": "did:aw:bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "to_stable_id": "did:aw:bob",
                "subject": "local outbound",
                "body": "local to global",
                "conversation_id": conversation_id,
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": local_did_key,
                "signature": sign_message(local_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert resp.status_code == 422, resp.text
    assert "Bare did:aw first-contact is unsupported" in resp.json()["detail"]
    registry.resolve_key.assert_not_awaited()
    assert remote_requests == []


@pytest.mark.asyncio
async def test_mail_reply_to_local_didkey_requires_learned_return_route_not_conversation_id(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    local_did_key = "did:key:z6MkLocalOnly"
    await _insert_team(aweb_cloud_db.aweb_db, "backend:remote.example")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:remote.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="remote.example/bob",
    )
    conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'backend:remote.example', 'did:key:z6MkLocalOnly')
        """,
        conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role)
        VALUES
            ($1, 'did:key:z6MkLocalOnly', NULL, 'local', 'did:key:z6MkLocalOnly', 'https://local.example', 'federation:https://local.example', 'initiator'),
            ($1, 'did:aw:bob', $2, 'bob', 'remote.example/bob', NULL, 'local', 'participant')
        """,
        conversation_id,
        bob_agent_id,
    )
    registry = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        envelope = json.loads(request.content)["envelope"]
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

    async def _auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="remote.example/bob",
            team_id="backend:remote.example",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "reply via learned route",
            "conversation_id": str(conversation_id),
            "from": "remote.example/bob",
            "from_did": bob_did_key,
            "from_stable_id": "did:aw:bob",
            "message_id": message_id,
            "subject": "learned route",
            "timestamp": timestamp,
            "to": local_did_key,
            "to_did": local_did_key,
            "to_stable_id": local_did_key,
            "type": "mail",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        routed = await client.post(
            "/v1/messages",
            json={
                "conversation_id": str(conversation_id),
                "subject": "learned route",
                "body": "reply via learned route",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": bob_did_key,
                "signature": sign_message(bob_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
        )

    assert routed.status_code == 200, routed.text
    assert len(remote_requests) == 1
    envelope = json.loads(remote_requests[0].content)["envelope"]
    assert str(remote_requests[0].url) == "https://local.example/v1/federation/messages"
    assert envelope["target_did_aw"] == local_did_key
    assert envelope["target_current_did_key"] == local_did_key
    assert envelope["target_delivery_origin"] == "https://local.example"

    blocked_conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'backend:remote.example', 'did:key:z6MkNoRoute')
        """,
        blocked_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, transport_hint, role)
        VALUES
            ($1, 'did:key:z6MkNoRoute', NULL, 'local', 'did:key:z6MkNoRoute', 'local-metadata-only', 'initiator'),
            ($1, 'did:aw:bob', $2, 'bob', 'remote.example/bob', 'local', 'participant')
        """,
        blocked_conversation_id,
        bob_agent_id,
    )
    blocked_message_id = str(uuid4())
    blocked_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    blocked_payload = canonical_json_bytes(
        {
            "body": "no route",
            "conversation_id": str(blocked_conversation_id),
            "from": "remote.example/bob",
            "from_did": bob_did_key,
            "from_stable_id": "did:aw:bob",
            "message_id": blocked_message_id,
            "subject": "no route",
            "timestamp": blocked_timestamp,
            "to": "did:key:z6MkNoRoute",
            "to_did": "did:key:z6MkNoRoute",
            "to_stable_id": "did:key:z6MkNoRoute",
            "type": "mail",
        }
    ).decode()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        blocked = await client.post(
            "/v1/messages",
            json={
                "conversation_id": str(blocked_conversation_id),
                "subject": "no route",
                "body": "no route",
                "message_id": blocked_message_id,
                "timestamp": blocked_timestamp,
                "from_did": bob_did_key,
                "signature": sign_message(bob_sk, blocked_payload.encode()),
                "signed_payload": blocked_payload,
            },
        )

    assert blocked.status_code == 422, blocked.text
    assert "Local did:key recipient requires local resolution or learned return route" in blocked.text
    assert len(remote_requests) == 1


@pytest.mark.asyncio
async def test_send_message_to_external_address_without_delivery_origin_fails_closed(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    registry = AsyncMock()
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
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/messages",
            json={"to_address": "otherco.com/bob", "subject": "no delivery", "body": "hello"},
        )

    assert resp.status_code == 424
    assert "no federated delivery origin" in resp.json()["detail"]
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE subject = 'no delivery'"
    )
    assert count == 0


@pytest.mark.asyncio
async def test_send_message_to_external_address_remote_failure_does_not_create_local_message(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-fail",
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
    app.state.federation_mail_transport = httpx.MockTransport(
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
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "subject": "remote failure",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": "otherco.com/bob",
        "subject": "remote failure",
        "body": "hello",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 502
    assert "remote unavailable" in resp.json()["detail"]
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE subject = 'remote failure'"
    )
    assert count == 0


@pytest.mark.asyncio
async def test_send_message_to_hosted_handle_alias_uses_canonical_address(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "default:jane.aweb.ai")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    c3po_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:jane.aweb.ai",
        alias="c3po",
        did_key="did:key:c3po",
        did_aw="did:aw:c3po",
        address="jane.aweb.ai/c3po",
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
    payload = {"to_alias": "@jane/c3po", "subject": "hosted handle", "body": "hello"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("jane.aweb.ai", "c3po", did_key=alice_did_key)
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'hosted handle'
        """
    )
    assert row["to_did"] == "did:aw:c3po"
    assert str(row["to_agent_id"]) == c3po_agent_id
    assert row["to_alias"] == "c3po"


@pytest.mark.asyncio
async def test_send_message_continues_conversation_without_address_discovery(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="otherco.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:bob", "subject": "initial", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address=None,
            team_id="ops:otherco.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    registry = app.state.awid_registry_client
    registry.resolve_address = AsyncMock(side_effect=AssertionError("continuation must not resolve address"))
    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "reply", "body": "hi"},
        )

    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, from_did, to_did, to_agent_id
        FROM {{tables.messages}}
        WHERE subject = 'reply'
        """
    )
    assert str(row["conversation_id"]) == conversation_id
    assert row["from_did"] == "did:aw:bob"
    assert row["to_did"] == "did:aw:alice"
    assert str(row["to_agent_id"]) == alice_agent_id


@pytest.mark.asyncio
async def test_send_message_to_address_reuses_existing_conversation_without_address_discovery(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="otherco.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address=None,
            team_id="ops:otherco.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:alice", "subject": "initial address thread", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    registry = app.state.awid_registry_client
    registry.resolve_address = AsyncMock(side_effect=AssertionError("address reply must use conversation"))
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={"to_address": "otherco.com/bob", "subject": "address reply", "body": "hi"},
        )

    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, from_did, to_did, to_agent_id
        FROM {{tables.messages}}
        WHERE subject = 'address reply'
        """
    )
    assert str(row["conversation_id"]) == conversation_id
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"
    assert str(row["to_agent_id"]) == bob_agent_id
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_send_message_to_address_with_existing_conversation_id_continues_local_thread(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="otherco.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="otherco.com/bob",
            team_id="ops:otherco.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:alice", "subject": "initial explicit thread", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    registry = app.state.awid_registry_client
    registry.resolve_address = AsyncMock(side_effect=AssertionError("same conversation reply must not rediscover address"))
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_address": "otherco.com/bob",
                "subject": "explicit same conversation reply",
                "body": "hi",
            },
        )

    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, from_did, to_did, to_agent_id
        FROM {{tables.messages}}
        WHERE subject = 'explicit same conversation reply'
        """
    )
    assert str(row["conversation_id"]) == conversation_id
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"
    assert str(row["to_agent_id"]) == bob_agent_id
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_signed_address_continuation_keeps_ephemeral_participant_address(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, gsk_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "devteam:test.local")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="devteam:test.local",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="test.local/alice",
    )
    gsk_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="devteam:test.local",
        alias="gsk",
        did_key=gsk_did_key,
        did_aw="",
        address="",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _gsk_auth():
        return MessagingAuth(
            did_key=gsk_did_key,
            did_aw="",
            address="test.local/gsk",
            team_id="devteam:test.local",
            alias="gsk",
            agent_id=gsk_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _gsk_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:alice", "subject": "ephemeral initial", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="test.local/alice",
            team_id="devteam:test.local",
            alias="alice",
            agent_id=alice_agent_id,
        )

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "reply",
            "conversation_id": conversation_id,
            "from": "test.local/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "priority": "normal",
            "subject": "ephemeral reply",
            "timestamp": timestamp,
            "to": "test.local/gsk",
            "to_did": gsk_did_key,
            "type": "mail",
        }
    )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    registry = app.state.awid_registry_client
    registry.resolve_address = AsyncMock(side_effect=AssertionError("local continuation must not rediscover address"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_address": "test.local/gsk",
                "subject": "ephemeral reply",
                "body": "reply",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload),
                "signed_payload": signed_payload.decode(),
            },
        )

    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id
        FROM {{tables.messages}}
        WHERE subject = 'ephemeral reply'
        """
    )
    assert row["to_did"] == gsk_did_key
    assert str(row["to_agent_id"]) == gsk_agent_id
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_mail_conversation_history_requires_participant_and_includes_sent_messages(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    _, _, mallory_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:bob", "subject": "initial history", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "reply history", "body": "hi"},
        )
    assert reply.status_code == 200, reply.text

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")

    assert history.status_code == 200, history.text
    messages = history.json()["messages"]
    assert [item["body"] for item in messages] == ["hello", "hi"]
    assert [item["conversation_id"] for item in messages] == [conversation_id, conversation_id]
    assert [item["from_did"] for item in messages] == ["did:aw:alice", "did:aw:bob"]

    async def _mallory_auth():
        return MessagingAuth(
            did_key=mallory_did_key,
            did_aw="did:aw:mallory",
            address="evil.example/mallory",
            team_id="backend:acme.com",
            alias="mallory",
        )

    app.dependency_overrides[get_messaging_auth] = _mallory_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        forbidden = await client.get(f"/v1/messages/conversations/{conversation_id}")
    assert forbidden.status_code == 403
    assert "not a participant" in forbidden.json()["detail"]


@pytest.mark.asyncio
async def test_mail_conversation_history_distinguishes_missing_and_legacy_message(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    legacy_message_id = "11111111-1111-1111-1111-111111111111"
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at
        )
        VALUES ($1, $2, 'did:aw:bob', 'alice', 'bob', 'legacy', 'old mail', 'normal', NOW())
        """,
        UUID(legacy_message_id),
        alice_did_key,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        legacy = await client.get(f"/v1/messages/conversations/{legacy_message_id}")
        missing = await client.get("/v1/messages/conversations/99999999-9999-4999-8999-999999999999")

    assert legacy.status_code == 404
    assert "legacy mail without a conversation" in legacy.json()["detail"]
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Conversation not found"


@pytest.mark.asyncio
async def test_send_message_continuation_rejects_non_participant_and_closed(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    _, _, mallory_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:bob", "subject": "initial closed", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    async def _mallory_auth():
        return MessagingAuth(
            did_key=mallory_did_key,
            did_aw="did:aw:mallory",
            address="evil.example/mallory",
            team_id="backend:acme.com",
            alias="mallory",
        )

    app.dependency_overrides[get_messaging_auth] = _mallory_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        leaked = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "leak", "body": "nope"},
        )
    assert leaked.status_code == 403
    assert "not a participant" in leaked.json()["detail"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversations}} SET status = 'closed' WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        closed = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "closed", "body": "nope"},
        )
    assert closed.status_code == 403
    assert "closed" in closed.json()["detail"]


@pytest.mark.asyncio
async def test_send_message_explicit_recipient_with_closed_conversation_id_rejects(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_address": "acme.com/bob", "subject": "initial explicit closed", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversations}} SET status = 'closed' WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        closed = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_address": "acme.com/bob",
                "subject": "closed explicit",
                "body": "nope",
            },
        )

    assert closed.status_code == 403
    assert "closed" in closed.json()["detail"]


@pytest.mark.asyncio
async def test_send_message_explicit_recipient_with_existing_conversation_id_rejects_target_mismatch(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    _, _, charlie_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="charlie",
        did_key=charlie_did_key,
        did_aw="did:aw:charlie",
        address="acme.com/charlie",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_address": "acme.com/bob", "subject": "initial mismatch guard", "body": "hello"},
        )
        mismatch = await client.post(
            "/v1/messages",
            json={
                "conversation_id": first.json()["conversation_id"],
                "to_address": "acme.com/charlie",
                "subject": "must not create",
                "body": "wrong target",
            },
        )

    assert first.status_code == 200, first.text
    assert mismatch.status_code == 409
    assert "recipient does not match" in mismatch.json()["detail"]
    count = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE conversation_id = $1",
        UUID(first.json()["conversation_id"]),
    )
    assert count == 1


@pytest.mark.asyncio
async def test_signed_continuation_requires_matching_conversation_id(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/messages",
            json={"to_did": "did:aw:bob", "subject": "initial signed", "body": "hello"},
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = json.dumps(
        {
            "type": "mail",
            "from": "alice",
            "priority": "normal",
            "subject": "signed continuation",
            "body": "hi",
            "from_did": "did:aw:alice",
            "message_id": message_id,
            "timestamp": timestamp,
            "conversation_id": "11111111-1111-1111-1111-111111111111",
        }
    )
    payload = {
        "conversation_id": conversation_id,
        "subject": "signed continuation",
        "body": "hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": "test-signature",
        "signed_payload": signed_payload,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "conversation_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_signed_legacy_first_mail_status_is_visible_and_allows_continuation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "type": "mail",
            "from": "alice",
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "subject": "legacy signed",
            "body": "hello",
            "from_did": alice_did_key,
            "message_id": message_id,
            "timestamp": timestamp,
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "subject": "legacy signed",
        "body": "hello",
        "from_did": alice_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=payload)
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")
        reply = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "reply", "body": "blocked"},
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["verification_status"] == "verified_legacy"
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id


@pytest.mark.asyncio
async def test_signed_legacy_latest_mail_that_is_not_first_still_blocks_continuation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    first_message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    first_signed_payload = canonical_json_bytes(
        {
            "type": "mail",
            "from": "alice",
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "subject": "bound signed",
            "body": "hello",
            "from_did": alice_did_key,
            "message_id": first_message_id,
            "conversation_id": conversation_id,
            "timestamp": timestamp,
        }
    )
    first_payload = {
        "to_did": "did:aw:bob",
        "subject": "bound signed",
        "body": "hello",
        "from_did": alice_did_key,
        "message_id": first_message_id,
        "conversation_id": conversation_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, first_signed_payload),
        "signed_payload": first_signed_payload.decode(),
    }

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=first_payload)
    assert first.status_code == 200, first.text

    legacy_message_id = str(uuid4())
    legacy_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    legacy_signed_payload = canonical_json_bytes(
        {
            "type": "mail",
            "from": "alice",
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "subject": "legacy latest",
            "body": "legacy body",
            "from_did": alice_did_key,
            "message_id": legacy_message_id,
            "timestamp": legacy_timestamp,
        }
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, conversation_id, from_agent_id, to_agent_id,
            from_alias, from_address, to_alias, from_did, to_did,
            subject, body, priority, signature, signed_payload, created_at
        )
        VALUES (
            $1, $2, $3, $4,
            'alice', 'acme.com/alice', 'bob', $5, 'did:aw:bob',
            'legacy latest', 'legacy body', 'normal', $6, $7, $8
        )
        """,
        legacy_message_id,
        conversation_id,
        alice_agent_id,
        bob_agent_id,
        alice_did_key,
        sign_message(alice_sk, legacy_signed_payload),
        legacy_signed_payload.decode(),
        datetime.now(timezone.utc) + timedelta(seconds=5),
    )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "reply", "body": "blocked"},
        )

    assert reply.status_code == 403
    assert "conversation_id" in reply.json()["detail"]


@pytest.mark.asyncio
async def test_signed_conversation_id_binding_status_is_visible_and_allows_continuation(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    conversation_id = str(uuid4())
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_agent_id,
        )

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
            agent_id=bob_agent_id,
        )

    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "type": "mail",
            "from": "alice",
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "subject": "bound signed",
            "body": "hello",
            "from_did": alice_did_key,
            "message_id": message_id,
            "timestamp": timestamp,
            "conversation_id": conversation_id,
        }
    )
    payload = {
        "to_did": "did:aw:bob",
        "conversation_id": conversation_id,
        "subject": "bound signed",
        "body": "hello",
        "from_did": alice_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
    }

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/messages", json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["conversation_id"] == conversation_id

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")
        reply = await client.post(
            "/v1/messages",
            json={"conversation_id": conversation_id, "subject": "reply", "body": "allowed"},
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["verification_status"] == "verified"
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open')
        """,
        alice_current_did,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'team_and_contacts')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open')
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
            delivery=AddressDelivery(origin="https://remote.example"),
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
    app.state.federation_mail_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "message_id": json.loads(request.content)["envelope"]["message_id"],
                "conversation_id": json.loads(request.content)["envelope"]["conversation_id"],
                "status": "delivered",
                "delivered_at": json.loads(request.content)["envelope"]["timestamp"],
            },
        )
    )

    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "subject": "external",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": "otherco.com/bob",
        "subject": "external",
        "body": "hello",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('dev:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open')
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
            delivery=AddressDelivery(origin="https://remote.example"),
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
    app.state.federation_mail_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "message_id": json.loads(request.content)["envelope"]["message_id"],
                "conversation_id": json.loads(request.content)["envelope"]["conversation_id"],
                "status": "delivered",
                "delivered_at": json.loads(request.content)["envelope"]["timestamp"],
            },
        )
    )

    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "acme.com/alice",
            "from_did": alice_did_key,
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "subject": "multi membership external",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": "otherco.com/bob",
        "subject": "multi membership external",
        "body": "hello",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('dev:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('ops:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open'),
            ('dev:acme.com', 'did:key:dev-bob', 'did:aw:dev-bob', 'acme.com/dev-bob', 'bob', 'global', 'developer', 'open')
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
        SELECT team_id, from_agent_id, from_alias, from_did, from_address, to_did, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'multi membership team auth'
        """
    )
    assert row["team_id"] == "ops:acme.com"
    assert row["from_agent_id"] == alice_ops_row["agent_id"]
    assert row["from_alias"] == "alice"
    assert row["from_did"] == "did:aw:alice"
    assert row["from_address"] == "acme.com/alice"
    assert row["to_did"] == "did:aw:bob"
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', $1, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
async def test_send_message_rejects_unsigned_stable_id_address_binding_when_awid_misses(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:team-stable'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-address')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('stable:identity.local', $1, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
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

    payload = {
        "to_address": "otherco.com/bob",
        "to_stable_id": "did:aw:bob",
        "subject": "duplicate local identity rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key="did:key:z6MkAliceCurrent")


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


def _federated_mail_payload(
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
    subject: str = "federated hello",
    body: str = "hello from another server",
    priority: str = "normal",
    message_id: str | None = None,
    conversation_id: str | None = None,
    signed_to_did: str | None = None,
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
            "priority": priority,
            "subject": subject,
            "timestamp": timestamp,
            "to": target_address,
            "to_did": signed_to_did or target_did_key,
            "to_stable_id": target_did_aw,
            "type": "mail",
        }
    ).decode()
    envelope = {
        "version": 1,
        "type": "mail",
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
        "subject": subject,
        "priority": priority,
    }
    return {
        "envelope": envelope,
        "signature": sign_message(sender_sk, signed_payload.encode()),
    }


@pytest.mark.asyncio
async def test_receive_old_v1_federated_mail_ignores_deprecated_fields_and_delivers(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
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
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
    )
    payload["envelope"].update(_deprecated_federation_v1_fields())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_with("beta.example", "bob")
    envelope = payload["envelope"]
    assert resp.json()["message_id"] == envelope["message_id"]
    assert resp.json()["conversation_id"] == envelope["conversation_id"]
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT message_id, conversation_id, from_did, to_did, from_address,
               to_agent_id, signature, signed_payload
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        UUID(envelope["message_id"]),
    )
    assert row["from_did"] == "did:aw:alice"
    assert row["to_did"] == "did:aw:bob"
    assert row["from_address"] == "alpha.example/alice"
    assert str(row["to_agent_id"]) == bob_agent_id
    assert row["signature"] == payload["signature"]
    assert row["signed_payload"] == envelope["signed_payload"]
    participants = await _conversation_participants(aweb_cloud_db.aweb_db, envelope["conversation_id"])
    sender_participant = next(item for item in participants if item["did"] == "did:aw:alice")
    assert sender_participant["address"] == "alpha.example/alice"
    assert sender_participant["delivery_origin"] == "https://sender.example"
    assert sender_participant["transport_hint"] == "federation:https://sender.example"


@pytest.mark.asyncio
async def test_receive_federated_mail_first_contact_to_unknown_local_didkey_fails_closed(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key)
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address="did:key:z6MkUnknownLocal",
        target_did_aw="did:key:z6MkUnknownLocal",
        target_did_key="did:key:z6MkUnknownLocal",
        target_delivery_origin="https://recipient.example",
        subject="unknown local",
        body="should fail",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert "Federation first-contact target_address must be domain/name" in resp.text
    registry.resolve_key.assert_awaited_once_with("did:aw:alice")
    assert await aweb_cloud_db.aweb_db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
async def test_receive_federated_mail_existing_local_didkey_first_contact_fails_closed(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, local_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="local",
        did_key=local_did_key,
        did_aw="",
        address="",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin="https://recipient.example",
        subject="first contact local",
        body="must fail",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert "Federation first-contact target_address must be domain/name" in resp.text
    assert await aweb_cloud_db.aweb_db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
async def test_receive_federated_mail_existing_local_didkey_reply_succeeds(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    local_sk, _, local_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    local_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="local",
        did_key=local_did_key,
        did_aw="",
        address="",
    )
    conversation_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'default:beta.example', $2)
        """,
        UUID(conversation_id),
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
        UUID(conversation_id),
        local_did_key,
        local_agent_id,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw="did:aw:bob",
        sender_address="remote.example/bob",
        sender_delivery_origin="https://remote.example",
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin="https://recipient.example",
        subject="learned reply",
        body="allowed reply",
        conversation_id=conversation_id,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did, to_agent_id FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert row["from_did"] == "did:aw:bob"
    assert row["to_did"] == local_did_key
    assert str(row["to_agent_id"]) == local_agent_id
    remote_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = 'did:aw:bob'
        """,
        UUID(conversation_id),
    )
    assert remote_participant["current_did_key"] == bob_did_key

    registry.resolve_key = AsyncMock(side_effect=AssertionError("continuation must use backfilled current did:key"))
    registry.resolve_address = AsyncMock(side_effect=AssertionError("continuation must not rediscover address"))
    remote_calls = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_calls.append(request)
        envelope = json.loads(request.content)["envelope"]
        assert envelope["target_current_did_key"] == bob_did_key
        assert envelope["target_delivery_origin"] == "https://remote.example"
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

    async def _local_auth():
        return MessagingAuth(
            did_key=local_did_key,
            did_aw="",
            address="",
            team_id="default:beta.example",
            alias="local",
            agent_id=local_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _local_auth
    reply_message_id = str(uuid4())
    reply_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "local continuation after backfill",
            "conversation_id": conversation_id,
            "from": "beta.example/local",
            "from_did": local_did_key,
            "message_id": reply_message_id,
            "priority": "normal",
            "subject": "Local reply",
            "timestamp": reply_timestamp,
            "to": "did:aw:bob",
            "to_did": "did:aw:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_did": "did:aw:bob",
                "to_stable_id": "did:aw:bob",
                "subject": "Local reply",
                "body": "local continuation after backfill",
                "from_did": local_did_key,
                "message_id": reply_message_id,
                "timestamp": reply_timestamp,
                "signature": sign_message(local_sk, reply_signed_payload),
                "signed_payload": reply_signed_payload.decode(),
            },
        )

    assert reply.status_code == 200, reply.text
    assert len(remote_calls) == 1
    registry.resolve_key.assert_not_called()
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_send_message_federated_conversation_reply_uses_recorded_participant_not_address_rediscovery(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    conversation_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did, created_at, updated_at
        )
        VALUES ($1, 'mail', 'default:beta.example', 'did:aw:alice', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute')
        """,
        UUID(conversation_id),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role
        )
        VALUES
            ($1, 'did:aw:alice', NULL, 'alice', 'alpha.example/alice', 'https://sender.example', $3, 'federation:https://sender.example', 'initiator'),
            ($1, 'did:aw:bob', $2, 'bob', 'beta.example/bob', NULL, $4, 'local', 'participant')
        """,
        UUID(conversation_id),
        UUID(bob_agent_id),
        alice_did_key,
        bob_did_key,
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(side_effect=AssertionError("federated continuation must use stored current did:key"))
    registry.resolve_address = AsyncMock(side_effect=AssertionError("federated continuation must not rediscover address"))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"

    remote_calls: list[dict] = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        remote_calls.append(body)
        envelope = body["envelope"]
        assert envelope["conversation_id"] == conversation_id
        assert envelope["target_address"] == "alpha.example/alice"
        assert envelope["target_did_aw"] == "did:aw:alice"
        assert envelope["target_current_did_key"] == alice_did_key
        assert envelope["target_delivery_origin"] == "https://sender.example"
        verify_federation_envelope(envelope, body["signature"])
        return httpx.Response(
            200,
            json={
                "message_id": envelope["message_id"],
                "conversation_id": envelope["conversation_id"],
                "status": "delivered",
                "delivered_at": envelope["timestamp"],
            },
        )

    app.state.federation_mail_transport = httpx.MockTransport(_remote_handler)

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="beta.example/bob",
            team_id="default:beta.example",
            alias="bob",
            agent_id=bob_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "federated continuation",
            "conversation_id": conversation_id,
            "from": "beta.example/bob",
            "from_did": bob_did_key,
            "from_stable_id": "did:aw:bob",
            "message_id": message_id,
            "priority": "normal",
            "subject": "Federated reply",
            "timestamp": timestamp,
            "to": "did:aw:alice",
            "to_did": "did:aw:alice",
            "to_stable_id": "did:aw:alice",
            "type": "mail",
        }
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_did": "did:aw:alice",
                "to_stable_id": "did:aw:alice",
                "subject": "Federated reply",
                "body": "federated continuation",
                "from_did": bob_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(bob_sk, signed_payload),
                "signed_payload": signed_payload.decode(),
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["conversation_id"] == conversation_id
    assert len(remote_calls) == 1
    registry.resolve_address.assert_not_called()
    registry.resolve_key.assert_not_called()

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET current_did_key = NULL
        WHERE conversation_id = $1 AND did = 'did:aw:alice'
        """,
        UUID(conversation_id),
    )
    second_message_id = str(uuid4())
    second_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    second_signed_payload = canonical_json_bytes(
        {
            "body": "federated continuation without stored key",
            "conversation_id": conversation_id,
            "from": "beta.example/bob",
            "from_did": bob_did_key,
            "from_stable_id": "did:aw:bob",
            "message_id": second_message_id,
            "priority": "normal",
            "subject": "Federated reply",
            "timestamp": second_timestamp,
            "to": "did:aw:alice",
            "to_did": "did:aw:alice",
            "to_stable_id": "did:aw:alice",
            "type": "mail",
        }
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        missing_key = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_did": "did:aw:alice",
                "to_stable_id": "did:aw:alice",
                "subject": "Federated reply",
                "body": "federated continuation without stored key",
                "from_did": bob_did_key,
                "message_id": second_message_id,
                "timestamp": second_timestamp,
                "signature": sign_message(bob_sk, second_signed_payload),
                "signed_payload": second_signed_payload.decode(),
            },
        )

    assert missing_key.status_code == 422, missing_key.text
    assert missing_key.json()["detail"] == "Remote mail recipient stored route is missing current did:key"
    assert len(remote_calls) == 1


@pytest.mark.asyncio
async def test_receive_federated_mail_stored_route_rejects_wrong_target_current_key(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    wrong_bob_key = "did:key:z6MkWrongBobKey"
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    conversation_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'default:beta.example', 'did:aw:alice')
        """,
        UUID(conversation_id),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role)
        VALUES
            ($1, 'did:aw:alice', NULL, 'alice', 'alpha.example/alice', 'https://sender.example', $2, 'federation:https://sender.example', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'beta.example/bob', NULL, $4, 'local', 'participant')
        """,
        UUID(conversation_id),
        alice_did_key,
        bob_agent_id,
        bob_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(side_effect=AssertionError("stored-route rejection must not rediscover target address"))
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address="did:aw:bob",
        target_did_aw="did:aw:bob",
        target_did_key=wrong_bob_key,
        target_delivery_origin="https://recipient.example",
        signed_to_did="did:aw:bob",
        subject="wrong key continuation",
        body="must reject before storing",
        conversation_id=conversation_id,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert "Federation target current key mismatch" in resp.text
    registry.resolve_key.assert_awaited_once_with("did:aw:alice")
    registry.resolve_address.assert_not_called()
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE conversation_id = $1",
        UUID(conversation_id),
    ) == 0


@pytest.mark.asyncio
async def test_receive_federated_mail_duplicate_message_id_is_idempotent(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
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
    payload = _federated_mail_payload(sender_sk=alice_sk, sender_did_key=alice_did_key, target_did_key=bob_did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/federation/messages", json=payload)
        second = await client.post("/v1/federation/messages", json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["message_id"] == first.json()["message_id"]
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert count == 1
    claims = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.federated_message_deliveries}}
        WHERE message_type = 'mail'
          AND sender_did_aw = 'did:aw:alice'
          AND target_did_aw = 'did:aw:bob'
          AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert claims == 1


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_routes_ciphertext_only(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
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
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id="did:aw:alice",
        recipient_did=bob_did_key,
        recipient_stable_id="did:aw:bob",
        recipient_address="beta.example/bob",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": "did:aw:alice",
            "sender_current_did_key": alice_did_key,
            "sender_address": "alpha.example/alice",
            "sender_delivery_origin": "https://sender.example",
            "target_address": "beta.example/bob",
            "target_did_aw": "did:aw:bob",
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": "https://recipient.example",
            "body": "",
            "message_id": message_id,
            "timestamp": encrypted["created_at"],
            "conversation_id": conversation_id,
            "subject": "",
            "priority": "normal",
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": encrypted,
        },
        "signature": encrypted["signature"],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/v1/federation/messages", json=payload)
        second = await client.post("/v1/federation/messages", json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT subject, body, content_mode, message_version, signature, signed_payload,
               encrypted_envelope, signed_envelope_hash
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        UUID(message_id),
    )
    assert row["subject"] == ""
    assert row["body"] == ""
    assert row["content_mode"] == "encrypted_v2"
    assert row["message_version"] == 2
    assert row["signature"] is None
    assert row["signed_payload"] is None
    assert str(row["signed_envelope_hash"]).startswith("sha256:")
    assert "sealed body" not in json.dumps(row["encrypted_envelope"])
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    ) == 1


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_rejects_plaintext_wrapper_and_timestamp_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
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
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id="did:aw:alice",
        recipient_did=bob_did_key,
        recipient_stable_id="did:aw:bob",
        recipient_address="beta.example/bob",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    base_payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": "did:aw:alice",
            "sender_current_did_key": alice_did_key,
            "sender_address": "alpha.example/alice",
            "sender_delivery_origin": "https://sender.example",
            "target_address": "beta.example/bob",
            "target_did_aw": "did:aw:bob",
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": "https://recipient.example",
            "body": "",
            "message_id": message_id,
            "timestamp": encrypted["created_at"],
            "conversation_id": conversation_id,
            "subject": "",
            "priority": "normal",
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": encrypted,
        },
        "signature": encrypted["signature"],
    }
    created_at = datetime.fromisoformat(encrypted["created_at"].replace("Z", "+00:00"))
    timestamp_mismatch = (created_at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    variants = [
        ("body", "plaintext sentinel", "body must be empty"),
        ("subject", "plaintext sentinel", "subject must be empty"),
        ("signed_payload", "legacy signed plaintext", "signed_payload must be absent"),
        ("timestamp", timestamp_mismatch, "timestamp does not match"),
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for field, value, expected in variants:
            payload = json.loads(json.dumps(base_payload))
            payload["envelope"][field] = value
            resp = await client.post("/v1/federation/messages", json=payload)
            assert resp.status_code == 422, (field, resp.text)
            assert expected in resp.text

    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    ) == 0


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_wrong_delivery_origin(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://different.example"
    payload = _federated_mail_payload(sender_sk=alice_sk, sender_did_key=alice_did_key, target_did_key=bob_did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 421, resp.text
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_sender_key_drift(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key="did:key:z6MkRotated"))
    registry.resolve_address = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(sender_sk=alice_sk, sender_did_key=alice_did_key, target_did_key=bob_did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert "sender current key mismatch" in resp.text
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_target_binding_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
            domain="beta.example",
            name="bob",
            did_aw="did:aw:mallory",
            current_did_key=bob_did_key,
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://recipient.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"
    payload = _federated_mail_payload(sender_sk=alice_sk, sender_did_key=alice_did_key, target_did_key=bob_did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 422, resp.text
    assert "target did:aw mismatch" in resp.text


@pytest.mark.asyncio
async def test_receive_federated_mail_allows_explicit_inbound_mode_open(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "default:beta.example")
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:beta.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="beta.example/bob",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id=str(uuid4()),
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
    payload = _federated_mail_payload(sender_sk=alice_sk, sender_did_key=alice_did_key, target_did_key=bob_did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/federation/messages", json=payload)

    assert resp.status_code == 200, resp.text
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert count == 1


@pytest.mark.asyncio
async def test_send_message_accepts_to_stable_id_did_binding_with_duplicate_identity_rows(aweb_cloud_db):
    _, _, bob_old_did_key = _make_keypair()
    _, _, bob_current_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:team-stable'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-address')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('stable:identity.local', $2, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
        """,
        bob_old_did_key,
        bob_current_did_key,
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
        "to_did": bob_old_did_key,
        "to_stable_id": "did:aw:bob",
        "subject": "duplicate did binding rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'duplicate did binding rows'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is not None
    assert row["to_alias"] == "bob-stable"


@pytest.mark.asyncio
async def test_send_message_accepts_to_stable_id_alias_binding_with_duplicate_identity_rows(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:team-stable'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-address')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('stable:identity.local', $1, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
        """,
        bob_did_key,
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
        "to_stable_id": "did:aw:bob",
        "subject": "duplicate stable alias binding rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'duplicate stable alias binding rows'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is not None
    assert row["to_alias"] == "bob-stable"


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk', 'local', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk', 'local', 'developer', 'open'),
            ('ops:test.local', $2, 'did:aw:carol', 'test.local/carol', 'carol', 'local', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
async def test_send_message_accepts_to_did_alias_binding_with_duplicate_identity_rows(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:team-stable'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-address')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('stable:identity.local', $1, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
        """,
        bob_did_key,
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
        "to_alias": "bob",
        "subject": "duplicate did alias binding rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'duplicate did alias binding rows'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is not None
    assert row["to_alias"] == "bob-stable"


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
async def test_send_message_accepts_to_address_alias_binding_with_duplicate_identity_rows(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:team-stable'),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team-address')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('stable:identity.local', $1, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
        """,
        bob_did_key,
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
        "to_alias": "bob",
        "subject": "duplicate address alias binding rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'duplicate address alias binding rows'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is not None
    assert row["to_alias"] == "bob-stable"


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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open'),
            ('ops:otherco.com', $2, 'did:aw:carol', 'otherco.com/carol', 'carol', 'global', 'developer', 'open')
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
async def test_send_message_accepts_to_agent_id_alias_binding_with_duplicate_identity_rows(aweb_cloud_db):
    _, _, bob_old_did_key = _make_keypair()
    _, _, bob_current_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z'),
            ('ops:otherco.com', $2, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z')
        """,
        bob_old_did_key,
        bob_current_did_key,
    )
    stable = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'bob-stable'"
    )
    assert stable is not None

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
        "to_agent_id": str(stable["agent_id"]),
        "to_alias": "bob",
        "subject": "duplicate agent alias binding rows",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'duplicate agent alias binding rows'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert str(row["to_agent_id"]) == str(stable["agent_id"])
    assert row["to_alias"] == "bob-stable"


@pytest.mark.asyncio
async def test_send_message_team_and_contacts_accepts_equivalent_owner_did(aweb_cloud_db):
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'team_and_contacts')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open')
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
async def test_send_message_team_and_contacts_accepts_verified_same_team_non_contact_http(aweb_cloud_db):
    """aapq: HTTP-level regression — a same-team valid team certificate
    authorizes delivery into a team_and_contacts recipient even without
    an exact active contact."""
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'team_and_contacts')
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
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_alias": "bob", "subject": "team delivery", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(alice_sk, alice_did_key, "backend:acme.com", cert_header, body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_send_message_team_and_contacts_accepts_verified_same_team_non_contact(aweb_cloud_db):
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'team_and_contacts')
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
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_alias": "bob", "subject": "team delivery", "body": "hi"}
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open'),
            ('eng:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('default:local', $1, NULL, NULL, 'alice', 'local', 'developer', 'open'),
            ('default:local', $2, NULL, NULL, 'bob', 'local', 'developer', 'open')
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
        identity_scope="local",
    )
    bob_cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="default:local",
        alias="bob",
        identity_scope="local",
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('ops:gsk.aweb.ai', $1, NULL, NULL, 'gsk', 'local', 'developer', 'open'),
            ('ops:gsk.aweb.ai', $2, NULL, NULL, 'amy', 'local', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES
            ('backend:acme.com', $1, NULL, NULL, 'alice', 'global', 'developer', 'open'),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'team_and_contacts')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('default:local', $1, NULL, NULL, 'alice', 'local', 'developer', 'open')
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
        identity_scope="local",
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
async def test_send_message_global_recipient_allows_explicit_inbound_mode_open(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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

    payload = {"to_did": "did:aw:bob", "subject": "allowed", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

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
async def test_send_message_to_global_address_team_and_contacts_rejects_non_contact(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob-contacts', 'did:aw:bob-contacts', 'otherco.com/bob-contacts', 'bob-contacts', 'global', 'developer', 'team_and_contacts')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-contacts",
            domain="otherco.com",
            name="bob-contacts",
            did_aw="did:aw:bob-contacts",
            current_did_key="did:key:bob-contacts",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_address": "otherco.com/bob-contacts", "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 403, resp.text
    assert "exact active contacts" in resp.text
    message_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.messages}}
        WHERE to_did = 'did:aw:bob-contacts'
        """
    )
    assert message_count == 0


@pytest.mark.asyncio
async def test_send_message_to_global_address_allows_explicit_inbound_mode_open(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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

    payload = {"to_address": "otherco.com/bob", "subject": "allowed", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_send_message_global_recipient_null_inbound_mode_fails_migration_required(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob-migration', 'did:aw:bob-migration', 'otherco.com/bob-migration', 'bob-migration', 'global', 'developer', NULL)
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_did": "did:aw:bob-migration", "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', NULL, NULL, 'bob', 'local', 'developer', 'open')
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
    assert "Local recipient only accepts" in resp.text


@pytest.mark.asyncio
async def test_send_message_to_address_does_not_fall_back_to_local_persistent_agent_when_awid_misses(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
        """
    )

    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key))
    registry.resolve_address = AsyncMock(return_value=None)
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.list_team_certificates = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"to_address": "otherco.com/bob", "subject": "hidden", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)


@pytest.mark.parametrize("recipient_identity_scope", ["global", "local"])
@pytest.mark.asyncio
async def test_send_message_to_address_uses_same_team_local_recipient_when_awid_misses(
    aweb_cloud_db,
    recipient_identity_scope,
):
    # The persistent branch is guarded by requires_registry_address_binding();
    # the ephemeral branch bypasses that predicate. Keep these as twins so
    # address routing cannot be accidentally covered with only one identity_scope.
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', $1, 'developer', 'open')
        """,
        recipient_identity_scope,
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

    subject = f"same team hidden {recipient_identity_scope}"
    payload = {"to_address": "otherco.com/bob", "subject": subject, "body": "hi"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = $1",
        subject,
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_address_rejects_cross_team_local_persistent_when_awid_misses(aweb_cloud_db):
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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

    payload = {"to_address": "otherco.com/bob", "subject": "cross team hidden", "body": "hi"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)


@pytest.mark.asyncio
async def test_send_message_to_address_uses_local_persistent_when_registry_unconfigured(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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

    payload = {"to_address": "otherco.com/bob", "subject": "local direct", "body": "hi"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = 'local direct'"
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_stable_id_address_binding_uses_local_persistent_when_registry_unconfigured(aweb_cloud_db):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
        "to_stable_id": "did:aw:bob",
        "to_address": "otherco.com/bob",
        "subject": "local bound",
        "body": "hi",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = 'local bound'"
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.parametrize("recipient_identity_scope", ["global", "local"])
@pytest.mark.asyncio
async def test_send_message_to_private_address_uses_client_recipient_binding(
    aweb_cloud_db,
    recipient_identity_scope,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', $1, 'developer', 'open')
        """,
        recipient_identity_scope,
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
            "body": "hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "priority": "normal",
            "subject": f"private bound {recipient_identity_scope}",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    )
    payload = {
        "to_address": "otherco.com/bob",
        "to_stable_id": "did:aw:bob",
        "subject": f"private bound {recipient_identity_scope}",
        "body": "hi",
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

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("otherco.com", "bob", did_key=alice_did_key)
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_alias
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        UUID(message_id),
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_private_address_rejects_unverified_client_recipient_binding(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('ops:otherco.com', 'did:key:bob', 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open')
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
            "body": "hi",
            "from": "did:aw:alice",
            "from_did": "did:aw:alice",
            "from_stable_id": "did:aw:alice",
            "message_id": message_id,
            "priority": "normal",
            "subject": "private spoof",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": "did:key:bob",
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    )
    payload = {
        "to_address": "otherco.com/bob",
        "to_stable_id": "did:aw:bob",
        "subject": "private spoof",
        "body": "hi",
        "from_did": "did:aw:alice",
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": "not-a-valid-signature",
        "signed_payload": signed_payload.decode(),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
