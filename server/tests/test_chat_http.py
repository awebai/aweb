from __future__ import annotations

from team_facts_fixtures import legacy_registry

from collections import OrderedDict
from time import monotonic
from aweb.error_responses import install_service_error_handlers
from aweb.identity_binding import IdentityBinding

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import httpx
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.federation_errors import FederationAuthorityError
from awid.registry import (
    IDTreeEnrollment,
    Address,
    AddressDelivery,
    KeyResolution,
)
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import E2EE_SUITE, _envelope_map, _hash_canonical, _key_wrap_map
from aweb.federation.envelope import verify_federation_envelope
from aweb.identity_auth_deps import (
    IDENTITY_DID_AW_HEADER,
    MessagingAuth,
    get_messaging_auth,
)
from aweb.identity_metadata import routable_chat_address
from aweb.messaging.chat_send import _resolve_remote_chat_route
from aweb.routes import chat as chat_routes
from aweb.routes.chat import router as chat_router
from aweb.routes.federation import router as federation_router
from federation_activation_support import TestFederationAuthority
from did_key_fixtures import named_did_key
from test_messages_http import (
    registered_mail_actors as registered_mail_actors,
    _registered_routing_pair,
    _record_federation,
    _registered_actor_headers,
    _registered_history,
    _registered_address_reads,
    _registered_outbound_chat_history,
    _MovedFederationTransport,
    _admit_registered_local,
    _mirror_retained_local_history,
    _store_retained_local_origin,
)

__all__ = ["registered_mail_actors"]


# Pytest loads the canonical fixture after this module's shared helpers exist.
pytest_plugins = ("chat_pair_support",)


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


def _raw_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _sha256_b64(data: bytes) -> str:
    return "sha256:" + _raw_b64(hashlib.sha256(data).digest())


def _encrypted_chat_envelope(
    *,
    sender_sk: bytes,
    sender_did: str,
    sender_stable_id: str,
    recipients: list[dict[str, str]],
    message_id: str,
    conversation_id: str,
    sender_address: str = "acme.com/alice",
    ciphertext: bytes = b"opaque-chat-ciphertext-with-tag",
):
    signing_key = SigningKey(sender_sk)
    delivery_wraps = []
    envelope_recipients = []
    for index, recipient in enumerate(recipients):
        key_byte = bytes([ord("r") + index])
        key_id = "sha256:" + _raw_b64(key_byte * 32)
        wrap = {
            "wrap_id": _sha256_b64(f"wrap-binding-{index}".encode()),
            "recipient_stable_id": recipient["stable_id"],
            "recipient_did": recipient["did"],
            "recipient_address": recipient["address"],
            "recipient_encryption_key_id": key_id,
            "sender_encryption_key_id": "sha256:" + _raw_b64(b"s" * 32),
            "sender_did": sender_did,
            "sender_stable_id": sender_stable_id,
            "wrap_purpose": "delivery",
            "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
            "encapsulated_key": _raw_b64(bytes([ord("e") + index]) * 32),
            "wrapped_cek": _raw_b64(bytes([ord("w") + index]) * 48),
        }
        delivery_wraps.append(wrap)
        envelope_recipients.append(
            {
                "address": recipient["address"],
                "did": recipient["did"],
                "stable_id": recipient["stable_id"],
                "encryption_key_id": key_id,
                "wrap_id": wrap["wrap_id"],
            }
        )
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
    key_wraps = [*delivery_wraps, sender_copy_wrap]
    envelope = {
        "message_version": 2,
        "envelope_type": "aweb.e2ee.message",
        "kind": "chat",
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
        "recipients": envelope_recipients,
        "routing": {
            "to": ",".join(recipient["address"] for recipient in recipients),
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
                [_key_wrap_map(item) for item in key_wraps],
            ),
        },
        "key_wraps": key_wraps,
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


def _signed_team_headers(
    agent_sk, agent_did_key, team_id: str, cert_header: str, body_bytes=b""
):
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


def _build_test_app(aweb_db, registry, *, verified_bindings=()):
    app = FastAPI()
    install_service_error_handlers(app)
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
                if message["type"] == "http.request" and not message.get(
                    "more_body", False
                ):
                    continue
                return message

        request._receive = _receive
        return await call_next(request)

    app.state.db = _DbShim()
    app.state.redis = None
    app.state.awid_registry_client = legacy_registry(registry)
    if registry is not None:
        # These routing unit cases select the supplied strict foreign authority.
        # Configured-home authority is exercised against real AWID apps.
        registry.registry_url = "https://home-registry.test"
        registry.registry_audience = AsyncMock(return_value="https://registry.test")
    # Routing/signature unit cases supply established authority facts explicitly.
    # Fresh registry admission and refusals use test_identity_binding_http.
    app.state.identity_binding_cache = OrderedDict(
        {
            (did_aw, did_key, selected_address): (
                monotonic() + 60,
                IdentityBinding(
                    did_aw,
                    selected_address,
                    id_tree=IDTreeEnrollment(enrolled=False, domain=None),
                ),
            )
            for did_aw, did_key, address in verified_bindings
            for selected_address in {"", address}
        }
    )
    app.state.federation_authority = TestFederationAuthority(aweb_db, registry)
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
            {
                "team_id": "ops:otherco.com",
                "alias": "gsk",
                "address": "otherco.com/gsk",
            },
            "support:acme.com",
            "gsk",
        )
        == "otherco.com/gsk"
    )


def test_bridged_participant_metadata_has_no_routable_address():
    # A bridged guest must never route as its bridge owner's native identity,
    # even when its metadata carries the owner's address, alias and team.
    bridged = {
        "participant_kind": "bridged",
        "team_id": "ops:acme.com",
        "alias": "bridge-owner",
        "address": "acme.com/bridge-owner",
    }
    assert routable_chat_address(bridged, "ops:acme.com", "bridge-owner") == ""
    assert routable_chat_address(bridged, "support:acme.com", "Same name") == ""


@pytest.mark.asyncio
async def test_chat_to_external_address_posts_federated_chat_and_projects_locally(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    remote_requests = _record_federation(world.source.node)
    address_path = f"/v1/namespaces/{bob.address.split('/')[0]}/addresses/bob"
    prior_reads = world.target.node.registry_calls.count(("GET", address_path))
    session_id = str(uuid4())
    message_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "hello remote chat",
            "conversation_id": session_id,
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob_did_key,
            "to_stable_id": bob.stable_id,
            "type": "chat",
            "wait_seconds": 30,
        }
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        resp = await client.post(
            "/v1/chat/sessions",
            json={
                "session_id": session_id,
                "to_addresses": [bob.address],
                "message": "hello remote chat",
                "wait_seconds": 30,
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signature": sign_message(alice_sk, signed_payload.encode()),
                "signed_payload": signed_payload,
            },
            headers=_registered_actor_headers(
                alice,
                payload={
                    "session_id": session_id,
                    "to_addresses": [bob.address],
                    "message": "hello remote chat",
                    "wait_seconds": 30,
                    "from_did": alice_did_key,
                    "message_id": message_id,
                    "timestamp": timestamp,
                    "signature": sign_message(alice_sk, signed_payload.encode()),
                    "signed_payload": signed_payload,
                },
            ),
        )
    assert resp.status_code == 200, resp.text
    assert (
        world.target.node.registry_calls.count(("GET", address_path)) == prior_reads + 1
    )
    assert resp.json()["session_id"] == session_id
    assert resp.json()["message_id"] == message_id
    assert len(remote_requests) == 1
    remote_body = json.loads(remote_requests[0].content)
    assert (
        str(remote_requests[0].url)
        == world.target.node.origin + "/v1/federation/messages"
    )
    assert remote_body["envelope"]["type"] == "chat"
    assert remote_body["envelope"]["sender_delivery_origin"] == world.source.node.origin
    assert remote_body["envelope"]["target_delivery_origin"] == world.target.node.origin
    for deprecated_field in (
        "sender_active_team_id",
        "sender_team_certificate",
        "target_address_lookup_authorization",
        "target_address_lookup_timestamp",
    ):
        assert deprecated_field not in remote_body["envelope"]
    assert remote_body["envelope"]["wait_seconds"] == 30
    chat_participants = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT did, delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        """,
        UUID(session_id),
    )
    chat_by_did = {row["did"]: dict(row) for row in chat_participants}
    assert chat_by_did[alice.stable_id]["delivery_origin"] is None
    assert chat_by_did[alice.stable_id]["current_did_key"] == alice_did_key
    assert chat_by_did[bob.stable_id]["delivery_origin"] == world.target.node.origin
    assert chat_by_did[bob.stable_id]["current_did_key"] == bob_did_key
    conversation_participants = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT did, delivery_origin, current_did_key, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        """,
        UUID(session_id),
    )
    conversation_by_did = {row["did"]: dict(row) for row in conversation_participants}
    assert conversation_by_did[alice.stable_id]["delivery_origin"] is None
    assert conversation_by_did[alice.stable_id]["current_did_key"] == alice_did_key
    assert conversation_by_did[alice.stable_id]["transport_hint"] == "local"
    assert (
        conversation_by_did[bob.stable_id]["delivery_origin"]
        == world.target.node.origin
    )
    assert conversation_by_did[bob.stable_id]["current_did_key"] == bob_did_key
    assert (
        conversation_by_did[bob.stable_id]["transport_hint"]
        == f"federation:{world.target.node.origin}"
    )
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT contact_address, label, reference_type, status
        FROM {{tables.contacts}}
        WHERE owner_did = $1 AND contact_address = $2
        """,
        alice.stable_id,
        bob.address,
    )
    assert dict(contact) == {
        "contact_address": bob.address,
        "label": "bob",
        "reference_type": "identity",
        "status": "active",
    }
    reply_payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=alice.address,
        target_did_aw=alice.stable_id,
        target_did_key=alice_did_key,
        target_delivery_origin=world.source.node.origin,
        body="reply through the projected chat route",
        conversation_id=session_id,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        reply = await client.post("/v1/federation/messages", json=reply_payload)
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == session_id


@pytest.mark.asyncio
async def test_chat_first_contact_to_external_address_requires_signed_payload(
    aweb_cloud_db,
):
    """Federated chat first contact must refuse an unsigned payload before delivery.

    The request carries from_did, message_id, timestamp and session_id, so the
    only thing _require_remote_chat_signature can object to is the missing
    signature pair. The asserted detail is emitted by nothing else in the
    request path, which is how this fixture proves it reached that gate.
    """
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
        RETURNING agent_id
        """,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(
            did_aw="did:aw:bob", current_did_key=named_did_key("bob")
        )
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=named_did_key("bob"),
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
        return httpx.Response(
            500, json={"detail": "unsigned chat must never reach the wire"}
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
            },
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "Federated chat delivery requires a sender-signed payload"
    )
    assert remote_requests == []
    session_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_sessions}} WHERE session_id = $1",
        UUID(session_id),
    )
    assert session_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("omitted", "expected_detail"),
    [
        ("from_did", "from_did is required for federated chat delivery"),
        (
            "message_id",
            "message_id, timestamp, and session_id are required for federated chat delivery",
        ),
    ],
)
async def test_chat_first_contact_to_external_address_requires_sender_attestation(
    aweb_cloud_db,
    omitted: str,
    expected_detail: str,
):
    """Each field _require_remote_chat_signature demands is refused by name.

    The request is otherwise a well-formed signed first contact, so dropping one
    field leaves that field's own raise as the next thing that can object. The
    detail is asserted rather than the status because dropping either field
    still yields 422 further down; only the message distinguishes which check
    made the decision.
    """
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
        RETURNING agent_id
        """,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(
            did_aw="did:aw:bob", current_did_key=named_did_key("bob")
        )
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=named_did_key("bob"),
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
        return httpx.Response(
            500, json={"detail": "incomplete chat must never reach the wire"}
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
            "to_stable_id": "did:aw:bob",
            "type": "chat",
            "wait_seconds": 30,
        }
    ).decode()
    body = {
        "session_id": session_id,
        "to_addresses": ["otherco.com/bob"],
        "message": "hello remote chat",
        "wait_seconds": 30,
        "from_did": alice_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    del body[omitted]

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=body)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == expected_detail
    assert remote_requests == []
    session_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_sessions}} WHERE session_id = $1",
        UUID(session_id),
    )
    assert session_count == 0


@pytest.mark.asyncio
async def test_chat_to_external_address_remote_failure_does_not_create_contact(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
        RETURNING agent_id
        """,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(
            did_aw="did:aw:bob", current_did_key=named_did_key("bob")
        )
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat-failure",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=named_did_key("bob"),
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_chat_continuation_to_remote_participant_uses_stored_delivery_origin(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
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
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */)
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
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'chat', 'participant')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError("chat continuation must use stored current did:key")
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-remote-chat",
            domain="otherco.com",
            name="bob",
            did_aw="did:aw:bob",
            current_did_key=named_did_key("bob"),
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert envelope["target_current_did_key"] == named_did_key("bob")
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
    second_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
            "to_stable_id": "did:aw:bob",
            "type": "chat",
        }
    ).decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert (
        missing_key.json()["detail"]
        == "Remote chat recipient stored route is missing current did:key"
    )
    assert len(remote_requests) == 1


@pytest.mark.asyncio
async def test_chat_continuation_to_remote_participant_requires_signed_payload(
    aweb_cloud_db,
):
    """Federated chat continuation must refuse an unsigned payload before delivery.

    Continuation skips _validate_signed_chat_payload entirely when no signature
    is present, so _require_remote_chat_signature is the only thing standing
    between an unsigned body and the remote server.
    """
    _, _, alice_did_key = _make_keypair()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
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
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */)
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
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'chat', 'participant')
        """,
        session_id,
        alice_agent_id,
        alice_did_key,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError("chat continuation must use stored current did:key")
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://local.example"
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        return httpx.Response(
            500, json={"detail": "unsigned chat must never reach the wire"}
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={
                "body": "continuing remote chat",
                "from_did": alice_did_key,
                "message_id": message_id,
                "timestamp": timestamp,
            },
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "Federated chat delivery requires a sender-signed payload"
    )
    assert remote_requests == []
    message_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE session_id = $1",
        session_id,
    )
    assert message_count == 0


@pytest.mark.asyncio
async def test_remote_chat_route_refresh_preserves_stable_authority_error():
    authority = SimpleNamespace(
        resolve_contact=AsyncMock(
            side_effect=FederationAuthorityError("federation_rate_limited")
        )
    )
    with pytest.raises(FederationAuthorityError) as error:
        await _resolve_remote_chat_route(
            SimpleNamespace(),
            runtime=SimpleNamespace(federation_authority=authority),
            source="127.0.0.1",
            registry_client=SimpleNamespace(),
            recipient={
                "address": "otherco.com/bob",
                "did": "did:aw:bob",
                "did_aw": "did:aw:bob",
                "delivery_origin": "https://old.example",
            },
        )

    assert error.value.reason == "federation_rate_limited"
    assert error.value.http_status == 429
    assert error.value.retryable is True
    assert error.value.retry_after_required is True


@pytest.mark.asyncio
async def test_chat_continuation_refreshes_stale_delivery_origin_once(route_pair):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    session_id = await _registered_outbound_chat_history(world)
    old_origin = "https://old.example"
    await world.source.node.db.execute(
        "UPDATE {{tables.chat_participants}} SET delivery_origin=$2 WHERE session_id=$1 AND did=$3",
        session_id,
        old_origin,
        bob.stable_id,
    )
    await world.source.node.db.execute(
        "UPDATE {{tables.conversation_participants}} SET delivery_origin=$2, transport_hint=$4 WHERE conversation_id=$1 AND did=$3",
        session_id,
        old_origin,
        bob.stable_id,
        f"federation:{old_origin}",
    )
    transport = _MovedFederationTransport(
        app.state.federation_authority.delivery_transport,
        refused_origin=old_origin,
    )
    app.state.federation_chat_transport = transport
    remote_requests = transport.requests
    await world.source.node.db.execute(
        "UPDATE {{tables.federation_address_authority_cohorts}} SET authoritative_read_completed_at=authoritative_read_completed_at-INTERVAL '2 minutes', expires_at=expires_at-INTERVAL '2 minutes' WHERE canonical_address=$1",
        bob.address,
    )
    prior_reads = _registered_address_reads(world.target)
    message_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "continuing after move",
            "conversation_id": str(session_id),
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob_did_key,
            "to_stable_id": bob.stable_id,
            "type": "chat",
        }
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
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
            headers=_registered_actor_headers(
                alice,
                payload={
                    "body": "continuing after move",
                    "from_did": alice_did_key,
                    "message_id": message_id,
                    "timestamp": timestamp,
                    "signature": sign_message(alice_sk, signed_payload.encode()),
                    "signed_payload": signed_payload,
                },
            ),
        )
    assert resp.status_code == 200, resp.text
    assert [str(request.url) for request in remote_requests] == [
        old_origin + "/v1/federation/messages",
        world.target.node.origin + "/v1/federation/messages",
    ]
    assert _registered_address_reads(world.target) == prior_reads + 2
    chat_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        bob.stable_id,
    )
    conversation_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT delivery_origin, current_did_key, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        session_id,
        bob.stable_id,
    )
    assert dict(chat_participant) == {
        "delivery_origin": world.target.node.origin,
        "current_did_key": bob_did_key,
    }
    assert dict(conversation_participant) == {
        "delivery_origin": world.target.node.origin,
        "current_did_key": bob_did_key,
        "transport_hint": f"federation:{world.target.node.origin}",
    }
    reply_payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=alice.address,
        target_did_aw=alice.stable_id,
        target_did_key=alice_did_key,
        target_delivery_origin=world.source.node.origin,
        body="reply after origin rotation",
        conversation_id=str(session_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        reply = await client.post("/v1/federation/messages", json=reply_payload)
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == str(session_id)


@pytest.mark.asyncio
async def test_chat_continuation_does_not_retry_when_refresh_keeps_same_origin(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    session_id = await _registered_outbound_chat_history(world)
    remote_requests = []

    async def refuse(request):
        remote_requests.append(request)
        return httpx.Response(421, json={"detail": "moved"})

    app.state.federation_chat_transport = httpx.MockTransport(refuse)
    await world.source.node.db.execute(
        "UPDATE {{tables.federation_address_authority_cohorts}} SET authoritative_read_completed_at=authoritative_read_completed_at-INTERVAL '2 minutes', expires_at=expires_at-INTERVAL '2 minutes' WHERE canonical_address=$1",
        bob.address,
    )
    prior_reads = _registered_address_reads(world.target)
    message_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "same origin failure",
            "conversation_id": str(session_id),
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob.did_key,
            "to_stable_id": bob.stable_id,
            "type": "chat",
        }
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
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
            headers=_registered_actor_headers(
                alice,
                payload={
                    "body": "same origin failure",
                    "from_did": alice_did_key,
                    "message_id": message_id,
                    "timestamp": timestamp,
                    "signature": sign_message(alice_sk, signed_payload.encode()),
                    "signed_payload": signed_payload,
                },
            ),
        )
    assert resp.status_code == 421, resp.text
    assert len(remote_requests) == 1
    assert _registered_address_reads(world.target) == prior_reads + 2
    chat_participant = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT delivery_origin FROM {{tables.chat_participants}} WHERE session_id = $1 AND did = $2",
        session_id,
        bob.stable_id,
    )
    assert chat_participant["delivery_origin"] == world.target.node.origin


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
    target_did_key: str = named_did_key("bob"),
    target_delivery_origin: str = "https://recipient.example",
    body: str = "hello from another server",
    message_id: str | None = None,
    conversation_id: str | None = None,
    signed_to_did: str | None = None,
):
    message_id = message_id or str(uuid4())
    conversation_id = conversation_id or str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": signed_to_did or target_did_key,
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
async def test_receive_old_v1_federated_chat_ignores_deprecated_fields_and_delivers(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.target.node.origin,
    )
    payload["envelope"].update(_deprecated_federation_v1_fields())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 200, resp.text
    assert (
        await app.state.awid_registry_client.resolve_address_fresh(
            *bob.address.split("/", 1)
        )
    ).did_aw == bob.stable_id
    session_id = resp.json()["session_id"]
    assert session_id == payload["envelope"]["conversation_id"]
    message = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, body, signature, signed_payload FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert message["from_did"] == alice.stable_id
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
    assert by_did[alice.stable_id]["delivery_origin"] == world.source.node.origin
    assert by_did[alice.stable_id]["current_did_key"] == alice_did_key
    assert by_did[bob.stable_id]["agent_id"] == UUID(bob.agent_id)
    assert by_did[bob.stable_id]["delivery_origin"] is None
    assert by_did[bob.stable_id]["current_did_key"] == bob_did_key
    remote_requests = _record_federation(world.target.node)
    sender_key_reads_before = world.source.node.registry_calls.count(
        ("GET", f"/v1/did/{alice.stable_id}/key")
    )
    reply_message_id = str(uuid4())
    reply_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "reply over stored route",
            "conversation_id": session_id,
            "from": bob.address,
            "from_did": bob_did_key,
            "from_stable_id": bob.stable_id,
            "message_id": reply_message_id,
            "timestamp": reply_timestamp,
            "to": alice.stable_id,
            "to_did": alice.stable_id,
            "to_stable_id": alice.stable_id,
            "type": "chat",
        }
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
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
            headers=_registered_actor_headers(
                bob,
                payload={
                    "body": "reply over stored route",
                    "from_did": bob_did_key,
                    "message_id": reply_message_id,
                    "timestamp": reply_timestamp,
                    "signature": sign_message(bob_sk, reply_signed_payload.encode()),
                    "signed_payload": reply_signed_payload,
                },
            ),
        )
    assert reply.status_code == 200, reply.text
    assert len(remote_requests) == 1
    remote_envelope = json.loads(remote_requests[0].content)["envelope"]
    assert (
        str(remote_requests[0].url)
        == world.source.node.origin + "/v1/federation/messages"
    )
    assert remote_envelope["target_address"] == alice.address
    assert remote_envelope["target_delivery_origin"] == world.source.node.origin
    assert (
        world.source.node.registry_calls.count(
            ("GET", f"/v1/did/{alice.stable_id}/key")
        )
        == sender_key_reads_before
    )


@pytest.mark.asyncio
async def test_receive_federated_chat_local_sender_omission_preserves_both_stored_routes(
    route_pair,
):
    """A retained local-key history input, not current first-contact authority."""
    from types import SimpleNamespace
    from aweb.messaging.kinds import MessageKind

    world = await _registered_routing_pair(route_pair)
    bob = world.target.actor
    local_sk, local_did_key = (world.source.node.local.sk, world.source.node.local.did)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    session_id = uuid4()
    await _mirror_retained_local_history(
        world,
        conversation_id=session_id,
        local_did_key=local_did_key,
        kind=MessageKind.CHAT,
        local_address="alpha.example/local",
    )
    target_address_reads_before = _registered_address_reads(world.target)
    payload = _federated_chat_payload(
        sender_sk=local_sk,
        sender_did_key=local_did_key,
        sender_did_aw=local_did_key,
        sender_address="alpha.example/local",
        target_address=bob.stable_id,
        target_did_key=bob_did_key,
        conversation_id=str(session_id),
        signed_to_did=bob.stable_id,
        sender_delivery_origin=world.source.node.origin,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.target.node.origin,
    )
    signed = json.loads(payload["envelope"]["signed_payload"])
    signed["from"] = local_did_key
    signed["from_stable_id"] = local_did_key
    payload["envelope"]["signed_payload"] = canonical_json_bytes(signed).decode()
    payload["signature"] = sign_message(
        local_sk, payload["envelope"]["signed_payload"].encode()
    )
    del payload["envelope"]["sender_address"]
    del payload["envelope"]["sender_delivery_origin"]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        response = await client.post("/v1/federation/messages", json=payload)
    assert response.status_code == 200, response.text
    conversation_route = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT address, delivery_origin, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        session_id,
        local_did_key,
    )
    chat_route = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT address, delivery_origin
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        local_did_key,
    )
    assert dict(conversation_route) == {
        "address": "alpha.example/local",
        "delivery_origin": world.source.node.origin,
        "transport_hint": f"federation:{world.source.node.origin}",
    }
    assert dict(chat_route) == {
        "address": "alpha.example/local",
        "delivery_origin": world.source.node.origin,
    }
    target_routes = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT 'conversation' AS store, address, delivery_origin
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        UNION ALL
        SELECT 'chat' AS store, address, delivery_origin
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        ORDER BY store
        """,
        session_id,
        bob.stable_id,
    )
    assert [dict(row) for row in target_routes] == [
        {"store": "chat", "address": bob.address, "delivery_origin": None},
        {"store": "conversation", "address": bob.address, "delivery_origin": None},
    ]
    injected = json.loads(json.dumps(payload))
    injected["envelope"]["message_id"] = str(uuid4())
    injected["envelope"]["target_address"] = "evil.example/injected"
    injected_signed = json.loads(injected["envelope"]["signed_payload"])
    injected_signed["message_id"] = injected["envelope"]["message_id"]
    injected["envelope"]["signed_payload"] = canonical_json_bytes(
        injected_signed
    ).decode()
    injected["signature"] = sign_message(
        local_sk, injected["envelope"]["signed_payload"].encode()
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        rejected = await client.post("/v1/federation/messages", json=injected)
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["reason"] == "recipient_route_mismatch"
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET address = 'changed.example/route',
            delivery_origin = 'https://changed.example',
            transport_hint = 'changed-route'
        WHERE conversation_id = $1
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.chat_participants}}
        SET address = 'changed.example/route',
            delivery_origin = 'https://changed.example'
        WHERE session_id = $1
        """,
        session_id,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        changed_route_replay = await client.post(
            "/v1/federation/messages", json=payload
        )
    assert changed_route_replay.status_code == 200, changed_route_replay.text
    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.chat_participants}} WHERE session_id = $1", session_id
    )
    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.conversation_participants}} WHERE conversation_id = $1",
        session_id,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        replay = await client.post("/v1/federation/messages", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["message_id"] == payload["envelope"]["message_id"]
    assert _registered_address_reads(world.target) == target_address_reads_before


@pytest.mark.asyncio
async def test_receive_federated_chat_existing_local_didkey_first_contact_fails_closed(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice = world.source.actor
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    local_did_key = world.target.node.local.did
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin=world.target.node.origin,
        body="first contact local chat",
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 422, resp.text
    assert resp.json()["reason"] == "federation_envelope_invalid"
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.chat_messages}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_chat_existing_local_didkey_reply_succeeds(route_pair):
    """Exercise retained local-key route history, never a current first-contact grant."""
    from types import SimpleNamespace
    from aweb.messaging.kinds import MessageKind

    world = await _registered_routing_pair(route_pair)
    bob = world.target.actor
    local = await _admit_registered_local(world.source.node)
    local_sk, local_did_key = (local.signing_key, local.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    session_id = uuid4()
    await _store_retained_local_origin(
        world, conversation_id=session_id, local=local, kind=MessageKind.CHAT
    )
    await _mirror_retained_local_history(
        world,
        conversation_id=session_id,
        local_did_key=local.did_key,
        kind=MessageKind.CHAT,
    )
    payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin=world.source.node.origin,
        body="learned chat reply",
        conversation_id=str(session_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, body FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert row["from_did"] == bob.stable_id
    assert row["body"] == "learned chat reply"
    session_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        bob.stable_id,
    )
    assert session_participant["current_did_key"] == bob_did_key
    conversation_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        session_id,
        bob.stable_id,
    )
    assert conversation_participant["current_did_key"] == bob_did_key
    peer_reads_before = (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    )
    remote_requests = _record_federation(world.source.node)
    reply_message_id = str(uuid4())
    reply_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "local chat continuation after backfill",
            "conversation_id": str(session_id),
            "from": f"{world.source.node.domain}/local",
            "from_did": local_did_key,
            "message_id": reply_message_id,
            "timestamp": reply_timestamp,
            "to": bob.address,
            "to_did": bob_did_key,
            "to_stable_id": bob.stable_id,
            "type": "chat",
        }
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
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
            headers=_registered_actor_headers(
                local,
                payload={
                    "body": "local chat continuation after backfill",
                    "from_did": local_did_key,
                    "message_id": reply_message_id,
                    "timestamp": reply_timestamp,
                    "signature": sign_message(local_sk, reply_signed_payload.encode()),
                    "signed_payload": reply_signed_payload,
                },
            ),
        )
    assert reply.status_code == 200, reply.text
    assert len(remote_requests) == 1
    assert (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    ) == peer_reads_before

    envelope = json.loads(remote_requests[0].content)["envelope"]
    assert envelope["target_current_did_key"] == bob_did_key
    assert envelope["target_delivery_origin"] == world.target.node.origin


@pytest.mark.asyncio
async def test_receive_federated_chat_stored_route_rejects_wrong_target_current_key(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    conversation_id = str(
        await _registered_history(world, make_payload=_federated_chat_payload)
    )
    session_id = UUID(conversation_id)
    wrong_bob_key = named_did_key("z6MkWrongBobKey")
    address_reads_before = _registered_address_reads(world.target)
    registry_reads_before = (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    )
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=bob.stable_id,
        target_did_aw=bob.stable_id,
        target_did_key=wrong_bob_key,
        target_delivery_origin=world.target.node.origin,
        signed_to_did=bob.stable_id,
        body="must reject before storing",
        conversation_id=str(session_id),
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 422, resp.text
    assert resp.json()["reason"] == "recipient_current_key_mismatch"
    assert (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    ) == registry_reads_before
    assert _registered_address_reads(world.target) == address_reads_before
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE session_id = $1",
            session_id,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_receive_federated_chat_local_didkey_missing_session_target_fails_closed(
    route_pair,
):
    """Exercise retained local-key route history, never a current first-contact grant."""
    from types import SimpleNamespace
    from aweb.messaging.kinds import MessageKind
    from messaging_actor_support import remove_messaging_agent_from_sessions

    world = await _registered_routing_pair(route_pair)
    bob = world.target.actor
    local = await _admit_registered_local(world.source.node)
    local_did_key = local.did_key
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    session_id = uuid4()
    await _store_retained_local_origin(
        world, conversation_id=session_id, local=local, kind=MessageKind.CHAT
    )
    from aweb.application_state import application_registry_client

    await remove_messaging_agent_from_sessions(
        world.source.node.db,
        app.state.redis,
        team_id=local.team_id,
        agent_id=local.agent_id,
        registry_client=application_registry_client(app.state),
    )
    payload = _federated_chat_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin=world.source.node.origin,
        body="stale session",
        conversation_id=str(session_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 409, resp.text
    assert resp.json()["reason"] == "federation_conversation_invalid"
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.chat_messages}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_chat_duplicate_message_id_is_idempotent(
    route_pair, monkeypatch
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.target.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        first = await client.post("/v1/federation/messages", json=payload)
        assert first.status_code == 200, first.text
        prior_cohort = await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT authoritative_read_completed_at, expires_at FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address = $1",
            alice.address,
        )
        assert prior_cohort is not None
        repository = app.state.federation_authority.core.repository
        monkeypatch.setattr(
            repository, "_cohort_check_time", lambda: prior_cohort["expires_at"]
        )
        second = await client.post("/v1/federation/messages", json=payload)
    assert second.status_code == 200, second.text
    cohort = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT authoritative_read_completed_at, expires_at FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address = $1",
        alice.address,
    )
    assert (
        cohort["authoritative_read_completed_at"]
        > prior_cohort["authoritative_read_completed_at"]
    )
    assert cohort["expires_at"] - cohort[
        "authoritative_read_completed_at"
    ] == timedelta(seconds=60)
    assert second.json()["message_id"] == payload["envelope"]["message_id"]
    message_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    receipt_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.message_ingress_receipts}}
        WHERE storage_kind = 'chat' AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert message_count == 1
    assert receipt_count == 1


@pytest.mark.asyncio
async def test_receive_federated_chat_rejects_closed_or_mismatched_conversation(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    from aweb.messaging.conversations import close_conversation

    closed_conversation_id = await _registered_history(
        world, make_payload=_federated_chat_payload
    )
    await close_conversation(
        world.target.node.server.db,
        conversation_id=closed_conversation_id,
        closed_by_did=bob.stable_id,
    )
    payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        conversation_id=str(closed_conversation_id),
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.target.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        closed = await client.post("/v1/federation/messages", json=payload)
    assert closed.status_code == 409, closed.text
    assert closed.json()["reason"] == "federation_conversation_invalid"
    delivery_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.federated_message_deliveries}}
        WHERE message_type = 'chat' AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert delivery_count == 0
    mismatched_conversation_id = await _registered_history(
        world, make_payload=_federated_chat_payload
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversation_participants}} SET did=$2 WHERE conversation_id=$1 AND did=$3",
        mismatched_conversation_id,
        "did:aw:carol",
        bob.stable_id,
    )
    mismatched_payload = _federated_chat_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        conversation_id=str(mismatched_conversation_id),
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.target.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        mismatched = await client.post(
            "/v1/federation/messages", json=mismatched_payload
        )
    assert mismatched.status_code == 409, mismatched.text
    assert mismatched.json()["reason"] == "federation_conversation_invalid"
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
async def test_create_chat_session_accepts_identity_auth_and_to_did(
    shared_test_pool, monkeypatch
):
    from aweb.application_state import application_registry_client
    from identity_binding_support import register_global_identity
    from test_dashboard_privacy import TEAM, privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        registry = application_registry_client(env.app.state)
        alice, bob = env.actors["alice"], env.actors["bob"]
        alice_stable = await register_global_identity(env, alice, "acme.com/alice")
        bob_stable = await register_global_identity(env, bob, "otherco.com/bob")
        other_team_sk, _, other_team_did = _make_keypair()
        controller = await env.registry.ensure_namespace(domain="otherco.com")
        await registry.register_team(
            domain="otherco.com",
            name="ops",
            display_name="ops",
            team_did_key=other_team_did,
            visibility="public",
            namespace_controller_signing_key=controller,
        )
        for alias, actor, stable, address, team, signing_key, team_did in (
            (
                "alice",
                alice,
                alice_stable,
                "acme.com/alice",
                TEAM,
                env.team_sk,
                env.team_did,
            ),
            (
                "bob",
                bob,
                bob_stable,
                "otherco.com/bob",
                "ops:otherco.com",
                other_team_sk,
                other_team_did,
            ),
        ):
            cert = _encode_certificate(
                _make_certificate(
                    signing_key,
                    team_did,
                    actor.did,
                    team_id=team,
                    alias=alias,
                    identity_scope="global",
                    member_did_aw=stable,
                    member_address=address,
                    certificate_id=f"identity-chat-{alias}",
                )
            )
            raw = b"{}"
            connected = await env.client.post(
                "/v1/connect",
                content=raw,
                headers={
                    **_signed_team_headers(actor.sk, actor.did, team, cert, raw),
                    "Content-Type": "application/json",
                },
            )
            assert connected.status_code == 200, connected.text

        raw = json.dumps({"to_dids": [bob_stable], "message": "hello bob"}).encode()
        response = await env.client.post(
            "/v1/chat/sessions",
            content=raw,
            headers={
                **_signed_identity_headers(alice.sk, alice.did, alice_stable, raw),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["session_id"]
        assert {participant["did"] for participant in payload["participants"]} == {
            alice_stable,
            bob_stable,
        }
        assert {participant["address"] for participant in payload["participants"]} == {
            "acme.com/alice",
            "otherco.com/bob",
        }


@pytest.mark.asyncio
async def test_create_encrypted_group_chat_stores_opaque_metadata_only(aweb_cloud_db):
    alice_sk, _, alice_did = _make_keypair()
    _, _, bob_did = _make_keypair()
    _, _, carol_did = _make_keypair()
    team_id = "backend:acme.com"
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', $2)
        """,
        team_id,
        named_did_key("zTeam"),
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_val(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ($1, 'alice', $2, 'did:aw:alice', 'acme.com/alice', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $2 END)
        RETURNING agent_id
        """,
        team_id,
        alice_did,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
          ($1, 'bob', $2, 'did:aw:bob', 'acme.com/bob', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $2 END),
          ($1, 'carol', $3, 'did:aw:carol', 'acme.com/carol', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:carol', '') IS NOT NULL THEN $3 END)
        """,
        team_id,
        bob_did,
        carol_did,
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id=team_id,
            alias="alice",
            agent_id=str(alice_agent_id),
        )

    session_id = "11111111-1111-4111-8111-111111111111"
    message_id = "22222222-2222-4222-8222-222222222222"
    envelope = _encrypted_chat_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did,
        sender_stable_id="did:aw:alice",
        recipients=[
            {"did": bob_did, "stable_id": "did:aw:bob", "address": "acme.com/bob"},
            {
                "did": carol_did,
                "stable_id": "did:aw:carol",
                "address": "acme.com/carol",
            },
        ],
        message_id=message_id,
        conversation_id=session_id,
    )
    payload = {
        "session_id": session_id,
        "to_aliases": ["bob", "carol"],
        "message": "",
        "message_id": message_id,
        "timestamp": envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": envelope,
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    headers = {
        **_signed_identity_headers(alice_sk, alice_did, "did:aw:alice", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/sessions", content=body_bytes, headers=headers
        )
    assert resp.status_code == 200, resp.text

    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT body, signature, signed_payload, content_mode, message_version, encrypted_envelope,
               encrypted_ciphertext_hash, encrypted_ciphertext_size, encrypted_key_wraps_hash,
               encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id,
               signed_envelope_hash
        FROM {{tables.chat_messages}}
        WHERE message_id = $1
        """,
        UUID(message_id),
    )
    assert row["body"] == ""
    assert row["signature"] is None
    assert row["signed_payload"] is None
    assert row["content_mode"] == "encrypted_v2"
    assert row["message_version"] == 2
    assert "group secret" not in json.dumps(row["encrypted_envelope"])
    assert row["encrypted_ciphertext_hash"] == envelope["crypto"]["ciphertext_hash"]
    assert row["encrypted_ciphertext_size"] == envelope["crypto"]["ciphertext_size"]
    assert row["encrypted_key_wraps_hash"] == envelope["crypto"]["key_wraps_hash"]
    assert row["encrypted_inner_header_hash"] == envelope["crypto"]["inner_header_hash"]
    assert row["encrypted_suite"] == envelope["crypto"]["suite"]
    assert row["encrypted_signing_key_id"] == envelope["signing_key_id"]
    assert str(row["signed_envelope_hash"]).startswith("sha256:")

    async def _bob_auth():
        return MessagingAuth(
            did_key=bob_did,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id=team_id,
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history_resp = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        pending_resp = await client.get("/v1/chat/pending")
    assert history_resp.status_code == 200, history_resp.text
    history_message = history_resp.json()["messages"][0]
    assert history_message["body"] == ""
    assert history_message["content_mode"] == "encrypted_v2"
    assert history_message["message_version"] == 2
    assert "encrypted_envelope" in history_message
    assert pending_resp.status_code == 200, pending_resp.text
    pending_item = pending_resp.json()["pending"][0]
    assert pending_item["last_message"] == ""
    assert pending_item["last_message_content_mode"] == "encrypted_v2"
    assert "last_encrypted_envelope" in pending_item


@pytest.mark.asyncio
async def test_encrypted_group_chat_excludes_removed_participant_from_future_wraps(
    aweb_cloud_db,
):
    alice_sk, _, alice_did = _make_keypair()
    _, _, bob_did = _make_keypair()
    _, _, carol_did = _make_keypair()
    team_id = "backend:acme.com"
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', $2)
        """,
        team_id,
        named_did_key("zTeam"),
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_val(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ($1, 'alice', $2, 'did:aw:alice', 'acme.com/alice', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $2 END)
        RETURNING agent_id
        """,
        team_id,
        alice_did,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
          ($1, 'bob', $2, 'did:aw:bob', 'acme.com/bob', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $2 END),
          ($1, 'carol', $3, 'did:aw:carol', 'acme.com/carol', 'global', 'dev', 'open', CASE WHEN NULLIF('did:aw:carol', '') IS NOT NULL THEN $3 END)
        """,
        team_id,
        bob_did,
        carol_did,
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id=team_id,
            alias="alice",
            agent_id=str(alice_agent_id),
        )

    session_id = "11111111-1111-4111-8111-111111111112"
    first_message_id = "22222222-2222-4222-8222-222222222223"
    first_envelope = _encrypted_chat_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did,
        sender_stable_id="did:aw:alice",
        recipients=[
            {"did": bob_did, "stable_id": "did:aw:bob", "address": "acme.com/bob"},
            {
                "did": carol_did,
                "stable_id": "did:aw:carol",
                "address": "acme.com/carol",
            },
        ],
        message_id=first_message_id,
        conversation_id=session_id,
    )
    create_payload = {
        "session_id": session_id,
        "to_aliases": ["bob", "carol"],
        "message": "",
        "message_id": first_message_id,
        "timestamp": first_envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": first_envelope,
    }
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        created = await client.post("/v1/chat/sessions", json=create_payload)
    assert created.status_code == 200, created.text

    async def _carol_auth():
        return MessagingAuth(
            did_key=carol_did,
            did_aw="did:aw:carol",
            address="acme.com/carol",
            team_id=team_id,
            alias="carol",
        )

    app.dependency_overrides[get_messaging_auth] = _carol_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        left = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            json={"body": "leaving", "leaving": True},
        )
    assert left.status_code == 200, left.text

    turn_message_id = "33333333-3333-4333-8333-333333333331"
    turn_envelope = _encrypted_chat_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did,
        sender_stable_id="did:aw:alice",
        recipients=[
            {"did": bob_did, "stable_id": "did:aw:bob", "address": "acme.com/bob"},
            {
                "did": carol_did,
                "stable_id": "did:aw:carol",
                "address": "acme.com/carol",
            },
        ],
        message_id=turn_message_id,
        conversation_id=session_id,
    )
    turn_payload = {
        "body": "",
        "message_id": turn_message_id,
        "timestamp": turn_envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": turn_envelope,
    }
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        turn = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=turn_payload
        )
    assert turn.status_code == 200, turn.text

    from messaging_actor_support import archive_messaging_actor

    carol_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2",
        team_id,
        carol_did,
    )
    await archive_messaging_actor(
        aweb_cloud_db.aweb_db,
        None,
        team_id=team_id,
        agent_id=carol_agent_id,
        registry_client=None,
    )

    stale_message_id = "33333333-3333-4333-8333-333333333332"
    stale_envelope = _encrypted_chat_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did,
        sender_stable_id="did:aw:alice",
        recipients=[
            {"did": bob_did, "stable_id": "did:aw:bob", "address": "acme.com/bob"},
            {
                "did": carol_did,
                "stable_id": "did:aw:carol",
                "address": "acme.com/carol",
            },
        ],
        message_id=stale_message_id,
        conversation_id=session_id,
    )
    stale_payload = {
        "body": "",
        "message_id": stale_message_id,
        "timestamp": stale_envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": stale_envelope,
    }
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        stale = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=stale_payload
        )
    assert stale.status_code == 422, stale.text
    assert "recipient" in stale.text

    future_message_id = "33333333-3333-4333-8333-333333333333"
    future_envelope = _encrypted_chat_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did,
        sender_stable_id="did:aw:alice",
        recipients=[
            {"did": bob_did, "stable_id": "did:aw:bob", "address": "acme.com/bob"},
        ],
        message_id=future_message_id,
        conversation_id=session_id,
    )
    future_payload = {
        "body": "",
        "message_id": future_message_id,
        "timestamp": future_envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": future_envelope,
    }
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        sessions = await client.get("/v1/chat/sessions")
        sent = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=future_payload
        )
    assert sessions.status_code == 200, sessions.text
    listed = sessions.json()["sessions"][0]
    assert listed["participant_dids"] == ["did:aw:bob"]
    assert listed["participant_addresses"] == ["acme.com/bob"]
    assert sent.status_code == 200, sent.text

    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT encrypted_envelope FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(future_message_id),
    )
    stored = json.loads(stored)
    delivery_wraps = [
        wrap for wrap in stored["key_wraps"] if wrap["wrap_purpose"] == "delivery"
    ]
    sender_copy_wraps = [
        wrap for wrap in stored["key_wraps"] if wrap["wrap_purpose"] == "sender_copy"
    ]
    assert [recipient["stable_id"] for recipient in stored["recipients"]] == [
        "did:aw:bob"
    ]
    assert [wrap["recipient_stable_id"] for wrap in delivery_wraps] == ["did:aw:bob"]
    assert [wrap["recipient_stable_id"] for wrap in sender_copy_wraps] == [
        "did:aw:alice"
    ]
    assert "did:aw:carol" not in json.dumps(stored)


@pytest.mark.asyncio
async def test_create_chat_session_accepts_cross_team_to_address(
    shared_test_pool, monkeypatch
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        await register_messaging_team(env, team_id="ops:otherco.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )
        bob = await admit_messaging_actor(
            env, alias="bob", team_id="ops:otherco.com", address="otherco.com/bob"
        )

        raw = json.dumps(
            {"to_addresses": [bob.address], "message": "hello bob"}
        ).encode()
        with record_registry_requests(env) as reads:
            response = await env.client.post(
                "/v1/chat/sessions",
                content=raw,
                headers={
                    **_signed_identity_headers(
                        alice.signing_key, alice.did_key, alice.stable_id, raw
                    ),
                    "Content-Type": "application/json",
                },
            )
        assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1, (
            reads
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["session_id"]
        assert {party["did"] for party in payload["participants"]} == {
            alice.stable_id,
            bob.stable_id,
        }
        assert {party["address"] for party in payload["participants"]} == {
            "acme.com/alice",
            "otherco.com/bob",
        }
        stored = await env.db.fetch_one(
            "SELECT body FROM {{tables.chat_messages}} WHERE session_id=$1",
            UUID(payload["session_id"]),
        )
        assert stored["body"] == "hello bob"


@pytest.mark.asyncio
async def test_cross_team_same_registry_chat_creates_bound_contact_from_resolved_address(
    shared_test_pool,
    monkeypatch,
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        await register_messaging_team(env, team_id="ops:otherco.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )
        bob = await admit_messaging_actor(
            env, alias="bob", team_id="ops:otherco.com", address="otherco.com/bob"
        )

        session_id, message_id = str(uuid4()), str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        signed_payload = canonical_json_bytes(
            {
                "type": "chat",
                "body": "same registry chat",
                "wait_seconds": 30,
                "conversation_id": session_id,
                "message_id": message_id,
                "timestamp": timestamp,
                "from": alice.address,
                "from_did": alice.did_key,
                "from_stable_id": alice.stable_id,
                "to": bob.address,
                "to_did": bob.did_key,
                "to_stable_id": bob.stable_id,
            }
        ).decode()
        raw = json.dumps(
            {
                "session_id": session_id,
                "to_addresses": [bob.address],
                "message": "same registry chat",
                "wait_seconds": 30,
                "from_did": alice.did_key,
                "message_id": message_id,
                "timestamp": timestamp,
                "signed_payload": signed_payload,
                "signature": sign_message(alice.signing_key, signed_payload.encode()),
            }
        ).encode()
        with record_registry_requests(env) as reads:
            response = await env.client.post(
                "/v1/chat/sessions",
                content=raw,
                headers={
                    **_signed_identity_headers(
                        alice.signing_key, alice.did_key, alice.stable_id, raw
                    ),
                    "Content-Type": "application/json",
                },
            )
        # The automatic contact needs one independently verified controller
        # binding; the sender's signature alone cannot grant contact trust.
        assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1, (
            reads
        )
        assert response.status_code == 200, response.text
        contact = dict(
            await env.db.fetch_one(
                "SELECT owner_did, contact_address, contact_did_aw, binding_controller_did, "
                "binding_accepted_at, status FROM {{tables.contacts}} "
                "WHERE owner_did=$1 AND contact_address=$2",
                alice.stable_id,
                bob.address,
            )
        )
        assert contact.pop("binding_accepted_at") is not None
        controller = await env.registry.namespace_authority("otherco.com")
        assert contact == {
            "owner_did": alice.stable_id,
            "contact_address": "otherco.com/bob",
            "contact_did_aw": bob.stable_id,
            "binding_controller_did": controller.controller_did,
            "status": "active",
        }
        stored = await env.db.fetch_one(
            "SELECT body, signed_payload FROM {{tables.chat_messages}} WHERE message_id=$1",
            UUID(message_id),
        )
        assert stored["body"] == "same registry chat"
        assert stored["signed_payload"] == signed_payload


@pytest.mark.asyncio
async def test_create_chat_session_external_address_without_delivery_origin_fails_closed(
    shared_test_pool, monkeypatch
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )

        from identity_binding_support import register_global_identity
        from aweb.application_state import application_registry_client

        target_sk, _, target_key = _make_keypair()
        target = SimpleNamespace(sk=target_sk, did=target_key)
        await register_global_identity(env, target, "otherco.com/bob")
        registry = application_registry_client(env.app.state)
        resolved = await registry.resolve_address_fresh(
            *"otherco.com/bob".split("/", 1)
        )
        assert resolved.delivery is None or not resolved.delivery.origin
        raw = json.dumps(
            {"to_addresses": ["otherco.com/bob"], "message": "no remote route"}
        ).encode()
        response = await env.client.post(
            "/v1/chat/sessions",
            content=raw,
            headers={
                **_signed_identity_headers(
                    alice.signing_key, alice.did_key, alice.stable_id, raw
                ),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 424, response.text
        assert "no federated delivery origin" in response.json()["detail"]
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}")
            == 0
        )
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
            == 0
        )


@pytest.mark.asyncio
async def test_create_chat_session_hosted_handle_without_delivery_origin_fails_closed(
    shared_test_pool, monkeypatch
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )

        from identity_binding_support import register_global_identity
        from aweb.application_state import application_registry_client

        target_sk, _, target_key = _make_keypair()
        target = SimpleNamespace(sk=target_sk, did=target_key)
        await register_global_identity(env, target, "jane.aweb.ai/c3po")
        registry = application_registry_client(env.app.state)
        resolved = await registry.resolve_address_fresh(
            *"jane.aweb.ai/c3po".split("/", 1)
        )
        assert resolved.delivery is None or not resolved.delivery.origin
        raw = json.dumps(
            {"to_aliases": ["@jane/c3po"], "message": "no remote route"}
        ).encode()
        with record_registry_requests(env) as reads:
            response = await env.client.post(
                "/v1/chat/sessions",
                content=raw,
                headers={
                    **_signed_identity_headers(
                        alice.signing_key, alice.did_key, alice.stable_id, raw
                    ),
                    "Content-Type": "application/json",
                },
            )
        assert (
            reads.count(("GET", "/v1/namespaces/jane.aweb.ai/addresses/c3po")) == 1
        ), reads
        assert response.status_code == 424, response.text
        assert "no federated delivery origin" in response.json()["detail"]
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}")
            == 0
        )
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
            == 0
        )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_existing_session_without_binding(
    aweb_cloud_db,
):
    _, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $2 END)
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert (
        reply.json()["detail"]
        == "Signed chat message must bind the existing session_id"
    )
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
async def test_create_chat_session_rejects_to_address_self_chat(
    shared_test_pool, monkeypatch
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )

        raw = json.dumps({"to_addresses": [alice.address], "message": "self"}).encode()
        response = await env.client.post(
            "/v1/chat/sessions",
            content=raw,
            headers={
                **_signed_identity_headers(
                    alice.signing_key, alice.did_key, alice.stable_id, raw
                ),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 400, response.text
        assert "Self-chat is not supported" in response.text
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}")
            == 0
        )
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
            == 0
        )


@pytest.mark.asyncio
async def test_create_chat_session_to_external_did_first_contact_fails_closed(
    shared_test_pool, monkeypatch
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="backend:acme.com")
        alice = await admit_messaging_actor(
            env, alias="alice", team_id="backend:acme.com", address="acme.com/alice"
        )

        from aweb.application_state import application_registry_client

        target_sk, _, target_key = _make_keypair()
        registry = application_registry_client(env.app.state)
        target = await registry.register_did(target_key, target_sk)
        key_path = f"/v1/did/{target.did_aw}/key"
        observed = []
        stack = (
            env.registry_app.middleware_stack
            or env.registry_app.build_middleware_stack()
        )

        async def record_registry(scope, receive, send):
            if scope.get("type") == "http":
                observed.append((scope["method"], scope["path"]))
            await stack(scope, receive, send)

        env.registry_app.middleware_stack = record_registry
        try:
            # Establish that the recorder sees a real read, then distinguish
            # sender admission reads from forbidden target-by-key routing.
            await registry.resolve_key_fresh(target.did_aw)
            assert ("GET", key_path) in observed
            observed.clear()
            env.app.state.identity_binding_cache.clear()
            raw = json.dumps(
                {"to_dids": [target.did_aw], "message": "raw did"}
            ).encode()
            response = await env.client.post(
                "/v1/chat/sessions",
                content=raw,
                headers={
                    **_signed_identity_headers(
                        alice.signing_key, alice.did_key, alice.stable_id, raw
                    ),
                    "Content-Type": "application/json",
                },
            )
            assert response.status_code == 422, response.text
            assert (
                "Bare did:aw first-contact is unsupported" in response.json()["detail"]
            )
            assert observed.count(("GET", key_path)) == 0
            address_reads = [
                path
                for method, path in observed
                if method == "GET" and "/addresses/" in path
            ]
            assert address_reads == ["/v1/namespaces/acme.com/addresses/alice"], (
                observed
            )
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.chat_sessions}}"
                )
                == 0
            )
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.chat_messages}}"
                )
                == 0
            )
        finally:
            env.registry_app.middleware_stack = stack


@pytest.mark.asyncio
async def test_create_chat_session_resolves_tilde_alias_cross_team(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */),
            ('eng:acme.com', 'acme.com', 'eng', 'did:key:z6MknDtoabfgEheshWvZPN7emDjz6EUyRUcYbZJUwAspDPJQ' /* team-eng */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('eng:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "message_id": message_id,
        "timestamp": timestamp,
        "signed_payload": signed_payload,
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"]
    assert {participant["did"] for participant in body["participants"]} == {
        "did:aw:alice",
        "did:aw:bob",
    }
    assert {participant["address"] for participant in body["participants"]} == {
        "acme.com/alice",
        "acme.com/bob",
    }
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
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */),
            ('eng:acme.com', 'acme.com', 'eng', 'did:key:z6MknDtoabfgEheshWvZPN7emDjz6EUyRUcYbZJUwAspDPJQ' /* team-eng */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('ops:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/sessions", json={"to_aliases": [target], "message": "hello"}
        )

    assert resp.status_code == expected_status, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_mutation_context_includes_from_did_aw(
    registered_mail_actors,
):
    from messaging_actor_support import (
        register_messaging_actors,
        set_messaging_inbound_mode,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=False
    )
    bob = others["bob"]
    await set_messaging_inbound_mode(env, bob, mode="open")
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    captured = {}
    original_mutation = app.state.on_mutation

    async def _capture(event_type, context):
        captured["event_type"] = event_type
        captured["context"] = dict(context)
        return await original_mutation(event_type, context)

    app.state.on_mutation = _capture
    payload = {"to_dids": [bob.stable_id], "message": "hello bob"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)
    assert resp.status_code == 200, resp.text
    assert captured["event_type"] == "chat.message_sent"
    assert captured["context"]["from_did_aw"] == alice.stable_id


@pytest.mark.asyncio
async def test_create_chat_session_to_did_does_not_create_unresolved_identity_contact(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import (
        register_messaging_actors,
        set_messaging_inbound_mode,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=False
    )
    bob = others["bob"]
    await set_messaging_inbound_mode(env, bob, mode="open")
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {"to_dids": [bob.stable_id], "message": "allowed"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)
    assert resp.status_code == 200, resp.text
    contact_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.contacts}}
        WHERE owner_did = $1
          AND contact_address = $2
          AND reference_type = 'identity'
          AND status = 'active'
        """,
        alice.stable_id,
        bob.address,
    )
    assert contact_count == 0


@pytest.mark.asyncio
async def test_create_chat_session_team_and_contacts_accepts_verified_same_team_non_contact(
    registered_mail_actors,
):
    from messaging_actor_support import set_messaging_inbound_mode

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    cert_header = alice.certificate
    payload = {"to_aliases": ["bob"], "message": "team delivery"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice_sk, alice_did_key, alice.team_id, cert_header, body
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_to_global_address_allows_explicit_inbound_mode_open(
    registered_mail_actors,
):
    from messaging_actor_support import (
        register_messaging_actors,
        set_messaging_inbound_mode,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=False
    )
    bob = others["bob"]
    await set_messaging_inbound_mode(env, bob, mode="open")
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {"to_addresses": [bob.address], "message": "allowed"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", content=body, headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_create_chat_session_to_address_local_ephemeral_without_route_is_not_routable(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import register_messaging_actors

    env, actors = registered_mail_actors
    alice = actors["alice"]
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=True
    )
    _ = others["bob"]
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {"to_addresses": ["otherco.com/bob"], "message": "blocked"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        refused = await client.post("/v1/chat/sessions", content=body, headers=headers)
    assert refused.status_code == 404, refused.text
    assert refused.json()["reason"] == "local_recipient_route_missing"
    assert refused.json()["retryable"] is False
    assert (
        refused.json()["detail"]
        == "otherco.com/bob is not a registered address. A local identity has no address and is reachable only from inside its own team, by alias; a global identity is reachable by address once one is assigned. Check the address or use a teammate alias and retry.".replace(
            "otherco.com/bob", "otherco.com/bob"
        )
    )
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.chat_messages}}"
        )
        == 0
    )
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.chat_sessions}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_create_chat_session_to_address_does_not_fall_back_to_local_persistent_agent_when_awid_misses(
    registered_mail_actors,
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    await register_messaging_team(env, team_id="ops:otherco.com")
    recipient = await admit_messaging_actor(
        env,
        alias="bob",
        team_id="ops:otherco.com",
        address="otherco.com/bob",
        signing_key=bob.signing_key,
    )
    controller = await env.registry.ensure_namespace(domain="otherco.com")
    registry = env.app.state.awid_registry_client
    certificate = json.loads(base64.b64decode(recipient.certificate))
    await registry.revoke_team_certificate(
        "otherco.com",
        "ops",
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate["certificate_id"],
    )
    await registry.delete_address("otherco.com", "bob", controller)
    payload = {"to_addresses": ["otherco.com/bob"], "message": "hidden"}
    body = json.dumps(payload).encode()
    with record_registry_requests(env) as reads:
        resp = await env.client.post(
            "/v1/chat/sessions",
            content=body,
            headers={
                "Content-Type": "application/json",
                **_signed_identity_headers(
                    alice.signing_key, alice.did_key, alice.stable_id, body
                ),
            },
        )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1


@pytest.mark.parametrize("recipient_identity_scope", ["global", "local"])
@pytest.mark.asyncio
async def test_create_chat_session_to_address_uses_same_team_local_recipient_when_awid_misses(
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
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6Mksty56NE8sLwnubZAGcm16vuLQnaMnSqUcsGmGygSk8mF' /* team-2 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('ops:otherco.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'otherco.com/bob', 'bob', $1, 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    payload = {
        "to_addresses": ["otherco.com/bob"],
        "message": f"same team hidden {recipient_identity_scope}",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_not_awaited()
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT did, alias FROM {{tables.chat_participants}} WHERE alias = 'bob'"
    )
    assert len(rows) == 1
    assert rows[0]["did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_create_chat_session_to_address_rejects_cross_team_local_persistent_when_awid_misses(
    registered_mail_actors,
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )

    env, actors = registered_mail_actors
    alice, bob = actors["alice"], actors["bob"]
    await register_messaging_team(env, team_id="ops:otherco.com")
    recipient = await admit_messaging_actor(
        env,
        alias="bob",
        team_id="ops:otherco.com",
        address="otherco.com/bob",
        signing_key=bob.signing_key,
    )
    controller = await env.registry.ensure_namespace(domain="otherco.com")
    registry = env.app.state.awid_registry_client
    certificate = json.loads(base64.b64decode(recipient.certificate))
    await registry.revoke_team_certificate(
        "otherco.com",
        "ops",
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate["certificate_id"],
    )
    await registry.delete_address("otherco.com", "bob", controller)
    payload = {"to_addresses": ["otherco.com/bob"], "message": "hidden"}
    body = json.dumps(payload).encode()
    with record_registry_requests(env) as reads:
        resp = await env.client.post(
            "/v1/chat/sessions",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Team-ID": alice.team_id,
                **_signed_identity_headers(
                    alice.signing_key, alice.did_key, alice.stable_id, body
                ),
            },
        )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1


@pytest.mark.asyncio
async def test_create_chat_session_to_did_and_address_uses_local_persistent_when_registry_unconfigured(
    aweb_cloud_db,
):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6Mksty56NE8sLwnubZAGcm16vuLQnaMnSqUcsGmGygSk8mF' /* team-2 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('ops:otherco.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT did, alias FROM {{tables.chat_participants}} WHERE alias = 'bob'"
    )
    assert len(rows) == 1
    assert rows[0]["did"] == "did:aw:bob"


@pytest.mark.parametrize("recipient_identity_scope", ["global", "local"])
@pytest.mark.asyncio
async def test_create_chat_session_to_private_address_uses_client_recipient_binding(
    registered_mail_actors, recipient_identity_scope
):
    from messaging_actor_support import (
        issue_global_certificate_to_local_member,
        messaging_actor_headers,
        register_messaging_actors,
        set_messaging_inbound_mode,
        record_registry_requests,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    sender_actors = await register_messaging_actors(
        env, team_id="sender:acme.com", aliases=("alice",), addressed=False
    )
    alice = sender_actors["alice"]
    others = await register_messaging_actors(
        env,
        team_id="ops:otherco.com",
        aliases=("bob",),
        local=recipient_identity_scope == "local",
    )
    bob = others["bob"]
    if recipient_identity_scope == "local":
        bob = await issue_global_certificate_to_local_member(
            env, bob, address="otherco.com/bob"
        )
    else:
        await set_messaging_inbound_mode(env, bob, mode="open")
    policy = await env.client.get(
        "/v1/agents/me/inbound-mode", headers=messaging_actor_headers(bob)
    )
    assert policy.status_code == 200, policy.text
    assert policy.json()["identity_scope"] == recipient_identity_scope
    assert policy.json()["inbound_mode"] == "open"
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    with record_registry_requests(env) as registry_calls:
        message_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        signed_payload = canonical_json_bytes(
            {
                "body": "private chat",
                "from": alice.stable_id,
                "from_did": alice.stable_id,
                "from_stable_id": alice.stable_id,
                "message_id": message_id,
                "timestamp": timestamp,
                "to": bob.address,
                "to_did": bob.did_key,
                "to_stable_id": bob.stable_id,
                "type": "chat",
            }
        )
        payload = {
            "to_addresses": [bob.address],
            "message": "private chat",
            "from_did": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "signature": sign_message(alice_sk, signed_payload),
            "signed_payload": signed_payload.decode(),
        }
        body = json.dumps(payload).encode()
        headers = {
            **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
            "Content-Type": "application/json",
        }
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/v1/chat/sessions", content=body, headers=headers)
        assert resp.status_code == 200, resp.text
        body_json = resp.json()
        assert {participant["did"] for participant in body_json["participants"]} == {
            alice.stable_id,
            bob.stable_id,
        }
        assert {
            participant["address"] for participant in body_json["participants"]
        } == {bob.address, None}
        assert any(
            (
                method == "GET"
                and path
                == "/v1/namespaces/" + bob.address.replace("/", "/addresses/", 1)
                for method, path in registry_calls
            )
        )


@pytest.mark.asyncio
async def test_create_chat_session_to_private_address_rejects_unverified_client_recipient_binding(
    registered_mail_actors,
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    await register_messaging_team(env, team_id="ops:otherco.com")
    recipient = await admit_messaging_actor(
        env,
        alias="bob",
        team_id="ops:otherco.com",
        address="otherco.com/bob",
        signing_key=bob.signing_key,
    )
    controller = await env.registry.ensure_namespace(domain="otherco.com")
    registry = env.app.state.awid_registry_client
    certificate = json.loads(base64.b64decode(recipient.certificate))
    await registry.revoke_team_certificate(
        "otherco.com",
        "ops",
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate["certificate_id"],
    )
    await registry.delete_address("otherco.com", "bob", controller)
    payload = {"to_addresses": ["otherco.com/bob"], "message": "hidden"}
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "body": "hidden",
            "from": alice.stable_id,
            "from_did": alice.stable_id,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": recipient.did_key,
            "to_stable_id": recipient.stable_id,
            "type": "chat",
        }
    )
    payload.update(
        from_did=alice.stable_id,
        message_id=message_id,
        timestamp=timestamp,
        signature="not-a-valid-signature",
        signed_payload=signed_payload.decode(),
    )
    body = json.dumps(payload).encode()
    resp = await env.client.post(
        "/v1/chat/sessions",
        content=body,
        headers={
            "Content-Type": "application/json",
            **_signed_identity_headers(
                alice.signing_key, alice.did_key, alice.stable_id, body
            ),
        },
    )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text


async def _signed_local_chat_app(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:timestamp.example', 'timestamp.example', 'backend', 'did:key:z6MkjCcu9yhvSHSN4rzwgiyisKzVNv9a1TBA4wRD5GywJzcC' /* team-timestamp */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:timestamp.example', $1, 'did:aw:alice-timestamp', 'timestamp.example/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice-timestamp', '') IS NOT NULL THEN $1 END),
            ('backend:timestamp.example', 'did:key:z6Mkf88FE4YeBCXz1pSpYAnrSYKAPVowYtAXG1Ld1gSKMzKo' /* bob-timestamp */, 'did:aw:bob-timestamp', 'timestamp.example/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob-timestamp', '') IS NOT NULL THEN 'did:key:z6Mkf88FE4YeBCXz1pSpYAnrSYKAPVowYtAXG1Ld1gSKMzKo' /* bob-timestamp */ END)
        """,
        alice_did_key,
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice-timestamp",
            address="timestamp.example/alice",
            team_id="backend:timestamp.example",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    return app, alice_sk, alice_did_key


def _signed_local_chat_payload(
    alice_sk, alice_did_key, *, timestamp, include_signed_payload=True
):
    session_id = str(uuid4())
    message_id = str(uuid4())
    signed_payload = canonical_json_bytes(
        {
            "body": "timestamp body",
            "conversation_id": session_id,
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
        "session_id": session_id,
        "to_aliases": ["bob"],
        "message": "timestamp body",
        "from_did": alice_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
    }
    if include_signed_payload:
        payload["signed_payload"] = signed_payload.decode()
    return message_id, payload


@pytest.mark.asyncio
async def test_signed_plaintext_chat_rejects_non_base64_signature_before_storage(
    aweb_cloud_db,
):
    app, alice_sk, alice_did_key = await _signed_local_chat_app(aweb_cloud_db)
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    message_id, payload = _signed_local_chat_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
    )
    payload["signature"] += "!!!!"

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/chat/sessions", json=payload)

    assert response.status_code == 422, response.text
    assert (
        response.json()["detail"]
        == "signature must be valid base64. Check the chat fields and sign the message again."
    )
    stored = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert stored is None


@pytest.mark.asyncio
@pytest.mark.parametrize("offset_seconds", [-360, 360])
async def test_signed_plaintext_chat_rejects_timestamp_outside_federation_window(
    aweb_cloud_db, offset_seconds
):
    app, alice_sk, alice_did_key = await _signed_local_chat_app(aweb_cloud_db)
    timestamp = (
        (
            datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(seconds=offset_seconds)
        )
        .isoformat()
        .replace("+00:00", "Z")
    )
    _, payload = _signed_local_chat_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/chat/sessions", json=payload)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == (
        "timestamp outside accepted skew. Sign the message again with the current UTC time and retry."
    )


@pytest.mark.asyncio
async def test_signed_plaintext_chat_stores_server_time_and_preserves_attestation(
    aweb_cloud_db,
):
    app, alice_sk, alice_did_key = await _signed_local_chat_app(aweb_cloud_db)
    attested_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        minutes=4
    )
    message_id, payload = _signed_local_chat_payload(
        alice_sk,
        alice_did_key,
        timestamp=attested_at.isoformat().replace("+00:00", "Z"),
    )

    before = datetime.now(timezone.utc)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/chat/sessions", json=payload)
    after = datetime.now(timezone.utc)

    assert response.status_code == 200, response.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT created_at, signed_payload FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert before <= row["created_at"] <= after
    assert row["created_at"] != attested_at
    assert json.loads(row["signed_payload"])["timestamp"] == payload["timestamp"]


@pytest.mark.asyncio
async def test_signed_plaintext_chat_requires_signed_payload(aweb_cloud_db):
    app, alice_sk, alice_did_key = await _signed_local_chat_app(aweb_cloud_db)
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    _, payload = _signed_local_chat_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
        include_signed_payload=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/chat/sessions", json=payload)

    assert response.status_code == 422, response.text
    assert (
        response.json()["detail"]
        == "signed_payload is required when signature is provided. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_accepts_signed_from_did_key_for_team_context(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    message_id = "11111111-1111-4111-8111-111111111111"
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "hello bob",
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
        "message": "hello bob",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"]
    assert {participant["alias"] for participant in body["participants"]} == {
        "alice",
        "bob",
    }


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_body_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload body must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_leaving_mismatch(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload sender_leaving must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_wait_seconds_mismatch(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload wait_seconds must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_recipient_mismatch(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload recipient must match the chat target. Check the recipient and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_partial_signed_recipient_binding_for_group_chat(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END),
            ('backend:acme.com', 'did:key:z6MkurnVcC1NM4SQDkmSZANg3zjE68ESm9AcnF9fU2JbHLn4' /* carol */, 'did:aw:carol', 'acme.com/carol', 'carol', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:carol', '') IS NOT NULL THEN 'did:key:z6MkurnVcC1NM4SQDkmSZANg3zjE68ESm9AcnF9fU2JbHLn4' /* carol */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload recipient must match the chat target. Check the recipient and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_from_stable_id_mismatch(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload from_stable_id must match the authenticated sender. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_create_chat_session_rejects_signed_payload_from_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/sessions", json=payload)

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload from must match the authenticated sender. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_send_message_accepts_signed_from_did_key_for_team_context(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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

    message_id = "22222222-2222-4222-8222-222222222222"
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "follow-up",
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
        "body": "follow-up",
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload),
        "signed_payload": signed_payload.decode(),
        "message_id": message_id,
        "timestamp": timestamp,
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["delivered"] is True


@pytest.mark.asyncio
async def test_chat_send_message_rejects_legacy_bound_session_continuation(
    pre_chat_coverage_db,
    chat_coverage_upgrade,
):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    session_id = uuid4()
    message_id = uuid4()
    await pre_chat_coverage_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    await pre_chat_coverage_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', $2, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $2 END)
        """,
        alice_did_key,
        bob_did_key,
    )
    alice_agent_id = await pre_chat_coverage_db.aweb_db.fetch_val(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'alice'"
    )
    bob_agent_id = await pre_chat_coverage_db.aweb_db.fetch_val(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'bob'"
    )
    await pre_chat_coverage_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'backend:acme.com', 'alice')
        """,
        session_id,
    )
    await pre_chat_coverage_db.aweb_db.execute(
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    await pre_chat_coverage_db.aweb_db.execute(
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

    await chat_coverage_upgrade.apply()

    app = _build_test_app(pre_chat_coverage_db.aweb_db, AsyncMock())

    async def _bob_auth_override():
        return MessagingAuth(
            did_key=bob_did_key,
            did_aw="did:aw:bob",
            address="acme.com/bob",
            team_id="backend:acme.com",
            alias="bob",
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json={"body": "blocked"}
        )
        create_or_send_resp = await client.post(
            "/v1/chat/sessions",
            json={"to_aliases": ["alice"], "message": "also blocked"},
        )

    assert resp.status_code == 403, resp.text
    assert "conversation_id" in resp.json()["detail"]
    assert create_or_send_resp.status_code == 403, create_or_send_resp.text
    assert "conversation_id" in create_or_send_resp.json()["detail"]


@pytest.mark.asyncio
async def test_chat_create_with_signed_fresh_session_bypasses_legacy_bound_session(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    alice_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END)
        RETURNING agent_id
        """,
        alice_did_key,
    )
    bob_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'bob', $1, 'did:aw:bob', 'acme.com/bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END)
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
    legacy_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    fresh_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload body must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_replayed_into_another_session(
    aweb_cloud_db,
):
    """A payload signed for one session must not be accepted by another.

    The same fixture is posted twice. Into its own session it is accepted, which
    is what proves every check ahead of the conversation_id comparison passes
    cleanly for this shape. Into the sibling session, where only the
    conversation_id now disagrees, it must be refused. The replay carries an
    unused message_id so message_id uniqueness cannot refuse it first.
    """
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
        """
    )
    session_ids = []
    for _ in range(2):
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
        session_ids.append(session_id)
    signed_session_id, other_session_id = session_ids

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _team_auth_override():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _team_auth_override

    def _signed_for_signed_session(message_id: str, timestamp: str) -> dict:
        signed_payload = canonical_json_bytes(
            {
                "body": "session-bound reply",
                "conversation_id": str(signed_session_id),
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
        return {
            "body": "session-bound reply",
            "from_did": alice_did_key,
            "signature": sign_message(alice_sk, signed_payload),
            "signed_payload": signed_payload.decode(),
            "message_id": message_id,
            "timestamp": timestamp,
        }

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    accepted_message_id = str(uuid4())
    replayed_message_id = str(uuid4())

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        accepted = await client.post(
            f"/v1/chat/sessions/{signed_session_id}/messages",
            json=_signed_for_signed_session(accepted_message_id, timestamp),
        )
        replayed = await client.post(
            f"/v1/chat/sessions/{other_session_id}/messages",
            json=_signed_for_signed_session(replayed_message_id, timestamp),
        )

    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["delivered"] is True
    assert replayed.status_code == 422, replayed.text
    assert (
        replayed.json()["detail"]
        == "signed_payload conversation_id must match. Check the chat fields and sign the message again."
    )
    replayed_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(replayed_message_id),
    )
    assert replayed_count == 0


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_hang_on_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload hang_on must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_leaving_mismatch(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload sender_leaving must match the chat message. Check the chat fields and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_send_message_rejects_signed_payload_recipient_mismatch(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload recipient must match the chat target. Check the recipient and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_send_message_rejects_partial_signed_recipient_binding_for_group_chat(
    aweb_cloud_db,
):
    alice_sk, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MknPNGi33ZA1E96cTvr2J1CmyppaBCCL2a56qAnPfFVfQo' /* team-1 */)
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('backend:acme.com', $1, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN $1 END),
            ('backend:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END),
            ('backend:acme.com', 'did:key:z6MkurnVcC1NM4SQDkmSZANg3zjE68ESm9AcnF9fU2JbHLn4' /* carol */, 'did:aw:carol', 'acme.com/carol', 'carol', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:carol', '') IS NOT NULL THEN 'did:key:z6MkurnVcC1NM4SQDkmSZANg3zjE68ESm9AcnF9fU2JbHLn4' /* carol */ END)
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

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "signed_payload recipient must match the chat target. Check the recipient and sign the message again."
    )


@pytest.mark.asyncio
async def test_chat_pending_counts_mail_and_sessions_for_global_participant(
    aweb_cloud_db,
):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES
            ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'acme.com/alice', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */ END, 'open'),
            ($2, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */, 'bob', 'acme.com/bob', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */ END, 'open')
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
        VALUES ($1, 'did:aw:bob', 'did:aw:alice', 'bob', 'alice', 'hi', 'mail body', 'normal', $2)
        """,
        uuid4(),
        created_at + timedelta(minutes=2),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_chat_routes_use_team_alias_for_same_namespace_sender_without_public_address(
    aweb_cloud_db,
):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:acme.com', 'acme.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */),
            ('support:acme.com', 'acme.com', 'support', 'did:key:z6MkhfcRfPdxNFAUvkyQqaEUbxVXPJ8chHwMiYyM2agaD3vT' /* team-support */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES
            ($1, 'ops:acme.com', 'did:aw:gsk', 'did:key:z6MknRdRNxTS9XiMUVaXK4hfoBJXiUCf1sEWWtsFvc6sPuMJ' /* gsk */, 'gsk', NULL, CASE WHEN NULLIF('did:aw:gsk', '') IS NOT NULL THEN 'did:key:z6MknRdRNxTS9XiMUVaXK4hfoBJXiUCf1sEWWtsFvc6sPuMJ' /* gsk */ END, 'open'),
            ($2, 'support:acme.com', 'did:aw:amy', 'did:key:z6MksPqe4mWxnUsYM45sJdppFQdyfxY5uvmzaFBTstqqYiMa' /* amy */, 'amy', NULL, CASE WHEN NULLIF('did:aw:amy', '') IS NOT NULL THEN 'did:key:z6MksPqe4mWxnUsYM45sJdppFQdyfxY5uvmzaFBTstqqYiMa' /* amy */ END, 'open')
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
            did_key=named_did_key("amy"),
            did_aw="did:aw:amy",
            address="",
            team_id="support:acme.com",
            alias="amy",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_cross_org_chat_create_persists_sender_address_without_local_metadata(
    aweb_cloud_db, monkeypatch
):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */),
            ('support:juan.aweb.ai', 'juan.aweb.ai', 'support', 'did:key:z6MkhfcRfPdxNFAUvkyQqaEUbxVXPJ8chHwMiYyM2agaD3vT' /* team-support */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('support:juan.aweb.ai', 'did:key:z6MksPqe4mWxnUsYM45sJdppFQdyfxY5uvmzaFBTstqqYiMa' /* amy */, 'did:aw:amy', 'juan.aweb.ai/amy', 'amy', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:amy', '') IS NOT NULL THEN 'did:key:z6MksPqe4mWxnUsYM45sJdppFQdyfxY5uvmzaFBTstqqYiMa' /* amy */ END)
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _sender_auth():
        return MessagingAuth(
            did_key=named_did_key("gsk"),
            did_aw="did:aw:gsk",
            address="otherco.com/gsk",
            team_id="ops:otherco.com",
            alias="gsk",
        )

    app.dependency_overrides[get_messaging_auth] = _sender_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        created = await client.post(
            "/v1/chat/sessions", json={"to_dids": ["did:aw:amy"], "message": "hello"}
        )

    assert created.status_code == 200, created.text
    session_id = created.json()["session_id"]
    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.chat_messages}} WHERE session_id = $1",
        UUID(session_id),
    )
    assert stored == "otherco.com/gsk"

    async def _amy_auth():
        return MessagingAuth(
            did_key=named_did_key("amy"),
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", timeout=5.0
    ) as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        pending = await client.get("/v1/chat/pending")
        stream = await client.get(
            f"/v1/chat/sessions/{session_id}/stream",
            params={
                "deadline": (
                    datetime.now(timezone.utc) + timedelta(seconds=1)
                ).isoformat(),
                "after": (
                    datetime.now(timezone.utc) - timedelta(minutes=1)
                ).isoformat(),
            },
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["from_address"] == "otherco.com/gsk"
    assert pending.status_code == 200, pending.text
    assert pending.json()["pending"][0]["last_from_address"] == "otherco.com/gsk"
    assert stream.status_code == 200, stream.text
    assert '"from_address": "otherco.com/gsk"' in stream.text


@pytest.mark.asyncio
async def test_chat_create_derives_ephemeral_sender_address_from_team_namespace(
    aweb_cloud_db,
):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('ops:acme.com', 'did:key:z6MkvgkDf2saqfounfm33qaY8smkZX4XZGcXtb3sHrzxzba3' /* alice */, NULL, NULL, 'alice', 'local', 'developer', 'open', CASE WHEN NULLIF(NULL, '') IS NOT NULL THEN 'did:key:z6MkvgkDf2saqfounfm33qaY8smkZX4XZGcXtb3sHrzxzba3' /* alice */ END),
            ('ops:acme.com', 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */, NULL, NULL, 'bob', 'local', 'developer', 'open', CASE WHEN NULLIF(NULL, '') IS NOT NULL THEN 'did:key:z6MkhjGZJUfS3HvzqmbwWDoehpXsNtnrcskFTpUYN727wRRH' /* bob */ END)
        """
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _alice_auth():
        return MessagingAuth(
            did_key=named_did_key("alice"),
            did_aw="",
            address="",
            team_id="ops:acme.com",
            alias="alice",
        )

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        created = await client.post(
            "/v1/chat/sessions", json={"to_aliases": ["bob"], "message": "hello"}
        )

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
        WHERE session_id = $1 AND did = 'did:key:z6MkvgkDf2saqfounfm33qaY8smkZX4XZGcXtb3sHrzxzba3' /* alice */
        """,
        UUID(created.json()["session_id"]),
    )
    assert participant_address == "acme.com/alice"


@pytest.mark.asyncio
async def test_cross_org_chat_reply_persists_sender_address_without_local_metadata(
    aweb_cloud_db,
):
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkiK4DciFkG7Sqj2U35cBvNezhk22uso3u8NQ6CKHQZxBb' /* team-ops */),
            ('support:juan.aweb.ai', 'juan.aweb.ai', 'support', 'did:key:z6MkhfcRfPdxNFAUvkyQqaEUbxVXPJ8chHwMiYyM2agaD3vT' /* team-support */)
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
            did_key=named_did_key("amy"),
            did_aw="did:aw:amy",
            address="juan.aweb.ai/amy",
            team_id="support:juan.aweb.ai",
            alias="amy",
        )

    app.dependency_overrides[get_messaging_auth] = _amy_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        sent = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json={"body": "reply"}
        )

    assert sent.status_code == 200, sent.text
    stored = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.chat_messages}} WHERE session_id = $1",
        session_id,
    )
    assert stored == "juan.aweb.ai/amy"

    async def _gsk_auth():
        return MessagingAuth(
            did_key=named_did_key("gsk"),
            did_aw="did:aw:gsk",
            address="otherco.com/gsk",
            team_id="ops:otherco.com",
            alias="gsk",
        )

    app.dependency_overrides[get_messaging_auth] = _gsk_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["from_address"] == "juan.aweb.ai/amy"


@pytest.mark.asyncio
async def test_chat_pending_excludes_global_participant_from_waiting_lookup(
    aweb_cloud_db, monkeypatch
):
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
            ($1, 'did:aw:alice', 'alice'),
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
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    captured: dict[str, list[str]] = {}

    async def _fake_waiting_by_session(_redis, wanted):
        captured.update(wanted)
        return {key: [] for key in wanted}

    app.dependency_overrides[get_messaging_auth] = _auth_override
    monkeypatch.setattr(
        chat_routes, "get_waiting_agents_by_session", _fake_waiting_by_session
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    assert captured == {str(session_id): ["did:aw:bob"]}


@pytest.mark.asyncio
async def test_chat_pending_preserves_last_from_did_without_address_mapping(
    aweb_cloud_db,
):
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
            ($1, 'did:aw:alice', 'alice'),
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
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["pending"]) == 1
    assert body["pending"][0]["last_from_address"] == ""
    assert body["pending"][0]["last_from_did"] == "did:aw:bob"
    assert body["pending"][0]["participant_dids"] == ["did:aw:bob"]


@pytest.mark.asyncio
async def test_chat_pending_includes_last_from_stable_id_for_current_sender_key(
    aweb_cloud_db,
):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at)
        VALUES ($1, 'backend:acme.com', 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice'),
            ($1, 'did:aw:bob', '')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, '', 'ping', $2)
        """,
        session_id,
        created_at + timedelta(minutes=1),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'acme.com/alice', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */ END, 'open')
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkBobCurrent"),
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/chat/pending")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["pending"]) == 1
    assert body["pending"][0]["last_from_did"] == named_did_key("z6MkAliceCurrent")
    assert body["pending"][0]["last_from_stable_id"] == "did:aw:alice"
    assert body["pending"][0]["last_from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_chat_send_message_accepts_global_session_participant(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, inbound_mode, did_aw_verified_key)
        VALUES ($1, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */, 'bob', 'acme.com/bob', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */ END)
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    payload = {"body": "follow-up"}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/v1/chat/sessions/{session_id}/messages", json=payload
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["delivered"] is True


@pytest.mark.asyncio
async def test_chat_history_and_dual_read_contract_for_global_participant(
    aweb_cloud_db, monkeypatch
):
    session_id = uuid4()
    first_message_id = uuid4()
    exact_message_id = uuid4()
    watermark_message_id = uuid4()
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
            ($2, $1, 'did:aw:bob', 'bob', 'first', $5),
            ($3, $1, 'did:aw:bob', 'bob', 'exact only', $6),
            ($4, $1, 'did:aw:bob', 'bob', 'watermark only', $7)
        """,
        session_id,
        first_message_id,
        exact_message_id,
        watermark_message_id,
        created_at + timedelta(minutes=1),
        created_at + timedelta(minutes=2),
        created_at + timedelta(minutes=3),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    monkeypatch.setattr(
        "aweb.messaging.chat_read.publish_chat_session_signal",
        AsyncMock(return_value=1),
    )

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")
        published_client_read = await client.post(
            f"/v1/chat/sessions/{session_id}/read",
            json={"up_to_message_id": str(first_message_id)},
        )
        unread_after_published_client_read = await client.get(
            f"/v1/chat/sessions/{session_id}/messages",
            params={"unread_only": "true"},
        )
        exact_read_retry = await client.post(
            f"/v1/chat/sessions/{session_id}/read",
            json={"message_ids": [str(first_message_id)]},
        )
        both_shapes = await client.post(
            f"/v1/chat/sessions/{session_id}/read",
            json={
                "up_to_message_id": str(watermark_message_id),
                "message_ids": [str(exact_message_id)],
            },
        )
        unread_after_both_shapes = await client.get(
            f"/v1/chat/sessions/{session_id}/messages",
            params={"unread_only": "true"},
        )
        neither_shape = await client.post(
            f"/v1/chat/sessions/{session_id}/read", json={}
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["conversation_id"] == str(session_id)
    assert [item["body"] for item in history.json()["messages"]] == [
        "first",
        "exact only",
        "watermark only",
    ]
    assert published_client_read.status_code == 200, published_client_read.text
    assert published_client_read.json()["messages_marked"] == 1
    assert unread_after_published_client_read.status_code == 200, (
        unread_after_published_client_read.text
    )
    assert [
        item["body"] for item in unread_after_published_client_read.json()["messages"]
    ] == [
        "exact only",
        "watermark only",
    ]
    assert exact_read_retry.status_code == 200, exact_read_retry.text
    assert exact_read_retry.json()["messages_marked"] == 0
    assert both_shapes.status_code == 200, both_shapes.text
    assert both_shapes.json()["messages_marked"] == 1
    assert unread_after_both_shapes.status_code == 200, unread_after_both_shapes.text
    assert [item["body"] for item in unread_after_both_shapes.json()["messages"]] == [
        "watermark only"
    ]
    assert neither_shape.status_code == 422, neither_shape.text
    assert "provide at least one" in neither_shape.text


@pytest.mark.asyncio
async def test_chat_history_includes_sender_stable_identity_for_current_key(
    aweb_cloud_db,
):
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
            ($1, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'acme.com/alice', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */ END, 'open')
        """,
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'hello', $3)
        """,
        message_id,
        session_id,
        created_at + timedelta(minutes=1),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkBob"),
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/chat/sessions/{session_id}/messages")

    assert history.status_code == 200, history.text
    body = history.json()
    assert body["messages"][0]["conversation_id"] == str(session_id)
    assert body["messages"][0]["from_did"] == named_did_key("z6MkAliceCurrent")
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
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(
            f"/v1/chat/sessions/{session_id}/messages?unread_only=true&message_id={second_message_id}"
        )

    assert history.status_code == 200, history.text
    body = history.json()
    assert [item["message_id"] for item in body["messages"]] == [str(second_message_id)]
    assert [item["conversation_id"] for item in body["messages"]] == [str(session_id)]
    assert [item["body"] for item in body["messages"]] == ["second"]


@pytest.mark.asyncio
async def test_chat_stream_accepts_global_session_participant(
    aweb_cloud_db, monkeypatch
):
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
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    seen: dict[str, str] = {}

    async def _fake_sse_events(
        *, viewer_did: str, contact_owner_dids: list[str], **kwargs
    ):
        seen["viewer_did"] = viewer_did
        seen["contact_owner_dids"] = contact_owner_dids
        yield ": keepalive\n\n"

    monkeypatch.setattr(chat_routes, "_sse_events", _fake_sse_events)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", timeout=5.0
    ) as client:
        resp = await client.get(
            f"/v1/chat/sessions/{session_id}/stream", params={"deadline": deadline}
        )

    assert resp.status_code == 200, resp.text
    assert "keepalive" in resp.text
    assert seen == {
        "viewer_did": "did:aw:alice",
        "contact_owner_dids": ["did:aw:alice"],
    }


@pytest.mark.asyncio
async def test_chat_stream_replay_includes_sender_stable_identity_for_current_key(
    aweb_cloud_db, monkeypatch
):
    session_id = uuid4()
    message_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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
            ($1, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'acme.com/alice', CASE WHEN NULLIF('did:aw:alice', '') IS NOT NULL THEN 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */ END, 'open')
        """,
        uuid4(),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:key:z6MkqWCS8v3rqKdSp7eVMLDwCZp4wt43T18F7oe7z5QbnLZ4' /* z6MkAliceCurrent */, 'alice', 'hello', $3)
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

        async def aclose(self):
            return None

    class _FakeRedis:
        def pubsub(self):
            return _FakePubSub()

    app.state.redis = _FakeRedis()

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkBob"),
            did_aw="did:aw:bob",
            address="acme.com/bob",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override
    monkeypatch.setattr(chat_routes, "register_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "unregister_waiting", AsyncMock(return_value=None))
    monkeypatch.setattr(chat_routes, "get_waiting_agents", AsyncMock(return_value=[]))

    deadline = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    after = created_at.isoformat()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", timeout=5.0
    ) as client:
        resp = await client.get(
            f"/v1/chat/sessions/{session_id}/stream",
            params={"deadline": deadline, "after": after},
        )

    assert resp.status_code == 200, resp.text
    assert f'"from_did": "{named_did_key("z6MkAliceCurrent")}"' in resp.text
    assert '"from_stable_id": "did:aw:alice"' in resp.text
    assert '"from_address": "acme.com/alice"' in resp.text


@pytest.mark.asyncio
async def test_chat_session_list_accepts_global_session_participant(aweb_cloud_db):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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
            ($1, 'did:aw:alice', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, did_aw_verified_key, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */, 'bob', 'acme.com/bob', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN 'did:key:z6MkpaT971acDhK45NmrbxAZj9q2bXnxJFqodxZDH17gZib9' /* z6MkBob */ END, 'open')
        """,
        uuid4(),
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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


class _SessionRowCountingManager:
    """Database manager wrapper recording how many rows each query returned.

    The session listing reads every session an identity has ever joined, so
    only the row counts coming back from the database show whether a page is
    cut in SQL or after the whole history is already in memory.
    """

    def __init__(self, inner):
        self._inner = inner
        self.row_counts: list[int] = []

    async def fetch_all(self, *args, **kwargs):
        rows = await self._inner.fetch_all(*args, **kwargs)
        self.row_counts.append(len(rows))
        return rows

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.mark.asyncio
async def test_list_sessions_reads_page_sized_rows_not_every_session(aweb_cloud_db):
    """Listing sessions must read in proportion to the page, not to history."""
    session_count = 12
    limit = 3

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    for index in range(session_count):
        session_id = uuid4()
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
            VALUES ($1, 'alice', $2)
            """,
            session_id,
            datetime.now(timezone.utc) - timedelta(minutes=index + 1),
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

    counting_db = _SessionRowCountingManager(aweb_cloud_db.aweb_db)
    app = _build_test_app(counting_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/v1/chat/sessions?limit={limit}")

    assert resp.status_code == 200, resp.text
    assert len(resp.json()["sessions"]) == limit

    # The page and its participant rows scale with the limit, not with the
    # twelve sessions on file.
    assert max(counting_db.row_counts) <= 3 * limit
    assert max(counting_db.row_counts) < session_count * 2


@pytest.mark.asyncio
async def test_list_sessions_reports_whether_the_limit_left_sessions_out(aweb_cloud_db):
    """A short page must say it is short; a complete one must not claim it is."""
    session_count = 6

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    for index in range(session_count):
        session_id = uuid4()
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
            VALUES ($1, 'alice', $2)
            """,
            session_id,
            datetime.now(timezone.utc) - timedelta(minutes=index + 1),
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

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _auth_override

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        truncated = await client.get("/v1/chat/sessions?limit=2")
        exact = await client.get(f"/v1/chat/sessions?limit={session_count}")
        roomy = await client.get("/v1/chat/sessions?limit=50")

    assert truncated.status_code == 200, truncated.text
    assert len(truncated.json()["sessions"]) == 2
    assert truncated.json()["has_more"] is True

    # A page that exactly consumes the limit is still complete, and must not
    # claim otherwise just because the lookahead row was fetched.
    assert exact.status_code == 200, exact.text
    assert len(exact.json()["sessions"]) == session_count
    assert exact.json()["has_more"] is False

    assert roomy.status_code == 200, roomy.text
    assert len(roomy.json()["sessions"]) == session_count
    assert roomy.json()["has_more"] is False
