from __future__ import annotations

from team_facts_fixtures import legacy_registry

from collections import OrderedDict
from time import monotonic
from aweb.error_responses import install_service_error_handlers
from aweb.identity_binding import IdentityBinding

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import (
    did_from_public_key,
    did_key_from_signing_key,
    stable_id_from_public_key,
)
from awid.e2ee_keys import (
    build_encryption_key_assertion,
    canonical_encryption_assertion,
    encryption_key_id,
)
from awid.registry import (
    IDTreeEnrollment,
    Address,
    AddressDelivery,
    KeyResolution,
)
from awid.signing import canonical_json_bytes, sign_message
from pgdbm.errors import ConnectionError as DatabaseConnectionError
from aweb.e2ee_messages import (
    E2EE_SUITE,
    E2EEEnvelopeError,
    _envelope_map,
    _hash_canonical,
    _key_wrap_map,
    validate_e2ee_mail_envelope,
)
from aweb.federation.envelope import verify_federation_envelope
from aweb.identity_auth_deps import (
    IDENTITY_DID_AW_HEADER,
    IdentityAuth,
    MessagingAuth,
    get_messaging_auth,
)
import aweb.routes.federation as federation_routes
from aweb.routes.federation import router as federation_router
from aweb.routes.messages import router as messages_router
from federation_activation_support import TestFederationAuthority
from did_key_fixtures import named_did_key, named_signing_key


# Pytest loads the canonical fixture after this module's shared helpers exist.
pytest_plugins = ("chat_pair_support",)


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


def _raw_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _sha256_b64(data: bytes) -> str:
    return "sha256:" + _raw_b64(hashlib.sha256(data).digest())


def _encryption_key_id(public_key: bytes) -> str:
    return encryption_key_id(_raw_b64(public_key))


async def _insert_agent_encryption_assertion(
    manager,
    *,
    agent_id,
    team_id: str,
    assertion: dict,
) -> None:
    canonical = canonical_encryption_assertion(assertion).decode()
    await manager.execute(
        """
        INSERT INTO {{tables.agent_encryption_keys}} (
            agent_id, team_id, encryption_key_id, encryption_public_key,
            algorithm, identity_did, identity_stable_id, assertion_custody,
            assertion_signature, assertion_canonical, created_at_text,
            not_before_text, expires_at_text, assertion_created_at,
            not_before_at, expires_at, previous_encryption_key_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11::text, $12::text, $13::text,
            $11::text::timestamptz, $12::text::timestamptz,
            $13::text::timestamptz, $14
        )
        """,
        agent_id,
        team_id,
        assertion["encryption_key_id"],
        assertion["encryption_public_key"],
        assertion["algorithm"],
        assertion["identity_did"],
        assertion.get("identity_stable_id"),
        assertion.get("custody"),
        assertion["signature"],
        canonical,
        assertion["created_at"],
        assertion["not_before"],
        assertion["expires_at"],
        assertion.get("previous_encryption_key_id"),
    )


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
    created_at: datetime | None = None,
):
    signing_key = SigningKey(sender_sk)
    delivery_wrap = {
        "wrap_id": _sha256_b64(b"wrap-binding"),
        "recipient_stable_id": recipient_stable_id,
        "recipient_did": recipient_did,
        "recipient_address": recipient_address,
        "recipient_encryption_key_id": _encryption_key_id(b"r" * 32),
        "sender_encryption_key_id": _encryption_key_id(b"s" * 32),
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
        "recipient_encryption_key_id": _encryption_key_id(b"s" * 32),
        "sender_encryption_key_id": _encryption_key_id(b"s" * 32),
        "sender_did": sender_did,
        "sender_stable_id": sender_stable_id,
        "wrap_purpose": "sender_copy",
        "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
        "encapsulated_key": _raw_b64(b"E" * 32),
        "wrapped_cek": _raw_b64(b"W" * 48),
    }
    created_at = (created_at or datetime.now(timezone.utc)).replace(microsecond=0)
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
            "encryption_key_id": _encryption_key_id(b"s" * 32),
        },
        "recipients": [
            {
                "address": recipient_address,
                "did": recipient_did,
                "stable_id": recipient_stable_id,
                "encryption_key_id": _encryption_key_id(b"r" * 32),
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


def test_encrypted_mail_rejects_non_base64_message_signature_shape():
    alice_sk, alice_pk, alice_did_key = _make_keypair()
    _, bob_pk, bob_did_key = _make_keypair()
    alice_stable = stable_id_from_public_key(alice_pk)
    bob_stable = stable_id_from_public_key(bob_pk)
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    envelope = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice_stable,
        recipient_did=bob_did_key,
        recipient_stable_id=bob_stable,
        message_id=message_id,
        conversation_id=conversation_id,
    )
    envelope["signature"] += "!!!!"

    with pytest.raises(E2EEEnvelopeError, match="signature must be valid base64"):
        validate_e2ee_mail_envelope(
            envelope,
            message_id=message_id,
            conversation_id=conversation_id,
            sender_did=alice_did_key,
            sender_stable_id=alice_stable,
            recipient_did=bob_did_key,
            recipient_stable_id=bob_stable,
            recipient_address="acme.com/bob",
        )


def _build_test_app(aweb_db, registry, *, verified_bindings=()):
    app = FastAPI()
    install_service_error_handlers(app)
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
    if isinstance(registry, AsyncMock):
        # These unit cases select the strict foreign authority supplied below.
        # Configured-home namespace routing is exercised against real AWID apps.
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
    app.state.public_origin = "http://test"
    return app


def _cert(
    certificate_id: str, member_did_aw: str, member_did_key: str, alias: str = "alice"
):
    return {
        "certificate_id": certificate_id,
        "member_did_aw": member_did_aw,
        "member_did_key": member_did_key,
        "member_address": "",
        "alias": alias,
        "identity_scope": "global",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


async def _admit_seeded_team_members(aweb_db, *, team_id: str, team_did_key: str):
    """Supply admitted-member facts in routing unit fixtures, not proof of admission."""
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET accepted_team_did_key=$2 WHERE team_id=$1",
        team_id,
        team_did_key,
    )


async def _insert_team(aweb_db, team_id: str):
    team_name, namespace = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6MktTJnUsVhPhJQmJrZgKFWXv7g44zYDtMN8fRBdX3KY6Jp' /* z6Mkteam */)
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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ($1, $2, $3, $4, $5, 'global', 'developer', $6, CASE WHEN NULLIF($3, '') IS NOT NULL THEN $2 END)
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


async def _registered_routing_pair(pair):
    """Borrow the real pair; current facts come from SDK writes and native admission."""
    from types import SimpleNamespace
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    sides = {}
    for side, node, alias in (
        ("source", pair.source, "alice"),
        ("target", pair.target, "bob"),
    ):
        domain = f"routing-{uuid4().hex}.test"
        controller = await node.registry.ensure_namespace(domain=domain)
        pair.dns.records[(f"_awid.{domain}", "TXT")] = [
            f'"awid=v1;controller={did_key_from_signing_key(controller)};registry={node.registry_origin}"'
        ]
        env = SimpleNamespace(
            app=node.server.app,
            client=node.client,
            registry=node.registry,
            team_sk=node.team_sk,
            team_did=node.team_did,
        )
        team_id = f"members:{domain}"
        await register_messaging_team(env, team_id=team_id)
        registry = node.server.app.state.awid_registry_client
        await registry.update_namespace_delivery_origin(domain, controller, node.origin)
        actor = await admit_messaging_actor(
            env,
            alias=alias,
            team_id=team_id,
            address=f"{domain}/{alias}",
        )
        sides[side] = SimpleNamespace(node=node, actor=actor, env=env)
    return SimpleNamespace(**sides)


class _RecordingFederationTransport(httpx.AsyncBaseTransport):
    """Observe actual delivery bytes and delegate to the unchanged checked transport."""

    def __init__(self, delegate):
        self.delegate = delegate
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return await self.delegate.handle_async_request(request)

    async def aclose(self):
        # The application owns the shared delegate's lifecycle.
        pass


class _MovedFederationTransport(_RecordingFederationTransport):
    """Inject only the old backend's negative reply; successful delivery stays real."""

    def __init__(self, delegate, *, refused_origin):
        super().__init__(delegate)
        self.refused_origin = refused_origin

    async def handle_async_request(self, request):
        if str(request.url).startswith(self.refused_origin + "/"):
            self.requests.append(request)
            return httpx.Response(421, json={"detail": "moved"})
        return await super().handle_async_request(request)


async def _publish_registered_encryption_key(side, assertion):
    actor = side.actor
    raw = json.dumps(assertion).encode()
    response = await side.node.client.put(
        "/v1/agents/me/encryption-key",
        content=raw,
        headers={
            "Content-Type": "application/json",
            **_signed_team_headers(
                actor.signing_key, actor.did_key, actor.team_id, actor.certificate, raw
            ),
        },
    )
    assert response.status_code == 200, response.text


async def _admit_registered_local(node):
    """Verify the existing fixture's real local certificate through native connect."""
    from messaging_actor_support import RegisteredMessagingActor

    local = node.local
    raw = b'{"agent_type":"agent"}'
    response = await node.client.post(
        "/v1/connect",
        content=raw,
        headers={
            "Content-Type": "application/json",
            **_signed_team_headers(
                local.sk, local.did, node.team_id, local.encoded_certificate, raw
            ),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["agent_id"] == str(local.id)
    return RegisteredMessagingActor(
        signing_key=local.sk,
        did_key=local.did,
        stable_id="",
        address="",
        team_id=node.team_id,
        agent_id=str(local.id),
        certificate=local.encoded_certificate,
    )


async def _store_retained_route(node, *, kind, conversation_id, team_id, parties):
    """Build an already trusted route with the product's persistence owner."""
    from aweb.messaging.chat import ensure_session
    from aweb.messaging.conversations import (
        ConversationParticipant,
        create_conversation,
    )
    from aweb.messaging.kinds import MessageKind

    infra = node.server.app.state.db
    conversation_id = UUID(str(conversation_id))
    if kind is MessageKind.CHAT:
        assert (
            await ensure_session(
                infra,
                team_id=team_id,
                participant_rows=parties,
                created_by=parties[0]["did"],
                session_id=conversation_id,
            )
            == conversation_id
        )
    else:
        await create_conversation(
            infra,
            conversation_type="mail",
            created_by_did=parties[0]["did"],
            initiator=ConversationParticipant(**parties[0]),
            recipients=[ConversationParticipant(**party) for party in parties[1:]],
            conversation_id=conversation_id,
            team_id=team_id,
            ttl=None,
        )


async def _mirror_retained_local_history(
    world, *, conversation_id, local_did_key, kind, local_address=None
):
    """Project retained local-key history on the global peer's server."""
    node, peer = world.target.node, world.target.actor
    local_origin = world.source.node.origin
    await _store_retained_route(
        node,
        kind=kind,
        conversation_id=conversation_id,
        team_id=peer.team_id,
        parties=[
            dict(
                did=local_did_key,
                current_did_key=local_did_key,
                alias="local",
                address=local_address or f"{world.source.node.domain}/local",
                delivery_origin=local_origin,
                transport_hint=f"federation:{local_origin}",
            ),
            dict(
                did=peer.stable_id,
                current_did_key=peer.did_key,
                agent_id=peer.agent_id,
                alias="bob",
                address=peer.address,
                transport_hint="local",
            ),
        ],
    )


async def _store_retained_local_origin(world, *, conversation_id, local, kind):
    """Project the same valid local-key participant on its own server."""
    peer, peer_origin = world.target.actor, world.target.node.origin
    await _store_retained_route(
        world.source.node,
        kind=kind,
        conversation_id=conversation_id,
        team_id=local.team_id,
        parties=[
            dict(
                did=local.did_key,
                current_did_key=local.did_key,
                agent_id=local.agent_id,
                alias="local",
                address=local.did_key,
                transport_hint="local",
            ),
            dict(
                did=peer.stable_id,
                current_did_key=peer.did_key,
                alias="bob",
                address=peer.address,
                delivery_origin=peer_origin,
                transport_hint=f"federation:{peer_origin}",
            ),
        ],
    )


async def _registered_history(world, *, make_payload):
    sender, target = world.source.actor, world.target.actor
    payload = make_payload(
        sender_sk=sender.signing_key,
        sender_did_key=sender.did_key,
        sender_did_aw=sender.stable_id,
        sender_address=sender.address,
        sender_delivery_origin=world.source.node.origin,
        target_did_key=target.did_key,
        target_did_aw=target.stable_id,
        target_address=target.address,
        target_delivery_origin=world.target.node.origin,
    )
    response = await world.target.node.client.post(
        "/v1/federation/messages", json=payload
    )
    assert response.status_code == 200, response.text
    return UUID(payload["envelope"]["conversation_id"])


async def _registered_outbound_chat_history(world):
    from types import SimpleNamespace
    from chat_pair_support import _send

    def participant(side):
        actor = side.actor
        return SimpleNamespace(
            sk=actor.signing_key,
            did=actor.did_key,
            stable=actor.stable_id,
            alias=actor.address.split("/", 1)[1],
            address=actor.address,
            encoded_certificate=actor.certificate,
            node=SimpleNamespace(client=side.node.client, team_id=actor.team_id),
        )

    response, submitted = await _send(
        participant(world.source), participant(world.target), "chat"
    )
    assert response.status_code == 200, response.text
    return submitted.cid


def _registered_address_reads(side):
    domain, alias = side.actor.address.split("/", 1)
    return side.node.registry_calls.count(
        ("GET", f"/v1/namespaces/{domain}/addresses/{alias}")
    )


def _record_federation(node):
    recorded = _RecordingFederationTransport(
        node.server.app.state.federation_authority.delivery_transport
    )
    node.server.app.state.federation_mail_transport = recorded
    node.server.app.state.federation_chat_transport = recorded
    return recorded.requests


def _registered_identity_headers(actor, *, payload):
    """Identity-only controls intentionally omit team selection."""
    headers = _registered_actor_headers(actor, payload=payload)
    headers.pop("X-Team-ID")
    return headers


def _registered_actor_headers(actor, *, payload):
    body = httpx.Request("POST", "http://test", json=payload).content
    return {
        "Content-Type": "application/json",
        "X-Team-ID": actor.team_id,
        **_signed_identity_headers(
            actor.signing_key, actor.did_key, actor.stable_id, body
        ),
    }


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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, conversation_id
    )
    by_did = {row["did"]: row for row in participants}
    assert by_did["did:aw:alice"]["role"] == "initiator"
    assert str(by_did["did:aw:alice"]["agent_id"]) == alice_agent_id
    assert by_did["did:aw:alice"]["current_did_key"] == alice_did_key
    assert by_did["did:aw:alice"]["transport_hint"] == "local"
    assert by_did["did:aw:bob"]["role"] == "participant"
    assert str(by_did["did:aw:bob"]["agent_id"]) == bob_agent_id
    assert by_did["did:aw:bob"]["current_did_key"] == bob_did_key
    assert by_did["did:aw:bob"]["transport_hint"] == "local"

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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    assert inbox_resp.json()["messages"][0]["conversation_id"] == conversation_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ingress_headers",
    [
        {
            "X-AWEB-Ingress-Namespace": "client",
            "X-AWEB-Ingress-Key": "event1",
            "X-AWEB-Ingress-Input-Hash": "sha256:" + "55" * 32,
        },
        {"X-AWEB-Ingress-Key": "event1"},
    ],
    ids=["all", "partial"],
)
async def test_send_message_with_ingress_headers_is_an_ordinary_send(
    aweb_cloud_db, ingress_headers
):
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
    payload = {"to_alias": "bob", "subject": "with ingress headers", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body_bytes),
        **ingress_headers,
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT conversation_id FROM {{tables.messages}} WHERE subject = 'with ingress headers'"
    )
    assert str(row["conversation_id"]) == resp.json()["conversation_id"]


@pytest.mark.asyncio
async def test_inbox_pagination_returns_every_message_without_overlap(aweb_cloud_db):
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    message_ids = [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003",
    ]
    for message_id in message_ids:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.messages}} (
                message_id, from_did, to_did, from_alias, to_alias,
                subject, body, priority, created_at
            )
            VALUES ($1, 'did:aw:alice', 'did:aw:bob', 'alice', 'bob',
                    'page', $2, 'normal', $3)
            """,
            UUID(message_id),
            message_id,
            created_at,
        )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.get("/v1/messages/inbox?limit=2")
        assert first.status_code == 200, first.text
        first_body = first.json()
        assert first_body["has_more"] is True
        assert first_body["next_cursor"]

        second = await client.get(
            "/v1/messages/inbox",
            params={"limit": 2, "cursor": first_body["next_cursor"]},
        )
        malformed = await client.get(
            "/v1/messages/inbox",
            params={
                "limit": 2,
                "cursor": "e30",
            },  # URL-safe base64 for an empty object.
        )

    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["has_more"] is False
    assert second_body["next_cursor"] is None
    first_ids = [item["message_id"] for item in first_body["messages"]]
    second_ids = [item["message_id"] for item in second_body["messages"]]
    assert len(first_ids) == 2
    assert len(second_ids) == 1
    assert set(first_ids).isdisjoint(second_ids)
    assert set(first_ids + second_ids) == set(message_ids)
    assert malformed.status_code == 422
    assert malformed.json()["detail"] == "Invalid inbox cursor"


@pytest.mark.asyncio
async def test_signed_human_plaintext_mail_lost_response_retry(aweb_cloud_db):
    human_sk, human_pk, human_key = _make_keypair()
    _, agent_pk, agent_key = _make_keypair()
    human_did = stable_id_from_public_key(human_pk)
    agent_did = stable_id_from_public_key(agent_pk)
    team_id = "backend:acme.com"
    await _insert_team(aweb_cloud_db.aweb_db, team_id)
    human_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id=team_id,
        alias="person",
        did_key=human_key,
        did_aw=human_did,
        address="acme.com/person",
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id = $1",
        UUID(human_id),
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id=team_id,
        alias="agent",
        did_key=agent_key,
        did_aw=agent_did,
        address="acme.com/agent",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth():
        return MessagingAuth(
            did_key=human_key,
            did_aw=human_did,
            address="acme.com/person",
            team_id=team_id,
            alias="person",
            agent_id=human_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def request_body(body):
        signed = canonical_json_bytes(
            {
                "type": "mail",
                "from": "person",
                "from_did": human_key,
                "from_stable_id": human_did,
                "to": agent_did,
                "to_did": agent_key,
                "to_stable_id": agent_did,
                "subject": "Private mail",
                "body": body,
                "timestamp": timestamp,
                "message_id": message_id,
                "conversation_id": conversation_id,
            }
        )
        return {
            "to_stable_id": agent_did,
            "subject": "Private mail",
            "body": body,
            "timestamp": timestamp,
            "message_id": message_id,
            "conversation_id": conversation_id,
            "new_conversation": True,
            "from_did": human_key,
            "signed_payload": signed.decode(),
            "signature": sign_message(human_sk, signed),
        }

    original = request_body("hello from the person")
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        first = await client.post("/v1/messages", json=original)
        assert first.status_code == 200, first.text
        before = dict(
            await aweb_cloud_db.aweb_db.fetch_one(
                "SELECT * FROM {{tables.messages}} WHERE message_id = $1",
                UUID(message_id),
            )
        )
        # The first response was lost after commit; retry the exact signed request.
        retry = await client.post("/v1/messages", json=original)
        changed = await client.post(
            "/v1/messages", json=request_body("changed content")
        )

    assert retry.status_code == 200, retry.text
    assert retry.json() == first.json()
    assert changed.status_code == 409, changed.text
    after = dict(
        await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT * FROM {{tables.messages}} WHERE message_id = $1",
            UUID(message_id),
        )
    )
    assert after == before
    assert after["signed_payload"] == original["signed_payload"]
    assert (
        await aweb_cloud_db.aweb_db.fetch_val(
            "SELECT count(*) FROM {{tables.messages}} WHERE conversation_id = $1",
            UUID(conversation_id),
        )
        == 1
    )


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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)

    assert resp.status_code == 200, resp.text
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        replay_resp = await client.post(
            "/v1/messages",
            content=body_bytes,
            headers={
                **_signed_identity_headers(
                    alice_sk, alice_did_key, alice_stable, body_bytes
                ),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        mutation_resp = await client.post(
            "/v1/messages",
            content=different_body,
            headers={
                **_signed_identity_headers(
                    alice_sk, alice_did_key, alice_stable, different_body
                ),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    message = inbox_resp.json()["messages"][0]
    assert message["content_mode"] == "encrypted_v2"
    assert message["message_version"] == 2
    assert "encrypted_envelope" in message
    assert "subject" not in message
    assert "body" not in message
    # The envelope signature vouches for the sender, though the legacy signature columns are empty.
    assert message["verification_status"] == "verified"
    assert message["from_address"] == "acme.com/alice"


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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/messages",
            content=body_bytes,
            headers={
                **_signed_identity_headers(
                    alice_sk, alice_did_key, "did:aw:alice", body_bytes
                ),
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 200, resp.text
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, conversation_id
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "initial alias thread",
                "body": "hello",
            },
        )
        assert first.status_code == 200, first.text
        conversation_id = first.json()["conversation_id"]
        message_id = str(uuid4())
        timestamp = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
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
    assert [str(row["conversation_id"]) for row in messages] == [
        conversation_id,
        conversation_id,
    ]
    assert messages[1]["to_agent_id"] is None
    assert messages[1]["to_did"] == "did:aw:bob"
    app.state.awid_registry_client.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_reused_alias_new_identity_explicit_id_creates_new_thread(aweb_cloud_db):
    _, _, old_worker_did_key = _make_keypair()
    _, _, new_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    old_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=old_worker_did_key,
        did_aw="did:aw:old-worker",
        address="acme.com/worker",
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

    async def _old_worker_auth():
        return MessagingAuth(
            did_key=old_worker_did_key,
            did_aw="did:aw:old-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=old_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _old_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "old worker thread",
                "body": "old hello",
            },
        )
    assert first.status_code == 200, first.text
    old_conversation_id = first.json()["conversation_id"]
    old_message_id = first.json()["message_id"]

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET status = 'deleted', deleted_at = NOW()
        WHERE agent_id = $1
        """,
        UUID(old_worker_agent_id),
    )
    new_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=new_worker_did_key,
        did_aw="did:aw:new-worker",
        address="acme.com/worker",
    )

    async def _new_worker_auth():
        return MessagingAuth(
            did_key=new_worker_did_key,
            did_aw="did:aw:new-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=new_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _new_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        second = await client.post(
            "/v1/messages",
            json={
                "conversation_id": str(uuid4()),
                "to_alias": "bob",
                "subject": "new worker thread explicit",
                "body": "new hello",
            },
        )
        old_visible = await client.get(f"/v1/messages/{old_message_id}")

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] != old_conversation_id
    assert old_visible.status_code == 404, old_visible.text
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, second.json()["conversation_id"]
    )
    assert {str(participant["agent_id"]) for participant in participants} == {
        new_worker_agent_id,
        bob_agent_id,
    }


@pytest.mark.asyncio
async def test_reused_alias_new_identity_without_explicit_id_creates_new_thread(
    aweb_cloud_db,
):
    _, _, old_worker_did_key = _make_keypair()
    _, _, new_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    old_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=old_worker_did_key,
        did_aw="did:aw:old-worker",
        address="acme.com/worker",
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

    async def _old_worker_auth():
        return MessagingAuth(
            did_key=old_worker_did_key,
            did_aw="did:aw:old-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=old_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _old_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "old worker no explicit",
                "body": "old hello",
            },
        )
    assert first.status_code == 200, first.text
    old_conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET status = 'deleted', deleted_at = NOW() WHERE agent_id = $1",
        UUID(old_worker_agent_id),
    )
    new_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=new_worker_did_key,
        did_aw="did:aw:new-worker",
        address="acme.com/worker",
    )

    async def _new_worker_auth():
        return MessagingAuth(
            did_key=new_worker_did_key,
            did_aw="did:aw:new-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=new_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _new_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        second = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "new worker no explicit",
                "body": "new hello",
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] != old_conversation_id
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, second.json()["conversation_id"]
    )
    assert {str(participant["agent_id"]) for participant in participants} == {
        new_worker_agent_id,
        bob_agent_id,
    }


@pytest.mark.asyncio
async def test_reused_recipient_alias_new_identity_without_explicit_id_creates_new_thread(
    aweb_cloud_db,
):
    _, _, old_worker_did_key = _make_keypair()
    _, _, new_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    old_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=old_worker_did_key,
        did_aw="did:aw:old-worker",
        address="acme.com/worker",
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

    async def _old_worker_auth():
        return MessagingAuth(
            did_key=old_worker_did_key,
            did_aw="did:aw:old-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=old_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _old_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "old worker recipient",
                "body": "old hello",
            },
        )
    assert first.status_code == 200, first.text
    old_conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET status = 'deleted', deleted_at = NOW() WHERE agent_id = $1",
        UUID(old_worker_agent_id),
    )
    new_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=new_worker_did_key,
        did_aw="did:aw:new-worker",
        address="acme.com/worker",
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

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        second = await client.post(
            "/v1/messages",
            json={
                "to_alias": "worker",
                "subject": "bob to new worker",
                "body": "hello new worker",
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] != old_conversation_id
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, second.json()["conversation_id"]
    )
    assert {str(participant["agent_id"]) for participant in participants} == {
        new_worker_agent_id,
        bob_agent_id,
    }
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_agent_id FROM {{tables.messages}} WHERE subject = 'bob to new worker'"
    )
    assert row["to_did"] == "did:aw:new-worker"
    assert str(row["to_agent_id"]) == new_worker_agent_id


@pytest.mark.asyncio
async def test_agent_deleted_participant_did_not_matched_by_reused_address(
    aweb_cloud_db,
):
    _, _, old_worker_did_key = _make_keypair()
    _, _, new_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    old_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=old_worker_did_key,
        did_aw="did:aw:old-worker",
        address="acme.com/worker",
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

    async def _old_worker_auth():
        return MessagingAuth(
            did_key=old_worker_did_key,
            did_aw="did:aw:old-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=old_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _old_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "old deleted worker",
                "body": "old hello",
            },
        )
    assert first.status_code == 200, first.text
    old_conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET agent_id = NULL
        WHERE conversation_id = $1 AND address = 'acme.com/worker'
        """,
        UUID(old_conversation_id),
    )
    old_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT agent_id, did, address
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND address = 'acme.com/worker'
        """,
        UUID(old_conversation_id),
    )
    assert old_participant["agent_id"] is None
    assert old_participant["did"] == "did:aw:old-worker"
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET status = 'deleted', deleted_at = NOW() WHERE agent_id = $1",
        UUID(old_worker_agent_id),
    )

    new_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=new_worker_did_key,
        did_aw="did:aw:new-worker",
        address="acme.com/worker",
    )

    async def _new_worker_auth():
        return MessagingAuth(
            did_key=new_worker_did_key,
            did_aw="did:aw:new-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=new_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _new_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        second = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "new after agent delete",
                "body": "new hello",
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] != old_conversation_id
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, second.json()["conversation_id"]
    )
    assert {str(participant["agent_id"]) for participant in participants} == {
        new_worker_agent_id,
        bob_agent_id,
    }


@pytest.mark.asyncio
async def test_empty_did_participant_not_matched_by_reused_address(aweb_cloud_db):
    _, _, new_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    sparse_conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'backend:acme.com', 'did:aw:legacy')
        """,
        sparse_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, transport_hint, role)
        VALUES
            ($1, '', NULL, 'worker', 'acme.com/worker', 'local', 'initiator'),
            ($1, 'did:aw:bob', $2, 'bob', 'acme.com/bob', 'local', 'participant')
        """,
        sparse_conversation_id,
        UUID(bob_agent_id),
    )
    new_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=new_worker_did_key,
        did_aw="did:aw:new-worker",
        address="acme.com/worker",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _new_worker_auth():
        return MessagingAuth(
            did_key=new_worker_did_key,
            did_aw="did:aw:new-worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=new_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _new_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "new after empty did",
                "body": "new hello",
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["conversation_id"] != str(sparse_conversation_id)
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, resp.json()["conversation_id"]
    )
    assert {str(participant["agent_id"]) for participant in participants} == {
        new_worker_agent_id,
        bob_agent_id,
    }


@pytest.mark.asyncio
async def test_same_stable_did_rotation_continues_existing_thread(aweb_cloud_db):
    _, _, old_worker_did_key = _make_keypair()
    _, _, rotated_worker_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    old_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=old_worker_did_key,
        did_aw="did:aw:worker",
        address="acme.com/worker",
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

    async def _old_worker_auth():
        return MessagingAuth(
            did_key=old_worker_did_key,
            did_aw="did:aw:worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=old_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _old_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_alias": "bob",
                "subject": "old stable worker",
                "body": "old hello",
            },
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET status = 'deleted', deleted_at = NOW() WHERE agent_id = $1",
        UUID(old_worker_agent_id),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET agent_id = NULL
        WHERE conversation_id = $1 AND did = 'did:aw:worker'
        """,
        UUID(conversation_id),
    )
    rotated_worker_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="worker",
        did_key=rotated_worker_did_key,
        did_aw="did:aw:worker",
        address="acme.com/worker",
    )

    async def _rotated_worker_auth():
        return MessagingAuth(
            did_key=rotated_worker_did_key,
            did_aw="did:aw:worker",
            address="acme.com/worker",
            team_id="backend:acme.com",
            alias="worker",
            agent_id=rotated_worker_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _rotated_worker_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        second = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "rotated stable worker",
                "body": "still same stable identity",
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["conversation_id"] == conversation_id
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, conversation_id
    )
    assert {participant["did"] for participant in participants} == {
        "did:aw:worker",
        "did:aw:bob",
    }
    assert bob_agent_id in {
        str(participant["agent_id"]) for participant in participants
    }


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
    await _insert_agent(
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
    payload = {
        "to_did": "did:aw:bob",
        "subject": "conversation to did",
        "body": "hello",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, conversation_id
    )
    by_did = {row["did"]: row for row in participants}

    assert conversation["team_id"] == "backend:acme.com"
    assert str(message["conversation_id"]) == conversation_id
    assert message["to_did"] == "did:aw:bob"
    assert by_did["did:aw:alice"]["current_did_key"] == alice_did_key
    assert by_did["did:aw:alice"]["transport_hint"] == "local"
    assert by_did["did:aw:bob"]["agent_id"] is None
    assert by_did["did:aw:bob"]["address"] is None
    assert by_did["did:aw:bob"]["current_did_key"] == bob_did_key
    assert by_did["did:aw:bob"]["transport_hint"] == "local"


@pytest.mark.asyncio
@pytest.mark.parametrize("new_conversation", [False, True])
async def test_send_message_to_external_address_posts_federated_mail_and_projects_locally(
    route_pair, new_conversation
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    remote_requests = _record_federation(world.source.node)
    address_path = (
        f"/v1/namespaces/{world.target.actor.address.split('/')[0]}/addresses/bob"
    )
    prior_reads = world.target.node.registry_calls.count(("GET", address_path))
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "subject": "conversation address",
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob_did_key,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": bob.address,
        "subject": "conversation address",
        "body": "hello",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    if new_conversation:
        payload["new_conversation"] = True
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        resp = await client.post(
            "/v1/messages",
            json=payload,
            headers=_registered_actor_headers(alice, payload=payload),
        )
    assert resp.status_code == 200, resp.text
    assert (
        world.target.node.registry_calls.count(("GET", address_path)) == prior_reads + 1
    )
    assert resp.json()["conversation_id"] == conversation_id
    assert resp.json()["message_id"] == message_id
    assert len(remote_requests) == 1
    assert (
        str(remote_requests[0].url)
        == f"{world.target.node.origin}/v1/federation/messages"
    )
    remote_body = json.loads(remote_requests[0].content)
    assert remote_body["signature"] == payload["signature"]
    assert remote_body["envelope"]["signed_payload"] == signed_payload
    assert remote_body["envelope"]["target_delivery_origin"] == world.target.node.origin
    for deprecated_field in (
        "sender_active_team_id",
        "sender_team_certificate",
        "target_address_lookup_authorization",
        "target_address_lookup_timestamp",
    ):
        assert deprecated_field not in remote_body["envelope"]
    assert remote_body["envelope"]["sender_did_aw"] == alice.stable_id
    assert remote_body["envelope"]["sender_current_did_key"] == alice_did_key
    assert remote_body["envelope"]["target_did_aw"] == bob.stable_id
    assert remote_body["envelope"]["target_current_did_key"] == bob_did_key
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, conversation_id
    )
    by_did = {row["did"]: row for row in participants}
    message = await aweb_cloud_db.aweb_db.fetch_one("""
        SELECT conversation_id, to_agent_id, to_did
        FROM {{tables.messages}}
        WHERE subject = 'conversation address'
        """)
    assert str(message["conversation_id"]) == conversation_id
    assert message["to_agent_id"] is None
    assert message["to_did"] == bob.stable_id
    assert by_did[bob.stable_id]["agent_id"] is None
    assert by_did[bob.stable_id]["address"] == bob.address
    assert by_did[alice.stable_id]["current_did_key"] == alice_did_key
    assert by_did[alice.stable_id]["delivery_origin"] is None
    assert by_did[alice.stable_id]["transport_hint"] == "local"
    assert by_did[bob.stable_id]["current_did_key"] == bob_did_key
    assert by_did[bob.stable_id]["delivery_origin"] == world.target.node.origin
    assert (
        by_did[bob.stable_id]["transport_hint"]
        == f"federation:{world.target.node.origin}"
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        retry = await client.post(
            "/v1/messages",
            json=payload,
            headers=_registered_actor_headers(alice, payload=payload),
        )
    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == message_id
    assert len(remote_requests) == 2
    assert (
        world.target.node.registry_calls.count(("GET", address_path)) == prior_reads + 1
    )
    projected_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert projected_count == 1
    reply_payload = _federated_mail_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=alice.address,
        target_did_aw=alice.stable_id,
        target_did_key=alice_did_key,
        target_delivery_origin=world.source.node.origin,
        subject="remote reply",
        body="reply through the projected route",
        conversation_id=conversation_id,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        reply = await client.post("/v1/federation/messages", json=reply_payload)
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id


@pytest.mark.asyncio
async def test_send_message_to_external_address_requires_signed_payload(aweb_cloud_db):
    """Federated mail first contact must refuse an unsigned payload before delivery.

    The request carries from_did, message_id, timestamp and conversation_id, so
    the missing signature pair is the only thing _require_remote_mail_signature
    can object to. The asserted detail is emitted by nothing else in the request
    path, which is how this fixture proves it reached that gate.
    """
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
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(
            did_aw="did:aw:bob", current_did_key=named_did_key("bob")
        )
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
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
    remote_requests = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_requests.append(request)
        return httpx.Response(
            500, json={"detail": "unsigned mail must never reach the wire"}
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
            "/v1/messages",
            json={
                "to_address": "otherco.com/bob",
                "subject": "conversation address",
                "body": "hello",
                "conversation_id": conversation_id,
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": alice_did_key,
            },
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "Federated mail delivery requires a sender-signed payload"
    )
    assert remote_requests == []
    projected_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert projected_count == 0


@pytest.mark.asyncio
async def test_send_encrypted_message_to_external_address_posts_ciphertext_only(
    aweb_cloud_db,
):
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
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(
            did_aw="did:aw:bob", current_did_key=named_did_key("bob")
        )
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-2",
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
        recipient_did=named_did_key("bob"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_send_message_from_local_didkey_to_global_did_first_contact_fails_closed(
    aweb_cloud_db,
):
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
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError("bare did:aw first-contact must not resolve by key")
    )
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
            "to_stable_id": "did:aw:bob",
            "type": "mail",
        }
    ).decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_retired_mail_recipient_refuses_even_with_a_learned_return_route(
    aweb_cloud_db,
):
    bob_sk, _, bob_did_key = _make_keypair()
    local_did_key = named_did_key("z6MkLocalOnly")
    await _insert_team(aweb_cloud_db.aweb_db, "backend:remote.example")
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:remote.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob",
        address="remote.example/bob",
    )
    retired_routed_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}}
            (team_id, did_key, alias, identity_scope, role, status, deleted_at, inbound_mode)
        VALUES
            ('backend:remote.example', $1, 'retired-routed', 'local', 'developer', 'deleted', NOW(), 'open')
        RETURNING agent_id
        """,
        local_did_key,
    )
    conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'backend:remote.example', 'did:key:z6MkskfbSekkwq5btte2YYYcANp4eSrRiSy9mkXKPgYwsJQj' /* z6MkLocalOnly */)
        """,
        conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role)
        VALUES
            ($1, 'did:key:z6MkskfbSekkwq5btte2YYYcANp4eSrRiSy9mkXKPgYwsJQj' /* z6MkLocalOnly */, $2, 'retired-routed', 'did:key:z6MkskfbSekkwq5btte2YYYcANp4eSrRiSy9mkXKPgYwsJQj' /* z6MkLocalOnly */, 'https://local.example', 'federation:https://local.example', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'remote.example/bob', NULL, 'local', 'participant')
        """,
        conversation_id,
        retired_routed_agent_id,
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    assert routed.status_code == 410, routed.text
    assert routed.json()["detail"] == {
        "code": "participant_retired",
        "message": "retired-routed has moved; start a new mail to retired-routed in backend:remote.example",
    }
    assert remote_requests == []

    retired_local_agent_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.agents}}
            (team_id, did_key, alias, identity_scope, role, status, deleted_at, inbound_mode)
        VALUES
            ('backend:remote.example', 'did:key:z6Mkgm6L6rFHRZFt7PKhqFhJygpzWYudLHjpg88q7Kw2yqmQ' /* z6MkNoRoute */, 'retired-local', 'local', 'developer', 'deleted', NOW(), 'open')
        RETURNING agent_id
        """
    )
    blocked_conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', 'backend:remote.example', 'did:key:z6Mkgm6L6rFHRZFt7PKhqFhJygpzWYudLHjpg88q7Kw2yqmQ' /* z6MkNoRoute */)
        """,
        blocked_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, agent_id, alias, address, transport_hint, role)
        VALUES
            ($1, 'did:key:z6Mkgm6L6rFHRZFt7PKhqFhJygpzWYudLHjpg88q7Kw2yqmQ' /* z6MkNoRoute */, $2, 'retired-local', 'did:key:z6Mkgm6L6rFHRZFt7PKhqFhJygpzWYudLHjpg88q7Kw2yqmQ' /* z6MkNoRoute */, 'local-metadata-only', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'remote.example/bob', 'local', 'participant')
        """,
        blocked_conversation_id,
        retired_local_agent_id,
        bob_agent_id,
    )
    blocked_message_id = str(uuid4())
    blocked_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to": named_did_key("z6MkNoRoute"),
            "to_did": named_did_key("z6MkNoRoute"),
            "to_stable_id": named_did_key("z6MkNoRoute"),
            "type": "mail",
        }
    ).decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    assert blocked.status_code == 410, blocked.text
    assert blocked.json()["detail"] == {
        "code": "participant_retired",
        "message": "retired-local has moved; start a new mail to retired-local in backend:remote.example",
    }
    assert remote_requests == []
    registry.resolve_key.assert_not_awaited()
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT count(*) FROM {{tables.messages}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_send_message_to_external_address_without_delivery_origin_fails_closed(
    aweb_cloud_db,
):
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
            current_did_key=named_did_key("bob"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "to_address": "otherco.com/bob",
                "subject": "no delivery",
                "body": "hello",
            },
        )

    assert resp.status_code == 424
    assert "no federated delivery origin" in resp.json()["detail"]
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE subject = 'no delivery'"
    )
    assert count == 0


@pytest.mark.asyncio
async def test_send_message_to_external_address_remote_failure_does_not_create_local_message(
    aweb_cloud_db,
):
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
            current_did_key=named_did_key("bob"),
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
            "to_did": named_did_key("bob"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 502
    assert (
        resp.json()["detail"]
        == "Federated mail delivery to https://remote.example failed: HTTP 503"
    )
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE subject = 'remote failure'"
    )
    assert count == 0


@pytest.mark.asyncio
async def test_send_message_to_hosted_handle_alias_uses_canonical_address(
    aweb_cloud_db,
):
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
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:jane.aweb.ai",
        alias="c3po",
        did_key=named_did_key("c3po"),
        did_aw="did:aw:c3po",
        address="jane.aweb.ai/c3po",
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key)
    )
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="addr-c3po",
            domain="jane.aweb.ai",
            name="c3po",
            did_aw="did:aw:c3po",
            current_did_key=named_did_key("c3po"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_awaited_once_with("jane.aweb.ai", "c3po")
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'hosted handle'
        """
    )
    assert row["to_did"] == "did:aw:c3po"
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "c3po"


@pytest.mark.asyncio
async def test_send_message_continues_conversation_without_address_discovery(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("continuation must not resolve address")
    )
    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert row["to_agent_id"] is None


@pytest.mark.asyncio
async def test_send_message_to_address_with_explicit_id_skips_address_discovery(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_did": "did:aw:alice",
                "subject": "initial address thread",
                "body": "hello",
            },
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
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("address reply must use conversation")
    )
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_address": "otherco.com/bob",
                "subject": "address reply",
                "body": "hi",
            },
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
    assert row["to_agent_id"] is None
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_send_message_to_address_with_existing_conversation_id_continues_local_thread(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_did": "did:aw:alice",
                "subject": "initial explicit thread",
                "body": "hello",
            },
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
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError(
            "same conversation reply must not rediscover address"
        )
    )
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert row["to_agent_id"] is None
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_signed_address_continuation_keeps_ephemeral_participant_address(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_did": "did:aw:alice",
                "subject": "ephemeral initial",
                "body": "hello",
            },
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("local continuation must not rediscover address")
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert row["to_agent_id"] is None
    registry.resolve_address.assert_not_called()


@pytest.mark.asyncio
async def test_mail_conversation_history_requires_participant_and_includes_sent_messages(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_did": "did:aw:bob",
                "subject": "initial history",
                "body": "hello",
            },
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "reply history",
                "body": "hi",
            },
        )
    assert reply.status_code == 200, reply.text

    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")

    assert history.status_code == 200, history.text
    messages = history.json()["messages"]
    assert [item["body"] for item in messages] == ["hello", "hi"]
    assert [item["conversation_id"] for item in messages] == [
        conversation_id,
        conversation_id,
    ]
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        forbidden = await client.get(f"/v1/messages/conversations/{conversation_id}")
    assert forbidden.status_code == 404
    assert forbidden.json() == {"detail": "Not found"}


@pytest.mark.asyncio
async def test_mail_conversation_history_distinguishes_missing_and_legacy_message(
    aweb_cloud_db,
):
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
        "did:aw:alice",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        legacy = await client.get(f"/v1/messages/conversations/{legacy_message_id}")
        missing = await client.get(
            "/v1/messages/conversations/99999999-9999-4999-8999-999999999999"
        )

    assert legacy.status_code == 404
    assert "legacy mail without a conversation" in legacy.json()["detail"]
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not found"}


@pytest.mark.asyncio
async def test_send_message_continuation_rejects_non_participant_and_closed(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        leaked = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "leak",
                "body": "nope",
            },
        )
    assert leaked.status_code == 404
    assert leaked.json() == {"detail": "Not found"}

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversations}} SET status = 'closed' WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    app.dependency_overrides[get_messaging_auth] = _alice_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        closed = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "closed",
                "body": "nope",
            },
        )
    assert closed.status_code == 403
    assert "closed" in closed.json()["detail"]


@pytest.mark.asyncio
async def test_send_message_explicit_recipient_with_closed_conversation_id_rejects(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_address": "acme.com/bob",
                "subject": "initial explicit closed",
                "body": "hello",
            },
        )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversations}} SET status = 'closed' WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_send_message_explicit_recipient_with_existing_conversation_id_rejects_target_mismatch(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={
                "to_address": "acme.com/bob",
                "subject": "initial mismatch guard",
                "body": "hello",
            },
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "conversation_id" in resp.json()["detail"]


async def _signed_local_mail_app(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    _, _, bob_did_key = _make_keypair()
    await _insert_team(aweb_cloud_db.aweb_db, "backend:timestamp.example")
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:timestamp.example",
        alias="alice",
        did_key=alice_did_key,
        did_aw="did:aw:alice-timestamp",
        address="timestamp.example/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:timestamp.example",
        alias="bob",
        did_key=bob_did_key,
        did_aw="did:aw:bob-timestamp",
        address="timestamp.example/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _auth():
        return MessagingAuth(
            did_key=alice_did_key,
            did_aw="did:aw:alice-timestamp",
            address="timestamp.example/alice",
            team_id="backend:timestamp.example",
            alias="alice",
            agent_id=alice_agent_id,
        )

    app.dependency_overrides[get_messaging_auth] = _auth
    return app, alice_sk, alice_did_key


def _signed_local_mail_payload(
    alice_sk, alice_did_key, *, timestamp, subject, include_signed_payload=True
):
    message_id = str(uuid4())
    signed_payload = canonical_json_bytes(
        {
            "body": "timestamp body",
            "from": "alice",
            "from_did": alice_did_key,
            "message_id": message_id,
            "subject": subject,
            "timestamp": timestamp,
            "to": "did:aw:bob-timestamp",
            "to_did": "did:aw:bob-timestamp",
            "type": "mail",
        }
    )
    payload = {
        "to_did": "did:aw:bob-timestamp",
        "subject": subject,
        "body": "timestamp body",
        "from_did": alice_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(alice_sk, signed_payload),
    }
    if include_signed_payload:
        payload["signed_payload"] = signed_payload.decode()
    return message_id, payload


@pytest.mark.asyncio
@pytest.mark.parametrize("offset_seconds", [-360, 360])
async def test_signed_plaintext_mail_rejects_timestamp_outside_federation_window(
    aweb_cloud_db, offset_seconds
):
    app, alice_sk, alice_did_key = await _signed_local_mail_app(aweb_cloud_db)
    timestamp = (
        (
            datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(seconds=offset_seconds)
        )
        .isoformat()
        .replace("+00:00", "Z")
    )
    _, payload = _signed_local_mail_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
        subject=f"mail skew {offset_seconds}",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/messages", json=payload)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == (
        "timestamp outside accepted skew. Sign the message again with the current UTC time and retry."
    )
    assert response.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"


@pytest.mark.asyncio
async def test_signed_plaintext_mail_stores_server_time_and_preserves_attestation(
    aweb_cloud_db,
):
    app, alice_sk, alice_did_key = await _signed_local_mail_app(aweb_cloud_db)
    attested_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        minutes=4
    )
    message_id, payload = _signed_local_mail_payload(
        alice_sk,
        alice_did_key,
        timestamp=attested_at.isoformat().replace("+00:00", "Z"),
        subject="mail separate timestamps",
    )

    before = datetime.now(timezone.utc)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/messages", json=payload)
    after = datetime.now(timezone.utc)

    assert response.status_code == 200, response.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT created_at, signed_payload FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert before <= row["created_at"] <= after
    assert row["created_at"] != attested_at
    assert json.loads(row["signed_payload"])["timestamp"] == payload["timestamp"]
    assert datetime.fromisoformat(response.json()["delivered_at"]) == row[
        "created_at"
    ].replace(microsecond=0)


@pytest.mark.asyncio
async def test_signed_plaintext_mail_rejects_non_base64_signature_before_storage(
    aweb_cloud_db,
):
    app, alice_sk, alice_did_key = await _signed_local_mail_app(aweb_cloud_db)
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    message_id, payload = _signed_local_mail_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
        subject="invalid signature alphabet",
    )
    payload["signature"] = base64.b64encode(bytes(64)).rstrip(b"=").decode() + "!!!!"

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/messages", json=payload)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "signature must be valid base64"
    stored = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert stored is None


@pytest.mark.asyncio
async def test_signed_plaintext_mail_rejects_wrong_length_signature_before_storage(
    aweb_cloud_db,
):
    app, alice_sk, alice_did_key = await _signed_local_mail_app(aweb_cloud_db)
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    message_id, payload = _signed_local_mail_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
        subject="invalid signature length",
    )
    payload["signature"] = base64.b64encode(bytes(63)).rstrip(b"=").decode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/messages", json=payload)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "signature must decode to 64 bytes"
    stored = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert stored is None


@pytest.mark.asyncio
async def test_signed_plaintext_mail_requires_signed_payload(aweb_cloud_db):
    app, alice_sk, alice_did_key = await _signed_local_mail_app(aweb_cloud_db)
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    _, payload = _signed_local_mail_payload(
        alice_sk,
        alice_did_key,
        timestamp=timestamp,
        subject="mail missing attestation",
        include_signed_payload=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/messages", json=payload)

    assert response.status_code == 422, response.text
    assert (
        response.json()["detail"]
        == "signed_payload is required when signature is provided"
    )


@pytest.mark.asyncio
async def test_signed_legacy_first_mail_status_is_visible_and_allows_continuation(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post("/v1/messages", json=payload)
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "reply",
                "body": "blocked",
            },
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["verification_status"] == "verified_legacy"
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id


@pytest.mark.asyncio
async def test_signed_legacy_latest_mail_that_is_not_first_still_blocks_continuation(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "reply",
                "body": "blocked",
            },
        )

    assert reply.status_code == 403
    assert "conversation_id" in reply.json()["detail"]


@pytest.mark.asyncio
async def test_signed_conversation_id_binding_status_is_visible_and_allows_continuation(
    aweb_cloud_db,
):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post("/v1/messages", json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["conversation_id"] == conversation_id

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        history = await client.get(f"/v1/messages/conversations/{conversation_id}")
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "subject": "reply",
                "body": "allowed",
            },
        )

    assert history.status_code == 200, history.text
    assert history.json()["messages"][0]["verification_status"] == "verified"
    assert reply.status_code == 200, reply.text
    assert reply.json()["conversation_id"] == conversation_id


@pytest_asyncio.fixture
async def registered_mail_actors(shared_test_pool, monkeypatch):
    """Borrow the shared real registry; admit the query subjects natively."""
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        await register_messaging_team(env, team_id="ops:acme.com")
        actors = {}
        for alias in ("alice", "bob", "carol"):
            actors[alias] = await admit_messaging_actor(
                env, alias=alias, team_id="ops:acme.com", address=f"acme.com/{alias}"
            )
        yield env, actors


@pytest.mark.asyncio
async def test_messages_inbox_accepts_identity_auth(registered_mail_actors):
    env, actors = registered_mail_actors
    alice, bob = actors["alice"], actors["bob"]
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(from_did,to_did,from_alias,to_alias,subject,body,priority) "
        "VALUES ($1,$2,'bob','alice','hi','hello','normal')",
        bob.stable_id,
        alice.stable_id,
    )
    response = await env.client.get(
        "/v1/messages/inbox",
        headers=_signed_identity_headers(
            alice.signing_key,
            alice.did_key,
            alice.stable_id,
        ),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert len(payload["messages"]) == 1
    assert payload["messages"][0]["to_did"] == alice.stable_id


@pytest.mark.asyncio
async def test_messages_inbox_includes_sender_stable_identity_for_current_key(
    registered_mail_actors,
):
    env, actors = registered_mail_actors
    alice, bob = actors["alice"], actors["bob"]
    # Historical message authorship keeps the recorded key; current verified
    # identity metadata comes from the actually admitted sender.
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(from_did,to_did,from_alias,to_alias,subject,body,priority) "
        "VALUES ($1,$2,'alice','bob','stable sender','hello','normal')",
        alice.did_key,
        bob.stable_id,
    )
    response = await env.client.get(
        "/v1/messages/inbox",
        headers=_signed_identity_headers(
            bob.signing_key,
            bob.did_key,
            bob.stable_id,
        ),
    )
    assert response.status_code == 200, response.text
    message = response.json()["messages"][0]
    assert message["from_did"] == alice.did_key
    assert message["from_stable_id"] == alice.stable_id
    assert message["from_address"] == "acme.com/alice"
    assert message["to_did"] == bob.stable_id
    assert message["to_stable_id"] == bob.stable_id
    assert message["to_address"] == "acme.com/bob"


@pytest.mark.asyncio
async def test_messages_inbox_prefers_stored_sender_address_without_local_metadata(
    registered_mail_actors,
):
    env, actors = registered_mail_actors
    bob = actors["bob"]
    # This retained external author deliberately has no local agent metadata.
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(from_did,to_did,from_alias,from_address,to_alias,subject,body,priority) "
        "VALUES ('did:aw:gsk',$1,'gsk','otherco.com/gsk','bob','external','hello','normal')",
        bob.stable_id,
    )
    response = await env.client.get(
        "/v1/messages/inbox",
        headers=_signed_identity_headers(
            bob.signing_key,
            bob.did_key,
            bob.stable_id,
        ),
    )
    assert response.status_code == 200, response.text
    message = response.json()["messages"][0]
    assert message["from_alias"] == "gsk"
    assert message["from_address"] == "otherco.com/gsk"


@pytest.mark.asyncio
async def test_messages_inbox_filters_by_message_id(registered_mail_actors):
    env, actors = registered_mail_actors
    alice, bob, carol = (actors[name] for name in ("alice", "bob", "carol"))
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(message_id,from_did,to_did,from_alias,to_alias,subject,body,priority) VALUES "
        "('11111111-1111-1111-1111-111111111111',$1,$2,'bob','alice','first','one','normal'),"
        "('22222222-2222-2222-2222-222222222222',$3,$2,'carol','alice','second','two','normal')",
        bob.stable_id,
        alice.stable_id,
        carol.stable_id,
    )
    response = await env.client.get(
        "/v1/messages/inbox?unread_only=true&message_id=22222222-2222-2222-2222-222222222222",
        headers=_signed_identity_headers(
            alice.signing_key, alice.did_key, alice.stable_id
        ),
    )
    assert response.status_code == 200, response.text
    assert [message["message_id"] for message in response.json()["messages"]] == [
        "22222222-2222-2222-2222-222222222222",
    ]


@pytest.mark.asyncio
async def test_send_message_mutation_context_includes_from_did_aw(
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
    payload = {"to_did": bob.stable_id, "subject": "hello", "body": "hi"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, alice.stable_id, body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", headers=headers, content=body)
    assert resp.status_code == 200, resp.text
    assert captured["event_type"] == "message.sent"
    assert captured["context"]["from_did_aw"] == alice.stable_id


@pytest.mark.asyncio
async def test_messages_inbox_rejects_invalid_identity_signature(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    other_sk, _, _ = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key)
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(other_sk, alice_did_key, "did:aw:alice")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 401
    assert "Invalid DIDKey signature" in resp.text


@pytest.mark.asyncio
async def test_messages_inbox_requires_timestamp(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:alice", current_did_key=alice_did_key)
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    headers = _signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice")
    headers.pop("X-AWEB-Timestamp")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/messages/inbox", headers=headers)

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_send_message_accepts_identity_auth(registered_mail_actors):
    from types import SimpleNamespace
    from messaging_actor_support import (
        register_messaging_actors,
        set_messaging_inbound_mode,
        add_messaging_contact,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=False
    )
    bob = others["bob"]
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    await add_messaging_contact(env, bob, address=alice.address, key_owner=False)
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {"to_did": bob.stable_id, "subject": "hello", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, from_address, to_did FROM {{tables.messages}} WHERE subject = 'hello'"
    )
    assert row["from_did"] == alice.stable_id
    assert row["from_address"] == alice.address
    assert row["to_did"] == bob.stable_id


@pytest.mark.asyncio
async def test_send_message_accepts_external_to_address_without_local_agent(route_pair):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    await app.state.awid_registry_client.register_did(bob.did_key, bob.signing_key)
    assert (
        await world.source.node.db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE did_aw=$1", bob.stable_id
        )
        == 0
    )
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "subject": "external",
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob.did_key,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": bob.address,
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
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        send_resp = await client.post(
            "/v1/messages", content=body_bytes, headers=headers
        )
    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one("""
        SELECT from_did, to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'external'
        """)
    assert row["from_did"] == alice.stable_id
    assert row["to_did"] == bob.stable_id
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "bob"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        inbox_resp = await client.get(
            "/v1/messages/inbox",
            headers=_signed_identity_headers(
                bob.signing_key, bob.did_key, bob.stable_id
            ),
        )
    assert inbox_resp.status_code == 200, inbox_resp.text
    inbox = inbox_resp.json()
    assert inbox["messages"][0]["to_did"] == bob.stable_id
    assert inbox["messages"][0]["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_identity_scoped_send_by_address_allows_persistent_multi_membership(
    route_pair,
):
    from types import SimpleNamespace
    from messaging_actor_support import register_messaging_team, admit_messaging_actor

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    second_team = "dev:" + alice.address.split("/", 1)[0]
    await register_messaging_team(world.source.env, team_id=second_team)
    second = await admit_messaging_actor(
        world.source.env,
        team_id=second_team,
        alias="alice",
        existing_identity=alice,
    )
    assert second.stable_id == alice.stable_id
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "subject": "multi membership external",
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob.did_key,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": bob.address,
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
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        send_resp = await client.post(
            "/v1/messages", content=body_bytes, headers=headers
        )
    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one("""
        SELECT team_id, from_agent_id, from_alias, from_did, from_address, to_did, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'multi membership external'
        """)
    assert row["team_id"] is None
    assert row["from_agent_id"] is None
    assert row["from_alias"] == alice.address
    assert row["from_did"] == alice.stable_id
    assert row["from_address"] == alice.address
    assert row["to_did"] == bob.stable_id
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_team_auth_alias_send_resolves_active_team_with_persistent_multi_membership(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    env, actors = registered_mail_actors
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice, bob = (actors["alice"], actors["bob"])
    await register_messaging_team(env, team_id="dev:acme.com")
    other_alice = await admit_messaging_actor(
        env, team_id="dev:acme.com", alias="alice", existing_identity=alice
    )
    other_bob = await admit_messaging_actor(
        env, team_id="dev:acme.com", alias="bob", address="acme.com/dev-bob"
    )
    assert other_alice.stable_id == alice.stable_id
    assert other_bob.stable_id != bob.stable_id
    alice_ops_row = await env.db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND alias='alice'",
        alice.team_id,
    )
    assert alice_ops_row is not None
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {
        "to_alias": "bob",
        "subject": "multi membership team auth",
        "body": "hello",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice_sk, alice_did_key, alice.team_id, alice.certificate, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        send_resp = await client.post(
            "/v1/messages", content=body_bytes, headers=headers
        )
    assert send_resp.status_code == 200, send_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one("""
        SELECT team_id, from_agent_id, from_alias, from_did, from_address, to_did, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'multi membership team auth'
        """)
    assert row["team_id"] == alice.team_id
    assert row["from_agent_id"] == alice_ops_row["agent_id"]
    assert row["from_alias"] == "alice"
    assert row["from_did"] == alice.stable_id
    assert row["from_address"] == alice.address
    assert row["to_did"] == bob.stable_id
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_stable_id_transport_routes_stable_and_accepts_current_binding(
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
    bob_did_key = bob.did_key
    payload = {
        "to_did": bob_did_key,
        "to_stable_id": bob.stable_id,
        "subject": "hello stable transport",
        "body": "hi",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did FROM {{tables.messages}} WHERE subject = 'hello stable transport'"
    )
    assert row["from_did"] == alice.stable_id
    assert row["to_did"] == bob.stable_id


@pytest.mark.asyncio
async def test_send_message_to_current_did_remains_visible_after_recipient_rotation(
    aweb_cloud_db,
):
    _, _, bob_old_did_key = _make_keypair()
    _, _, bob_new_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END)
        """,
        bob_old_did_key,
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def _send_auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
            did_aw="did:aw:alice",
            address="acme.com/alice",
        )

    app.dependency_overrides[get_messaging_auth] = _send_auth_override

    payload = {"to_did": bob_old_did_key, "subject": "hello current did", "body": "hi"}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        inbox_resp = await client.get("/v1/messages/inbox")

    assert inbox_resp.status_code == 200, inbox_resp.text
    body = inbox_resp.json()
    assert [item["subject"] for item in body["messages"]] == ["hello current did"]


@pytest.mark.asyncio
async def test_send_message_rejects_unsigned_stable_id_address_binding_when_awid_misses(
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
    addressed = await admit_messaging_actor(
        env,
        alias="bob",
        team_id="ops:otherco.com",
        address="otherco.com/bob",
        signing_key=bob.signing_key,
    )
    controller = await env.registry.ensure_namespace(domain="otherco.com")
    registry = env.app.state.awid_registry_client
    certificate = json.loads(base64.b64decode(addressed.certificate))
    await registry.revoke_team_certificate(
        "otherco.com",
        "ops",
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate["certificate_id"],
    )
    await registry.delete_address("otherco.com", "bob", controller)
    assert addressed.stable_id == bob.stable_id
    payload = {
        "to_address": "otherco.com/bob",
        "to_stable_id": bob.stable_id,
        "subject": "duplicate local identity rows",
        "body": "hi",
    }
    body = json.dumps(payload).encode()
    with record_registry_requests(env) as reads:
        resp = await env.client.post(
            "/v1/messages",
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
    target_did_key: str = named_did_key("bob"),
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
async def test_receive_old_v1_federated_mail_ignores_deprecated_fields_and_delivers(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    payload = _federated_mail_payload(
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
    resolved = await app.state.awid_registry_client.resolve_address_fresh(
        *bob.address.split("/", 1)
    )
    assert (resolved.did_aw, resolved.current_did_key, resolved.delivery.origin) == (
        bob.stable_id,
        bob.did_key,
        world.target.node.origin,
    )
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
    assert row["from_did"] == alice.stable_id
    assert row["to_did"] == bob.stable_id
    assert row["from_address"] == alice.address
    assert row["to_agent_id"] == UUID(bob.agent_id)
    assert row["signature"] == payload["signature"]
    assert row["signed_payload"] == envelope["signed_payload"]
    participants = await _conversation_participants(
        aweb_cloud_db.aweb_db, envelope["conversation_id"]
    )
    sender_participant = next(
        (item for item in participants if item["did"] == alice.stable_id)
    )
    assert sender_participant["address"] == alice.address
    assert sender_participant["delivery_origin"] == world.source.node.origin
    assert (
        sender_participant["transport_hint"] == f"federation:{world.source.node.origin}"
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_first_contact_to_unknown_local_didkey_fails_closed(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice = world.source.actor
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=named_did_key("z6MkUnknownLocal"),
        target_did_aw=named_did_key("z6MkUnknownLocal"),
        target_did_key=named_did_key("z6MkUnknownLocal"),
        target_delivery_origin=world.target.node.origin,
        subject="unknown local",
        body="should fail",
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
    assert ("GET", f"/v1/did/{alice.stable_id}/key") in world.source.node.registry_calls
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.messages}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_existing_local_didkey_first_contact_fails_closed(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice = world.source.actor
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    local_did_key = world.target.node.local.did
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin=world.target.node.origin,
        subject="first contact local",
        body="must fail",
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
            "SELECT COUNT(*) FROM {{tables.messages}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_existing_local_didkey_reply_succeeds(route_pair):
    """Exercise retained local-key route history, never a current first-contact grant."""
    from types import SimpleNamespace
    from aweb.messaging.kinds import MessageKind

    world = await _registered_routing_pair(route_pair)
    bob = world.target.actor
    local = await _admit_registered_local(world.source.node)
    local_sk, local_did_key = (local.signing_key, local.did_key)
    local_agent_id = UUID(local.agent_id)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    app = world.source.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.source.node.db)
    conversation_id = str(uuid4())
    await _store_retained_local_origin(
        world, conversation_id=conversation_id, local=local, kind=MessageKind.MAIL
    )
    await _mirror_retained_local_history(
        world,
        conversation_id=conversation_id,
        local_did_key=local.did_key,
        kind=MessageKind.MAIL,
    )
    payload = _federated_mail_payload(
        sender_sk=bob_sk,
        sender_did_key=bob_did_key,
        sender_did_aw=bob.stable_id,
        sender_address=bob.address,
        sender_delivery_origin=world.target.node.origin,
        target_address=local_did_key,
        target_did_aw=local_did_key,
        target_did_key=local_did_key,
        target_delivery_origin=world.source.node.origin,
        subject="learned reply",
        body="allowed reply",
        conversation_id=conversation_id,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did, to_agent_id FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert row["from_did"] == bob.stable_id
    assert row["to_did"] == local_did_key
    assert str(row["to_agent_id"]) == str(local_agent_id)
    remote_participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        UUID(conversation_id),
        bob.stable_id,
    )
    assert remote_participant["current_did_key"] == bob_did_key
    peer_reads_before = (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    )
    remote_calls = _record_federation(world.source.node)
    reply_message_id = str(uuid4())
    reply_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    reply_signed_payload = canonical_json_bytes(
        {
            "body": "local continuation after backfill",
            "conversation_id": conversation_id,
            "from": f"{world.source.node.domain}/local",
            "from_did": local_did_key,
            "message_id": reply_message_id,
            "priority": "normal",
            "subject": "Local reply",
            "timestamp": reply_timestamp,
            "to": bob.stable_id,
            "to_did": bob.stable_id,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.source.node.origin
    ) as client:
        reply = await client.post(
            "/v1/messages",
            json={
                "conversation_id": conversation_id,
                "to_did": bob.stable_id,
                "to_stable_id": bob.stable_id,
                "subject": "Local reply",
                "body": "local continuation after backfill",
                "from_did": local_did_key,
                "message_id": reply_message_id,
                "timestamp": reply_timestamp,
                "signature": sign_message(local_sk, reply_signed_payload),
                "signed_payload": reply_signed_payload.decode(),
            },
            headers=_registered_actor_headers(
                local,
                payload={
                    "conversation_id": conversation_id,
                    "to_did": bob.stable_id,
                    "to_stable_id": bob.stable_id,
                    "subject": "Local reply",
                    "body": "local continuation after backfill",
                    "from_did": local_did_key,
                    "message_id": reply_message_id,
                    "timestamp": reply_timestamp,
                    "signature": sign_message(local_sk, reply_signed_payload),
                    "signed_payload": reply_signed_payload.decode(),
                },
            ),
        )
    assert reply.status_code == 200, reply.text
    assert len(remote_calls) == 1
    assert (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    ) == peer_reads_before
    envelope = json.loads(remote_calls[0].content)["envelope"]
    assert envelope["target_current_did_key"] == bob_did_key
    assert envelope["target_delivery_origin"] == world.target.node.origin


@pytest.mark.asyncio
async def test_send_message_federated_conversation_reply_uses_recorded_participant_not_address_rediscovery(
    aweb_cloud_db,
):
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
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError(
            "federated continuation must use stored current did:key"
        )
    )
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("federated continuation must not rediscover address")
    )
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    second_timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert (
        missing_key.json()["detail"]
        == "Remote mail recipient stored route is missing current did:key"
    )
    assert len(remote_calls) == 1


@pytest.mark.asyncio
async def test_send_message_federated_conversation_reply_requires_signed_payload(
    aweb_cloud_db,
):
    """Federated mail continuation must refuse an unsigned payload before delivery.

    Continuation skips _validate_signed_mail_payload entirely when no signature
    is present, so _require_remote_mail_signature is the only thing standing
    between an unsigned body and the remote server.
    """
    _, _, alice_did_key = _make_keypair()
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
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError(
            "federated continuation must use stored current did:key"
        )
    )
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("federated continuation must not rediscover address")
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"

    remote_calls: list[dict] = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_calls.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            500, json={"detail": "unsigned mail must never reach the wire"}
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
            },
        )

    assert resp.status_code == 422, resp.text
    assert (
        resp.json()["detail"]
        == "Federated mail delivery requires a sender-signed payload"
    )
    assert remote_calls == []
    projected_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(message_id),
    )
    assert projected_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("omitted", "expected_detail"),
    [
        ("from_did", "from_did is required for federated mail delivery"),
        (
            "message_id",
            "message_id, timestamp, and conversation_id are required for federated mail delivery",
        ),
    ],
)
async def test_send_message_federated_conversation_reply_requires_sender_attestation(
    aweb_cloud_db,
    omitted: str,
    expected_detail: str,
):
    """Each field _require_remote_mail_signature demands is refused by name.

    Continuation only. On first contact these two raises are unreachable,
    because the signed-payload block at messages.py:1517-1527 rejects a missing
    from_did or message_id before _require_remote_mail_signature is called; a
    first-contact test would name a line it never reaches. Continuation has no
    such upstream block, so these raises are the ones that decide.

    Without them the request does not fail closed cleanly - it raises an
    unhandled validation error building the federation envelope. The clean 422
    is the property a client depends on, so that is what is asserted.
    """
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
    registry.resolve_key = AsyncMock(
        side_effect=AssertionError(
            "federated continuation must use stored current did:key"
        )
    )
    registry.resolve_address = AsyncMock(
        side_effect=AssertionError("federated continuation must not rediscover address")
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)
    app.state.public_origin = "https://recipient.example"

    remote_calls: list[dict] = []

    async def _remote_handler(request: httpx.Request) -> httpx.Response:
        remote_calls.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            500, json={"detail": "incomplete mail must never reach the wire"}
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
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
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
    ).decode()
    body = {
        "conversation_id": conversation_id,
        "to_did": "did:aw:alice",
        "to_stable_id": "did:aw:alice",
        "subject": "Federated reply",
        "body": "federated continuation",
        "from_did": bob_did_key,
        "message_id": message_id,
        "timestamp": timestamp,
        "signature": sign_message(bob_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    del body[omitted]

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=body)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == expected_detail
    assert remote_calls == []


@pytest.mark.asyncio
async def test_receive_federated_mail_stored_route_rejects_wrong_target_current_key(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    conversation_id = str(
        await _registered_history(world, make_payload=_federated_mail_payload)
    )
    wrong_bob_key = named_did_key("z6MkWrongBobKey")
    address_reads_before = _registered_address_reads(world.target)
    registry_reads_before = (
        tuple(world.source.node.registry_calls),
        tuple(world.target.node.registry_calls),
    )
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=bob.stable_id,
        target_did_aw=bob.stable_id,
        target_did_key=wrong_bob_key,
        target_delivery_origin=world.target.node.origin,
        signed_to_did=bob.stable_id,
        subject="wrong key continuation",
        body="must reject before storing",
        conversation_id=conversation_id,
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
            "SELECT COUNT(*) FROM {{tables.messages}} WHERE conversation_id = $1",
            UUID(conversation_id),
        )
        == 1
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_historical_continuation_uses_stored_sender_address(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    conversation_id = str(
        await _registered_history(world, make_payload=_federated_mail_payload)
    )
    address_reads_before = _registered_address_reads(world.target)
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_address=bob.stable_id,
        target_did_aw=bob.stable_id,
        target_did_key=bob_did_key,
        target_delivery_origin=world.target.node.origin,
        signed_to_did=bob.stable_id,
        conversation_id=conversation_id,
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
    )
    signed = json.loads(payload["envelope"]["signed_payload"])
    signed["from"] = alice.stable_id
    payload["envelope"]["signed_payload"] = canonical_json_bytes(signed).decode()
    payload["signature"] = sign_message(
        alice_sk, payload["envelope"]["signed_payload"].encode()
    )
    del payload["envelope"]["sender_address"]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        response = await client.post("/v1/federation/messages", json=payload)
    assert response.status_code == 200, response.text
    stored_address = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT from_address FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert stored_address == alice.address
    target_route = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT address, delivery_origin, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        UUID(conversation_id),
        bob.stable_id,
    )
    assert dict(target_route) == {
        "address": bob.address,
        "delivery_origin": None,
        "transport_hint": "local",
    }
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET address = 'changed.example/route',
            delivery_origin = 'https://changed.example',
            transport_hint = 'changed-route'
        WHERE conversation_id = $1
        """,
        UUID(conversation_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        changed_route_replay = await client.post(
            "/v1/federation/messages", json=payload
        )
    assert changed_route_replay.status_code == 200, changed_route_replay.text
    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.conversations}} WHERE conversation_id = $1",
        UUID(conversation_id),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        replay = await client.post("/v1/federation/messages", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["message_id"] == payload["envelope"]["message_id"]
    assert _registered_address_reads(world.target) == address_reads_before


@pytest.mark.asyncio
async def test_receive_federated_mail_local_sender_omission_preserves_stored_route(
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
    conversation_id = uuid4()
    await _mirror_retained_local_history(
        world,
        conversation_id=conversation_id,
        local_did_key=local_did_key,
        kind=MessageKind.MAIL,
        local_address="alpha.example/local",
    )
    target_address_reads_before = _registered_address_reads(world.target)
    payload = _federated_mail_payload(
        sender_sk=local_sk,
        sender_did_key=local_did_key,
        sender_did_aw=local_did_key,
        sender_address="alpha.example/local",
        target_address=bob.stable_id,
        target_did_key=bob_did_key,
        conversation_id=str(conversation_id),
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
    participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT address, delivery_origin, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
        conversation_id,
        local_did_key,
    )
    assert dict(participant) == {
        "address": "alpha.example/local",
        "delivery_origin": world.source.node.origin,
        "transport_hint": f"federation:{world.source.node.origin}",
    }
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT from_address FROM {{tables.messages}} WHERE message_id = $1",
            UUID(payload["envelope"]["message_id"]),
        )
        == "alpha.example/local"
    )
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
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            """
        SELECT address FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = $2
        """,
            conversation_id,
            bob.stable_id,
        )
        == bob.address
    )
    assert _registered_address_reads(world.target) == target_address_reads_before


@pytest.mark.asyncio
async def test_receive_federated_mail_duplicate_message_id_is_idempotent(route_pair):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    payload = _federated_mail_payload(
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
        second = await client.post("/v1/federation/messages", json=payload)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["message_id"] == first.json()["message_id"]
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert count == 1
    receipts = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.message_ingress_receipts}}
        WHERE storage_kind = 'mail' AND message_id = $1
        """,
        UUID(payload["envelope"]["message_id"]),
    )
    assert receipts == 1


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_routes_ciphertext_only(route_pair):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    bob_agent_id = bob.agent_id
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice.stable_id,
        recipient_did=bob_did_key,
        recipient_stable_id=bob.stable_id,
        recipient_address=bob.address,
        sender_address=alice.address,
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": alice.stable_id,
            "sender_current_did_key": alice_did_key,
            "sender_address": alice.address,
            "sender_delivery_origin": world.source.node.origin,
            "target_address": bob.address,
            "target_did_aw": bob.stable_id,
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": world.target.node.origin,
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        missing_assertion = await client.post("/v1/federation/messages", json=payload)
    assert missing_assertion.status_code == 424, missing_assertion.text
    assert (
        missing_assertion.json()["reason"] == "recipient_encryption_assertion_missing"
    )
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_address_authority_cohorts}}"
        )
        == 1
    )
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
            UUID(message_id),
        )
        == 0
    )
    recipient_assertion = build_encryption_key_assertion(
        signing_key=bob_sk,
        identity_did=bob_did_key,
        identity_stable_id=bob.stable_id,
        encryption_public_key=b"r" * 32,
        now=datetime.fromisoformat(encrypted["created_at"].replace("Z", "+00:00")),
    )
    await _publish_registered_encryption_key(world.target, recipient_assertion)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        first = await client.post("/v1/federation/messages", json=payload)
        different_encrypted = _encrypted_mail_envelope(
            sender_sk=alice_sk,
            sender_did=alice_did_key,
            sender_stable_id=alice.stable_id,
            recipient_did=bob_did_key,
            recipient_stable_id=bob.stable_id,
            recipient_address=bob.address,
            sender_address=alice.address,
            message_id=message_id,
            conversation_id=conversation_id,
            ciphertext=b"different-opaque-ciphertext-with-tag",
        )
        different_payload = json.loads(json.dumps(payload))
        different_payload["envelope"]["timestamp"] = different_encrypted["created_at"]
        different_payload["envelope"]["encrypted_envelope"] = different_encrypted
        different_payload["signature"] = different_encrypted["signature"]
        different = await client.post("/v1/federation/messages", json=different_payload)
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agent_encryption_keys}}
            SET revoked_at = clock_timestamp()
            WHERE agent_id = $1 AND encryption_key_id = $2
            """,
            bob_agent_id,
            recipient_assertion["encryption_key_id"],
        )
        second = await client.post("/v1/federation/messages", json=payload)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert different.status_code == 409, different.text
    assert different.json()["reason"] == "federation_message_replay_conflict"
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
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
            UUID(message_id),
        )
        == 1
    )


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_rejects_assertion_expired_at_receive_time(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    bob_agent_id = bob.agent_id
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    received_at = datetime.now(timezone.utc).replace(microsecond=0)
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice.stable_id,
        recipient_did=bob_did_key,
        recipient_stable_id=bob.stable_id,
        recipient_address=bob.address,
        sender_address=alice.address,
        message_id=str(uuid4()),
        conversation_id=str(uuid4()),
        created_at=received_at - timedelta(minutes=2),
    )
    assertion = build_encryption_key_assertion(
        signing_key=bob_sk,
        identity_did=bob_did_key,
        identity_stable_id=bob.stable_id,
        encryption_public_key=b"r" * 32,
        now=received_at - timedelta(days=90, minutes=1),
    )
    await _insert_agent_encryption_assertion(
        aweb_cloud_db.aweb_db,
        agent_id=bob_agent_id,
        team_id=bob.team_id,
        assertion=assertion,
    )
    payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": alice.stable_id,
            "sender_current_did_key": alice_did_key,
            "sender_address": alice.address,
            "sender_delivery_origin": world.source.node.origin,
            "target_address": bob.address,
            "target_did_aw": bob.stable_id,
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": world.target.node.origin,
            "body": "",
            "message_id": encrypted["message_id"],
            "timestamp": encrypted["created_at"],
            "conversation_id": encrypted["conversation_id"],
            "subject": "",
            "priority": "normal",
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": encrypted,
        },
        "signature": encrypted["signature"],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        response = await client.post("/v1/federation/messages", json=payload)
    assert response.status_code == 422, response.text
    assert (
        response.json()["reason"] == "recipient_encryption_assertion_invalid_or_stale"
    )


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_rechecks_concurrent_assertion_revocation(
    route_pair, monkeypatch
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    bob_agent_id = bob.agent_id
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice.stable_id,
        recipient_did=bob_did_key,
        recipient_stable_id=bob.stable_id,
        recipient_address=bob.address,
        sender_address=alice.address,
        message_id=str(uuid4()),
        conversation_id=str(uuid4()),
    )
    assertion = build_encryption_key_assertion(
        signing_key=bob_sk,
        identity_did=bob_did_key,
        identity_stable_id=bob.stable_id,
        encryption_public_key=b"r" * 32,
    )
    await _publish_registered_encryption_key(world.target, assertion)
    original_delivery = federation_routes.deliver_federated_phase_b
    phase_b_entered = asyncio.Event()

    async def mark_phase_b_entry(*args, **kwargs):
        phase_b_entered.set()
        return await original_delivery(*args, **kwargs)

    monkeypatch.setattr(
        federation_routes, "deliver_federated_phase_b", mark_phase_b_entry
    )
    payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": alice.stable_id,
            "sender_current_did_key": alice_did_key,
            "sender_address": alice.address,
            "sender_delivery_origin": world.source.node.origin,
            "target_address": bob.address,
            "target_did_aw": bob.stable_id,
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": world.target.node.origin,
            "body": "",
            "message_id": encrypted["message_id"],
            "timestamp": encrypted["created_at"],
            "conversation_id": encrypted["conversation_id"],
            "subject": "",
            "priority": "normal",
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": encrypted,
        },
        "signature": encrypted["signature"],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        async with aweb_cloud_db.aweb_db.transaction() as revocation:
            await revocation.execute(
                """
                UPDATE {{tables.agent_encryption_keys}}
                SET revoked_at = clock_timestamp()
                WHERE agent_id = $1 AND encryption_key_id = $2
                """,
                bob_agent_id,
                assertion["encryption_key_id"],
            )
            request = asyncio.create_task(
                client.post("/v1/federation/messages", json=payload)
            )
            entry = asyncio.create_task(phase_b_entered.wait())
            try:
                done, _ = await asyncio.wait(
                    {entry, request}, timeout=10, return_when=asyncio.FIRST_COMPLETED
                )
                if request in done:
                    early = await request
                    pytest.fail(
                        f"Federated send completed before the Phase-B barrier: {early.status_code} {early.text}"
                    )
                if entry not in done:
                    request.cancel()
                    await asyncio.gather(request, return_exceptions=True)
                    pytest.fail(
                        "Federated send did not enter Phase B within 10 seconds"
                    )
            finally:
                entry.cancel()
                await asyncio.gather(entry, return_exceptions=True)
            await asyncio.sleep(0.1)
            assert not request.done(), "Phase B must wait for assertion revocation"
        response = await request
    assert response.status_code == 424, response.text
    assert response.json()["reason"] == "recipient_encryption_assertion_missing"
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
            UUID(encrypted["message_id"]),
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_keeps_success_after_postcommit_outbox_db_failure(
    route_pair, monkeypatch
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)

    async def fail_after_commit(*_args, **_kwargs):
        raise DatabaseConnectionError("outbox database unavailable")

    monkeypatch.setattr(
        federation_routes, "replay_federation_mutation_outbox", fail_after_commit
    )
    payload = _federated_mail_payload(
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
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url=world.target.node.origin,
    ) as client:
        response = await client.post("/v1/federation/messages", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["message_id"] == payload["envelope"]["message_id"]
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_mutation_outbox}} WHERE message_id = $1",
            UUID(payload["envelope"]["message_id"]),
        )
        == 1
    )


@pytest.mark.asyncio
async def test_receive_federated_encrypted_mail_rejects_plaintext_wrapper_and_timestamp_mismatch(
    route_pair,
):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice.stable_id,
        recipient_did=bob_did_key,
        recipient_stable_id=bob.stable_id,
        recipient_address=bob.address,
        sender_address=alice.address,
        message_id=message_id,
        conversation_id=conversation_id,
    )
    base_payload = {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": alice.stable_id,
            "sender_current_did_key": alice_did_key,
            "sender_address": alice.address,
            "sender_delivery_origin": world.source.node.origin,
            "target_address": bob.address,
            "target_did_aw": bob.stable_id,
            "target_current_did_key": bob_did_key,
            "target_delivery_origin": world.target.node.origin,
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
    timestamp_mismatch = (
        (created_at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    )
    variants = [
        ("body", "plaintext sentinel", "federation_envelope_invalid"),
        ("subject", "plaintext sentinel", "federation_envelope_invalid"),
        ("signed_payload", "legacy signed plaintext", "federation_envelope_invalid"),
        ("timestamp", timestamp_mismatch, "federation_timestamp_invalid"),
    ]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        for field, value, expected_reason in variants:
            payload = json.loads(json.dumps(base_payload))
            payload["envelope"][field] = value
            resp = await client.post("/v1/federation/messages", json=payload)
            assert resp.status_code == 422, (field, resp.text)
            assert resp.json()["reason"] == expected_reason
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
            UUID(message_id),
        )
        == 0
    )


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_wrong_delivery_origin(route_pair):
    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    address_reads_before = _registered_address_reads(world.target)
    payload = _federated_mail_payload(
        sender_sk=alice_sk,
        sender_did_key=alice_did_key,
        target_did_key=bob_did_key,
        sender_did_aw=alice.stable_id,
        sender_address=alice.address,
        sender_delivery_origin=world.source.node.origin,
        target_address=bob.address,
        target_did_aw=bob.stable_id,
        target_delivery_origin=world.source.node.origin,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=world.target.node.origin
    ) as client:
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 421, resp.text
    assert _registered_address_reads(world.target) == address_reads_before


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_sender_key_drift(route_pair):
    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    alice_sk, _, alice_did_key = _make_keypair()
    address_reads_before = _registered_address_reads(world.target)
    payload = _federated_mail_payload(
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
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 422, resp.text
    assert resp.json()["reason"] == "sender_current_key_mismatch"
    assert _registered_address_reads(world.target) == address_reads_before


@pytest.mark.asyncio
async def test_receive_federated_mail_rejects_target_binding_mismatch(route_pair):
    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    registry = app.state.awid_registry_client
    domain, alias = bob.address.split("/", 1)
    controller = await world.target.env.registry.ensure_namespace(domain=domain)
    certificate = json.loads(base64.b64decode(bob.certificate))
    await registry.revoke_team_certificate(
        domain,
        "members",
        team_controller_signing_key=world.target.env.team_sk,
        certificate_id=certificate["certificate_id"],
    )
    other_key, _, other_did = _make_keypair()
    other_identity = await registry.register_did(other_did, other_key)
    await registry.reassign_address(domain, alias, other_identity.did_aw, controller)
    payload = _federated_mail_payload(
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
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 422, resp.text
    assert resp.json()["reason"] == "recipient_address_did_mismatch"


@pytest.mark.asyncio
async def test_receive_federated_mail_allows_explicit_inbound_mode_open(route_pair):
    from types import SimpleNamespace

    world = await _registered_routing_pair(route_pair)
    alice, bob = (world.source.actor, world.target.actor)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = world.target.node.server.app
    aweb_cloud_db = SimpleNamespace(aweb_db=world.target.node.db)
    raw = b'{"inbound_mode":"open"}'
    configured = await world.target.node.client.patch(
        "/v1/agents/me/inbound-mode",
        content=raw,
        headers={
            "Content-Type": "application/json",
            **_signed_team_headers(
                bob.signing_key, bob.did_key, bob.team_id, bob.certificate, raw
            ),
        },
    )
    assert configured.status_code == 200, configured.text
    payload = _federated_mail_payload(
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
        resp = await client.post("/v1/federation/messages", json=payload)
    assert resp.status_code == 200, resp.text
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(payload["envelope"]["message_id"]),
    )
    assert count == 1


@pytest_asyncio.fixture
async def registered_selector_pair(shared_test_pool, monkeypatch):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        domain = f"selector-{uuid4().hex}.test"
        primary, secondary = f"ops:{domain}", f"stable:{domain}"
        for team in (primary, secondary):
            await register_messaging_team(env, team_id=team)
        sender = await admit_messaging_actor(
            env, alias="alice", team_id=primary, address=f"{domain}/alice"
        )
        recipient = await admit_messaging_actor(
            env, alias="bob", team_id=primary, address=f"{domain}/bob"
        )
        yield env, sender, recipient, secondary


async def _send_registered_selector_mail(env, sender, payload):
    body = json.dumps(payload).encode()
    return await env.client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_team_headers(
                sender.signing_key,
                sender.did_key,
                sender.team_id,
                sender.certificate,
                body,
            ),
            "Content-Type": "application/json",
        },
    )


@pytest.mark.asyncio
async def test_send_message_accepts_to_stable_id_did_binding_with_duplicate_identity_rows(
    registered_selector_pair,
):
    env, sender, recipient, secondary = registered_selector_pair
    registry = env.app.state.awid_registry_client
    current_key, _, current_did = _make_keypair()
    await registry.rotate_key(
        recipient.stable_id, current_did, recipient.signing_key, current_key
    )
    certificate_fields = _make_certificate(
        env.team_sk,
        env.team_did,
        current_did,
        team_id=secondary,
        alias="bob-current",
        identity_scope="global",
        member_did_aw=recipient.stable_id,
        member_address=recipient.address,
        certificate_id=f"selector-current-{uuid4()}",
    )
    certificate = _encode_certificate(certificate_fields)
    name, domain = secondary.split(":", 1)
    await registry.register_team_certificate(
        domain,
        name,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate_fields["certificate_id"],
        member_did_key=current_did,
        member_did_aw=recipient.stable_id,
        member_address=recipient.address,
        alias="bob-current",
        identity_scope="global",
        certificate=certificate,
    )
    connected = await env.client.post(
        "/v1/connect",
        content=b"{}",
        headers={
            **_signed_team_headers(
                current_key, current_did, secondary, certificate, b"{}"
            ),
            "Content-Type": "application/json",
        },
    )
    assert connected.status_code == 200, connected.text
    policy = b'{"inbound_mode":"open"}'
    configured = await env.client.patch(
        "/v1/agents/me/inbound-mode",
        content=policy,
        headers={
            **_signed_team_headers(
                current_key, current_did, secondary, certificate, policy
            ),
            "Content-Type": "application/json",
        },
    )
    assert configured.status_code == 200, configured.text
    old = await env.db.fetch_one(
        "SELECT did_aw_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
        UUID(recipient.agent_id),
    )
    assert old["did_aw_verified_key"] is None
    payload = {
        "to_did": recipient.did_key,
        "to_stable_id": recipient.stable_id,
        "subject": "duplicate did binding rows",
        "body": "hi",
    }
    obsolete = await _send_registered_selector_mail(env, sender, payload)
    assert obsolete.status_code == 422, obsolete.text
    assert "to_did" in obsolete.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    response = await _send_registered_selector_mail(
        env, sender, {**payload, "to_did": current_did}
    )
    assert response.status_code == 200, response.text
    row = await env.db.fetch_one(
        "SELECT to_did,to_agent_id,to_alias FROM {{tables.messages}} WHERE message_id=$1",
        UUID(response.json()["message_id"]),
    )
    assert row["to_did"] == recipient.stable_id
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "bob-current"


@pytest.mark.asyncio
async def test_send_message_accepts_to_stable_id_alias_binding_with_duplicate_identity_rows(
    registered_selector_pair,
):
    from messaging_actor_support import admit_messaging_actor

    env, sender, recipient, secondary = registered_selector_pair
    duplicate = await admit_messaging_actor(
        env,
        alias="bob-secondary",
        team_id=secondary,
        signing_key=recipient.signing_key,
    )
    assert duplicate.stable_id == recipient.stable_id
    assert duplicate.agent_id != recipient.agent_id
    payload = {
        "to_alias": "bob",
        "to_stable_id": recipient.stable_id,
        "subject": "duplicate alias binding rows",
        "body": "hi",
    }
    response = await _send_registered_selector_mail(env, sender, payload)
    assert response.status_code == 200, response.text
    row = await env.db.fetch_one(
        "SELECT to_did,to_agent_id,to_alias FROM {{tables.messages}} WHERE message_id=$1",
        UUID(response.json()["message_id"]),
    )
    assert row["to_did"] == recipient.stable_id
    assert row["to_agent_id"] is None
    assert row["to_alias"] == recipient.stable_id


@pytest.mark.asyncio
async def test_send_message_accepts_signed_local_address_binding_without_registry_lookup(
    aweb_cloud_db,
):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:test.local', 'test.local', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk', 'local', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END)
        """,
        bob_did_key,
    )

    # Direct Address Send Protocol (docs/identity-messaging-contract.md:148-163): verified
    # signed local binding needs no registry read.
    registry = AsyncMock()
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
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
        "signature": sign_message(
            named_signing_key("z6MkAliceCurrent"), signed_payload
        ),
        "signed_payload": signed_payload.decode(),
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_not_awaited()
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_agent_id, to_alias
        FROM {{tables.messages}}
        WHERE subject = 'local address binding'
        """
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "gsk"


@pytest.mark.asyncio
async def test_send_message_rejects_mismatched_local_to_address_binding_when_awid_misses(
    aweb_cloud_db,
):
    _, _, bob_did_key = _make_keypair()
    _, _, carol_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:test.local', 'test.local', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES
            ('ops:test.local', $1, 'did:aw:bob', 'test.local/gsk', 'gsk', 'local', 'developer', 'open', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END),
            ('ops:test.local', $2, 'did:aw:carol', 'test.local/carol', 'carol', 'local', 'developer', 'open', CASE WHEN NULLIF('did:aw:carol', '') IS NOT NULL THEN $2 END)
        """,
        bob_did_key,
        carol_did_key,
    )

    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=None)
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    async def _send_auth_override():
        return MessagingAuth(
            did_key=named_did_key("z6MkAliceCurrent"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 422
    assert "to_address" in resp.text
    registry.resolve_address.assert_awaited_once_with("test.local", "gsk")


@pytest.mark.asyncio
async def test_send_message_accepts_to_did_alias_binding_with_duplicate_identity_rows(
    registered_selector_pair,
):
    from messaging_actor_support import admit_messaging_actor

    env, sender, recipient, secondary = registered_selector_pair
    duplicate = await admit_messaging_actor(
        env,
        alias="bob-secondary",
        team_id=secondary,
        signing_key=recipient.signing_key,
    )
    assert duplicate.stable_id == recipient.stable_id
    assert duplicate.agent_id != recipient.agent_id
    payload = {
        "to_did": recipient.stable_id,
        "to_alias": "bob",
        "subject": "duplicate alias binding rows",
        "body": "hi",
    }
    response = await _send_registered_selector_mail(env, sender, payload)
    assert response.status_code == 200, response.text
    row = await env.db.fetch_one(
        "SELECT to_did,to_agent_id,to_alias FROM {{tables.messages}} WHERE message_id=$1",
        UUID(response.json()["message_id"]),
    )
    assert row["to_did"] == recipient.stable_id
    assert row["to_agent_id"] is None
    assert row["to_alias"] == recipient.stable_id


@pytest.mark.asyncio
async def test_send_message_accepts_to_address_alias_binding_with_duplicate_identity_rows(
    aweb_cloud_db,
):
    _, _, bob_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('stable:identity.local', 'identity.local', 'stable', 'did:key:z6MkiaaDnotCpnwVHYrGYjT1pbYPxbMcPbysqfiGpJZSZtAg' /* team-stable */),
            ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkjcDPjZawPWvfr97BGyobCr6SkdZYyrxYu8CBESNWJyZi' /* team-address */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at, did_aw_verified_key)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END),
            ('stable:identity.local', $1, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END)
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
            did_key=named_did_key("z6MkAliceCurrent"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    assert row["to_agent_id"] is None
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_accepts_to_agent_id_alias_binding_with_duplicate_identity_rows(
    aweb_cloud_db,
):
    _, _, bob_old_did_key = _make_keypair()
    _, _, bob_current_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode, created_at, did_aw_verified_key)
        VALUES
            ('ops:otherco.com', $1, 'did:aw:bob', 'otherco.com/bob', 'bob', 'global', 'developer', 'open', '2026-04-25T00:00:00Z', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $1 END),
            ('ops:otherco.com', $2, 'did:aw:bob', NULL, 'bob-stable', 'global', 'developer', 'open', '2026-04-26T00:00:00Z', CASE WHEN NULLIF('did:aw:bob', '') IS NOT NULL THEN $2 END)
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
            did_key=named_did_key("z6MkAliceCurrent"),
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
async def test_send_message_team_and_contacts_accepts_equivalent_owner_did(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import (
        register_messaging_actors,
        set_messaging_inbound_mode,
        add_messaging_contact,
    )

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    others = await register_messaging_actors(
        env, team_id="ops:otherco.com", aliases=("bob",), local=False
    )
    bob = others["bob"]
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    await add_messaging_contact(env, bob, address=alice.address, key_owner=True)
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {
        "to_did": bob.stable_id,
        "subject": "hello via legacy owner",
        "body": "hi",
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, to_did FROM {{tables.messages}} WHERE subject = 'hello via legacy owner'"
    )
    assert row["from_did"] == alice.stable_id
    assert row["to_did"] == bob.stable_id


@pytest.mark.asyncio
async def test_send_message_accepts_team_auth(registered_mail_actors):
    from messaging_actor_support import set_messaging_inbound_mode

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    await set_messaging_inbound_mode(env, bob, mode="open")
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    cert_header = alice.certificate
    payload = {"to_alias": "bob", "subject": "hello", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice_sk, alice_did_key, alice.team_id, cert_header, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_send_message_team_and_contacts_accepts_verified_same_team_non_contact_http(
    registered_mail_actors,
):
    from messaging_actor_support import set_messaging_inbound_mode

    env, actors = registered_mail_actors
    alice, bob = (actors["alice"], actors["bob"])
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    app = env.app
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    cert_header = alice.certificate
    payload = {"to_alias": "bob", "subject": "team delivery", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice_sk, alice_did_key, alice.team_id, cert_header, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_send_message_resolves_tilde_alias_cross_team(aweb_cloud_db):
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/messages",
            json={
                "to_alias": "eng~bob",
                "subject": "hello eng",
                "body": "hi",
                "from_did": alice_did_key,
                "signature": sign_message(alice_sk, signed_payload.encode()),
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
            "/v1/messages",
            json={"to_alias": target, "subject": "hello", "body": "hi"},
        )

    assert resp.status_code == expected_status, resp.text


@pytest.mark.asyncio
async def test_ephemeral_team_auth_mail_routes_by_did_key_and_inboxes_by_identity_did_key(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import register_messaging_actors

    env, actors = registered_mail_actors
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    locals = await register_messaging_actors(
        env, team_id="default:local.test", aliases=("alice", "bob"), local=True
    )
    alice, bob = (locals["alice"], locals["bob"])
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    alice_payload = {"to_alias": "bob", "subject": "local to bob", "body": "hello bob"}
    alice_body = json.dumps(alice_payload).encode()
    alice_headers = {
        **_signed_team_headers(
            alice_sk, alice_did_key, alice.team_id, alice.certificate, alice_body
        ),
        "Content-Type": "application/json",
    }
    bob_payload = {
        "to_alias": "alice",
        "subject": "local to alice",
        "body": "hello alice",
    }
    bob_body = json.dumps(bob_payload).encode()
    bob_headers = {
        **_signed_team_headers(
            bob_sk, bob_did_key, alice.team_id, bob.certificate, bob_body
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        alice_send = await client.post(
            "/v1/messages", content=alice_body, headers=alice_headers
        )
        bob_send = await client.post(
            "/v1/messages", content=bob_body, headers=bob_headers
        )
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
    messages = await aweb_cloud_db.aweb_db.fetch_all("""
        SELECT from_did, from_address, to_did, subject
        FROM {{tables.messages}}
        WHERE subject IN ('local to bob', 'local to alice')
        ORDER BY subject
        """)
    assert [row["subject"] for row in messages] == ["local to alice", "local to bob"]
    assert messages[0]["from_did"] == bob_did_key
    assert messages[0]["from_address"] == "local.test/bob"
    assert messages[0]["to_did"] == alice_did_key
    assert messages[1]["from_did"] == alice_did_key
    assert messages[1]["from_address"] == "local.test/alice"
    assert messages[1]["to_did"] == bob_did_key
    alice_body_json = alice_inbox.json()
    bob_body_json = bob_inbox.json()
    assert [item["subject"] for item in alice_body_json["messages"]] == [
        "local to alice"
    ]
    assert [item["subject"] for item in bob_body_json["messages"]] == ["local to bob"]
    assert alice_body_json["messages"][0]["to_did"] == alice_did_key
    assert alice_body_json["messages"][0]["to_stable_id"] is None
    assert bob_body_json["messages"][0]["to_did"] == bob_did_key
    assert bob_body_json["messages"][0]["to_stable_id"] is None


@pytest.mark.asyncio
async def test_identity_auth_mail_derives_sender_address_from_agent_row(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import register_messaging_actors

    env, actors = registered_mail_actors
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    locals = await register_messaging_actors(
        env, team_id="ops:gsk.aweb.ai", aliases=("gsk", "amy"), local=True
    )
    alice, bob = (locals["gsk"], locals["amy"])
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    payload = {"to_did": bob_did_key, "subject": "identity sender", "body": "hello"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "", body_bytes),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one("""
        SELECT from_did, from_alias, from_address, to_did
        FROM {{tables.messages}}
        WHERE subject = 'identity sender'
        """)
    assert row["from_did"] == alice_did_key
    assert row["from_alias"] == "gsk"
    assert row["from_address"] == "gsk.aweb.ai/gsk"
    assert row["to_did"] == bob_did_key


@pytest.mark.asyncio
async def test_send_message_team_auth_uses_global_certificate_before_reconnect(
    registered_mail_actors,
):
    from messaging_actor_support import (
        add_messaging_contact,
        admit_messaging_actor,
        issue_global_certificate_to_local_member,
        register_messaging_team,
        set_messaging_inbound_mode,
    )

    env, _ = registered_mail_actors
    team_id = "upgrade:acme.com"
    await register_messaging_team(env, team_id=team_id)
    alice = await admit_messaging_actor(env, team_id=team_id, alias="alice", local=True)
    bob = await admit_messaging_actor(
        env, team_id=team_id, alias="bob", address="acme.com/upgrade-bob"
    )
    alice = await issue_global_certificate_to_local_member(
        env, alice, address="acme.com/upgrade-alice"
    )
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    await add_messaging_contact(env, bob, address=alice.address)
    alice_row = await env.db.fetch_one(
        "SELECT agent_id, did_aw, address FROM {{tables.agents}} WHERE agent_id=$1",
        UUID(alice.agent_id),
    )
    assert (
        alice_row is not None and not alice_row["did_aw"] and not alice_row["address"]
    )
    payload = {"to_alias": "bob", "subject": "hello partial", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_team_headers(
            alice.signing_key, alice.did_key, team_id, alice.certificate, body_bytes
        ),
        "Content-Type": "application/json",
    }
    resp = await env.client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    row = await env.db.fetch_one(
        "SELECT from_agent_id, from_did FROM {{tables.messages}} WHERE subject = 'hello partial'"
    )
    assert row["from_agent_id"] == alice_row["agent_id"]
    assert row["from_did"] == alice.stable_id


@pytest.mark.asyncio
async def test_global_inbox_does_not_include_current_key_identity(
    registered_mail_actors,
):
    from messaging_actor_support import register_messaging_actors, send_messaging_mail

    env, _ = registered_mail_actors
    locals = await register_messaging_actors(
        env,
        team_id="before-enrollment:local.test",
        aliases=("sender", "reader"),
        local=True,
    )
    bob = locals["reader"]
    await send_messaging_mail(
        env,
        locals["sender"],
        payload={"to_alias": "reader", "subject": "hello", "body": "hi"},
    )
    mapping = await env.app.state.awid_registry_client.register_did(
        bob.did_key, bob.signing_key
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE did_aw=$1", mapping.did_aw
        )
        == 0
    )
    headers = _signed_identity_headers(bob.signing_key, bob.did_key, mapping.did_aw)
    resp = await env.client.get("/v1/messages/inbox", headers=headers)
    assert resp.status_code == 200, resp.text
    messages = resp.json()["messages"]
    assert messages == []
    local_headers = _signed_identity_headers(bob.signing_key, bob.did_key, "")
    local = await env.client.get("/v1/messages/inbox", headers=local_headers)
    assert local.status_code == 200, local.text
    assert [item["body"] for item in local.json()["messages"]] == ["hi"]


@pytest.mark.asyncio
async def test_messages_inbox_and_ack_accept_persistent_cert_auth(
    shared_test_pool, monkeypatch
):
    from identity_binding_support import register_global_identity
    from test_dashboard_privacy import TEAM, privacy_stack

    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        alice, bob = env.actors["alice"], env.actors["bob"]
        stable = await register_global_identity(env, alice, "example.test/alice")
        cert = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                alice.did,
                team_id=TEAM,
                alias="alice",
                identity_scope="global",
                member_did_aw=stable,
                member_address="example.test/alice",
                certificate_id="persistent-cert-inbox",
            )
        )
        raw = b"{}"
        connected = await env.client.post(
            "/v1/connect",
            content=raw,
            headers={
                **_signed_team_headers(alice.sk, alice.did, TEAM, cert, raw),
                "Content-Type": "application/json",
            },
        )
        assert connected.status_code == 200, connected.text
        raw = json.dumps(
            {"to_did": stable, "subject": "persistent cert inbox", "body": "hello"}
        ).encode()
        sent = await env.client.post(
            "/v1/messages",
            content=raw,
            headers={
                **_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate, raw),
                "Content-Type": "application/json",
            },
        )
        assert sent.status_code == 200, sent.text
        message_id = sent.json()["message_id"]
        inbox = await env.client.get(
            "/v1/messages/inbox",
            headers=_signed_team_headers(alice.sk, alice.did, TEAM, cert),
        )
        acknowledged = await env.client.post(
            f"/v1/messages/{message_id}/ack",
            headers=_signed_team_headers(alice.sk, alice.did, TEAM, cert),
        )
        assert inbox.status_code == 200, inbox.text
        assert [item["subject"] for item in inbox.json()["messages"]] == [
            "persistent cert inbox"
        ]
        assert acknowledged.status_code == 200, acknowledged.text
        row = await env.db.fetch_one(
            "SELECT read_at FROM {{tables.messages}} WHERE message_id=$1",
            UUID(message_id),
        )
        assert row["read_at"] is not None


@pytest.mark.asyncio
async def test_exact_message_read_is_participant_visible_side_effect_free_and_cert_authenticated(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import (
        messaging_actor_headers,
        register_messaging_actors,
        send_messaging_mail,
    )

    env, actors = registered_mail_actors
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice, bob, carol = (actors["alice"], actors["bob"], actors["carol"])
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_sk, bob_did_key = (bob.signing_key, bob.did_key)
    local_actors = await register_messaging_actors(
        env,
        team_id="recipient-view:local.test",
        aliases=("sender", "reader"),
        local=True,
    )
    local_reader = local_actors["reader"]
    encrypted_id = "66666666-6666-4666-8666-666666666666"
    encrypted_conversation_id = "77777777-7777-4777-8777-777777777777"
    encrypted = _encrypted_mail_envelope(
        sender_sk=alice_sk,
        sender_did=alice_did_key,
        sender_stable_id=alice.stable_id,
        recipient_did=bob_did_key,
        recipient_stable_id=bob.stable_id,
        message_id=encrypted_id,
        conversation_id=encrypted_conversation_id,
    )
    await send_messaging_mail(
        env,
        alice,
        payload={
            "to_alias": "bob",
            "subject": "global plaintext",
            "body": "hello",
            "message_id": "55555555-5555-4555-8555-555555555555",
        },
    )
    await send_messaging_mail(
        env,
        local_actors["sender"],
        payload={
            "to_alias": "reader",
            "subject": "local plaintext",
            "body": "hello",
            "message_id": "88888888-8888-4888-8888-888888888888",
        },
    )
    recipient_assertion = build_encryption_key_assertion(
        signing_key=bob_sk,
        identity_did=bob_did_key,
        identity_stable_id=bob.stable_id,
        encryption_public_key=b"r" * 32,
        now=datetime.fromisoformat(encrypted["created_at"].replace("Z", "+00:00")),
    )
    await _publish_registered_encryption_key(
        SimpleNamespace(actor=bob, node=SimpleNamespace(client=env.client)),
        recipient_assertion,
    )
    await send_messaging_mail(
        env,
        alice,
        payload={
            "to_alias": "bob",
            "subject": "",
            "body": "",
            "message_id": encrypted_id,
            "conversation_id": encrypted_conversation_id,
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": encrypted,
        },
    )
    alice_headers = messaging_actor_headers(alice)
    bob_headers = messaging_actor_headers(bob)
    carol_headers = messaging_actor_headers(carol)
    absent_id = "99999999-9999-4999-8999-999999999999"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        sender_global = await client.get(
            "/v1/messages/55555555-5555-4555-8555-555555555555", headers=alice_headers
        )
        recipient_local = await client.get(
            "/v1/messages/88888888-8888-4888-8888-888888888888", headers=bob_headers
        )
        local_key_read = await client.get(
            "/v1/messages/88888888-8888-4888-8888-888888888888",
            headers=_signed_identity_headers(
                local_reader.signing_key, local_reader.did_key, ""
            ),
        )
        sender_encrypted = await client.get(
            f"/v1/messages/{encrypted_id}", headers=alice_headers
        )
        unrelated = await client.get(
            "/v1/messages/55555555-5555-4555-8555-555555555555", headers=carol_headers
        )
        absent = await client.get(f"/v1/messages/{absent_id}", headers=carol_headers)
        sender_ack = await client.post(
            "/v1/messages/55555555-5555-4555-8555-555555555555/ack",
            headers=alice_headers,
        )
        recipient_ack = await client.post(
            "/v1/messages/55555555-5555-4555-8555-555555555555/ack", headers=bob_headers
        )
    assert sender_global.status_code == 200, sender_global.text
    assert sender_global.json()["subject"] == "global plaintext"
    assert recipient_local.status_code == 404, recipient_local.text
    assert local_key_read.status_code == 200, local_key_read.text
    assert local_key_read.json()["subject"] == "local plaintext"
    assert sender_encrypted.status_code == 200, sender_encrypted.text
    assert sender_encrypted.json()["content_mode"] == "encrypted_v2"
    assert sender_encrypted.json()["encrypted_envelope"] == encrypted
    assert unrelated.status_code == absent.status_code == 404
    assert unrelated.json() == absent.json() == {"detail": "Message not found"}
    assert sender_ack.status_code == 404
    assert recipient_ack.status_code == 200
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT message_id, read_at FROM {{tables.messages}} ORDER BY message_id"
    )
    read_at_by_id = {str(row["message_id"]): row["read_at"] for row in rows}
    assert read_at_by_id["55555555-5555-4555-8555-555555555555"] is not None
    assert read_at_by_id["88888888-8888-4888-8888-888888888888"] is None
    assert read_at_by_id[encrypted_id] is None


@pytest.mark.asyncio
async def test_messages_inbox_and_ack_accept_ephemeral_cert_auth(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import register_messaging_actors, send_messaging_mail

    env, actors = registered_mail_actors
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    locals = await register_messaging_actors(
        env, team_id="default:local.test", aliases=("alice", "bob"), local=True
    )
    alice, bob = (locals["alice"], locals["bob"])
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    cert_header = alice.certificate
    await send_messaging_mail(
        env,
        bob,
        payload={
            "to_alias": "alice",
            "subject": "ephemeral cert inbox",
            "body": "hello",
            "message_id": "44444444-4444-4444-4444-444444444444",
        },
    )
    headers = _signed_team_headers(alice_sk, alice_did_key, alice.team_id, cert_header)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        inbox_resp = await client.get("/v1/messages/inbox", headers=headers)
        ack_resp = await client.post(
            "/v1/messages/44444444-4444-4444-4444-444444444444/ack", headers=headers
        )
    assert inbox_resp.status_code == 200, inbox_resp.text
    assert [item["subject"] for item in inbox_resp.json()["messages"]] == [
        "ephemeral cert inbox"
    ]
    assert inbox_resp.json()["messages"][0]["to_did"] == alice_did_key
    assert ack_resp.status_code == 200, ack_resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT read_at FROM {{tables.messages}} WHERE message_id = '44444444-4444-4444-4444-444444444444'"
    )
    assert row["read_at"] is not None


async def _assert_registered_mail_field_refusal(
    registered_mail_actors,
    *,
    detail: str,
    signed_changes: dict[str, str] | None = None,
    request_changes: dict[str, str] | None = None,
    omit_fields: tuple[str, ...] = (),
) -> None:
    """Refuse one changed field, then accept the exact valid neighboring wire."""
    env, actors = registered_mail_actors
    alice, bob = actors["alice"], actors["bob"]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    original = {
        "type": "mail",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "timestamp": timestamp,
        "subject": "signed subject",
        "body": "signed hi",
        "priority": "normal",
        "from": alice.address,
        "from_did": alice.did_key,
        "from_stable_id": alice.stable_id,
        "to": bob.address,
        "to_did": bob.did_key,
        "to_stable_id": bob.stable_id,
    }

    def request(signed_fields: dict[str, str]) -> dict[str, str]:
        encoded = canonical_json_bytes(signed_fields)
        return {
            "to_did": bob.stable_id,
            "conversation_id": conversation_id,
            "subject": "signed subject",
            "body": "signed hi",
            "priority": "normal",
            "from_did": alice.did_key,
            "message_id": message_id,
            "timestamp": timestamp,
            "signature": sign_message(alice.signing_key, encoded),
            "signed_payload": encoded.decode(),
        }

    async def post(payload: dict[str, str]):
        raw = json.dumps(payload).encode()
        return await env.client.post(
            "/v1/messages",
            content=raw,
            headers={
                **_signed_identity_headers(
                    alice.signing_key, alice.did_key, alice.stable_id, raw
                ),
                "Content-Type": "application/json",
            },
        )

    changed = request({**original, **(signed_changes or {})})
    changed.update(request_changes or {})
    for field in omit_fields:
        changed.pop(field)
    refused = await post(changed)
    assert refused.status_code == 422, refused.text
    assert detail in refused.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.conversations}}") == 0
    )
    accepted = await post(request(original))
    assert accepted.status_code == 200, accepted.text
    stored = await env.db.fetch_one(
        "SELECT body,signed_payload FROM {{tables.messages}} WHERE message_id=$1",
        UUID(message_id),
    )
    assert stored["body"] == "signed hi"
    assert stored["signed_payload"] == canonical_json_bytes(original).decode()
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1


@pytest.mark.asyncio
async def test_send_message_requires_timestamp_when_signature_is_provided(
    registered_mail_actors,
):
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        omit_fields=("timestamp",),
        detail="message_id and timestamp are required",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_body_mismatch(
    registered_mail_actors,
):
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        request_changes={"body": "tampered hi"},
        detail="signed_payload body must match the mail body",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_priority_mismatch(
    registered_mail_actors,
):
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        request_changes={"priority": "urgent"},
        detail="signed_payload priority must match the mail message",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_recipient_mismatch(
    registered_mail_actors,
):
    _, actors = registered_mail_actors
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        signed_changes={"to": actors["carol"].stable_id},
        detail="signed_payload recipient must match the mail recipient",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_from_stable_id_mismatch(
    registered_mail_actors,
):
    _, actors = registered_mail_actors
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        signed_changes={"from_stable_id": actors["carol"].stable_id},
        detail="signed_payload from_stable_id must match the authenticated sender",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_payload_from_mismatch(
    registered_mail_actors,
):
    _, actors = registered_mail_actors
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        signed_changes={"from": actors["carol"].address},
        detail="signed_payload from must match the authenticated sender",
    )


@pytest.mark.asyncio
async def test_send_message_rejects_signed_from_did_mismatch(registered_mail_actors):
    _, actors = registered_mail_actors
    await _assert_registered_mail_field_refusal(
        registered_mail_actors,
        request_changes={"from_did": actors["bob"].did_key},
        detail="from_did must match the authenticated sender",
    )


@pytest.mark.asyncio
async def test_cross_team_same_registry_address_send_creates_bound_contact_without_lookup(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        record_registry_requests,
    )

    env, actors = registered_mail_actors
    alice, previous_bob = (actors["alice"], actors["bob"])
    await register_messaging_team(env, team_id="ops:otherco.com")
    bob = await admit_messaging_actor(
        env,
        alias="bob",
        team_id="ops:otherco.com",
        address="otherco.com/bob",
        signing_key=previous_bob.signing_key,
    )
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    bob_did_key = bob.did_key
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    controller_did = (
        await env.registry.namespace_authority("otherco.com")
    ).controller_did
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed_payload = canonical_json_bytes(
        {
            "body": "same registry",
            "conversation_id": conversation_id,
            "from": alice.address,
            "from_did": alice_did_key,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "subject": "local authority",
            "timestamp": timestamp,
            "to": bob.address,
            "to_did": bob_did_key,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    ).decode()
    payload = {
        "to_address": bob.address,
        "subject": "local authority",
        "body": "same registry",
        "conversation_id": conversation_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": alice_did_key,
        "signature": sign_message(alice_sk, signed_payload.encode()),
        "signed_payload": signed_payload,
    }
    with record_registry_requests(env) as reads:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url=str(env.client.base_url)
        ) as client:
            response = await client.post(
                "/v1/messages",
                json=payload,
                headers=_registered_actor_headers(alice, payload=payload),
            )
    assert response.status_code == 200, response.text
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT owner_did, contact_address, contact_did_aw,
               binding_controller_did, binding_accepted_at, status
        FROM {{tables.contacts}}
        WHERE owner_did = $1 AND contact_address = $2
        """,
        alice.stable_id,
        bob.address,
    )
    contact = dict(contact)
    assert contact.pop("binding_accepted_at") is not None
    assert contact == {
        "owner_did": alice.stable_id,
        "contact_address": bob.address,
        "contact_did_aw": bob.stable_id,
        "binding_controller_did": controller_did,
        "status": "active",
    }
    assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1
    assert reads.count(("GET", "/v1/namespaces/otherco.com")) == 1


@pytest.mark.asyncio
async def test_send_message_to_did_does_not_create_unresolved_identity_contact(
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
    payload = {"to_did": bob.stable_id, "subject": "allowed", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
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
async def test_send_message_to_global_address_team_and_contacts_rejects_non_contact(
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
        env, team_id="ops:otherco.com", aliases=("bob-contacts",), local=False
    )
    bob = others["bob-contacts"]
    await set_messaging_inbound_mode(env, bob, mode="team_and_contacts")
    app = env.app
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    payload = {"to_address": bob.address, "subject": "blocked", "body": "hi"}
    body_bytes = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(
            alice_sk, alice_did_key, alice.stable_id, body_bytes
        ),
        "Content-Type": "application/json",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", content=body_bytes, headers=headers)
    assert resp.status_code == 403, resp.text
    assert "exact active contacts" in resp.text
    message_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.messages}}
        WHERE to_did = $1
        """,
        bob.stable_id,
    )
    assert message_count == 0


@pytest.mark.asyncio
async def test_send_message_to_address_local_ephemeral_without_route_is_not_routable(
    registered_mail_actors,
):
    from types import SimpleNamespace
    from aweb.application_state import application_registry_client
    from test_local_policy_refusal_boundaries import admitted_local_recipient

    env, actors = registered_mail_actors
    alice = actors["alice"]
    server = SimpleNamespace(
        fixture=env, registry=application_registry_client(env.app.state)
    )
    bob = await admitted_local_recipient(server, team="eng:otherco.com", alias="bob")
    body = json.dumps(
        {"to_address": "otherco.com/bob", "subject": "blocked", "body": "hi"}
    ).encode()
    refused = await env.client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_identity_headers(
                alice.signing_key, alice.did_key, alice.stable_id, body
            ),
            "Content-Type": "application/json",
        },
    )
    assert refused.status_code == 404, refused.text
    assert refused.json()["reason"] == "local_recipient_route_missing"
    assert refused.json()["retryable"] is False
    assert (
        refused.json()["detail"]
        == "otherco.com/bob is not a registered address. A local identity has no address and is reachable only from inside its own team, by alias; a global identity is reachable by address once one is assigned. Check the address or use a teammate alias and retry."
    )
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    member_body = json.dumps(
        {"to_alias": "bob", "subject": "same-team", "body": "allowed"}
    ).encode()
    accepted = await env.client.post(
        "/v1/messages",
        content=member_body,
        headers={
            **_signed_team_headers(
                bob.sk, bob.did, bob.team, bob.certificate, member_body
            ),
            "Content-Type": "application/json",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert await env.db.fetch_value("SELECT to_did FROM {{tables.messages}}") == bob.did


@pytest.mark.asyncio
async def test_send_message_to_address_does_not_fall_back_to_local_persistent_agent_when_awid_misses(
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
    payload = {"to_address": "otherco.com/bob", "subject": "hidden", "body": "hi"}
    with record_registry_requests(env) as reads:
        resp = await env.client.post(
            "/v1/messages",
            json=payload,
            headers=_registered_identity_headers(alice, payload=payload),
        )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1


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
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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

    subject = f"same team hidden {recipient_identity_scope}"
    payload = {"to_address": "otherco.com/bob", "subject": subject, "body": "hi"}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    registry.resolve_address.assert_not_awaited()
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = $1",
        subject,
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_address_rejects_cross_team_local_persistent_when_awid_misses(
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
    payload = {"to_address": "otherco.com/bob", "subject": "hidden", "body": "hi"}
    with record_registry_requests(env) as reads:
        resp = await env.client.post(
            "/v1/messages",
            json=payload,
            headers=_registered_actor_headers(alice, payload=payload),
        )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text
    assert reads.count(("GET", "/v1/namespaces/otherco.com/addresses/bob")) == 1


@pytest.mark.asyncio
async def test_send_message_to_address_uses_local_persistent_when_registry_unconfigured(
    aweb_cloud_db,
):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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

    payload = {"to_address": "otherco.com/bob", "subject": "local direct", "body": "hi"}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/messages", json=payload)

    assert resp.status_code == 200, resp.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_did, to_alias FROM {{tables.messages}} WHERE subject = 'local direct'"
    )
    assert row["to_did"] == "did:aw:bob"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_send_message_to_stable_id_address_binding_uses_local_persistent_when_registry_unconfigured(
    aweb_cloud_db,
):
    _, _, alice_did_key = _make_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:otherco.com', 'otherco.com', 'ops', 'did:key:z6MkhhodeuD8atLozQZK9giDHHwvgioQW3LxmP8osbz3qzU8' /* team */)
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
        "to_stable_id": "did:aw:bob",
        "to_address": "otherco.com/bob",
        "subject": "local bound",
        "body": "hi",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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
    registered_mail_actors, recipient_identity_scope
):
    from types import SimpleNamespace
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
    aweb_cloud_db = SimpleNamespace(aweb_db=env.db)
    alice_sk, alice_did_key = (alice.signing_key, alice.did_key)
    with record_registry_requests(env) as registry_calls:
        message_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        signed_payload = canonical_json_bytes(
            {
                "body": "hi",
                "from": alice.stable_id,
                "from_did": alice.stable_id,
                "from_stable_id": alice.stable_id,
                "message_id": message_id,
                "priority": "normal",
                "subject": f"private bound {recipient_identity_scope}",
                "timestamp": timestamp,
                "to": bob.address,
                "to_did": bob.did_key,
                "to_stable_id": bob.stable_id,
                "type": "mail",
            }
        )
        payload = {
            "to_address": bob.address,
            "to_stable_id": bob.stable_id,
            "subject": f"private bound {recipient_identity_scope}",
            "body": "hi",
            "from_did": alice.stable_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "signature": sign_message(alice_sk, signed_payload),
            "signed_payload": signed_payload.decode(),
        }
        body_bytes = json.dumps(payload).encode()
        headers = {
            **_signed_identity_headers(
                alice_sk, alice_did_key, alice.stable_id, body_bytes
            ),
            "Content-Type": "application/json",
        }
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/messages", content=body_bytes, headers=headers
            )
        assert resp.status_code == 200, resp.text
        row = await aweb_cloud_db.aweb_db.fetch_one(
            """
        SELECT to_did, to_alias
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
            UUID(message_id),
        )
        assert row["to_did"] == bob.stable_id
        assert row["to_alias"] == "bob"
        assert any(
            (
                method == "GET"
                and path
                == "/v1/namespaces/" + bob.address.replace("/", "/addresses/", 1)
                for method, path in registry_calls
            )
        )


@pytest.mark.asyncio
async def test_send_message_to_private_address_rejects_unverified_client_recipient_binding(
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
    payload = {
        "to_address": "otherco.com/bob",
        "subject": "private spoof",
        "body": "hi",
    }
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed_payload = canonical_json_bytes(
        {
            "body": "hi",
            "from": alice.stable_id,
            "from_did": alice.stable_id,
            "from_stable_id": alice.stable_id,
            "message_id": message_id,
            "priority": "normal",
            "subject": "private spoof",
            "timestamp": timestamp,
            "to": "otherco.com/bob",
            "to_did": bob.did_key,
            "to_stable_id": bob.stable_id,
            "type": "mail",
        }
    )
    payload.update(
        to_stable_id=bob.stable_id,
        from_did=alice.stable_id,
        message_id=message_id,
        timestamp=timestamp,
        signature="not-a-valid-signature",
        signed_payload=signed_payload.decode(),
    )
    resp = await env.client.post(
        "/v1/messages",
        json=payload,
        headers=_registered_identity_headers(alice, payload=payload),
    )
    assert resp.status_code == 404, resp.text
    assert "Recipient address not found" in resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry_seconds", [-1, 0, 1, None])
async def test_recipient_mail_starts_new_conversation_regardless_of_pair_expiry(
    aweb_cloud_db, monkeypatch, expiry_seconds
):
    from aweb.messaging import conversations

    now = datetime.now(timezone.utc)
    monkeypatch.setattr(conversations, "_now_utc", lambda: now)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    _, _, alice_key = _make_keypair()
    _, _, bob_key = _make_keypair()
    alice_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_key,
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=bob_key,
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())

    async def auth():
        return MessagingAuth(
            did_key=alice_key,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            team_id="backend:acme.com",
            alias="alice",
            agent_id=alice_id,
        )

    app.dependency_overrides[get_messaging_auth] = auth
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/messages",
            json={"to_alias": "bob", "subject": "before expiry", "body": "hello"},
        )
        assert first.status_code == 200, first.text
        old_id = first.json()["conversation_id"]
        expiry = (
            None if expiry_seconds is None else now + timedelta(seconds=expiry_seconds)
        )
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.conversations}} SET expires_at = $2 WHERE conversation_id = $1",
            UUID(old_id),
            expiry,
        )
        assert (
            await aweb_cloud_db.aweb_db.fetch_value(
                "SELECT status FROM {{tables.conversations}} WHERE conversation_id = $1",
                UUID(old_id),
            )
            == "active"
        )
        # Pair status and expiry never select a recipient-only send's thread.
        sent = await client.post(
            "/v1/messages",
            json={"to_alias": "bob", "subject": "after expiry", "body": "hello again"},
        )
        assert sent.status_code == 200, sent.text
        new_id = sent.json()["conversation_id"]
        assert new_id != old_id
        stored = await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT conversation_id, to_did FROM {{tables.messages}} WHERE message_id = $1",
            UUID(sent.json()["message_id"]),
        )
        assert str(stored["conversation_id"]) == new_id
        assert stored["to_did"] == "did:aw:bob"
