from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.external_authority import OriginContext
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from awid.registry import Address, AddressDelivery, IDTreeEnrollment, KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.api import create_app
from aweb.federation.activation import FederationAuthorityActivation
from aweb.federation.authority import FederationAuthorityCore
from aweb.federation.authority_state import AuthorityRepository
from aweb.federation.authority_work import AuthorityWorkRepository, AuthorityWorkResult
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER
from aweb.routes.contacts import router as contacts_router
from federation_activation_support import TestFederationAuthority
from test_federation_preactivation_harness import (
    _LoopbackHosts,
    _RecordedDNS,
    _TLSRegistry,
    _identity_registry_responses,
)
from test_messages_http import _encode_certificate, _make_certificate


class _ContactRegistry(_TLSRegistry):
    async def _handle(self, reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        self.requests.append(request)
        path = request.split(b" ", 2)[1].decode()
        status = b"200 OK" if path in self.responses else b"404 Not Found"
        body = json.dumps(self.responses.get(path, {"detail": "target.not_found"})).encode()
        writer.write(
            b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()


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
    app.include_router(contacts_router)

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
    app.state.federation_authority = TestFederationAuthority(aweb_db, registry)
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["namespace", "address", "key", "log"])
async def test_contact_add_unregistered_cross_namespace_target(aweb_cloud_db, missing):
    owner_sk, _, owner_key = _make_keypair()
    registry = AsyncMock()
    team_sk, _, team_key = _make_keypair()
    registry.get_team_public_key.return_value = team_key
    registry.get_team_revocations.return_value = set()
    registry.list_team_certificates.return_value = [{"certificate_id": "cert-001"}]
    db = aweb_cloud_db.aweb_db
    team_id = "aweb:jro.aweb.ai"
    alias = "oats-operator-portfolio-ops"
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'jro.aweb.ai', 'aweb', $2)",
        team_id, team_key,
    )
    await db.execute(
        "INSERT INTO {{tables.agents}} (team_id, did_key, alias, identity_scope) VALUES ($1, $2, $3, 'local')",
        team_id, owner_key, alias,
    )
    certificate = _make_certificate(
        team_sk, team_key, owner_key, team_id=team_id, alias=alias, identity_scope="local",
    )
    app = create_app(public_origin="https://jro.aweb.ai")
    app.state.db = SimpleNamespace(get_manager=lambda name="aweb": db)
    app.state.redis = None
    app.state.rate_limiter = None
    app.state.awid_registry_client = registry
    target = "juan.aweb.ai/aweb-expert-secrets-root"
    mapping, responses = _identity_registry_responses(
        "juan.aweb.ai", "aweb-expert-secrets-root", "https://target.test"
    )
    controller_key = mapping["initial_did_key"]
    missing_path = next(
        path for path in responses
        if (missing == "namespace" and path == "/v1/namespaces/juan.aweb.ai")
        or (missing == "address" and "/addresses/" in path)
        or (missing in {"key", "log"} and path.endswith("/" + missing))
    )
    del responses[missing_path]
    if missing == "log":
        key_row = next(value for path, value in responses.items() if path.endswith("/key"))
        key_row["status"] = "OK_DEGRADED"
    async with _ContactRegistry("registry.test", responses) as external:
        dns = _RecordedDNS("juan.aweb.ai", controller_key, external.origin)
        resolver = StrictExternalRegistry(
            txt_resolver=dns, host_resolver=_LoopbackHosts(),
            origin_context=OriginContext(
                app_env="development", federation_test_enabled=True,
                listener_origin="https://jro.test",
            ),
            ssl_context=external.client_context,
        )
        app.state.federation_authority = FederationAuthorityActivation(
            core=FederationAuthorityCore(AuthorityRepository(db)),
            work=AuthorityWorkRepository(db), resolver=resolver, txt_resolver=dns,
        )
        body = json.dumps({"contact_address": target, "label": "ho6-secrets-root"}).encode()
        timestamp = datetime.now(timezone.utc).isoformat()
        signed_payload = canonical_json_bytes({
            "v": 2, "aud": "https://jro.aweb.ai", "method": "POST", "path": "/v1/contacts",
            "team_id": team_id, "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        })
        headers = {
            "Authorization": f"DIDKey {owner_key} {sign_message(owner_sk, signed_payload)}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed_payload).rstrip(b"=").decode(),
            "X-AWID-Team-Certificate": _encode_certificate(certificate),
            "Content-Type": "application/json",
        }
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="https://jro.aweb.ai") as client:
                response = await client.post("/v1/contacts", content=body, headers=headers)
        finally:
            await resolver.aclose()
        assert any(missing_path.encode() + b" " in request for request in external.requests), response.text
    assert response.status_code == (503 if missing == "log" else 404), response.text
    expected_reason = (
        "sender_identity_unverifiable" if missing == "log" else "recipient_identity_not_found"
    )
    assert response.json()["reason"] == expected_reason
    assert response.json()["retryable"] is (missing == "log")
    assert await db.fetch_val("SELECT COUNT(*) FROM {{tables.contacts}}") == 0


@pytest.mark.asyncio
async def test_contacts_routes_accept_equivalent_identity_owner_did(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key_fresh = AsyncMock(return_value=KeyResolution(
        did_aw="did:aw:bob", current_did_key=bob_did_key, id_tree=IDTreeEnrollment(False, None),
    ))
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    contact_id = await aweb_cloud_db.aweb_db.fetch_val(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, 'acme.com/alice', 'Alice')
        RETURNING contact_id
        """,
        bob_did_key,
    )

    headers = _signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        list_resp = await client.get("/v1/contacts", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        body = list_resp.json()
        assert [c["contact_address"] for c in body["contacts"]] == ["acme.com/alice"]

        delete_resp = await client.delete(f"/v1/contacts/{contact_id}", headers=headers)
        assert delete_resp.status_code == 200, delete_resp.text

    remaining = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.contacts}} WHERE owner_did = $1",
        bob_did_key,
    )
    assert remaining == 0


@pytest.mark.asyncio
async def test_contacts_route_normalizes_hosted_handle_address(aweb_cloud_db):
    alice_sk, _, alice_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key_fresh = AsyncMock(return_value=KeyResolution(
        did_aw="did:aw:alice", current_did_key=alice_did_key, id_tree=IDTreeEnrollment(False, None),
    ))
    registry.list_did_addresses = AsyncMock(return_value=[])
    registry.resolve_address = AsyncMock(
        return_value=Address(
            address_id="contact-address",
            domain="jane.aweb.ai",
            name="c3po",
            did_aw="did:aw:c3po",
            current_did_key="did:key:z6Mkc3po",
            reachability="public",
            created_at=datetime.now(timezone.utc).isoformat(),
            delivery=AddressDelivery(origin="https://aweb.jane.example"),
        )
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    payload = {"contact_address": "@jane/c3po", "label": "C-3PO"}
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(alice_sk, alice_did_key, "did:aw:alice", body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/contacts", content=body, headers=headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["contact_address"] == "jane.aweb.ai/c3po"
    stored = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT contact_address FROM {{tables.contacts}} WHERE owner_did = 'did:aw:alice'"
    )
    assert stored == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_contact_reassignment_requires_signed_explicit_acceptance(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    controller_sk, _, controller_did = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key_fresh = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key, id_tree=IDTreeEnrollment(enrolled=False, domain=None))
    )
    registry.list_did_addresses = AsyncMock(return_value=[])
    app = _build_test_app(aweb_cloud_db.aweb_db, registry)

    class _Authority:
        async def resolve_contact(self, address: str, *, source_ip: str):
            del source_ip
            return SimpleNamespace(
                canonical_address=address,
                did_aw="did:aw:alice-reassigned",
                current_did_key="did:key:z6Mkalicecurrent",
                controller_did=controller_did,
                delivery_origin="https://aweb.alpha.example",
            )

    app.state.federation_authority = _Authority()
    contact_id = await aweb_cloud_db.aweb_db.fetch_val(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:bob', 'alpha.example/alice', 'did:aw:alice-old',
            $1, clock_timestamp(), 'Alice'
        ) RETURNING contact_id
        """,
        controller_did,
    )
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    announcement = canonical_json_bytes(
        {
            "address": "alpha.example/alice",
            "controller_did": controller_did,
            "new_did": "did:aw:alice-reassigned",
            "old_did": "did:aw:alice-old",
            "timestamp": timestamp,
        }
    )
    payload = {
        "expected_old_did_aw": "did:aw:alice-old",
        "address": "alpha.example/alice",
        "new_did_aw": "did:aw:alice-reassigned",
        "controller_did": controller_did,
        "timestamp": timestamp,
        "signature": sign_message(controller_sk, announcement),
        "accept_reassignment": True,
    }
    body = json.dumps(payload).encode()
    headers = {
        **_signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob", body),
        "Content-Type": "application/json",
    }

    rejected_payload = payload | {"accept_reassignment": False}
    rejected_body = json.dumps(rejected_payload).encode()
    rejected_headers = {
        **_signed_identity_headers(bob_sk, bob_did_key, "did:aw:bob", rejected_body),
        "Content-Type": "application/json",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        with pytest.raises(FederationAuthorityError) as rejected:
            await client.post(
                f"/v1/contacts/{contact_id}/bind",
                content=rejected_body,
                headers=rejected_headers,
            )
        response = await client.post(
            f"/v1/contacts/{contact_id}/bind",
            content=body,
            headers=headers,
        )

    assert rejected.value.reason == "contact_identity_binding_required"
    assert response.status_code == 200, response.text
    assert response.json()["contact_did_aw"] == "did:aw:alice-reassigned"


@pytest.mark.asyncio
@pytest.mark.parametrize("published_reason", ["sender_identity_not_found", "recipient_identity_not_found"])
@pytest.mark.parametrize("contact", [False, True])
async def test_shared_not_found_result_uses_current_lookup_role(published_reason, contact):
    # Sender authorization and contact resolution share the same singleflight key.
    activation = FederationAuthorityActivation(
        core=None, work=None, resolver=None, txt_resolver=None
    )
    result = AuthorityWorkResult(
        scope_key="discovery:juan.aweb.ai/missing", fence=1, status="failed",
        evidence={"reason": published_reason}, expires_at=datetime.now(timezone.utc),
    )
    with pytest.raises(FederationAuthorityError) as raised:
        if contact:
            await activation._contact_from_result("juan.aweb.ai/missing", result)
        else:
            await activation._authorize_from_result(None, result)
    expected_reason = "recipient_identity_not_found" if contact else "sender_identity_not_found"
    assert raised.value.reason == expected_reason
