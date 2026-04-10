from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import KeyResolution
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER
from aweb.routes.contacts import router as contacts_router


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
    return app


@pytest.mark.asyncio
async def test_contacts_routes_accept_equivalent_identity_owner_did(aweb_cloud_db):
    bob_sk, _, bob_did_key = _make_keypair()
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=bob_did_key))
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
