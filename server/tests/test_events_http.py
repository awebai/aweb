"""HTTP-level regression tests for GET /v1/events/stream."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.routes.events import router as events_router


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
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "bob"),
        "lifetime": kwargs.get("lifetime", "persistent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    cert["signature"] = sign_message(team_sk, payload)
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_request(agent_sk, agent_did_key, team_id, body_bytes=b""):
    import hashlib

    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team_id": team_id,
        "timestamp": timestamp,
    })
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, team_did_key):
    app = FastAPI()
    app.include_router(events_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    import hashlib as _hashlib
    from unittest.mock import AsyncMock

    @app.middleware("http")
    async def cache_body(request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            request.state.cached_body = b""
            request.state.body_sha256 = _hashlib.sha256(b"").hexdigest()
            return await call_next(request)

        original_receive = request._receive
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = _hashlib.sha256(body).hexdigest()
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

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry
    return app


@pytest.mark.asyncio
async def test_events_stream_includes_existing_unread_mail(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    alice_sk, _, alice_did_key = _make_keypair()
    bob_sk, _, bob_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        bob_did_key,
        team_id="backend:acme.com",
        alias="bob",
        lifetime="persistent",
    )
    cert_header = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        team_did_key,
    )

    alice = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'alice', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        alice_did_key,
    )
    bob = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'bob', 'persistent', 'developer')
        RETURNING agent_id
        """,
        "backend:acme.com",
        bob_did_key,
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (team_id, from_agent_id, to_agent_id, from_alias, to_alias, subject, body)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        "backend:acme.com",
        alice["agent_id"],
        bob["agent_id"],
        "alice",
        "bob",
        "",
        "hello from alice",
    )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    headers = _signed_request(bob_sk, bob_did_key, "backend:acme.com")
    headers["X-AWID-Team-Certificate"] = cert_header

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/events/stream", params={"deadline": deadline}, headers=headers)

    assert resp.status_code == 200
    assert "event: connected" in resp.text
    assert '"team_id": "backend:acme.com"' in resp.text
    assert "event: actionable_mail" in resp.text
    assert '"from_alias": "alice"' in resp.text
