"""HTTP-level tests for POST /v1/agents/suggest-alias-prefix."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.routes.agents import router as agents_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(team_sk, team_did_key, member_did_key, **kwargs):
    cert = {
        "version": 1,
        "certificate_id": kwargs.get("certificate_id", "cert-001"),
        "team": kwargs.get("team_address", "acme.com/backend"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "ephemeral"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    cert["signature"] = sign_message(team_sk, payload)
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_request(agent_sk, agent_did_key, team_address, body_bytes=b""):
    import hashlib

    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team": team_address,
        "timestamp": timestamp,
    })
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, team_did_key):
    app = FastAPI()
    app.include_router(agents_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    import hashlib as _hashlib

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
    app.state.rate_limiter = None

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    return app


async def _insert_team(aweb_db, team_address: str, team_did_key: str) -> None:
    namespace, team_name = team_address.split("/", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        namespace,
        team_name,
        team_did_key,
    )


@pytest.mark.asyncio
async def test_suggest_alias_prefix_returns_next_available_name(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_address="acme.com/backend",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "acme.com/backend", team_did_key)

    alice_agent_id = uuid4()
    bob_agent_id = uuid4()
    alice01_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, status)
        VALUES
            ($1, $2, $3, $4, 'ephemeral', 'active'),
            ($5, $2, $6, 'bob', 'ephemeral', 'active'),
            ($7, $2, $8, 'alice-01', 'ephemeral', 'active')
        """,
        alice_agent_id,
        "acme.com/backend",
        agent_did_key,
        "alice",
        bob_agent_id,
        "did:key:z6Mkbob",
        alice01_agent_id,
        "did:key:z6Mkalice01",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_address, agent_id, alias, workspace_type)
        VALUES
            ($1, $2, $3, 'alice', 'agent'),
            ($4, $2, $5, 'bob', 'agent'),
            ($6, $2, $7, 'alice-01', 'agent')
        """,
        uuid4(),
        "acme.com/backend",
        alice_agent_id,
        uuid4(),
        bob_agent_id,
        uuid4(),
        alice01_agent_id,
    )

    body_bytes = b"{}"
    headers = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_address": "acme.com/backend",
        "name_prefix": "charlie",
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_uses_agent_aliases_without_workspace_rows(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_address="acme.com/backend",
        alias="alice",
    )
    cert_header = _encode_certificate(cert)
    await _insert_team(aweb_cloud_db.aweb_db, "acme.com/backend", team_did_key)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, 'ephemeral', 'active')
        """,
        uuid4(),
        "acme.com/backend",
        agent_did_key,
        "alice",
    )

    body_bytes = b"{}"
    headers = _signed_request(agent_sk, agent_did_key, "acme.com/backend", body_bytes)
    headers["X-AWID-Team-Certificate"] = cert_header

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/agents/suggest-alias-prefix",
            content=body_bytes,
            headers={**headers, "Content-Type": "application/json"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "team_address": "acme.com/backend",
        "name_prefix": "bob",
    }
