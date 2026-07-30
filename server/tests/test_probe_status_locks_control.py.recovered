"""Probe: does GET /v1/status report reservations held by the workspace's agent?"""

from __future__ import annotations

import base64
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
from awid.signing import canonical_json_bytes, sign_message
from aweb.routes.status import router as status_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return bytes(sk), pk, did_from_public_key(pk)


def _make_certificate(team_sk, team_did_key, member_did_key, *, team_id, alias):
    cert = {
        "version": 1,
        "certificate_id": "cert-probe",
        "team_id": team_id,
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": alias,
        "identity_scope": "local",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_headers(agent_sk, agent_did_key, team_id):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"DIDKey {agent_did_key} {sign_message(agent_sk, payload)}",
        "X-AWEB-Timestamp": timestamp,
    }


class _FakeRedis:
    async def smembers(self, key):
        return set()

    async def hgetall(self, key):
        return {}

    def pipeline(self, transaction=True):
        return self

    def hgetall_pipe(self, key):
        return self

    async def execute(self):
        return []


@pytest.mark.asyncio
async def test_probe_status_locks_control(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_id = "backend:acme.com"

    app = FastAPI()
    app.include_router(status_router)

    class _Infra:
        def get_manager(self, name="aweb"):
            return aweb_db

    @app.middleware("http")
    async def cache_body(request, call_next):
        request.state.cached_body = b""
        request.state.body_sha256 = hashlib.sha256(b"").hexdigest()
        return await call_next(request)

    app.state.db = _Infra()
    app.state.redis = _FakeRedis()
    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    await aweb_db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1,$2,$3,$4)",
        team_id,
        "acme.com",
        "backend",
        team_did_key,
    )
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1,$2,$3,'probe','local','active')
        """,
        agent_id,
        team_id,
        agent_did_key,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias, last_seen_at, updated_at)
        VALUES ($1,$2,$3,'probe',NOW(),NOW())
        """,
        workspace_id,
        team_id,
        agent_id,
    )
    now = datetime.now(timezone.utc)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.reservations}}
            (team_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json)
        VALUES ($1,$2,$3,'probe',$4,$5,'{}'::jsonb)
        """,
        team_id,
        "server/src/aweb/routes/status.py",
        workspace_id,
        now,
        now + timedelta(hours=1),
    )

    headers = _signed_headers(agent_sk, agent_did_key, team_id)
    headers["X-AWID-Team-Certificate"] = _make_certificate(
        team_sk, team_did_key, agent_did_key, team_id=team_id, alias="probe"
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/v1/status", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    print("AGENT_ID     ", agent_id)
    print("WORKSPACE_ID ", workspace_id)
    print("LOCKS        ", json.dumps(body["locks"]))
    print("AGENT LOCKS  ", json.dumps([a["reservations"] for a in body["agents"]]))
    reservations_rows = await aweb_db.fetch_all(
        "SELECT resource_key, holder_agent_id FROM {{tables.reservations}} WHERE team_id = $1",
        team_id,
    )
    print("DB ROWS      ", [dict(r) for r in reservations_rows])
    assert body["locks"], "status reported no locks while a live reservation exists"
