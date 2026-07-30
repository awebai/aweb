"""Probe: does POST /v1/agents/heartbeat make the workspace roster show 'active'?"""

from __future__ import annotations

import base64
import hashlib
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
from aweb.coordination.routes.workspaces import router as workspaces_router


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return bytes(sk), pk, did_from_public_key(pk)


def _cert(team_sk, team_did_key, member_did_key, *, team_id, alias):
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


def _headers(agent_sk, agent_did_key, team_id, body=b""):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"DIDKey {agent_did_key} {sign_message(agent_sk, payload)}",
        "X-AWEB-Timestamp": timestamp,
    }


class _Pipe:
    def __init__(self, store):
        self.store = store
        self.ops = []

    def hset(self, key, mapping=None):
        self.ops.append(("hset", key, mapping))
        return self

    def hgetall(self, key):
        self.ops.append(("hgetall", key, None))
        return self

    def expire(self, key, ttl):
        self.ops.append(("noop", key, None))
        return self

    def persist(self, key):
        self.ops.append(("noop", key, None))
        return self

    def sadd(self, key, member):
        self.ops.append(("sadd", key, member))
        return self

    def set(self, key, value, ex=None):
        self.ops.append(("set", key, value))
        return self

    async def execute(self):
        out = []
        for op, key, arg in self.ops:
            if op == "hset":
                self.store.hashes.setdefault(key, {}).update(arg or {})
                out.append(len(arg or {}))
            elif op == "hgetall":
                out.append(dict(self.store.hashes.get(key, {})))
            elif op == "sadd":
                self.store.sets.setdefault(key, set()).add(arg)
                out.append(1)
            elif op == "set":
                self.store.strings[key] = arg
                out.append(True)
            else:
                out.append(True)
        return out


class _FakeRedis:
    def __init__(self):
        self.hashes = {}
        self.sets = {}
        self.strings = {}

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def smembers(self, key):
        return set(self.sets.get(key, set()))

    async def get(self, key):
        return self.strings.get(key)

    async def exists(self, key):
        return int(key in self.hashes)


@pytest.mark.asyncio
async def test_probe_presence_key(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_id = "backend:acme.com"

    app = FastAPI()
    app.include_router(agents_router)
    app.include_router(workspaces_router)

    class _Infra:
        def get_manager(self, name="aweb"):
            return aweb_db

    @app.middleware("http")
    async def cache_body(request, call_next):
        body = b"" if request.method in {"GET", "HEAD"} else await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        return await call_next(request)

    redis = _FakeRedis()
    app.state.db = _Infra()
    app.state.redis = redis
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        hb = await client.post(
            "/v1/agents/heartbeat",
            headers={
                **_headers(agent_sk, agent_did_key, team_id),
                "X-AWID-Team-Certificate": _cert(
                    team_sk, team_did_key, agent_did_key, team_id=team_id, alias="probe"
                ),
            },
        )
        assert hb.status_code == 200, hb.text
        roster = await client.get(
            "/v1/workspaces?include_presence=true",
            headers={
                **_headers(agent_sk, agent_did_key, team_id),
                "X-AWID-Team-Certificate": _cert(
                    team_sk, team_did_key, agent_did_key, team_id=team_id, alias="probe"
                ),
            },
        )
        assert roster.status_code == 200, roster.text
        agents_list = await client.get(
            "/v1/agents",
            headers={
                **_headers(agent_sk, agent_did_key, team_id),
                "X-AWID-Team-Certificate": _cert(
                    team_sk, team_did_key, agent_did_key, team_id=team_id, alias="probe"
                ),
            },
        )
        assert agents_list.status_code == 200, agents_list.text

    print("AGENT_ID       ", agent_id)
    print("WORKSPACE_ID   ", workspace_id)
    print("PRESENCE KEYS  ", sorted(redis.hashes))
    print("ROSTER STATUS  ", [(w["alias"], w["status"]) for w in roster.json()["workspaces"]])
    print("AGENTS STATUS  ", [(a["alias"], a["status"], a["online"]) for a in agents_list.json()["agents"]])
