"""Workspace roster, heartbeat and patch routing unit cases.

Destructive cleanup is exercised by test_workspace_delete_real_http.py.
"""

from __future__ import annotations

from team_facts_fixtures import legacy_registry

import base64
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
from aweb.coordination.routes.workspaces import router as workspaces_router


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
        "identity_scope": kwargs.get("identity_scope", "local"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _signed_request(agent_sk, agent_did_key, team_id, body_bytes=b""):
    import hashlib

    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    payload_bytes = canonical_json_bytes(
        {
            "body_sha256": body_sha256,
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )
    sig = sign_message(agent_sk, payload_bytes)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        "X-AWEB-Timestamp": timestamp,
    }


def _build_test_app(aweb_db, team_did_key, redis=None):
    app = FastAPI()
    app.include_router(workspaces_router)

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
    app.state.redis = redis

    registry = AsyncMock()
    registry.get_team_public_key = AsyncMock(return_value=team_did_key)
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = legacy_registry(registry)
    return app


class _FakeRedisPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.actions = []

    def hgetall(self, key):
        self.actions.append(("hgetall", key))
        return self

    def exists(self, key):
        self.actions.append(("exists", key))
        return self

    def srem(self, key, member):
        self.actions.append(("srem", key, member))
        return self

    async def execute(self):
        results = []
        for action, key, *_ in self.actions:
            if action == "hgetall":
                results.append(self.redis.presence.get(key, {}))
            elif action == "exists":
                results.append(int(key in self.redis.presence))
            else:
                results.append(1)
        return results


class _FakeRedis:
    def __init__(self):
        self.presence = {}

    async def exists(self, key):
        return int(key in self.presence)

    async def smembers(self, key):
        if key.startswith("idx:team_workspaces:"):
            return {
                presence["workspace_id"]
                for presence in self.presence.values()
                if presence.get("workspace_id")
            }
        return set()

    async def get(self, key):
        return None

    def pipeline(self, transaction=True):
        return _FakeRedisPipeline(self)


@pytest.mark.asyncio
async def test_team_roster_prioritizes_live_presence_and_reports_truncation(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_id = "backend:acme.com"
    now = datetime.now(timezone.utc)

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id=team_id,
        alias="live-0",
        identity_scope="local",
    )
    headers = _signed_request(agent_sk, agent_did_key, team_id)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "acme.com",
        "backend",
        team_did_key,
    )

    redis = _FakeRedis()
    active_aliases = {f"live-{index}" for index in range(5)}
    self_workspace_id = None
    for index, alias in enumerate(sorted(active_aliases)):
        workspace_id = uuid4()
        agent_id = uuid4()
        did_key = agent_did_key if alias == "live-0" else _make_keypair()[2]
        if alias == "live-0":
            self_workspace_id = workspace_id
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, team_id, did_key, alias, identity_scope, status)
            VALUES ($1, $2, $3, $4, 'local', 'active')
            """,
            agent_id,
            team_id,
            did_key,
            alias,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.workspaces}}
                (workspace_id, team_id, agent_id, alias, last_seen_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            """,
            workspace_id,
            team_id,
            agent_id,
            alias,
            now - timedelta(seconds=index),
        )
        redis.presence[f"presence:{workspace_id}"] = {
            "workspace_id": str(workspace_id),
            "alias": alias,
            "team_id": team_id,
            "status": "active",
            "last_seen": (now - timedelta(seconds=index)).isoformat(),
        }

    stale_seen_at = now - timedelta(days=60)
    for index in range(10):
        alias = f"stale-{index}"
        workspace_id = uuid4()
        agent_id = uuid4()
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, team_id, did_key, alias, identity_scope, status)
            VALUES ($1, $2, $3, $4, 'local', 'active')
            """,
            agent_id,
            team_id,
            _make_keypair()[2],
            alias,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.workspaces}}
                (workspace_id, team_id, agent_id, alias, last_seen_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            """,
            workspace_id,
            team_id,
            agent_id,
            alias,
            stale_seen_at,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.task_claims}}
                (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
            VALUES ($1, $2, $3, '', $4, $5)
            """,
            team_id,
            workspace_id,
            alias,
            f"backend-stale-{index}",
            stale_seen_at,
        )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key, redis=redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/v1/workspaces/team",
            params={
                "include_claims": "true",
                "include_presence": "true",
                "only_with_claims": "false",
                "always_include_workspace_id": str(self_workspace_id),
                "limit": 5,
            },
            headers=headers,
        )
        response_without_presence = await client.get(
            "/v1/workspaces/team",
            params={
                "include_claims": "true",
                "include_presence": "false",
                "only_with_claims": "false",
                "limit": 5,
            },
            headers=headers,
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["has_more"] is True
    assert {workspace["alias"] for workspace in data["workspaces"]} == active_aliases
    assert all(workspace["status"] == "active" for workspace in data["workspaces"])
    assert response_without_presence.status_code == 200, response_without_presence.text
    assert response_without_presence.json()["has_more"] is True


@pytest.mark.asyncio
async def test_team_roster_keeps_live_presence_outside_sql_candidate_window(aweb_cloud_db):
    team_sk, _, team_did_key = _make_keypair()
    agent_sk, _, agent_did_key = _make_keypair()
    team_id = "backend:acme.com"
    now = datetime.now(timezone.utc)

    cert = _make_certificate(
        team_sk,
        team_did_key,
        agent_did_key,
        team_id=team_id,
        alias="live",
        identity_scope="local",
    )
    headers = _signed_request(agent_sk, agent_did_key, team_id)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "acme.com",
        "backend",
        team_did_key,
    )

    live_workspace_id = uuid4()
    live_agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, 'live', 'local', 'active')
        """,
        live_agent_id,
        team_id,
        agent_did_key,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, last_seen_at, updated_at)
        VALUES ($1, $2, $3, 'live', $4, $4)
        """,
        live_workspace_id,
        team_id,
        live_agent_id,
        now - timedelta(days=60),
    )

    redis = _FakeRedis()
    redis.presence[f"presence:{live_workspace_id}"] = {
        "workspace_id": str(live_workspace_id),
        "alias": "live",
        "team_id": team_id,
        "status": "active",
        "last_seen": now.isoformat(),
    }

    for index in range(5):
        alias = f"offline-{index}"
        workspace_id = uuid4()
        agent_id = uuid4()
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, team_id, did_key, alias, identity_scope, status)
            VALUES ($1, $2, $3, $4, 'local', 'active')
            """,
            agent_id,
            team_id,
            _make_keypair()[2],
            alias,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.workspaces}}
                (workspace_id, team_id, agent_id, alias, last_seen_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            """,
            workspace_id,
            team_id,
            agent_id,
            alias,
            now - timedelta(seconds=index),
        )

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key, redis=redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/v1/workspaces/team",
            params={
                "include_presence": "true",
                "only_with_claims": "false",
                "limit": 1,
            },
            headers=headers,
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["has_more"] is True
    assert [workspace["alias"] for workspace in data["workspaces"]] == ["live"]
    assert data["workspaces"][0]["status"] == "active"


async def _seed_local_member(
    aweb_cloud_db, *, team_id, team_did_key, agent_did_key, alias, last_seen_at
):
    """One live local member: agent row plus its workspace, seen at last_seen_at."""
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, role)
        VALUES ($1, $2, $3, $4, 'local', 'developer')
        """,
        agent_id,
        team_id,
        agent_did_key,
        alias,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_path, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        workspace_id,
        team_id,
        agent_id,
        alias,
        f"/tmp/{alias}-worktree",
        last_seen_at,
    )
    return agent_id, workspace_id


async def _seed_two_members_for_ownership(aweb_cloud_db):
    """A team with a certified caller and another member whose seat it targets."""
    team_sk, _, team_did_key = _make_keypair()
    caller_sk, _, caller_did_key = _make_keypair()
    _, _, owner_did_key = _make_keypair()
    team_id = "backend:acme.com"
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "acme.com",
        "backend",
        team_did_key,
    )
    seen_at = datetime.now(timezone.utc) - timedelta(hours=2)
    _, caller_workspace_id = await _seed_local_member(
        aweb_cloud_db,
        team_id=team_id,
        team_did_key=team_did_key,
        agent_did_key=caller_did_key,
        alias="caller",
        last_seen_at=seen_at,
    )
    _, owner_workspace_id = await _seed_local_member(
        aweb_cloud_db,
        team_id=team_id,
        team_did_key=team_did_key,
        agent_did_key=owner_did_key,
        alias="bot",
        last_seen_at=seen_at,
    )
    cert = _make_certificate(
        team_sk,
        team_did_key,
        caller_did_key,
        team_id=team_id,
        alias="caller",
        identity_scope="local",
    )

    def caller_headers(body_bytes):
        headers = _signed_request(caller_sk, caller_did_key, team_id, body_bytes)
        headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)
        headers["Content-Type"] = "application/json"
        return headers

    return team_did_key, caller_workspace_id, owner_workspace_id, seen_at, caller_headers


async def _workspace_row(aweb_cloud_db, workspace_id):
    return await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT hostname, workspace_path, role, last_seen_at, focus_task_ref
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )


def _record_presence_updates(monkeypatch):
    from aweb.coordination.routes import workspaces as workspaces_routes

    calls = []

    async def _record(_redis, **kwargs):
        calls.append(kwargs)
        return datetime.now(timezone.utc).isoformat()

    monkeypatch.setattr(workspaces_routes, "update_agent_presence", _record)
    return calls


@pytest.mark.asyncio
async def test_workspace_heartbeat_refuses_another_members_workspace(
    aweb_cloud_db, monkeypatch, caplog
):
    """A certified member cannot keep another member's seat looking alive."""
    (
        team_did_key,
        _,
        owner_workspace_id,
        seen_at,
        caller_headers,
    ) = await _seed_two_members_for_ownership(aweb_cloud_db)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    presence_updates = _record_presence_updates(monkeypatch)
    body = json.dumps(
        {"workspace_id": str(owner_workspace_id), "alias": "bot", "hostname": "attacker-host"},
        separators=(",", ":"),
    ).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/workspaces/heartbeat", content=body, headers=caller_headers(body)
        )

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == f"Workspace {owner_workspace_id} belongs to another agent."
    row = await _workspace_row(aweb_cloud_db, owner_workspace_id)
    assert row["hostname"] is None
    assert row["last_seen_at"] == seen_at
    assert presence_updates == []
    assert [record.getMessage() for record in caplog.records if record.levelname == "WARNING"] == [
        "Workspace heartbeat refused: workspace belongs to another agent"
    ]


@pytest.mark.asyncio
async def test_workspace_heartbeat_refreshes_the_callers_own_workspace(aweb_cloud_db, monkeypatch):
    (
        team_did_key,
        caller_workspace_id,
        _,
        seen_at,
        caller_headers,
    ) = await _seed_two_members_for_ownership(aweb_cloud_db)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    presence_updates = _record_presence_updates(monkeypatch)
    body = json.dumps(
        {"workspace_id": str(caller_workspace_id), "alias": "caller", "hostname": "caller-host"},
        separators=(",", ":"),
    ).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/workspaces/heartbeat", content=body, headers=caller_headers(body)
        )

    assert resp.status_code == 200, resp.text
    row = await _workspace_row(aweb_cloud_db, caller_workspace_id)
    assert row["hostname"] == "caller-host"
    assert row["last_seen_at"] > seen_at
    assert [call["workspace_id"] for call in presence_updates] == [str(caller_workspace_id)]


@pytest.mark.asyncio
async def test_workspace_patch_refuses_another_members_workspace(aweb_cloud_db, caplog):
    """A certified member cannot overwrite another member's seat metadata."""
    team_did_key, _, owner_workspace_id, _, caller_headers = await _seed_two_members_for_ownership(
        aweb_cloud_db
    )
    body = json.dumps(
        {
            "hostname": "attacker-host",
            "workspace_path": "/tmp/elsewhere",
            "focus_task_ref": "backend-x",
        },
        separators=(",", ":"),
    ).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(
            f"/v1/workspaces/{owner_workspace_id}", content=body, headers=caller_headers(body)
        )

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == f"Workspace {owner_workspace_id} belongs to another agent."
    row = await _workspace_row(aweb_cloud_db, owner_workspace_id)
    assert row["hostname"] is None
    assert row["workspace_path"] == "/tmp/bot-worktree"
    assert row["focus_task_ref"] is None
    assert [record.getMessage() for record in caplog.records if record.levelname == "WARNING"] == [
        "Workspace update refused: workspace belongs to another agent"
    ]


@pytest.mark.asyncio
async def test_workspace_patch_updates_the_callers_own_workspace(aweb_cloud_db):
    team_did_key, caller_workspace_id, _, _, caller_headers = await _seed_two_members_for_ownership(
        aweb_cloud_db
    )
    body = json.dumps(
        {"hostname": "caller-host", "focus_task_ref": "backend-y"},
        separators=(",", ":"),
    ).encode()

    app = _build_test_app(aweb_cloud_db.aweb_db, team_did_key)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(
            f"/v1/workspaces/{caller_workspace_id}", content=body, headers=caller_headers(body)
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] is True
    row = await _workspace_row(aweb_cloud_db, caller_workspace_id)
    assert row["hostname"] == "caller-host"
    assert row["focus_task_ref"] == "backend-y"
