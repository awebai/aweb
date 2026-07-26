from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.routes.session_leases import router
from aweb.team_auth_deps import TeamIdentity, get_team_identity

TEAM_ID = "backend:acme.com"
KEY_A = "a" * 64
KEY_B = "b" * 64


class _DbShim:
    def __init__(self, manager):
        self.manager = manager

    def get_manager(self, name="aweb"):
        return self.manager


class _RecordingLockManager:
    def __init__(self, manager):
        self.manager = manager
        self.locks = []

    @asynccontextmanager
    async def transaction(self):
        async with self.manager.transaction() as tx:
            outer = self

            class RecordingTx:
                def __getattr__(self, name):
                    return getattr(tx, name)

                async def fetch_value(self, query, *args):
                    if "pg_advisory_xact_lock" in query:
                        outer.locks.append(args[0])
                    return await tx.fetch_value(query, *args)

            yield RecordingTx()


class _FailAuditManager:
    def __init__(self, manager):
        self.manager = manager

    @asynccontextmanager
    async def transaction(self):
        async with self.manager.transaction() as tx:
            class FailAuditTx:
                def __getattr__(self, name):
                    return getattr(tx, name)

                async def execute(self, query, *args):
                    if "INSERT INTO {{tables.audit_log}}" in query:
                        raise RuntimeError("forced audit failure")
                    return await tx.execute(query, *args)

            yield FailAuditTx()


async def _identity(request: Request):
    return TeamIdentity(
        team_id=TEAM_ID, alias="alice", did_key="did:key:zAlice", did_aw="did:aw:alice",
        address="acme.com/alice", agent_id=request.app.state.agent_id,
        identity_scope="global", certificate_id="cert-1",
    )


async def _fixture(aweb_db):
    agent_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:zTeam')
        """,
        TEAM_ID,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, role, status)
        VALUES ($1, $2, 'alice', 'did:key:zAlice', 'developer', 'active')
        """,
        agent_id, TEAM_ID,
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_team_identity] = _identity
    app.state.db = _DbShim(aweb_db)
    app.state.agent_id = str(agent_id)
    return app, agent_id


@pytest.mark.asyncio
async def test_session_lease_uses_session_key_and_audited_takeover(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        acquired = await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})
        conflict = await client.post("/v1/session-leases", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60})
        same_id_wrong_key = await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_B, "ttl_seconds": 60})
        different_id_same_key = await client.post("/v1/session-leases", json={"session_id": "session-b", "session_key": KEY_A, "ttl_seconds": 60})
        wrong_renew = await client.post("/v1/session-leases/renew", json={"session_id": "session-a", "session_key": KEY_B, "ttl_seconds": 60})
        wrong_release = await client.post("/v1/session-leases/release", json={"session_id": "session-a", "session_key": KEY_B})
        renewed = await client.post("/v1/session-leases/renew", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})
        for bad_reason in (None, "", "   "):
            takeover_body = {"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60}
            if bad_reason is not None:
                takeover_body["reason"] = bad_reason
            invalid_takeover = await client.post("/v1/session-leases/takeover", json=takeover_body)
            assert invalid_takeover.status_code == 422
        takeover = await client.post("/v1/session-leases/takeover", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60, "reason": " operator-confirmed migration "})
        old_release = await client.post("/v1/session-leases/release", json={"session_id": "session-a", "session_key": KEY_A})
        released = await client.post("/v1/session-leases/release", json={"session_id": "session-b", "session_key": KEY_B})

    assert acquired.status_code == 200
    assert conflict.status_code == 409
    assert same_id_wrong_key.status_code == 409
    assert different_id_same_key.status_code == 409
    assert wrong_renew.status_code == 409
    assert wrong_release.status_code == 409
    assert renewed.status_code == 200
    assert takeover.status_code == 200
    assert takeover.json()["generation"] == 2
    assert old_release.status_code == 409
    assert released.status_code == 200
    audit = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT event_type, resource, details FROM {{tables.audit_log}} WHERE event_type = 'session_lease.takeover'"
    )
    assert audit["resource"] == str(agent_id)
    details = json.loads(audit["details"]) if isinstance(audit["details"], str) else audit["details"]
    assert details["old_session_id"] == "session-a"
    assert details["new_session_id"] == "session-b"
    assert details["reason"] == "operator-confirmed migration"


@pytest.mark.asyncio
async def test_expired_lease_allows_new_session_and_increments_generation(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})).status_code == 200
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.session_admission_leases}} SET expires_at = NOW() - INTERVAL '1 second' WHERE team_id = $1 AND principal_agent_id = $2",
            TEAM_ID, str(agent_id),
        )
        acquired = await client.post("/v1/session-leases", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60})
    assert acquired.status_code == 200
    assert acquired.json()["session_id"] == "session-b"
    assert acquired.json()["generation"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["acquire", "renew", "takeover"])
async def test_ttl_starts_after_waiting_for_serialization_lock(aweb_cloud_db, operation):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    lock_key = f"session-admission:{TEAM_ID}:{agent_id}"
    path = "/v1/session-leases" if operation == "acquire" else f"/v1/session-leases/{operation}"
    payload = {"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 1}
    if operation == "takeover":
        payload = {"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 1, "reason": "held-lock proof"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        if operation != "acquire":
            initial = await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})
            assert initial.status_code == 200
        async with aweb_cloud_db.aweb_db.transaction() as tx:
            await tx.fetch_value("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lock_key)
            pending = asyncio.create_task(client.post(path, json=payload))
            await asyncio.sleep(1.1)
        response = await pending
    assert response.status_code == 200
    assert datetime.fromisoformat(response.json()["expires_at"]) > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_takeover_rolls_back_when_audit_write_fails(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})).status_code == 200
    app.state.db = _DbShim(_FailAuditManager(aweb_cloud_db.aweb_db))
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        failed = await client.post("/v1/session-leases/takeover", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60, "reason": "test rollback"})
    assert failed.status_code == 500
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT session_id, generation FROM {{tables.session_admission_leases}} WHERE team_id = $1",
        TEAM_ID,
    )
    assert row["session_id"] == "session-a"
    assert row["generation"] == 1


def test_session_lease_routes_are_registered_on_production_app():
    paths = {route.path for route in create_app().routes}
    assert {"/v1/session-leases", "/v1/session-leases/renew", "/v1/session-leases/release", "/v1/session-leases/takeover"} <= paths


@pytest.mark.asyncio
async def test_acquire_uses_principal_scoped_transaction_lock(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    manager = _RecordingLockManager(aweb_cloud_db.aweb_db)
    app.state.db = _DbShim(manager)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})
    assert response.status_code == 200
    assert manager.locks == [f"session-admission:{TEAM_ID}:{agent_id}"]


@pytest.mark.asyncio
async def test_concurrent_session_acquire_admits_exactly_one(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first, second = await asyncio.gather(
            client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60}),
            client.post("/v1/session-leases", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60}),
        )
    assert sorted([first.status_code, second.status_code]) == [200, 409]
