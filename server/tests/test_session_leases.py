from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

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
        wrong_renew = await client.post("/v1/session-leases/renew", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60})
        renewed = await client.post("/v1/session-leases/renew", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60})
        takeover = await client.post("/v1/session-leases/takeover", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60, "reason": "operator-confirmed migration"})
        old_release = await client.post("/v1/session-leases/release", json={"session_id": "session-a", "session_key": KEY_A})
        released = await client.post("/v1/session-leases/release", json={"session_id": "session-b", "session_key": KEY_B})

    assert acquired.status_code == 200
    assert conflict.status_code == 409
    assert wrong_renew.status_code == 409
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
async def test_concurrent_session_acquire_admits_exactly_one(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first, second = await asyncio.gather(
            client.post("/v1/session-leases", json={"session_id": "session-a", "session_key": KEY_A, "ttl_seconds": 60}),
            client.post("/v1/session-leases", json={"session_id": "session-b", "session_key": KEY_B, "ttl_seconds": 60}),
        )
    assert sorted([first.status_code, second.status_code]) == [200, 409]
