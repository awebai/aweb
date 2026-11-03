"""Claim transitions against real storage and the public task HTTP handlers."""
import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from aweb.service_errors import ServiceError
from tests.test_tasks_http import (
    TEAM_ID, _DbShim, _build_tasks_app, _fake_team_identity, _insert_task, _seed_team,
)
from aweb.coordination.tasks_service import list_ready_tasks, update_task
from aweb import mutation_hooks
from aweb.mcp import mutations
from aweb.mcp.tools import tasks as mcp_tasks, work as mcp_work


async def seed_claim(db, *, fresh=False, grant=None, app_request=False):
    await _seed_team(db)
    now = datetime.now(timezone.utc)
    seen = now - timedelta(seconds=10 if fresh else 1801)
    agents, workspaces = {}, {}
    for alias in ("alice", "bob", "carol"):
        agents[alias], workspaces[alias] = uuid4(), uuid4()
        await db.execute(
            """INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key)
               VALUES ($1,$2,$3,$4)""", agents[alias], TEAM_ID, alias, f"did:key:z{alias}",
        )
        await db.execute(
            """INSERT INTO {{tables.workspaces}}
               (workspace_id, team_id, agent_id, alias, last_seen_at)
               VALUES ($1,$2,$3,$4,$5)""",
            workspaces[alias], TEAM_ID, agents[alias], alias, seen if alias == "bob" else now,
        )
    task_id = uuid4()
    if app_request:
        # The fixed target is the real holder; a generic claim must never adopt it.
        await db.execute(
            """INSERT INTO {{tables.tasks}} (task_id,team_id,task_number,root_task_seq,
               task_ref_suffix,title,status,assignee_alias,assignee_did,app_request)
               VALUES ($1,$2,1,1,'aaaa','Fixed request','in_progress','bob','did:key:zbob','{}')""",
            task_id, TEAM_ID,
        )
    else:
        await _insert_task(db, task_id=task_id, task_number=1, root_task_seq=1,
                           suffix="aaaa", title="Recover work", status="in_progress", assignee_alias="bob")
    await db.execute(
        """INSERT INTO {{tables.task_claims}} (team_id,workspace_id,alias,task_ref,claimed_at)
           VALUES ($1,$2,'bob','backend-aaaa',$3)""", TEAM_ID, workspaces["bob"], seen,
    )
    if grant:
        gid = uuid4()
        grant_seen = now - timedelta(seconds=1801 if grant == "stale" else 5)
        await db.execute(
            """INSERT INTO {{tables.identity_session_grants}}
               (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at,revoked_at)
               VALUES ($1,$2,$3,'did:key:zsession',ARRAY['coord.write'],$4,$5,$6)""",
            gid, TEAM_ID, agents["bob"], now-timedelta(hours=1),
            now+timedelta(hours=1) if grant != "expired" else now-timedelta(seconds=1),
            now if grant == "revoked" else None,
        )
        await db.execute(
            """INSERT INTO {{tables.identity_grant_liveness}}
               (grant_id,team_id,subject_agent_id,workspace_id,alias,session_did_key,last_seen_at,expires_at)
               VALUES ($1,$2,$3,$4,'bob','did:key:zsession',$5,$6)""",
            gid, TEAM_ID, agents["bob"], workspaces["bob"], grant_seen, now+timedelta(hours=1),
        )
    return task_id, workspaces, seen


def http_client(db, alias="alice", callback=None):
    app = _build_tasks_app(db)

    async def identity():
        agent_id = await db.fetch_value("SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND alias=$2", TEAM_ID, alias)
        return replace(await _fake_team_identity(), alias=alias, agent_id=str(agent_id))

    for key in app.dependency_overrides:
        app.dependency_overrides[key] = identity
    app.state.on_mutation = callback

    @app.exception_handler(ServiceError)
    async def service_error(request, exc):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_stale_takeover_records_and_reclaim_names_current_holder(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    task_id, ws, seen = await seed_claim(db)
    async with http_client(db) as client:
        ready = (await client.get("/v1/tasks/ready")).json()["tasks"]
        assert len(ready) == 1
        assert ready[0]["stale"] is True
        assert ready[0]["owner_alias"] == "bob"
        assert datetime.fromisoformat(ready[0]["owner_last_seen_at"]) == seen
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
        assert response.status_code == 200, response.text
        assert response.json()["assignee_alias"] == "alice"
    claims = await db.fetch_all("SELECT workspace_id,alias FROM {{tables.task_claims}}")
    assert [(r["workspace_id"], r["alias"]) for r in claims] == [(ws["alice"], "alice")]
    comments = await db.fetch_all("SELECT body FROM {{tables.task_comments}} WHERE task_id=$1", task_id)
    assert len(comments) == 1
    assert all(s in comments[0]["body"] for s in ("alice", "bob", seen.isoformat()))
    async with http_client(db, "bob") as client:
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
        assert response.status_code == 409
        assert "alice" in response.json()["detail"]
        claimed_at = await db.fetch_value("SELECT claimed_at FROM {{tables.task_claims}}")
        assert claimed_at.isoformat() in response.json()["detail"]
    # Athena88b41c93: displaced holders retain the general member edit policy.
    await update_task(_DbShim(db), team_id=TEAM_ID, ref="backend-aaaa", actor_alias="bob", notes="late edit")
    await update_task(_DbShim(db), team_id=TEAM_ID, ref="backend-aaaa", actor_alias="carol", notes="reviewed")
    row = await db.fetch_one("SELECT status,notes FROM {{tables.tasks}} WHERE task_id=$1", task_id)
    assert row["status"] == "in_progress" and row["notes"] == "reviewed"
    assert await list_ready_tasks(_DbShim(db), team_id=TEAM_ID) == []
    await update_task(_DbShim(db), team_id=TEAM_ID, ref="backend-aaaa", actor_alias="bob", status="closed")


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh,grant", [(True,None), (False,"fresh")])
async def test_live_holder_is_not_ready_and_keeps_claim(aweb_cloud_db, fresh, grant):
    db = aweb_cloud_db.aweb_db
    _, ws, _ = await seed_claim(db, fresh=fresh, grant=grant)
    async with http_client(db) as client:
        assert (await client.get("/v1/tasks/ready")).json()["tasks"] == []
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
        assert response.status_code == 409
        assert "bob" in response.json()["detail"]
    assert await db.fetch_value("SELECT workspace_id FROM {{tables.task_claims}}") == ws["bob"]
    assert await db.fetch_value("SELECT count(*) FROM {{tables.task_comments}}") == 0


@pytest.mark.asyncio
async def test_concurrent_takeovers_have_one_winner(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await seed_claim(db)
    async with http_client(db, "alice") as alice, http_client(db, "carol") as carol:
        responses = await asyncio.gather(*[
            c.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
            for c in (alice, carol)
        ])
    assert sorted(r.status_code for r in responses) == [200,409]
    winner = next(r.json()["assignee_alias"] for r in responses if r.status_code == 200)
    assert winner in next(r.json()["detail"] for r in responses if r.status_code == 409)
    assert await db.fetch_value("SELECT alias FROM {{tables.task_claims}}") == winner
    assert await db.fetch_value("SELECT count(*) FROM {{tables.task_comments}}") == 1


@pytest.mark.asyncio
async def test_human_holder_never_requires_heartbeat(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, ws, _ = await seed_claim(db)
    await db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE alias='bob'")
    async with http_client(db) as client:
        assert (await client.get("/v1/tasks/ready")).json()["tasks"] == []
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status":"in_progress"})
        assert response.status_code == 409
        assert "bob" in response.json()["detail"]
    assert await db.fetch_value("SELECT workspace_id FROM {{tables.task_claims}}") == ws["bob"]
    assert await db.fetch_value("SELECT count(*) FROM {{tables.task_comments}}") == 0


@pytest.mark.asyncio
async def test_new_claim_is_live_without_recent_workspace_heartbeat(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, ws, _ = await seed_claim(db)
    await db.execute("UPDATE {{tables.task_claims}} SET claimed_at=NOW()")
    async with http_client(db) as client:
        assert (await client.get("/v1/tasks/ready")).json()["tasks"] == []
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status":"in_progress"})
        assert response.status_code == 409
        assert "bob" in response.json()["detail"]
    assert await db.fetch_value("SELECT workspace_id FROM {{tables.task_claims}}") == ws["bob"]
    assert await db.fetch_value("SELECT count(*) FROM {{tables.task_comments}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("grant", ["stale", "revoked", "expired"])
async def test_invalid_grant_does_not_keep_claim_alive(aweb_cloud_db, grant):
    db = aweb_cloud_db.aweb_db
    await seed_claim(db, grant=grant)
    async with http_client(db) as client:
        assert (await client.get("/v1/tasks/ready")).json()["tasks"][0]["stale"]
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
        assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_app_request_excludes_takeover(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, ws, _ = await seed_claim(db, app_request=True)
    async with http_client(db) as client:
        assert (await client.get("/v1/tasks/ready")).json()["tasks"] == []
        response = await client.patch("/v1/tasks/backend-aaaa", json={"status": "in_progress"})
        assert response.status_code in (403,409)
    assert await db.fetch_value("SELECT workspace_id FROM {{tables.task_claims}}") == ws["bob"]
    assert await db.fetch_value("SELECT assignee_did FROM {{tables.tasks}}") == "did:key:zbob"
    assert await db.fetch_value("SELECT count(*) FROM {{tables.task_comments}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter", ["http", "mcp"])
async def test_takeover_emits_existing_unclaim_and_claim_events(aweb_cloud_db, monkeypatch, adapter):
    db = aweb_cloud_db.aweb_db
    _, ws, _ = await seed_claim(db, grant="revoked")
    workspace_events, team_events = [], []

    async def capture_workspace(redis, event):
        workspace_events.append(event)

    async def capture_team(redis, event):
        team_events.append(event)

    monkeypatch.setattr(mutation_hooks, "publish_event", capture_workspace)
    monkeypatch.setattr(mutation_hooks, "publish_team_event", capture_team)
    callback = mutation_hooks.create_mutation_handler(redis=None, db_infra=_DbShim(db))
    if adapter == "http":
        async with http_client(db, callback=callback) as client:
            response = await client.patch("/v1/tasks/backend-aaaa", json={"status":"in_progress"})
            assert response.status_code == 200, response.text
            result = response.json()
    else:
        auth = SimpleNamespace(team_id=TEAM_ID, alias="alice", workspace_id=str(ws["alice"]),
                               agent_id=str(await db.fetch_value("SELECT agent_id FROM {{tables.workspaces}} WHERE workspace_id=$1", ws["alice"])))
        for module in (mcp_work, mcp_tasks):
            monkeypatch.setattr(module, "require_team_context", lambda: (auth, None))
        assert json.loads(await mcp_work.work_ready(_DbShim(db)))["tasks"][0]["stale"]
        token = mutations.set_mutation_callback(callback)
        try:
            result = json.loads(await mcp_tasks.task_claim(_DbShim(db), ref="backend-aaaa"))
        finally:
            mutations.reset_mutation_callback(token)
    assert "released_claims" not in result and "claim_preacquired" not in result
    assert [(e.type,e.alias) for e in team_events if e.type in ("task.unclaimed","task.claimed")] == [
        ("task.unclaimed","bob"), ("task.claimed","alice")]
    assert [(e.type,e.workspace_id) for e in workspace_events if e.type in ("task.unclaimed","task.claimed")] == [
        ("task.unclaimed",str(ws["bob"])), ("task.claimed",str(ws["alice"]))]
    grant_seen = await db.fetch_value("SELECT last_seen_at FROM {{tables.identity_grant_liveness}}")
    assert grant_seen.isoformat() in await db.fetch_value("SELECT body FROM {{tables.task_comments}}")
