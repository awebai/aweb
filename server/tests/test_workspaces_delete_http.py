"""Workspace roster, heartbeat and patch through the real serving stack.

Destructive cleanup is exercised by test_workspace_delete_real_http.py.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from aweb.presence import update_agent_presence
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair

__all__ = ["privacy_app"]


async def _connect_member(env, *, alias):
    sk, _, did = _make_keypair()
    certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            did,
            team_id=TEAM,
            alias=alias,
            identity_scope="local",
            certificate_id=f"r15-{uuid4()}",
        )
    )
    actor = SimpleNamespace(sk=sk, did=did, certificate=certificate)
    env.actors[alias] = actor
    response = await request_as(
        env, alias=alias, method="POST", path="/v1/connect", payload={}
    )
    assert response.status_code == 200, response.text
    actor.id = UUID(response.json()["agent_id"])
    actor.workspace = UUID(response.json()["workspace_id"])
    return actor


@pytest.mark.asyncio
async def test_team_roster_prioritizes_live_presence_and_reports_truncation(
    privacy_app,
):
    env = privacy_app
    active_aliases = set(env.actors)
    for alias in active_aliases:
        heartbeat = await request_as(
            env, alias=alias, method="POST", path="/v1/agents/heartbeat"
        )
        assert heartbeat.status_code == 200, heartbeat.text
    for index in range(5):
        alias = f"stale-{index}"
        actor = await _connect_member(env, alias=alias)
        task = await request_as(
            env,
            alias=alias,
            method="POST",
            path="/v1/tasks",
            payload={"title": f"Held work {index}"},
        )
        assert task.status_code == 200, task.text
        claimed = await request_as(
            env,
            alias=alias,
            method="PATCH",
            path=f"/v1/tasks/{task.json()['task_ref']}",
            payload={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text
        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
            datetime.now(UTC) - timedelta(days=60),
            actor.workspace,
        )
        await env.redis.delete(f"presence:{actor.workspace}")
    path = "/v1/workspaces/team?only_with_claims=false&include_claims=true&limit=3"
    response = await request_as(env, alias="alice", method="GET", path=path)
    assert response.status_code == 200, response.text
    assert response.json()["has_more"] is True
    assert {
        workspace["alias"] for workspace in response.json()["workspaces"]
    } == active_aliases
    assert all(
        workspace["status"] == "active" for workspace in response.json()["workspaces"]
    )
    plain = await request_as(
        env, alias="alice", method="GET", path=path + "&include_presence=false"
    )
    assert plain.status_code == 200, plain.text
    assert plain.json()["has_more"] is True


@pytest.mark.asyncio
async def test_team_roster_keeps_live_presence_outside_sql_candidate_window(
    privacy_app,
):
    env = privacy_app
    now = datetime.now(UTC)
    for alias, actor in env.actors.items():
        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
            now - timedelta(days=60 if alias == "alice" else 2),
            actor.workspace,
        )
    for index in range(4):
        actor = await _connect_member(env, alias=f"offline-{index}")
        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
            now - timedelta(days=2),
            actor.workspace,
        )
    await update_agent_presence(
        env.redis,
        workspace_id=str(env.actors["alice"].workspace),
        alias="alice",
        team_id=TEAM,
    )
    response = await request_as(
        env,
        alias="alice",
        method="GET",
        path="/v1/workspaces/team?only_with_claims=false&limit=1",
    )
    assert response.status_code == 200, response.text
    assert response.json()["has_more"] is True
    assert [workspace["alias"] for workspace in response.json()["workspaces"]] == [
        "alice"
    ]
    assert response.json()["workspaces"][0]["status"] == "active"


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["heartbeat", "patch"])
async def test_workspace_writes_refuse_another_members_workspace(
    privacy_app, caplog, operation
):
    env = privacy_app
    owner = env.actors["bob"]
    before = await env.db.fetch_one(
        "SELECT hostname,workspace_path,focus_task_ref,last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        owner.workspace,
    )
    presence = await env.redis.hgetall(f"presence:{owner.workspace}")
    if operation == "heartbeat":
        response = await request_as(
            env,
            alias="alice",
            method="POST",
            path="/v1/workspaces/heartbeat",
            payload={
                "workspace_id": str(owner.workspace),
                "alias": "bob",
                "hostname": "attacker-host",
            },
        )
        warning = "Workspace heartbeat refused: workspace belongs to another agent"
    else:
        response = await request_as(
            env,
            alias="alice",
            method="PATCH",
            path=f"/v1/workspaces/{owner.workspace}",
            payload={
                "hostname": "attacker-host",
                "workspace_path": "/workspace/elsewhere",
                "focus_task_ref": "other-task",
            },
        )
        warning = "Workspace update refused: workspace belongs to another agent"
    assert response.status_code == 403, response.text
    assert (
        response.json()["detail"]
        == f"Workspace {owner.workspace} belongs to another agent."
    )
    after = await env.db.fetch_one(
        "SELECT hostname,workspace_path,focus_task_ref,last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        owner.workspace,
    )
    assert dict(after) == dict(before)
    assert await env.redis.hgetall(f"presence:{owner.workspace}") == presence
    assert warning in [
        record.getMessage()
        for record in caplog.records
        if record.levelname == "WARNING"
    ]


@pytest.mark.asyncio
async def test_workspace_heartbeat_refreshes_the_callers_own_workspace(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    response = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/workspaces/heartbeat",
        payload={
            "workspace_id": str(actor.workspace),
            "alias": "alice",
            "hostname": "caller-host",
        },
    )
    assert response.status_code == 200, response.text
    row = await env.db.fetch_one(
        "SELECT hostname,last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        actor.workspace,
    )
    assert row["hostname"] == "caller-host"
    assert row["last_seen_at"] is not None
    presence = await env.redis.hgetall(f"presence:{actor.workspace}")
    assert presence["workspace_id"] == str(actor.workspace)
    assert presence["alias"] == "alice"
    assert presence["team_id"] == TEAM


@pytest.mark.asyncio
async def test_workspace_patch_updates_the_callers_own_workspace(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    response = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/workspaces/{actor.workspace}",
        payload={"hostname": "caller-host", "focus_task_ref": "retained-task"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["updated"] is True
    row = await env.db.fetch_one(
        "SELECT hostname,focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id=$1",
        actor.workspace,
    )
    assert row["hostname"] == "caller-host"
    assert row["focus_task_ref"] == "retained-task"


@pytest.mark.asyncio
async def test_authenticated_patch_requires_a_body_without_changing_the_workspace(
    privacy_app,
):
    env = privacy_app
    workspace = env.actors["alice"].workspace
    before = await env.db.fetch_one(
        "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
    )
    presence = await env.redis.hgetall(f"presence:{workspace}")
    missing = await request_as(
        env, alias="alice", method="PATCH", path=f"/v1/workspaces/{workspace}"
    )
    assert missing.status_code == 422, missing.text
    assert missing.json()["detail"] == {
        "code": "workspace_update_body_required",
        "message": "Send a JSON object containing the workspace fields to update, then retry this PATCH.",
    }
    after = await env.db.fetch_one(
        "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
    )
    assert dict(after) == dict(before)
    assert await env.redis.hgetall(f"presence:{workspace}") == presence
    valid = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/workspaces/{workspace}",
        payload={"hostname": "valid-host"},
    )
    assert valid.status_code == 200, valid.text
    assert valid.json()["updated"] is True
    assert (
        await env.db.fetch_value(
            "SELECT hostname FROM {{tables.workspaces}} WHERE workspace_id=$1",
            workspace,
        )
        == "valid-host"
    )
