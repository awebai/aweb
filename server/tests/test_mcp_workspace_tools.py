"""MCP coordination reads through the real signed transport and mounted tools."""

import pytest
from test_dashboard_privacy import privacy_app

from test_coordination_state_http import call_mcp, request_as
from test_coordination_state_http import coordination_mcp

__all__ = ["coordination_mcp", "privacy_app"]


@pytest.mark.asyncio
async def test_workspace_status_uses_workspace_rows_as_primary_identity(
    coordination_mcp,
):
    env = coordination_mcp
    task = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Held by the workspace"},
    )
    assert task.status_code == 200, task.text
    claim = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/tasks/{task.json()['task_ref']}",
        payload={"status": "in_progress"},
    )
    assert claim.status_code == 200, claim.text
    body = await call_mcp(env, name="workspace_status")
    alice = env.actors["alice"]
    assert alice.workspace != alice.id
    assert body["workspace_id"] == str(alice.workspace)
    assert body["self"]["workspace_id"] == str(alice.workspace)
    assert [claim["task_ref"] for claim in body["self"]["claims"]] == [
        task.json()["task_ref"]
    ]
    assert {entry["workspace_id"] for entry in body["team_agents"]} == {
        str(env.actors[alias].workspace) for alias in ("bob", "carol")
    }
    assert body["self"]["status"] == "active"
    assert body["self"]["last_seen"]
    agents = await call_mcp(env, name="list_agents")
    assert {entry["alias"] for entry in agents["agents"] if entry["online"]} == set(
        env.actors
    )


@pytest.mark.asyncio
async def test_work_ready_excludes_tasks_claimed_by_another_workspace(coordination_mcp):
    env = coordination_mcp
    tasks = {}
    for alias in ("alice", "bob"):
        created = await request_as(
            env,
            alias=alias,
            method="POST",
            path="/v1/tasks",
            payload={"title": f"Work for {alias}"},
        )
        assert created.status_code == 200, created.text
        tasks[alias] = created.json()
    claimed = await request_as(
        env,
        alias="bob",
        method="PATCH",
        path=f"/v1/tasks/{tasks['bob']['task_ref']}",
        payload={"status": "in_progress"},
    )
    assert claimed.status_code == 200, claimed.text
    body = await call_mcp(env, name="work_ready")
    assert [task["task_ref"] for task in body["tasks"]] == [tasks["alice"]["task_ref"]]


@pytest.mark.asyncio
async def test_active_claim_activity_matches_http_and_mcp(coordination_mcp):
    from datetime import UTC, datetime, timedelta
    from aweb.presence import update_agent_presence

    env = coordination_mcp
    created = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Active observation"},
    )
    assert created.status_code == 200, created.text
    claimed = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/tasks/{created.json()['task_ref']}",
        payload={"status": "in_progress"},
    )
    assert claimed.status_code == 200, claimed.text
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
        datetime.now(UTC) - timedelta(days=2),
        env.actors["alice"].workspace,
    )
    # Supply the actual team, independent of whether the task DTO includes it.
    from test_dashboard_privacy import TEAM

    newest = await update_agent_presence(
        env.redis,
        workspace_id=str(env.actors["alice"].workspace),
        alias="alice",
        team_id=TEAM,
        current_branch="work-branch",
    )
    http = await request_as(env, alias="alice", method="GET", path="/v1/tasks/active")
    assert http.status_code == 200, http.text
    mcp = await call_mcp(env, name="work_active")
    for rows in (http.json()["tasks"], mcp["tasks"]):
        assert len(rows) == 1
        assert rows[0]["task_ref"] == created.json()["task_ref"]
        assert rows[0]["workspace_id"] == str(env.actors["alice"].workspace)
        assert rows[0]["owner_last_seen_at"] == newest
        assert rows[0]["branch"] == "work-branch"
