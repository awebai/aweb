"""MCP coordination reads through the real signed transport and mounted tools."""

import pytest
from test_dashboard_privacy import privacy_app as privacy_app

from test_coordination_state_http import call_mcp, request_as
from test_coordination_state_http import coordination_mcp as coordination_mcp


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
