"""Coordination rules through signed HTTP/MCP and the real registry/DB/Redis."""

import json
from uuid import UUID

import pytest

from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.mcp import create_mcp_app
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import _signed_team_headers


async def request_as(env, *, alias, method, path, payload=None):
    actor = env.actors[alias]
    body = json.dumps(payload).encode() if payload is not None else b""
    return await env.client.request(
        method,
        path,
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )


@pytest.mark.asyncio
async def test_claim_and_focus_titles_use_the_full_hyphenated_team_ref(privacy_app):
    env = privacy_app
    assert "-" in TEAM.split(":")[0]
    parent = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Coordination apex", "task_type": "epic"},
    )
    assert parent.status_code == 200, parent.text
    child = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Claimed task", "parent_task_id": parent.json()["task_id"]},
    )
    assert child.status_code == 200, child.text
    claimed = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/tasks/{child.json()['task_ref']}",
        payload={"status": "in_progress"},
    )
    assert claimed.status_code == 200, claimed.text

    for path in ("/v1/workspaces", "/v1/workspaces/team"):
        response = await request_as(env, alias="alice", method="GET", path=path)
        assert response.status_code == 200, response.text
        workspace = next(
            item
            for item in response.json()["workspaces"]
            if item["workspace_id"] == str(env.actors["alice"].workspace)
        )
        assert workspace["focus_task_title"] == "Coordination apex"
        assert workspace["focus_task_type"] == "epic"
        claim = next(
            item
            for item in workspace["claims"]
            if item["task_ref"] == child.json()["task_ref"]
        )
        assert (claim["title"], claim["apex_title"], claim["apex_type"]) == (
            "Claimed task",
            "Coordination apex",
            "epic",
        )

    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
    )
    env.app.mount("/coordination-mcp", mcp)
    await mcp.startup()
    try:
        response = await request_as(
            env,
            alias="alice",
            method="POST",
            path="/coordination-mcp/",
            payload={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "workspace_status", "arguments": {}},
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        status = json.loads(result["content"][0]["text"])
        assert status["self"]["claims"][0]["title"] == "Claimed task"
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
async def test_member_without_a_workspace_cannot_take_another_members_claim(
    privacy_app,
):
    env = privacy_app
    task = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Held by Alice"},
    )
    assert task.status_code == 200, task.text
    path = f"/v1/tasks/{task.json()['task_ref']}"
    claimed = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path=path,
        payload={"status": "in_progress"},
    )
    assert claimed.status_code == 200, claimed.text
    # An embedding host can release coordination state while keeping a member.
    cleanup = await apply_lifecycle_cascade(
        env.infra,
        env.redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(
                actor_id=str(env.actors["bob"].id), actor_type="agent", authority="self"
            ),
            team_id=TEAM,
            target_agent_id=str(env.actors["bob"].id),
            workspace_scope="all_for_agent",
            agent_disposition=AgentDisposition.PRESERVED,
        ),
    )
    assert not cleanup.errors, cleanup
    assert (
        await env.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.workspaces}} WHERE agent_id=$1 AND deleted_at IS NULL",
            env.actors["bob"].id,
        )
        == 0
    )
    refused = await request_as(
        env,
        alias="bob",
        method="PATCH",
        path=path,
        payload={"status": "in_progress"},
    )
    assert refused.status_code == 409, refused.text
    assert (
        await env.db.fetch_value(
            "SELECT assignee_alias FROM {{tables.tasks}} WHERE task_id=$1",
            UUID(task.json()["task_id"]),
        )
        == "alice"
    )
    holders = await env.db.fetch_all(
        "SELECT alias FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        TEAM,
        task.json()["task_ref"],
    )
    assert [row["alias"] for row in holders] == ["alice"]


@pytest.mark.asyncio
async def test_agent_heartbeat_preserves_workspace_metadata(privacy_app):
    env = privacy_app
    metadata = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/workspaces/heartbeat",
        payload={
            "workspace_id": str(env.actors["alice"].workspace),
            "alias": "alice",
            "human_name": "Workspace owner",
            "role": "builder",
        },
    )
    assert metadata.status_code == 200, metadata.text
    before = await env.redis.hgetall(f"presence:{env.actors['alice'].workspace}")
    assert before["human_name"] == "Workspace owner"
    assert before["program"] == "aw"
    assert before["role"] == "builder"
    heartbeat = await request_as(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat"
    )
    assert heartbeat.status_code == 200, heartbeat.text
    after = await env.redis.hgetall(f"presence:{env.actors['alice'].workspace}")
    for field in ("human_name", "program", "role", "repo_id", "current_branch"):
        assert after.get(field) == before.get(field), field
    assert after["last_seen"] >= before["last_seen"]
