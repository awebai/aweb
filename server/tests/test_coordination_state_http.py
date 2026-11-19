"""Coordination rules through signed HTTP/MCP and the real registry/DB/Redis."""

import json
from uuid import UUID

import pytest
import pytest_asyncio

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


@pytest_asyncio.fixture
async def coordination_mcp(privacy_app):
    env = privacy_app
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
    )
    env.app.mount("/coordination-mcp", mcp)
    await mcp.startup()
    try:
        yield env
    finally:
        await mcp.shutdown()


async def call_mcp(env, *, name, arguments=None):
    response = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/coordination-mcp/",
        payload={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


@pytest.mark.asyncio
async def test_claim_and_focus_titles_use_the_full_hyphenated_team_ref(
    coordination_mcp,
):
    env = coordination_mcp
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

    status = await call_mcp(env, name="workspace_status")
    assert status["self"]["claims"][0]["title"] == "Claimed task"


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


@pytest.mark.asyncio
async def test_root_activity_without_a_redis_beat_is_visible_on_every_http_reader(
    privacy_app,
):
    env = privacy_app
    for alias in env.actors:
        await env.redis.delete(f"presence:{env.actors[alias].workspace}")
    for path in (
        "/v1/agents",
        "/v1/status",
        "/v1/workspaces",
        "/v1/workspaces/online",
        "/v1/workspaces/team?only_with_claims=false",
    ):
        response = await request_as(env, alias="alice", method="GET", path=path)
        assert response.status_code == 200, response.text
        entries = response.json().get("agents", response.json().get("workspaces"))
        alice = next(item for item in entries if item["alias"] == "alice")
        if "online" in alice:
            assert alice["online"] is True, path
        else:
            assert alice["status"] == "active", path
        assert alice.get("last_seen"), path


@pytest.mark.asyncio
async def test_committed_deletion_reports_claim_release_failure_and_retries(
    privacy_app,
):
    env = privacy_app
    created = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Deletion with a held claim"},
    )
    assert created.status_code == 200, created.text
    ref = created.json()["task_ref"]
    path = f"/v1/tasks/{ref}"
    claimed = await request_as(
        env, alias="alice", method="PATCH", path=path, payload={"status": "in_progress"}
    )
    assert claimed.status_code == 200, claimed.text
    # Real database failure at the release statement, scoped to this test's
    # disposable database and this exact task. Auth/hooks/queries stay real.
    await env.db.execute("""
        CREATE FUNCTION aweb.r15_fail_claim_release() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'r15 owned claim-release fault'; END $$
    """)
    safe_ref = ref.replace("'", "''")
    await env.db.execute(f"""
        CREATE TRIGGER r15_claim_release_fault BEFORE DELETE ON {{{{tables.task_claims}}}}
        FOR EACH ROW WHEN (OLD.task_ref = '{safe_ref}')
        EXECUTE FUNCTION aweb.r15_fail_claim_release()
    """)
    try:
        deleted = await request_as(env, alias="alice", method="DELETE", path=path)
        assert deleted.status_code == 503, deleted.text
        assert deleted.json()["detail"]["code"] == "task_deleted_cleanup_pending"
        assert deleted.json()["detail"]["task_id"] == created.json()["task_id"]
        assert await env.db.fetch_value(
            "SELECT deleted_at IS NOT NULL FROM {{tables.tasks}} WHERE task_id=$1",
            UUID(created.json()["task_id"]),
        )
        assert (
            await env.db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
                TEAM,
                ref,
            )
            == 1
        )
    finally:
        await env.db.execute(
            "DROP TRIGGER r15_claim_release_fault ON {{tables.task_claims}}"
        )
        await env.db.execute("DROP FUNCTION aweb.r15_fail_claim_release()")
    retried = await request_as(env, alias="alice", method="DELETE", path=path)
    assert retried.status_code == 200, retried.text
    assert retried.json()["task_id"] == created.json()["task_id"]
    assert (
        await env.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
            TEAM,
            ref,
        )
        == 0
    )
