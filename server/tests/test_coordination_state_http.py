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
from aweb.internal_auth import application_proxy_verification
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


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
    for alias in env.actors:
        heartbeat = await request_as(
            env, alias=alias, method="POST", path="/v1/agents/heartbeat"
        )
        assert heartbeat.status_code == 200, heartbeat.text
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
        proxy_verification=application_proxy_verification(env.app.state),
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

    for path in ("/v1/workspaces?include_claims=true", "/v1/workspaces/team"):
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
        env.db,
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
        registry_client=env.app.state.awid_registry_client,
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
        heartbeat = await request_as(
            env, alias=alias, method="POST", path="/v1/agents/heartbeat"
        )
        assert heartbeat.status_code == 200, heartbeat.text
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
async def test_deletion_rolls_back_on_claim_release_failure_and_retries(
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
        assert deleted.status_code == 500, deleted.text
        assert not await env.db.fetch_value(
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
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.tasks}} WHERE task_id=$1",
        UUID(retried.json()["task_id"]),
    )
    assert (
        await env.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
            TEAM,
            ref,
        )
        == 0
    )
    repeated = await request_as(env, alias="alice", method="DELETE", path=path)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == retried.json()
    contexts = [
        ctx
        for event_type, ctx in env.dispatched
        if event_type == "task.deleted" and ctx["task_ref"] == ref
    ]
    assert [ctx["released_claim_workspace_ids"] for ctx in contexts] == [
        [str(env.actors["alice"].workspace)],
        [],
    ]


@pytest.mark.asyncio
async def test_deletion_notification_failure_reports_the_committed_release(
    privacy_app, monkeypatch
):
    from aweb.mutation_hooks import create_mutation_handler
    from test_workspace_delete_real_http import _redis_without_command

    env = privacy_app
    created = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Committed deletion notification"},
    )
    assert created.status_code == 200, created.text
    ref = created.json()["task_ref"]
    path = f"/v1/tasks/{ref}"
    claimed = await request_as(
        env, alias="alice", method="PATCH", path=path, payload={"status": "in_progress"}
    )
    assert claimed.status_code == 200, claimed.text
    async with _redis_without_command(env, "publish") as restricted:
        with monkeypatch.context() as configured:
            configured.setattr(
                env.app.state,
                "on_mutation",
                create_mutation_handler(restricted, env.infra),
            )
            response = await request_as(env, alias="alice", method="DELETE", path=path)
            assert response.status_code == 503, response.text
            detail = response.json()["detail"]
            assert detail["code"] == "task_deleted_notification_failed"
            assert detail["failed_stages"] == ["publication"]
            assert detail["remaining_claims"] == 0
    deleted = await request_as(env, alias="alice", method="GET", path=path)
    assert deleted.status_code == 404, deleted.text
    assert not await env.db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        TEAM,
        ref,
    )
    repeated = await request_as(env, alias="alice", method="DELETE", path=path)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["task_ref"] == ref


@pytest.mark.asyncio
async def test_narrow_heartbeat_refreshes_only_current_metadata_indices(privacy_app):
    from aweb.presence import update_agent_presence

    env = privacy_app
    workspace = str(env.actors["alice"].workspace)
    await update_agent_presence(
        env.redis,
        workspace_id=workspace,
        alias="alice",
        team_id=TEAM,
        repo_id="old-repo",
        current_branch="old-branch",
        ttl_seconds=30,
    )
    await update_agent_presence(
        env.redis,
        workspace_id=workspace,
        alias="alice",
        team_id=TEAM,
        repo_id="current-repo",
        current_branch="current-branch",
        ttl_seconds=30,
    )
    old_key = "idx:repo_workspaces:old-repo"
    current_key = "idx:repo_workspaces:current-repo"
    branch_key = "idx:branch_workspaces:current-repo:current-branch"
    for key in (old_key, current_key, branch_key):
        await env.redis.expire(key, 1)
    heartbeat = await request_as(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat"
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert await env.redis.ttl(current_key) > 30
    assert await env.redis.ttl(branch_key) > 30
    assert await env.redis.ttl(old_key) <= 1


@pytest.mark.asyncio
async def test_claim_waits_for_workspace_before_locking_the_agent(privacy_app):
    import asyncio

    env = privacy_app
    task = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Claim lock order"},
    )
    assert task.status_code == 200, task.text
    pending = None
    try:
        async with env.db.transaction() as held:
            await held.fetch_one(
                "SELECT workspace_id FROM {{tables.workspaces}} WHERE workspace_id=$1 FOR UPDATE",
                env.actors["alice"].workspace,
            )
            pending = asyncio.create_task(
                request_as(
                    env,
                    alias="alice",
                    method="PATCH",
                    path=f"/v1/tasks/{task.json()['task_ref']}",
                    payload={"status": "in_progress"},
                )
            )
            async with asyncio.timeout(4):
                while True:
                    await held.fetch_value("SELECT pg_stat_clear_snapshot()")
                    blocked = await held.fetch_value("""
                        SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                          WHERE datname=current_database() AND pid<>pg_backend_pid()
                            AND wait_event_type='Lock' AND query LIKE '%workspaces%'
                            AND query LIKE '%FOR UPDATE%')
                    """)
                    if blocked:
                        break
                    assert not pending.done(), (await pending).text
                    await asyncio.sleep(0.01)
            # The waiting request must not hold a member lock. This real second
            # connection can lock the agent without waiting, matching lifecycle.
            agent = await held.fetch_value(
                "SELECT agent_id FROM {{tables.agents}} WHERE agent_id=$1 FOR UPDATE NOWAIT",
                env.actors["alice"].id,
            )
            assert agent == env.actors["alice"].id
        response = await pending
        assert response.status_code == 200, response.text
        holders = await env.db.fetch_all(
            "SELECT workspace_id FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
            TEAM,
            task.json()["task_ref"],
        )
        assert [row["workspace_id"] for row in holders] == [
            env.actors["alice"].workspace
        ]
    finally:
        if pending is not None:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
