"""Lifecycle cleanup through the real SQL transaction and Redis outbox."""

import asyncio
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

import pytest
import aweb.lifecycle as lifecycle
from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
    replay_lifecycle_side_effects,
)
from aweb.messaging.waiting import get_waiting_agents, register_waiting
from aweb.lifecycle_agent import apply_agent_disposition_on
from aweb.member_status import MemberStatus
from aweb.presence import update_agent_presence
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_workspace_liveness_http import _send_member_request
from test_lifecycle import _seed_waiting_chat, _seed_workspace_with_claim
from test_lifecycle import lifecycle_redis as lifecycle_redis


class WorkspaceState(StrEnum):
    ACTIVE = "active"
    DELETED = "deleted"
    ABSENT = "absent"


@pytest.mark.asyncio
async def test_outer_transaction_removed_workspace_retry_completes_without_replay(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    await db.execute("DELETE FROM {{tables.task_claims}} WHERE workspace_id=$1", workspace)
    await db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE workspace_id=$1", workspace
    )
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
        team_id=team,
        target_workspace_ids=(str(workspace),),
        workspace_scope="explicit",
    )
    replay_tasks_before = set(lifecycle._outbox_replay_tasks)
    async with db.transaction() as outer:
        for _attempt in range(2):
            result = await apply_lifecycle_cascade(outer, None, request)
            assert not result.errors
            assert result.post_commit_status == "completed"
            assert result.outbox_operation_id is None
            assert result.workspace_changes == ()
            assert result.task_unclaim_count == 0
            assert not (lifecycle._outbox_replay_tasks - replay_tasks_before)
        assert (
            await outer.fetch_value(
                "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1",
                team,
            )
            == 0
        )
    assert await db.fetch_value(
        "SELECT deleted_at IS NULL FROM {{tables.agents}} WHERE agent_id=$1", agent
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", list(AgentDisposition))
@pytest.mark.parametrize("workspace_state", list(WorkspaceState))
async def test_agent_cleanup_retains_history_and_completion_credentials_without_live_workspace(
    aweb_cloud_db, lifecycle_redis, disposition, workspace_state
):
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db, identity_scope="global")
    if workspace_state != WorkspaceState.ACTIVE:
        if workspace_state == WorkspaceState.ABSENT:
            await db.execute("DELETE FROM {{tables.task_claims}} WHERE workspace_id=$1", workspace)
            await db.execute("DELETE FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace)
        else:
            await db.execute(
                "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE workspace_id=$1", workspace
            )
    session, did = await _seed_waiting_chat(db, team_id=team, agent_id=agent)
    await register_waiting(lifecycle_redis, str(session), did)
    await update_agent_presence(
        lifecycle_redis, workspace_id=str(agent), alias="alice", team_id=team
    )
    if workspace_state != WorkspaceState.ABSENT:
        await update_agent_presence(
            lifecycle_redis, workspace_id=str(workspace), alias="alice", team_id=team
        )
    mail_id = uuid4()
    await db.execute(
        "INSERT INTO {{tables.messages}} (message_id,team_id,from_did,to_did,from_agent_id,to_agent_id,body) "
        "VALUES ($1,$2,$3,$3,$4,$4,'retained mail')",
        mail_id,
        team,
        did,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.agent_status}} (agent_id,team_id,publisher_did,seq,reachable,observed_at,valid_until,signed_payload,signature) "
        "VALUES ($1,$2,$3,1,'online',NOW(),NOW()+INTERVAL '1 hour','{}','fixture')",
        agent,
        team,
        did,
    )
    await db.execute(
        "INSERT INTO {{tables.chat_messages}} (session_id,from_agent_id,from_did,from_alias,body) "
        "VALUES ($1,$2,$3,'alice','retained history')",
        session,
        agent,
        did,
    )
    await db.execute(
        "INSERT INTO {{tables.reservations}} (team_id,resource_key,holder_alias,holder_agent_id,expires_at) "
        "VALUES ($1,'cleanup','alice',$2,NOW()+INTERVAL '1 hour')",
        team,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.session_admission_leases}} "
        "(team_id,principal_agent_id,session_id,session_key_hash,acquired_at,expires_at) "
        "VALUES ($1,$2,'session',$3,NOW(),NOW()+INTERVAL '1 hour')",
        team,
        agent,
        b"hash",
    )
    grant = uuid4()
    await db.execute(
        "INSERT INTO {{tables.identity_session_grants}} "
        "(grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at) "
        "VALUES ($1,$2,$3,'did:key:z6Mkgrant',ARRAY['mail.read'],NOW(),NOW()+INTERVAL '1 hour')",
        grant,
        team,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.identity_grant_liveness}} "
        "(grant_id,team_id,subject_agent_id,alias,session_did_key,last_seen_at,expires_at) "
        "VALUES ($1,$2,$3,'alice','did:key:z6Mkgrant',NOW(),NOW()+INTERVAL '1 hour')",
        grant,
        team,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.control_signals}} (team_id,target_agent_id,from_agent_id,signal_type) "
        "VALUES ($1,$2,$2,'pause')",
        team,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.agent_status_hosts}} (team_id,agent_id,host_did,designated_by_did) "
        "VALUES ($1,$2,$3,$3)",
        team,
        agent,
        did,
    )
    result = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
            team_id=team,
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=disposition,
        ),
    )
    assert result.errors == ()
    row = await db.fetch_one(
        "SELECT status,deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent
    )
    expected_status = {
        AgentDisposition.PRESERVED: "active",
        AgentDisposition.PREPARED_REMOVAL: "active",
        AgentDisposition.DELETED: "deleted",
        AgentDisposition.RETIRED: "retired",
    }[disposition]
    assert row["status"] == expected_status
    assert (row["deleted_at"] is None) == (disposition == AgentDisposition.PRESERVED)
    assert result.identity_deleted == (disposition == AgentDisposition.DELETED)
    assert result.identity_retired == (disposition == AgentDisposition.RETIRED)
    assert await db.fetch_value(
        "SELECT left_at IS NOT NULL FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
        session,
        did,
    )
    assert (
        await db.fetch_value(
            "SELECT body FROM {{tables.chat_messages}} WHERE session_id=$1", session
        )
        == "retained history"
    )
    assert (
        await db.fetch_value("SELECT body FROM {{tables.messages}} WHERE message_id=$1", mail_id)
        == "retained mail"
    )
    assert await lifecycle_redis.exists(f"presence:{agent}") == 0
    if workspace_state != WorkspaceState.ABSENT:
        assert await lifecycle_redis.exists(f"presence:{workspace}") == 0
    assert await get_waiting_agents(lifecycle_redis, str(session), [did]) == []
    assert (
        await db.fetch_value(
            "SELECT wait_started_by FROM {{tables.chat_sessions}} WHERE session_id=$1", session
        )
        is None
    )
    for table in (
        "reservations",
        "session_admission_leases",
        "identity_grant_liveness",
        "agent_status_hosts",
        "agent_status",
    ):
        assert (
            await db.fetch_value(
                f"SELECT count(*) FROM {{{{tables.{table}}}}} WHERE team_id=$1", team
            )
            == 0
        )
    assert await db.fetch_value(
        "SELECT consumed_at IS NOT NULL FROM {{tables.control_signals}} WHERE target_agent_id=$1",
        agent,
    )
    assert (
        await db.fetch_value(
            "SELECT revoked_at FROM {{tables.identity_session_grants}} WHERE grant_id=$1", grant
        )
        is None
    )
    replay = await replay_lifecycle_side_effects(
        db, lifecycle_redis, operation_id=result.outbox_operation_id
    )
    assert replay.pending_count == 0
    repeated = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
            team_id=team,
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=disposition,
        ),
    )
    assert repeated.errors == ()
    assert repeated.identity_deleted == result.identity_deleted
    assert repeated.identity_retired == result.identity_retired
    assert (
        await db.fetch_value("SELECT status FROM {{tables.agents}} WHERE agent_id=$1", agent)
        == expected_status
    )


@pytest.mark.asyncio
async def test_cleanup_scope_refuses_an_agent_of_another_team(aweb_cloud_db, lifecycle_redis):
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    result = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
            team_id="another:acme.com",
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=AgentDisposition.DELETED,
        ),
    )
    assert [error.code for error in result.errors] == ["agent_not_found"]
    assert (
        await db.fetch_value("SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent)
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
        )
        is None
    )


@pytest.mark.asyncio
async def test_coordination_cleanup_rolls_back_with_its_outer_transaction(
    aweb_cloud_db, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    session, did = await _seed_waiting_chat(db, team_id=team, agent_id=agent)
    await register_waiting(lifecycle_redis, str(session), did)
    with pytest.raises(RuntimeError, match="outer transaction refused"):
        async with db.transaction() as tx:
            result = await apply_lifecycle_cascade(
                tx,
                lifecycle_redis,
                LifecycleCascadeRequest(
                    operation="cleanup_agent_coordination_state",
                    actor=LifecycleActor(
                        actor_id="owner", actor_type="system", authority="embedding"
                    ),
                    team_id=team,
                    target_agent_id=str(agent),
                    workspace_scope="all_for_agent",
                    agent_disposition=AgentDisposition.PREPARED_REMOVAL,
                ),
            )
            assert not result.errors
            assert result.post_commit_status == "pending"
            assert await tx.fetch_value(
                "SELECT left_at IS NOT NULL FROM {{tables.chat_participants}} WHERE session_id=$1",
                session,
            )
            raise RuntimeError("outer transaction refused")
    assert (
        await db.fetch_value("SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent)
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
        )
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT left_at FROM {{tables.chat_participants}} WHERE session_id=$1", session
        )
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", workspace
        )
        == 1
    )
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1", team
        )
        == 0
    )
    assert await get_waiting_agents(lifecycle_redis, str(session), [did]) == [did]


@pytest.mark.asyncio
async def test_prepared_removal_denies_ordinary_member_activity(privacy_app):
    env = privacy_app
    agent = env.actors["alice"].id
    result = await apply_lifecycle_cascade(
        env.db,
        env.redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
            team_id=TEAM,
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=AgentDisposition.PREPARED_REMOVAL,
        ),
    )
    assert not result.errors
    response = await _send_member_request(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat", body={}
    )
    assert response.status_code == 403, response.text
    assert (
        await env.db.fetch_value("SELECT status FROM {{tables.agents}} WHERE agent_id=$1", agent)
        == "active"
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.agents}} WHERE agent_id=$1", agent
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", [AgentDisposition.DELETED, AgentDisposition.RETIRED])
async def test_concurrent_terminal_disposition_cannot_be_restored_by_prepared_removal(
    aweb_cloud_db, lifecycle_redis, terminal
):
    """The checked native state and its write agree under READ COMMITTED."""
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    prepared_pid = asyncio.get_running_loop().create_future()

    async def prepare():
        async with db.transaction() as prepared_tx:
            prepared_pid.set_result(await prepared_tx.fetch_value("SELECT pg_backend_pid()"))
            return await apply_lifecycle_cascade(
                prepared_tx,
                lifecycle_redis,
                LifecycleCascadeRequest(
                    operation="cleanup_agent_coordination_state",
                    actor=LifecycleActor(
                        actor_id="owner", actor_type="system", authority="embedding"
                    ),
                    team_id=team,
                    target_agent_id=str(agent),
                    workspace_scope="all_for_agent",
                    agent_disposition=AgentDisposition.PREPARED_REMOVAL,
                ),
            )

    prepared_task = None
    try:
        async with db.transaction() as terminal_tx:
            terminal_pid = await terminal_tx.fetch_value("SELECT pg_backend_pid()")
            changed = await apply_agent_disposition_on(
                terminal_tx,
                agent_ids=[agent],
                team_id=team,
                disposition=terminal,
                deleted_at=datetime.now(timezone.utc),
            )
            assert changed == 1
            prepared_task = asyncio.create_task(prepare())
            pid = await prepared_pid
            assert pid != terminal_pid
            # Wait for the real blocked UPDATE, not a guessed scheduling delay.
            async with asyncio.timeout(5):
                while not await db.fetch_value("SELECT cardinality(pg_blocking_pids($1)) > 0", pid):
                    assert not prepared_task.done()
                    await asyncio.sleep(0.01)
        result = await prepared_task
        assert [error.code for error in result.errors] == ["terminal_agent_cannot_prepare_removal"]
        expected_status = {
            AgentDisposition.DELETED: MemberStatus.DELETED,
            AgentDisposition.RETIRED: MemberStatus.RETIRED,
        }[terminal]
        assert (
            await db.fetch_value("SELECT status FROM {{tables.agents}} WHERE agent_id=$1", agent)
            == expected_status
        )
        assert (
            await db.fetch_value(
                "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
            )
            is None
        )
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", workspace
            )
            == 1
        )
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1",
                team,
            )
            == 0
        )
    finally:
        if prepared_task is not None and not prepared_task.done():
            prepared_task.cancel()
            with suppress(asyncio.CancelledError):
                await prepared_task


@pytest.mark.asyncio
async def test_omitted_team_retry_uses_retained_workspace_team_binding(
    aweb_cloud_db, lifecycle_redis
):
    """A released embedding retry stays scoped after its workspace is deleted."""
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    await db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE workspace_id=$1", workspace
    )
    result = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
            target_workspace_ids=(str(workspace),),
        ),
    )
    assert result.errors == ()
    assert result.workspace_changes == ()
    assert result.identity_deleted is False
    assert (
        await db.fetch_value("SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent)
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT team_id FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
        )
        == team
    )


@pytest.mark.asyncio
async def test_explicit_workspace_cannot_select_another_agent_for_cleanup(privacy_app):
    """The exact agent binding, not a supplied workspace id, chooses the target."""
    env = privacy_app
    alice = env.actors["alice"]
    bob = env.actors["bob"]
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=LifecycleActor(actor_id="owner", actor_type="system", authority="embedding"),
        team_id=TEAM,
        target_agent_id=str(alice.id).upper(),
        target_workspace_ids=(str(bob.workspace),),
        agent_disposition=AgentDisposition.PRESERVED,
    )
    refused = await apply_lifecycle_cascade(env.db, env.redis, request)
    assert [error.code for error in refused.errors] == ["lifecycle_workspace_target_mismatch"]
    for actor in (alice, bob):
        assert (
            await env.db.fetch_value(
                "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
                actor.workspace,
            )
            is None
        )
    accepted = await apply_lifecycle_cascade(
        env.db,
        env.redis,
        replace(request, target_workspace_ids=(str(alice.workspace),)),
    )
    assert accepted.errors == ()
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
        alice.workspace,
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", alice.id
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", bob.workspace
        )
        is None
    )


@pytest.mark.asyncio
async def test_cleanup_locks_all_workspaces_before_deleting_any_claim(
    aweb_cloud_db, lifecycle_redis
):
    """Cleanup and claim release share UUID workspace order before claim writes."""
    db = aweb_cloud_db.aweb_db
    team, agent, first = await _seed_workspace_with_claim(db, identity_scope="global")
    second = uuid4()
    await db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias,workspace_type,last_seen_at) "
        "VALUES ($1,$2,$3,'alice-second','manual',NOW()-INTERVAL '2 hours')",
        second,
        team,
        agent,
    )
    await db.execute(
        "INSERT INTO {{tables.task_claims}} (team_id,workspace_id,alias,human_name,task_ref,claimed_at) "
        "VALUES ($1,$2,'alice-second','Alice','backend-778',NOW())",
        team,
        second,
    )
    low, high = sorted((first, second))
    await db.execute(
        "UPDATE {{tables.workspaces}} SET updated_at=NOW()-INTERVAL '1 hour' WHERE workspace_id=$1",
        high,
    )
    cleanup_pid = asyncio.get_running_loop().create_future()

    async def clean():
        async with db.transaction() as cleanup_tx:
            cleanup_pid.set_result(await cleanup_tx.fetch_value("SELECT pg_backend_pid()"))
            return await apply_lifecycle_cascade(
                cleanup_tx,
                lifecycle_redis,
                LifecycleCascadeRequest(
                    operation="cleanup_agent_coordination_state",
                    actor=LifecycleActor(
                        actor_id="owner", actor_type="system", authority="embedding"
                    ),
                    team_id=team,
                    target_agent_id=str(agent),
                    workspace_scope="all_for_agent",
                    agent_disposition=AgentDisposition.PRESERVED,
                ),
            )

    cleanup_task = None
    try:
        async with db.transaction() as holder:
            holder_pid = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_one(
                "SELECT workspace_id FROM {{tables.workspaces}} WHERE workspace_id=$1 FOR UPDATE",
                high,
            )
            cleanup_task = asyncio.create_task(clean())
            pid = await cleanup_pid
            assert pid != holder_pid
            async with asyncio.timeout(5):
                while not await db.fetch_value("SELECT cardinality(pg_blocking_pids($1)) > 0", pid):
                    assert not cleanup_task.done()
                    await asyncio.sleep(0.01)
            # A delete before the full workspace lock set would lock this row.
            claim = await holder.fetch_one(
                "SELECT task_ref FROM {{tables.task_claims}} WHERE workspace_id=$1 FOR UPDATE NOWAIT",
                low,
            )
            assert claim is not None
        result = await cleanup_task
        assert result.errors == ()
        assert result.task_unclaim_count == 2
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.task_claims}} WHERE team_id=$1", team
            )
            == 0
        )
    finally:
        if cleanup_task is not None and not cleanup_task.done():
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
