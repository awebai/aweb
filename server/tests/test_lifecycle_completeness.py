"""Lifecycle cleanup through the real SQL transaction and Redis outbox."""

import asyncio
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID

import pytest
from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.messaging.waiting import get_waiting_agents, register_waiting
from aweb.lifecycle_agent import apply_agent_disposition_on
from aweb.member_status import MemberStatus
from test_dashboard_privacy import TEAM, _request
from test_dashboard_privacy import privacy_app
from test_team_room import admit_room_member
from test_workspace_liveness_http import _send_member_request
from test_lifecycle import _seed_waiting_chat, _seed_workspace_with_claim
from test_lifecycle import lifecycle_redis

__all__ = ["lifecycle_redis", "privacy_app"]


class WorkspaceState(StrEnum):
    ACTIVE = "active"
    DELETED = "deleted"


@pytest.mark.asyncio
async def test_outer_transaction_removed_workspace_retry_completes_without_replay(
    privacy_app,
):
    env = privacy_app
    member = env.actors["alice"]
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(
            actor_id="owner", actor_type="system", authority="embedding"
        ),
        team_id=TEAM,
        target_workspace_ids=(str(member.workspace),),
        workspace_scope="explicit",
    )
    arguments = dict(registry_client=env.app.state.awid_registry_client)
    removed = await apply_lifecycle_cascade(env.db, env.redis, request, **arguments)
    assert removed.errors == ()
    assert [change.workspace_id for change in removed.workspace_changes] == [
        str(member.workspace)
    ]
    async with env.db.transaction() as outer:
        before = await outer.fetch_value(
            "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1",
            TEAM,
        )
        for _attempt in range(2):
            result = await apply_lifecycle_cascade(
                outer, env.redis, request, **arguments
            )
            assert not result.errors
            assert result.post_commit_status == "completed"
            assert result.outbox_operation_id is None
            assert result.workspace_changes == ()
            assert result.task_unclaim_count == 0
        assert (
            await outer.fetch_value(
                "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1",
                TEAM,
            )
            == before
        )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NULL FROM {{tables.agents}} WHERE agent_id=$1", member.id
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", list(AgentDisposition))
@pytest.mark.parametrize("workspace_state", list(WorkspaceState))
async def test_agent_cleanup_retains_history_and_releases_live_coordination(
    privacy_app, disposition, workspace_state
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    for alias in ("alice", "bob"):
        await admit_room_member(env, alias=alias)
    actor = LifecycleActor(
        actor_id="test-host", actor_type="system", authority="embedding"
    )
    registry = env.app.state.awid_registry_client
    if workspace_state is WorkspaceState.DELETED:
        removed = await apply_lifecycle_cascade(
            env.db,
            env.redis,
            LifecycleCascadeRequest(
                operation="cleanup_agent_coordination_state",
                actor=actor,
                team_id=TEAM,
                target_workspace_ids=(str(alice.workspace),),
            ),
            registry_client=registry,
        )
        assert removed.errors == ()
        assert removed.workspace_changes
        assert not removed.identity_deleted

    mail = await _request(
        env,
        "alice",
        "POST",
        "/v1/messages",
        {"to_did": bob.did, "subject": "Cleanup history", "body": "retained mail"},
    )
    assert mail.status_code == 200, mail.text
    chat = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {"to_dids": [bob.did], "message": "retained history"},
    )
    assert chat.status_code == 200, chat.text
    message_id, session_id = (
        UUID(mail.json()["message_id"]),
        UUID(chat.json()["session_id"]),
    )
    control = (
        ("POST", "/v1/reservations", {"resource_key": "cleanup", "ttl_seconds": 600}),
        (
            "POST",
            "/v1/session-leases",
            {"session_id": "cleanup", "session_key": "c" * 32},
        ),
        ("PUT", "/v1/agents/me/status-host", {"host_did": bob.did}),
    )
    for method, route, body in control:
        response = await _send_member_request(
            env, alias="alice", method=method, path=route, body=body
        )
        assert response.status_code == 200, response.text

    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=actor,
        team_id=TEAM,
        target_agent_id=str(alice.id),
        workspace_scope="all_for_agent",
        agent_disposition=disposition,
    )
    result = await apply_lifecycle_cascade(
        env.db, env.redis, request, registry_client=registry
    )
    assert result.errors == ()
    row = await env.db.fetch_one(
        "SELECT status,deleted_at FROM {{tables.agents}} WHERE agent_id=$1", alice.id
    )
    expected_status = {
        AgentDisposition.PRESERVED: "active",
        AgentDisposition.PREPARED_REMOVAL: "active",
        AgentDisposition.DELETED: "deleted",
        AgentDisposition.RETIRED: "retired",
    }[disposition]
    assert row["status"] == expected_status
    assert (row["deleted_at"] is None) == (disposition is AgentDisposition.PRESERVED)
    assert result.identity_deleted == (disposition is AgentDisposition.DELETED)
    assert result.identity_retired == (disposition is AgentDisposition.RETIRED)
    assert result.chat_participant_cleanup_count == 1
    assert not await env.db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2)",
        session_id,
        alice.did,
    )
    assert await env.db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2)",
        session_id,
        bob.did,
    )
    assert await env.db.fetch_value(
        """SELECT EXISTS(
            SELECT 1 FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2
        )""",
        session_id,
        alice.did,
    )
    assert (
        await env.db.fetch_value(
            "SELECT body FROM {{tables.chat_messages}} WHERE session_id=$1", session_id
        )
        == "retained history"
    )
    assert (
        await env.db.fetch_value(
            "SELECT body FROM {{tables.messages}} WHERE message_id=$1", message_id
        )
        == "retained mail"
    )
    for table in ("reservations", "session_admission_leases", "agent_status_hosts"):
        assert not await env.db.fetch_value(
            f"SELECT COUNT(*) FROM {{{{tables.{table}}}}} WHERE team_id=$1", TEAM
        )
    repeated = await apply_lifecycle_cascade(
        env.db, env.redis, request, registry_client=registry
    )
    assert repeated.errors == ()
    assert repeated.identity_deleted == result.identity_deleted
    assert repeated.identity_retired == result.identity_retired


@pytest.mark.asyncio
async def test_cleanup_scope_refuses_an_agent_of_another_team(
    aweb_cloud_db, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    result = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(
                actor_id="owner", actor_type="system", authority="embedding"
            ),
            team_id="another:acme.com",
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=AgentDisposition.DELETED,
        ),
        registry_client=None,
    )
    assert [error.code for error in result.errors] == ["agent_not_found"]
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent
        )
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            workspace,
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
                registry_client=None,
            )
            assert not result.errors
            assert result.post_commit_status == "pending"
            assert not await tx.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1)",
                session,
            )
            raise RuntimeError("outer transaction refused")
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent
        )
        is None
    )
    assert (
        await db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            workspace,
        )
        is None
    )
    assert await db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2)",
        session,
        did,
    )
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            workspace,
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
            actor=LifecycleActor(
                actor_id="owner", actor_type="system", authority="embedding"
            ),
            team_id=TEAM,
            target_agent_id=str(agent),
            workspace_scope="all_for_agent",
            agent_disposition=AgentDisposition.PREPARED_REMOVAL,
        ),
        registry_client=env.app.state.awid_registry_client,
    )
    assert not result.errors
    response = await _send_member_request(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat", body={}
    )
    assert response.status_code == 403, response.text
    assert (
        await env.db.fetch_value(
            "SELECT status FROM {{tables.agents}} WHERE agent_id=$1", agent
        )
        == "active"
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.agents}} WHERE agent_id=$1", agent
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal", [AgentDisposition.DELETED, AgentDisposition.RETIRED]
)
async def test_concurrent_terminal_disposition_cannot_be_restored_by_prepared_removal(
    aweb_cloud_db, lifecycle_redis, terminal
):
    """The checked native state and its write agree under READ COMMITTED."""
    db = aweb_cloud_db.aweb_db
    team, agent, workspace = await _seed_workspace_with_claim(db)
    prepared_pid = asyncio.get_running_loop().create_future()

    async def prepare():
        async with db.transaction() as prepared_tx:
            prepared_pid.set_result(
                await prepared_tx.fetch_value("SELECT pg_backend_pid()")
            )
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
                registry_client=None,
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
                while not await db.fetch_value(
                    "SELECT cardinality(pg_blocking_pids($1)) > 0", pid
                ):
                    assert not prepared_task.done()
                    await asyncio.sleep(0.01)
        result = await prepared_task
        assert [error.code for error in result.errors] == [
            "terminal_agent_cannot_prepare_removal"
        ]
        expected_status = {
            AgentDisposition.DELETED: MemberStatus.DELETED,
            AgentDisposition.RETIRED: MemberStatus.RETIRED,
        }[terminal]
        assert (
            await db.fetch_value(
                "SELECT status FROM {{tables.agents}} WHERE agent_id=$1", agent
            )
            == expected_status
        )
        assert (
            await db.fetch_value(
                "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
                workspace,
            )
            is None
        )
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
                workspace,
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
    privacy_app,
):
    """A released embedding retry stays scoped after its workspace is deleted."""
    env = privacy_app
    member = env.actors["alice"]
    actor = LifecycleActor(actor_id="owner", actor_type="system", authority="embedding")
    registry = env.app.state.awid_registry_client
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=actor,
        team_id=TEAM,
        target_workspace_ids=(str(member.workspace),),
    )
    removed = await apply_lifecycle_cascade(
        env.db, env.redis, request, registry_client=registry
    )
    assert removed.errors == ()
    assert removed.workspace_changes
    result = await apply_lifecycle_cascade(
        env.db, env.redis, replace(request, team_id=None), registry_client=registry
    )
    assert result.errors == ()
    assert result.workspace_changes == ()
    assert result.identity_deleted is False
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", member.id
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT team_id FROM {{tables.workspaces}} WHERE workspace_id=$1",
            member.workspace,
        )
        == TEAM
    )


@pytest.mark.asyncio
async def test_explicit_workspace_cannot_select_another_agent_for_cleanup(privacy_app):
    """The exact agent binding, not a supplied workspace id, chooses the target."""
    env = privacy_app
    alice = env.actors["alice"]
    bob = env.actors["bob"]
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=LifecycleActor(
            actor_id="owner", actor_type="system", authority="embedding"
        ),
        team_id=TEAM,
        target_agent_id=str(alice.id).upper(),
        target_workspace_ids=(str(bob.workspace),),
        agent_disposition=AgentDisposition.PRESERVED,
    )
    refused = await apply_lifecycle_cascade(
        env.db, env.redis, request, registry_client=env.app.state.awid_registry_client
    )
    assert [error.code for error in refused.errors] == [
        "lifecycle_workspace_target_mismatch"
    ]
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
        registry_client=env.app.state.awid_registry_client,
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
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            bob.workspace,
        )
        is None
    )


@pytest.mark.asyncio
async def test_cleanup_locks_all_workspaces_before_deleting_any_claim(
    privacy_app,
):
    """Cleanup and claim release share UUID workspace order before claim writes."""
    env = privacy_app
    db = env.db
    aliases = sorted(("alice", "bob"), key=lambda alias: env.actors[alias].workspace)
    low, high = (env.actors[alias].workspace for alias in aliases)
    # Claim high first so the product puts low first in recency order.
    for alias in reversed(aliases):
        task = await _send_member_request(
            env,
            alias=alias,
            method="POST",
            path="/v1/tasks",
            body={"title": f"Cleanup ordering claim for {alias}"},
        )
        assert task.status_code == 200, task.text
        claimed = await _send_member_request(
            env,
            alias=alias,
            method="PATCH",
            path=f"/v1/tasks/{task.json()['task_ref']}",
            body={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text
    cleanup_pid = asyncio.get_running_loop().create_future()

    async def clean():
        async with db.transaction() as cleanup_tx:
            cleanup_pid.set_result(
                await cleanup_tx.fetch_value("SELECT pg_backend_pid()")
            )
            return await apply_lifecycle_cascade(
                cleanup_tx,
                env.redis,
                LifecycleCascadeRequest(
                    operation="cleanup_agent_coordination_state",
                    actor=LifecycleActor(
                        actor_id="owner", actor_type="system", authority="embedding"
                    ),
                    team_id=TEAM,
                    target_workspace_ids=(str(low), str(high)),
                ),
                registry_client=env.app.state.awid_registry_client,
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
                while not await db.fetch_value(
                    "SELECT cardinality(pg_blocking_pids($1)) > 0", pid
                ):
                    assert not cleanup_task.done(), cleanup_task.result().errors
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
                "SELECT count(*) FROM {{tables.task_claims}} WHERE team_id=$1", TEAM
            )
            == 0
        )
    finally:
        if cleanup_task is not None and not cleanup_task.done():
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
