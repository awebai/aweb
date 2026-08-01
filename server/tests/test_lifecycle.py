from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import aweb.lifecycle as lifecycle
from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
    plan_lifecycle_cascade,
)


async def _seed_workspace_with_claim(aweb_db, *, identity_scope: str = "local"):
    team_id = "backend:acme.com"
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        """,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', $3, 'developer')
        """,
        agent_id,
        team_id,
        identity_scope,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'alice', 'Alice', 'developer', 'manual', $4)
        """,
        workspace_id,
        team_id,
        agent_id,
        datetime.now(timezone.utc) - timedelta(hours=1),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, 'alice', 'Alice', 'backend-777', NOW())
        """,
        team_id,
        workspace_id,
    )
    return team_id, agent_id, workspace_id


class _FakeRedis:
    def __init__(self):
        self.zrem_calls: list[tuple[str, str]] = []

    async def zrem(self, key: str, member: str):
        self.zrem_calls.append((key, member))
        return 1


async def _seed_waiting_chat(aweb_db, *, team_id: str, agent_id):
    session_id = uuid4()
    did = "did:key:z6Mkalice"
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (
            session_id, team_id, created_by, wait_seconds, wait_started_at,
            wait_started_by
        )
        VALUES ($1, $2, $3, 60, NOW(), $4)
        """,
        session_id,
        team_id,
        did,
        agent_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES ($1, $2, $3, 'alice')
        """,
        session_id,
        did,
        agent_id,
    )
    return session_id, did


def _request(
    *, team_id: str, agent_id, workspace_id, dry_run: bool = False
) -> LifecycleCascadeRequest:
    return LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(
            actor_id=str(agent_id),
            actor_type="agent",
            authority="test",
        ),
        team_id=team_id,
        target_agent_id=str(agent_id),
        target_workspace_ids=(str(workspace_id),),
        workspace_scope="explicit",
        dry_run=dry_run,
        require_identity_scope="local",
        stale_before=datetime.now(timezone.utc) - timedelta(minutes=10),
        mark_local_agent_deleted=True,
    )


@pytest.mark.asyncio
async def test_lifecycle_plan_reports_claims_without_mutating(aweb_cloud_db):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db
    )

    result = await plan_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        _request(
            team_id=team_id,
            agent_id=agent_id,
            workspace_id=workspace_id,
            dry_run=True,
        ),
    )

    assert result.dry_run is True
    assert result.errors == ()
    assert result.task_unclaim_count == 1
    assert result.presence_cleanup_status == "planned"
    assert result.workspace_changes[0].workspace_id == str(workspace_id)

    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert workspace_deleted_at is None
    assert claim_count == 1


@pytest.mark.asyncio
async def test_lifecycle_outer_transaction_defers_side_effects_until_commit(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    session_id, did = await _seed_waiting_chat(
        db, team_id=team_id, agent_id=agent_id
    )
    published: list[tuple[str, str]] = []
    presence_clears: list[tuple[str, ...]] = []
    waiting_clears: list[tuple[str, str]] = []

    async def _capture_workspace_event(_redis, event):
        published.append(("workspace", event.task_ref))
        return 1

    async def _capture_team_event(_redis, event):
        published.append(("team", event.task_ref))
        return 1

    async def _capture_presence(_redis, workspace_ids):
        presence_clears.append(tuple(workspace_ids))
        return len(workspace_ids)

    async def _capture_waiting(_redis, captured_session_id, captured_did):
        waiting_clears.append((captured_session_id, captured_did))

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)
    monkeypatch.setattr(lifecycle, "unregister_waiting", _capture_waiting)

    async with db.transaction() as outer:
        result = await apply_lifecycle_cascade(
            outer,
            object(),
            _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
        )
        assert result.post_commit_status == "pending"
        assert result.outbox_operation_id is not None
        assert published == []
        assert presence_clears == []
        assert waiting_clears == []

    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        object(),
        operation_id=result.outbox_operation_id,
    )

    assert replay.pending_count == 0
    assert set(published) == {("workspace", "backend-777"), ("team", "backend-777")}
    assert set(presence_clears[0]) == {str(workspace_id), str(agent_id)}
    assert waiting_clears == [(str(session_id), did)]


@pytest.mark.asyncio
async def test_lifecycle_outer_transaction_rollback_emits_no_side_effects(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    observed: list[str] = []

    async def _capture_workspace_event(_redis, _event):
        observed.append("workspace_event")
        return 1

    async def _capture_team_event(_redis, _event):
        observed.append("team_event")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        observed.append("presence")
        return 1

    async def _capture_waiting(_redis, _session_id, _did):
        observed.append("waiting")

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)
    monkeypatch.setattr(lifecycle, "unregister_waiting", _capture_waiting)

    class _Rollback(Exception):
        pass

    with pytest.raises(_Rollback):
        async with db.transaction() as outer:
            result = await apply_lifecycle_cascade(
                outer,
                object(),
                _request(
                    team_id=team_id,
                    agent_id=agent_id,
                    workspace_id=workspace_id,
                ),
            )
            assert result.post_commit_status == "pending"
            assert result.outbox_operation_id is not None
            assert observed == []
            raise _Rollback

    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        object(),
        operation_id=result.outbox_operation_id,
    )
    assert replay.pending_count == 0
    assert observed == []
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    ) == 1
    assert await db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    ) is None


@pytest.mark.asyncio
async def test_lifecycle_plain_handle_still_publishes_side_effects(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    observed: list[str] = []

    async def _capture_workspace_event(_redis, _event):
        observed.append("workspace_event")
        return 1

    async def _capture_team_event(_redis, _event):
        observed.append("team_event")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        observed.append("presence")
        return 1

    async def _capture_waiting(_redis, _session_id, _did):
        observed.append("waiting")

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)
    monkeypatch.setattr(lifecycle, "unregister_waiting", _capture_waiting)

    result = await apply_lifecycle_cascade(
        db,
        object(),
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )

    assert result.post_commit_status == "completed"
    assert result.outbox_operation_id is not None
    assert observed.count("workspace_event") == 1
    assert observed.count("team_event") == 1
    assert observed.count("presence") == 1
    assert observed.count("waiting") == 1


@pytest.mark.asyncio
async def test_lifecycle_committed_outbox_replays_after_process_death(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    observed: list[str] = []

    monkeypatch.setattr(
        lifecycle,
        "_schedule_replay_after_outer_transaction",
        lambda *_args, **_kwargs: None,
    )

    async def _capture_workspace_event(_redis, _event):
        observed.append("workspace_event")
        return 1

    async def _capture_team_event(_redis, _event):
        observed.append("team_event")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        observed.append("presence")
        return 1

    async def _capture_waiting(_redis, _session_id, _did):
        observed.append("waiting")

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)
    monkeypatch.setattr(lifecycle, "unregister_waiting", _capture_waiting)

    async with db.transaction() as outer:
        result = await apply_lifecycle_cascade(
            outer,
            object(),
            _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
        )
        assert result.post_commit_status == "pending"

    assert observed == []
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    ) == 0
    assert await db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE delivered_at IS NULL
        """
    ) == 4

    assert result.outbox_operation_id is not None
    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        object(),
        operation_id=result.outbox_operation_id,
    )

    assert replay.delivered_count == 4
    assert replay.pending_count == 0
    assert set(observed) == {
        "workspace_event",
        "team_event",
        "presence",
        "waiting",
    }


@pytest.mark.asyncio
async def test_operation_replay_drains_more_than_the_global_batch_default(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        SELECT $1, $2, 'alice', 'Alice', 'backend-' || series, NOW()
        FROM generate_series(1, 50) AS series
        """,
        team_id,
        workspace_id,
    )
    published: list[str] = []

    monkeypatch.setattr(
        lifecycle,
        "_schedule_replay_after_outer_transaction",
        lambda *_args, **_kwargs: None,
    )

    async def _capture_workspace_event(_redis, _event):
        published.append("workspace")
        return 1

    async def _capture_team_event(_redis, _event):
        published.append("team")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    async with db.transaction() as outer:
        result = await apply_lifecycle_cascade(
            outer,
            object(),
            _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
        )

    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        object(),
        operation_id=result.outbox_operation_id,
    )

    assert replay.delivered_count == 103
    assert replay.pending_count == 0
    assert published.count("workspace") == 51
    assert published.count("team") == 51


@pytest.mark.asyncio
async def test_lifecycle_duplicate_replay_does_not_redeliver_completed_rows(
    aweb_cloud_db, monkeypatch
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    published: list[str] = []

    async def _capture_workspace_event(_redis, _event):
        published.append("workspace")
        return 1

    async def _capture_team_event(_redis, _event):
        published.append("team")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    result = await apply_lifecycle_cascade(
        db,
        object(),
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )
    assert result.post_commit_status == "completed"
    assert published == ["workspace", "team"]

    duplicate = await lifecycle.replay_lifecycle_side_effects(db, object())

    assert duplicate.attempted_count == 0
    assert duplicate.delivered_count == 0
    assert duplicate.pending_count == 0
    assert published == ["workspace", "team"]


@pytest.mark.asyncio
async def test_lifecycle_apply_reports_post_commit_event_failures(aweb_cloud_db, monkeypatch):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db
    )
    cleared_workspaces: list[list[str]] = []

    async def _fail_workspace_event(_redis, _event):
        raise RuntimeError("publish failed")

    async def _capture_team_event(_redis, _event):
        return 1

    async def _capture_presence(_redis, workspace_ids):
        cleared_workspaces.append(list(workspace_ids))
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _fail_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        object(),
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )

    assert result.errors == ()
    assert result.post_commit_status == "failed"
    assert result.task_unclaim_count == 1
    assert result.workspace_event_count == 0
    assert result.team_event_count == 1
    assert len(result.failed_event_intents) == 1
    assert result.failed_event_intents[0].event_kind == "workspace_task_unclaimed"
    assert result.presence_cleanup_status == "cleared"
    assert {str(workspace_id), str(agent_id)} in [set(ids) for ids in cleared_workspaces]

    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert claim_count == 0
    assert workspace_deleted_at is not None
    assert await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE delivered_at IS NULL
        """
    ) == 1

    retried: list[str] = []

    async def _retry_workspace_event(_redis, event):
        retried.append(event.task_ref)
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _retry_workspace_event)
    replay = await lifecycle.replay_lifecycle_side_effects(
        aweb_cloud_db.aweb_db, object()
    )
    duplicate = await lifecycle.replay_lifecycle_side_effects(
        aweb_cloud_db.aweb_db, object()
    )

    assert replay.workspace_event_count == 1
    assert replay.pending_count == 0
    assert retried == ["backend-777"]
    assert duplicate.attempted_count == 0


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_cleans_coordination_state(
    aweb_cloud_db,
    monkeypatch,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="global",
    )
    second_workspace_id = uuid4()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        "ALTER TABLE {{tables.agents}} ADD COLUMN signing_key_enc BYTEA"
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET signing_key_enc = $2 WHERE agent_id = $1",
        agent_id,
        b"hosted-key",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'alice-laptop', 'Alice', 'developer', 'manual', $4)
        """,
        second_workspace_id,
        team_id,
        agent_id,
        datetime.now(timezone.utc) - timedelta(hours=2),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, 'alice-laptop', 'Alice', 'backend-778', NOW())
        """,
        team_id,
        second_workspace_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.reservations}} (
            team_id, resource_key, holder_alias, holder_agent_id, expires_at
        )
        VALUES ($1, 'repo:deploy', 'alice', $2, NOW() + INTERVAL '1 hour')
        """,
        team_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (
            session_id, team_id, created_by, wait_seconds, wait_started_at,
            wait_started_by
        )
        VALUES ($1, $2, 'did:key:z6Mkalice', 60, NOW(), $3)
        """,
        session_id,
        team_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES ($1, 'did:key:z6Mkalice', $2, 'alice')
        """,
        session_id,
        agent_id,
    )
    redis = _FakeRedis()

    async def _publish_noop(_redis, _event):
        return 1

    async def _clear_presence_noop(_redis, workspace_ids):
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _publish_noop)
    monkeypatch.setattr(lifecycle, "publish_team_event", _publish_noop)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _clear_presence_noop)

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        redis,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    assert result.errors == ()
    assert result.identity_archived is True
    assert result.task_unclaim_count == 2
    assert result.reservation_release_count == 1
    assert result.chat_participant_cleanup_count == 1
    assert result.chat_waiting_cleanup_status == "cleared"
    assert result.chat_waiting_session_clear_count == 1
    assert result.chat_waiting_cleared_count == 1
    assert len(result.workspace_changes) == 2
    assert "agent.archive_global" in result.completed_mutations
    assert redis.zrem_calls == [(f"chat:waiting:{session_id}", "did:key:z6Mkalice")]

    agent = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT status, deleted_at, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        agent_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id = $1",
        team_id,
    )
    reservation_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.reservations}} WHERE holder_agent_id = $1",
        agent_id,
    )
    participant_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_participants}} WHERE agent_id = $1",
        agent_id,
    )
    wait_started_by = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT wait_started_by FROM {{tables.chat_sessions}} WHERE session_id = $1",
        session_id,
    )
    active_workspace_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.workspaces}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        agent_id,
    )

    assert agent["status"] == "archived"
    assert agent["deleted_at"] is not None
    assert agent["signing_key_enc"] is None
    assert claim_count == 0
    assert reservation_count == 0
    assert participant_count == 0
    assert wait_started_by is None
    assert active_workspace_count == 0


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_without_workspace_archives_agent(
    aweb_cloud_db,
):
    team_id = "backend:acme.com"
    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        """,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', 'global', 'developer')
        """,
        agent_id,
        team_id,
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    assert result.errors == ()
    assert result.workspace_changes == ()
    assert result.identity_archived is True
    assert result.post_commit_status == "completed"
    assert agent["status"] == "archived"
    assert agent["deleted_at"] is not None


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_rejects_workspace_subset(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="global",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            target_workspace_ids=(str(workspace_id),),
            workspace_scope="explicit",
            require_identity_scope="global",
        ),
    )

    assert [error.code for error in result.errors] == [
        "global_archive_requires_all_agent_workspaces"
    ]
    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert agent["status"] == "active"
    assert agent["deleted_at"] is None
    assert workspace_deleted_at is None
    assert claim_count == 1


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_rejects_non_global_target(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="local",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    assert "lifecycle_identity_scope_precondition_failed" in {
        error.code for error in result.errors
    }
    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert agent["status"] == "active"
    assert agent["deleted_at"] is None
    assert workspace_deleted_at is None
    assert claim_count == 1
