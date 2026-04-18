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


async def _seed_workspace_with_claim(aweb_db, *, lifetime: str = "ephemeral"):
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
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', $3, 'developer')
        """,
        agent_id,
        team_id,
        lifetime,
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


def _request(
    *, team_id: str, agent_id, workspace_id, dry_run: bool = False
) -> LifecycleCascadeRequest:
    return LifecycleCascadeRequest(
        operation="delete_ephemeral_workspace",
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
        require_lifetime="ephemeral",
        stale_before=datetime.now(timezone.utc) - timedelta(minutes=10),
        mark_ephemeral_agent_deleted=True,
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
    assert [str(workspace_id)] in cleared_workspaces

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


@pytest.mark.asyncio
async def test_lifecycle_archive_persistent_agent_cleans_coordination_state(
    aweb_cloud_db,
    monkeypatch,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        lifetime="persistent",
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
            operation="archive_persistent_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_lifetime="persistent",
        ),
    )

    assert result.errors == ()
    assert result.identity_archived is True
    assert result.task_unclaim_count == 2
    assert result.reservation_release_count == 1
    assert result.chat_participant_cleanup_count == 1
    assert result.chat_waiting_cleanup_status == "cleared"
    assert result.chat_waiting_cleared_count == 1
    assert len(result.workspace_changes) == 2
    assert "agent.archive_persistent" in result.completed_mutations
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
async def test_lifecycle_archive_persistent_agent_without_workspace_archives_agent(
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
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', 'persistent', 'developer')
        """,
        agent_id,
        team_id,
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_persistent_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_lifetime="persistent",
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
async def test_lifecycle_archive_persistent_agent_rejects_workspace_subset(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        lifetime="persistent",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_persistent_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            target_workspace_ids=(str(workspace_id),),
            workspace_scope="explicit",
            require_lifetime="persistent",
        ),
    )

    assert [error.code for error in result.errors] == [
        "persistent_archive_requires_all_agent_workspaces"
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
async def test_lifecycle_archive_persistent_agent_rejects_non_persistent_target(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        lifetime="ephemeral",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_persistent_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_lifetime="persistent",
        ),
    )

    assert "lifecycle_lifetime_precondition_failed" in {
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
