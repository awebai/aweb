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
