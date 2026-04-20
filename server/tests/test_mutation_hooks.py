from __future__ import annotations

from uuid import uuid4

import pytest

import aweb.lifecycle as lifecycle
import aweb.mutation_hooks as mutation_hooks
from aweb.events import (
    ReservationAcquiredEvent,
    TaskCreatedEvent,
    TeamChatMessageSentEvent,
    TeamMessageAcknowledgedEvent,
    TeamReservationAcquiredEvent,
    TeamReservationReleasedEvent,
    TeamReservationRenewedEvent,
    TeamTaskClaimedEvent,
    TeamTaskStatusChangedEvent,
    TeamTaskUnclaimedEvent,
)


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


@pytest.mark.asyncio
async def test_agent_deleted_cascade_releases_claims_events_and_presence(aweb_cloud_db, monkeypatch):
    agent_id = uuid4()
    workspace_id = uuid4()
    published_workspace: list[object] = []
    published_team: list[object] = []
    cleared_workspaces: list[list[str]] = []

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6Mkteam')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, lifetime, role)
        VALUES ($1, 'backend:acme.com', 'did:key:z6Mkdeleted', 'alice', 'ephemeral', 'developer')
        """,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role, workspace_type
        )
        VALUES ($1, 'backend:acme.com', $2, 'alice', 'Alice', 'developer', 'manual')
        """,
        workspace_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ('backend:acme.com', $1, 'alice', 'Alice', 'backend-777', NOW())
        """,
        workspace_id,
    )

    async def _capture_workspace_event(_redis, event):
        published_workspace.append(event)
        return 1

    async def _capture_team_event(_redis, event):
        published_team.append(event)
        return 1

    async def _capture_clear_presence(_redis, workspace_ids):
        cleared_workspaces.append(list(workspace_ids))
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_clear_presence)

    handler = mutation_hooks.create_mutation_handler(redis=object(), db_infra=_DbShim(aweb_cloud_db.aweb_db))
    await handler("agent.deleted", {"agent_id": str(agent_id)})

    workspace_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.task_claims}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )

    assert workspace_row["deleted_at"] is not None
    assert claim_count == 0
    assert any(
        event.type == "task.unclaimed"
        and event.workspace_id == str(workspace_id)
        and event.task_ref == "backend-777"
        and event.alias == "alice"
        for event in published_workspace
    )
    assert any(
        event.type == "task.unclaimed"
        and event.team_id == "backend:acme.com"
        and event.task_ref == "backend-777"
        and event.alias == "alice"
        for event in published_team
    )
    assert [str(workspace_id)] in cleared_workspaces


@pytest.mark.asyncio
async def test_mutation_handler_backfills_from_did_aw_from_agent_id(aweb_cloud_db, monkeypatch):
    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6Mkteam')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, did_aw, alias, lifetime, role, messaging_policy)
        VALUES ($1, 'backend:acme.com', 'did:key:z6Mkalice', 'did:aw:alice', 'alice', 'persistent', 'developer', 'everyone')
        """,
        agent_id,
    )

    seen: dict[str, str] = {}

    def _capture_translate(event_type: str, ctx: dict):
        seen["event_type"] = event_type
        seen["from_did_aw"] = str(ctx.get("from_did_aw") or "")
        return None

    monkeypatch.setattr(mutation_hooks, "_translate", _capture_translate)
    monkeypatch.setattr(mutation_hooks, "_translate_team_event", lambda event_type, ctx: None)

    handler = mutation_hooks.create_mutation_handler(redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db))
    await handler(
        "message.sent",
        {
            "team_id": "backend:acme.com",
            "from_agent_id": str(agent_id),
            "to_agent_id": str(uuid4()),
            "message_id": str(uuid4()),
            "subject": "hello",
        },
    )

    assert seen["event_type"] == "message.sent"
    assert seen["from_did_aw"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_mutation_handler_backfills_actor_workspace_id_from_agent_id(aweb_cloud_db, monkeypatch):
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES ($1, 'backend:acme.com', $2, 'alice', 'manual')
        """,
        workspace_id,
        agent_id,
    )

    seen: dict[str, str] = {}

    def _capture_translate(event_type: str, ctx: dict):
        seen["event_type"] = event_type
        seen["actor_workspace_id"] = str(ctx.get("actor_workspace_id") or "")
        return None

    monkeypatch.setattr(mutation_hooks, "_translate", _capture_translate)
    monkeypatch.setattr(mutation_hooks, "_translate_team_event", lambda event_type, ctx: None)

    handler = mutation_hooks.create_mutation_handler(redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db))
    await handler(
        "task.created",
        {
            "team_id": "backend:acme.com",
            "actor_agent_id": str(agent_id),
            "task_ref": "backend-1234",
            "title": "Fix workspace split",
        },
    )

    assert seen["event_type"] == "task.created"
    assert seen["actor_workspace_id"] == str(workspace_id)


def test_translate_uses_workspace_ids_for_workspace_oriented_events():
    actor_workspace_id = str(uuid4())
    holder_workspace_id = str(uuid4())

    task_event = mutation_hooks._translate(
        "task.created",
        {
            "actor_agent_id": str(uuid4()),
            "actor_workspace_id": actor_workspace_id,
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Fix workspace split",
        },
    )
    reservation_event = mutation_hooks._translate(
        "reservation.acquired",
        {
            "holder_agent_id": str(uuid4()),
            "holder_workspace_id": holder_workspace_id,
            "resource_key": "repo:backend",
            "ttl_seconds": 60,
        },
    )

    assert isinstance(task_event, TaskCreatedEvent)
    assert task_event.workspace_id == actor_workspace_id
    assert isinstance(reservation_event, ReservationAcquiredEvent)
    assert reservation_event.workspace_id == holder_workspace_id


@pytest.mark.asyncio
async def test_mutation_handler_publishes_dashboard_team_events(aweb_cloud_db, monkeypatch):
    published: list[object] = []

    async def _capture_publish_team(_redis, event):
        published.append(event)
        return 1

    monkeypatch.setattr(mutation_hooks, "publish_team_event", _capture_publish_team)

    handler = mutation_hooks.create_mutation_handler(redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db))

    await handler(
        "message.acknowledged",
        {
            "team_id": "backend:acme.com",
            "alias": "bob",
            "from_alias": "alice",
            "subject": "Ship dashboard events",
        },
    )
    await handler(
        "chat.message_sent",
        {
            "team_id": "backend:acme.com",
            "from_alias": "alice",
            "to_aliases": ["bob", "carol"],
            "preview": "short preview",
        },
    )
    await handler(
        "task.status_changed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Ship dashboard events",
            "old_status": "open",
            "new_status": "closed",
        },
    )
    await handler(
        "task.claimed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "alias": "alice",
            "title": "Ship dashboard events",
        },
    )
    await handler(
        "task.unclaimed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "alias": "alice",
            "title": "Ship dashboard events",
        },
    )
    await handler(
        "reservation.acquired",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )
    await handler(
        "reservation.released",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )
    await handler(
        "reservation.renewed",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )

    assert len(published) == 8
    assert all(event.team_id == "backend:acme.com" for event in published)

    assert isinstance(published[0], TeamMessageAcknowledgedEvent)
    assert published[0].alias == "bob"
    assert published[0].from_alias == "alice"
    assert published[0].subject == "Ship dashboard events"

    assert isinstance(published[1], TeamChatMessageSentEvent)
    assert published[1].from_alias == "alice"
    assert published[1].to_aliases == ["bob", "carol"]
    assert published[1].preview == "short preview"

    assert isinstance(published[2], TeamTaskStatusChangedEvent)
    assert published[2].task_ref == "backend-1234"
    assert published[2].title == "Ship dashboard events"
    assert published[2].old_status == "open"
    assert published[2].new_status == "closed"

    assert isinstance(published[3], TeamTaskClaimedEvent)
    assert published[3].task_ref == "backend-1234"
    assert published[3].alias == "alice"
    assert published[3].title == "Ship dashboard events"

    assert isinstance(published[4], TeamTaskUnclaimedEvent)
    assert published[4].task_ref == "backend-1234"
    assert published[4].alias == "alice"
    assert published[4].title == "Ship dashboard events"

    assert isinstance(published[5], TeamReservationAcquiredEvent)
    assert published[5].alias == "alice"
    assert published[5].paths == ["repo:backend"]

    assert isinstance(published[6], TeamReservationReleasedEvent)
    assert published[6].alias == "alice"
    assert published[6].paths == ["repo:backend"]

    assert isinstance(published[7], TeamReservationRenewedEvent)
    assert published[7].alias == "alice"
    assert published[7].paths == ["repo:backend"]


@pytest.mark.asyncio
async def test_task_status_changed_claims_with_workspace_id_not_agent_id(aweb_cloud_db, monkeypatch):
    agent_id = uuid4()
    workspace_id = uuid4()
    published: list[object] = []

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role, workspace_type
        )
        VALUES ($1, 'backend:acme.com', $2, 'alice', 'Alice', 'developer', 'manual')
        """,
        workspace_id,
        agent_id,
    )

    async def _capture_publish(_redis, event):
        published.append(event)
        return 1

    monkeypatch.setattr(mutation_hooks, "publish_event", _capture_publish)
    monkeypatch.setattr(mutation_hooks, "publish_team_event", _capture_publish)
    monkeypatch.setattr(mutation_hooks, "_translate", lambda event_type, ctx: None)
    monkeypatch.setattr(mutation_hooks, "_translate_team_event", lambda event_type, ctx: None)

    handler = mutation_hooks.create_mutation_handler(redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db))
    await handler(
        "task.status_changed",
        {
            "team_id": "backend:acme.com",
            "actor_agent_id": str(agent_id),
            "task_ref": "backend-1234",
            "title": "Fix workspace split",
            "old_status": "open",
            "new_status": "in_progress",
        },
    )

    claim = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT workspace_id
        FROM {{tables.task_claims}}
        WHERE team_id = 'backend:acme.com' AND task_ref = 'backend-1234'
        """
    )
    assert str(claim["workspace_id"]) == str(workspace_id)
    assert any(getattr(event, "workspace_id", None) == str(workspace_id) for event in published)
