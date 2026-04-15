from __future__ import annotations

from uuid import uuid4

import pytest

import aweb.mutation_hooks as mutation_hooks
from aweb.events import ReservationAcquiredEvent, TaskCreatedEvent


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


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
