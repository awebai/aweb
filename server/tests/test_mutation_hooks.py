from __future__ import annotations

from uuid import uuid4

import pytest

import aweb.mutation_hooks as mutation_hooks


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
