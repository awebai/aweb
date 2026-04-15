from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import _common as common_tools
from aweb.mcp.tools import work as work_tools
from aweb.mcp.tools import workspace as workspace_tools


class DBInfra:
    def __init__(self, aweb_db):
        self._aweb_db = aweb_db

    def get_manager(self, name: str):
        if name != "aweb":
            raise KeyError(name)
        return self._aweb_db


@pytest.mark.asyncio
async def test_work_ready_uses_workspace_id_not_agent_id(aweb_cloud_db, monkeypatch):
    workspace_id = uuid4()
    other_workspace_id = uuid4()
    agent_id = uuid4()
    team_id = "backend:acme.com"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES ($1, $2, 'alice', 'Alice', 'backend-1234', $3)
        """,
        team_id,
        workspace_id,
        datetime.now(timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES ($1, $2, 'bob', 'Bob', 'backend-5678', $3)
        """,
        team_id,
        other_workspace_id,
        datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        common_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(agent_id),
            workspace_id=str(workspace_id),
            alias="alice",
            did_key="did:key:z6MkAlice",
        ),
    )
    async def _list_ready_tasks(*_args, **_kwargs):
        return [
            {
                "task_ref": "backend-1234",
                "title": "Fix workspace split",
                "priority": 1,
            },
            {
                "task_ref": "backend-5678",
                "title": "Held elsewhere",
                "priority": 1,
            },
        ]

    monkeypatch.setattr(work_tools, "list_ready_tasks", _list_ready_tasks)

    body = json.loads(await work_tools.work_ready(DBInfra(aweb_cloud_db.aweb_db)))

    assert [item["task_ref"] for item in body["tasks"]] == ["backend-1234"]


@pytest.mark.asyncio
async def test_workspace_status_uses_workspace_rows_as_primary_identity(aweb_cloud_db, monkeypatch):
    team_id = "backend:acme.com"
    alice_agent_id = uuid4()
    alice_workspace_id = uuid4()
    bob_agent_id = uuid4()
    bob_workspace_id = uuid4()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:team')
        """,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, alias, human_name, role, lifetime, status, agent_type, messaging_policy
        )
        VALUES
            ($1, $2, 'did:key:alice', 'alice', 'Alice', 'developer', 'persistent', 'active', 'agent', 'everyone'),
            ($3, $2, 'did:key:bob', 'bob', 'Bob', 'reviewer', 'persistent', 'active', 'agent', 'everyone')
        """,
        alice_agent_id,
        team_id,
        bob_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role, workspace_type
        )
        VALUES
            ($1, $3, $2, 'alice', 'Alice', 'developer', 'manual'),
            ($4, $3, $5, 'bob', 'Bob', 'reviewer', 'manual')
        """,
        alice_workspace_id,
        alice_agent_id,
        team_id,
        bob_workspace_id,
        bob_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES ($1, $2, 'alice', 'Alice', 'backend-1234', $3)
        """,
        team_id,
        alice_workspace_id,
        datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        common_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id=str(alice_workspace_id),
            alias="alice",
            did_key="did:key:alice",
        ),
    )
    async def _list_presences(_redis, workspace_ids):
        return [
            {"workspace_id": str(alice_workspace_id), "status": "active", "role": "developer"},
            {"workspace_id": str(bob_workspace_id), "status": "active", "role": "reviewer"},
        ]

    monkeypatch.setattr(workspace_tools, "list_agent_presences_by_workspace_ids", _list_presences)

    body = json.loads(await workspace_tools.workspace_status(DBInfra(aweb_cloud_db.aweb_db), None))

    assert body["workspace_id"] == str(alice_workspace_id)
    assert body["self"]["workspace_id"] == str(alice_workspace_id)
    assert [claim["task_ref"] for claim in body["self"]["claims"]] == ["backend-1234"]
    assert [entry["workspace_id"] for entry in body["team_agents"]] == [str(bob_workspace_id)]
