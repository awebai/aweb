"""Tests for dashboard read endpoints (JWT-authenticated)."""

from __future__ import annotations

import time

import httpx
import uuid
from datetime import datetime, timezone

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from aweb.routes.dashboard import router as dashboard_router

from dashboard_test_support import _JWT_SECRET as _JWT_SECRET, _make_jwt as _make_jwt
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app


class _FailingRegistryClient:
    async def get_team(self, domain: str, name: str):
        raise RuntimeError(f"registry unavailable for {domain}/{name}")


class _ConnectFailingRegistryClient:
    async def get_team(self, domain: str, name: str):
        raise httpx.ConnectError(f"connect failed for {domain}/{name}")


def _build_app(aweb_db, *, registry_client=None, redis=None):
    app = FastAPI()
    app.include_router(dashboard_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    app.state.db = _DbShim()
    app.state.dashboard_jwt_secret = _JWT_SECRET
    app.state.redis = redis
    if registry_client is not None:
        app.state.awid_registry_client = registry_client
    return app


async def _seed(aweb_db):
    """Create a team with agents, messages, tasks for dashboard testing."""
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
    )

    alice_id = uuid.uuid4()
    bob_id = uuid.uuid4()

    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, did_aw, address, alias, identity_scope, role, status, human_name, agent_type
        )
        VALUES
            ($1, 'backend:acme.com', 'did:key:z6Mkalice', 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'active', 'Alice', 'coder'),
            ($2, 'backend:acme.com', 'did:key:z6Mkbob', NULL, NULL, 'bob', 'local', 'reviewer', 'active', 'Bob', 'reviewer')
        """,
        alice_id,
        bob_id,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (from_did, to_did, from_alias, to_alias, subject, body, team_id, from_agent_id, to_agent_id)
        VALUES ('did:key:z6Mkalice', 'did:key:z6Mkbob', 'alice', 'bob', 'Hello', 'Hi Bob!', 'backend:acme.com', $1, $2)
        """,
        alice_id,
        bob_id,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            team_id, task_number, root_task_seq, task_ref_suffix, title, status, priority, task_type, created_at
        )
        VALUES (
            'backend:acme.com', 1, 1, 'aaaa', 'Fix bug', 'open', 2, 'task',
            TIMESTAMPTZ '2026-04-08T12:03:00Z'
        )
        """,
    )

    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
        alice_id,
    )
    return str(alice_id), str(bob_id)


@pytest.mark.asyncio
async def test_claims(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    alice_id, _ = await _seed(aweb_cloud_db.aweb_db)
    workspace_id = uuid.uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path
        )
        VALUES (
            $1, 'backend:acme.com', $2, 'alice', '/Users/alice/project'
        )
        """,
        workspace_id,
        uuid.UUID(alice_id),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES (
            'backend:acme.com', $1, 'alice', 'Alice', 'backend-aaaa',
            TIMESTAMPTZ '2026-04-08T12:15:00Z'
        )
        """,
        workspace_id,
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/claims",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "claims": [
            {
                "task_ref": "backend-aaaa",
                "workspace_id": str(workspace_id),
                "alias": "alice",
                "claimed_at": "2026-04-08T12:15:00+00:00",
            }
        ]
    }


@pytest.mark.asyncio
async def test_claims_unauthorized_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["team:other.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/claims",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_claims_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/claims")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_messages_route_is_removed(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/messages",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
async def test_tasks(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["tasks"]) == 1
    assert data["tasks"][0]["title"] == "Fix bug"
    assert data["has_more"] is False
    assert data["next_cursor"] is None


@pytest.mark.asyncio
async def test_tasks_filters_and_paginates(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    parent_task_id = uuid.uuid4()
    blocked_task_id = uuid.uuid4()
    blocker_task_id = uuid.uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            status, priority, task_type, labels, assignee_alias, parent_task_id, created_at, updated_at
        )
        VALUES
            ($1, 'backend:acme.com', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', $2,
             TIMESTAMPTZ '2026-04-08T12:05:00Z', TIMESTAMPTZ '2026-04-08T12:06:00Z'),
            ($2, 'backend:acme.com', 3, 3, 'aaac', 'Parent task', 'Parent for dashboard task',
             'open', 1, 'epic', ARRAY['backend']::text[], NULL, NULL,
             TIMESTAMPTZ '2026-04-08T12:04:30Z', TIMESTAMPTZ '2026-04-08T12:04:45Z'),
            ($3, 'backend:acme.com', 4, 4, 'aaad', 'Blocked task', 'Blocked by dashboard task',
             'open', 1, 'chore', ARRAY['docs']::text[], NULL, NULL,
             TIMESTAMPTZ '2026-04-08T12:04:00Z', TIMESTAMPTZ '2026-04-08T12:04:10Z')
        """,
        blocked_task_id,
        parent_task_id,
        blocker_task_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_id, team_id)
        VALUES ($1, $2, 'backend:acme.com')
        """,
        blocked_task_id,
        blocker_task_id,
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={
                "status": "in_progress",
                "assignee_alias": "alice",
                "task_type": "feature",
                "priority": "P0",
                "labels": "dashboard,backend",
                "q": "dashboard filters",
                "limit": 1,
            },
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert [task["title"] for task in data["tasks"]] == ["Build dashboard"]
    assert data["tasks"][0]["parent_task_id"] == str(parent_task_id)
    assert data["tasks"][0]["labels"] == ["dashboard", "backend"]
    assert data["tasks"][0]["updated_at"] == "2026-04-08T12:06:00+00:00"
    assert data["tasks"][0]["blocker_count"] == 1
    assert data["has_more"] is False
    assert data["next_cursor"] is None


@pytest.mark.asyncio
async def test_tasks_empty_result_set(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"status": "closed"},
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_unknown_assignee_returns_empty_results(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"assignee_alias": "someone-who-left"},
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_invalid_cursor_returns_422(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"cursor": "not-base64"},
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 422
    assert resp.json()["detail"] == "Invalid cursor"


@pytest.mark.asyncio
async def test_tasks_filters_in_isolation(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            status, priority, task_type, labels, assignee_alias, created_at
        )
        VALUES
            ($1, 'backend:acme.com', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, 'backend:acme.com', 3, 3, 'aaac', 'Document claims', 'Write pagination docs',
             'open', 1, 'chore', ARRAY['docs']::text[], NULL, TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        status_resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"status": "in_progress"},
            headers={"X-Dashboard-Token": token},
        )
        assignee_resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"assignee_alias": "alice"},
            headers={"X-Dashboard-Token": token},
        )
        priority_resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"priority": "P0"},
            headers={"X-Dashboard-Token": token},
        )
        q_resp = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"q": "pagination docs"},
            headers={"X-Dashboard-Token": token},
        )

    assert [task["title"] for task in status_resp.json()["tasks"]] == [
        "Build dashboard"
    ]
    assert [task["title"] for task in assignee_resp.json()["tasks"]] == [
        "Build dashboard"
    ]
    assert [task["title"] for task in priority_resp.json()["tasks"]] == [
        "Build dashboard"
    ]
    assert [task["title"] for task in q_resp.json()["tasks"]] == ["Document claims"]


@pytest.mark.asyncio
async def test_tasks_cursor_pagination(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at
        )
        VALUES
            ($1, 'backend:acme.com', 2, 2, 'aaab', 'Second task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, 'backend:acme.com', 3, 3, 'aaac', 'Third task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"limit": 2},
            headers={"X-Dashboard-Token": token},
        )
        assert first.status_code == 200
        first_data = first.json()
        assert [task["title"] for task in first_data["tasks"]] == [
            "Second task",
            "Third task",
        ]
        assert first_data["has_more"] is True
        assert first_data["next_cursor"] is not None

        second = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"limit": 2, "cursor": first_data["next_cursor"]},
            headers={"X-Dashboard-Token": token},
        )

    assert second.status_code == 200
    second_data = second.json()
    assert [task["title"] for task in second_data["tasks"]] == ["Fix bug"]
    assert second_data["has_more"] is False
    assert second_data["next_cursor"] is None


@pytest.mark.asyncio
async def test_events_stream_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/events/stream")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_events_stream_unauthorized_team_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["team:other.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/events/stream",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthorized_team_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = _make_jwt(["team:other.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_anonymous_request_reports_upstream_registry_connect_errors_as_503(
    aweb_cloud_db,
):
    app = _build_app(
        aweb_cloud_db.aweb_db, registry_client=_ConnectFailingRegistryClient()
    )
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 503
    assert (
        "AWID dashboard team visibility lookup upstream unavailable (ConnectError)"
        in resp.json()["detail"]
    )


@pytest.mark.asyncio
async def test_anonymous_request_surfaces_unexpected_registry_lookup_errors(
    aweb_cloud_db,
):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=_FailingRegistryClient())
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 500
    assert (
        "Unexpected AWID dashboard team visibility lookup dependency error (RuntimeError)"
        in resp.json()["detail"]
    )


@pytest.mark.asyncio
async def test_anonymous_request_returns_500_during_partial_init_without_registry_client(
    aweb_cloud_db,
):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=None)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 500
    assert (
        resp.json()["detail"]
        == "AWID dashboard team visibility lookup registry client not configured"
    )


@pytest.mark.asyncio
async def test_usage_endpoint(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/usage",
            params={"team_id": "backend:acme.com"},
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["team_id"] == "backend:acme.com"
    assert data["messages_sent"] >= 1
    assert data["active_agents"] >= 2


@pytest.mark.asyncio
async def test_roles_active_empty(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/roles/active",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json()["roles"] is None


@pytest.mark.asyncio
async def test_instructions_active_empty(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/instructions/active",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json()["instructions"] is None


@pytest.mark.asyncio
async def test_agent_not_found_returns_404(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents/nonexistent",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_expired_jwt_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = jwt.encode(
        {
            "user_id": "user-123",
            "team_ids": ["backend:acme.com"],
            "exp": int(time.time()) - 3600,
        },
        _JWT_SECRET,
        algorithm="HS256",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_agents_and_detail_keep_workspace_and_identity_fields(privacy_app):
    env = privacy_app
    alice = env.actors["alice"]
    now = datetime.now(timezone.utc)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET human_name='Alice', role='developer', agent_type='coder' WHERE agent_id=$1",
        alice.id,
    )
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/workspace/alice', last_seen_at=$1 WHERE workspace_id=$2",
        now,
        alice.workspace,
    )
    headers = {"X-Dashboard-Token": _make_jwt([TEAM])}
    response = await env.client.get(f"/v1/teams/{TEAM}/agents", headers=headers)
    assert response.status_code == 200, response.text
    agents = {agent["alias"]: agent for agent in response.json()["agents"]}
    assert set(agents) == set(env.actors)
    assert agents["alice"]["workspace_path"] == "/workspace/alice"
    assert agents["alice"]["last_seen"] == now.isoformat()
    assert (
        agents["alice"]["human_name"],
        agents["alice"]["role"],
        agents["alice"]["agent_type"],
    ) == ("Alice", "developer", "coder")
    assert agents["bob"]["last_seen"] is None
    assert agents["bob"]["address"] is None
    detail = await env.client.get(f"/v1/teams/{TEAM}/agents/alice", headers=headers)
    assert detail.status_code == 200, detail.text
    for field in ("alias", "did_key", "human_name", "role", "agent_type", "address"):
        assert detail.json()[field] == agents["alice"][field]


@pytest.mark.asyncio
async def test_list_agents_prefers_live_workspace_over_newer_deleted_workspace(
    privacy_app,
):
    env = privacy_app
    bob = env.actors["bob"]
    now = datetime.now(timezone.utc)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/workspace/live',last_seen_at=$1 WHERE workspace_id=$2",
        now,
        bob.workspace,
    )
    await env.db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias,workspace_path,last_seen_at,deleted_at) VALUES ($1,$2,$3,'bob-stale','/workspace/stale',$4,NOW())",
        uuid.uuid4(),
        TEAM,
        bob.id,
        now,
    )
    response = await env.client.get(
        f"/v1/teams/{TEAM}/agents", headers={"X-Dashboard-Token": _make_jwt([TEAM])}
    )
    assert response.status_code == 200, response.text
    bob_row = next(row for row in response.json()["agents"] if row["alias"] == "bob")
    assert bob_row["workspace_path"] == "/workspace/live"
    assert bob_row["last_seen"] == now.isoformat()


@pytest.mark.asyncio
async def test_list_agents_excludes_human_typed_attribution_rows(privacy_app):
    env = privacy_app
    await env.db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1",
        env.actors["carol"].id,
    )
    response = await env.client.get(
        f"/v1/teams/{TEAM}/agents", headers={"X-Dashboard-Token": _make_jwt([TEAM])}
    )
    assert response.status_code == 200, response.text
    assert {row["alias"] for row in response.json()["agents"]} == {"alice", "bob"}


@pytest.mark.asyncio
async def test_public_team_allows_anonymous_dashboard_reads(privacy_app):
    response = await privacy_app.client.get(f"/v1/teams/{TEAM}/agents")
    assert response.status_code == 200, response.text
    assert {row["alias"] for row in response.json()["agents"]} == set(
        privacy_app.actors
    )


@pytest.mark.asyncio
async def test_status_endpoint_uses_shared_activity(privacy_app):
    from test_coordination_state_http import request_as

    env = privacy_app
    heartbeat = await request_as(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat"
    )
    assert heartbeat.status_code == 200, heartbeat.text
    await env.redis.delete(f"presence:{env.actors['alice'].workspace}")
    response = await env.client.get(
        f"/v1/teams/{TEAM}/status", headers={"X-Dashboard-Token": _make_jwt([TEAM])}
    )
    assert response.status_code == 200, response.text
    assert response.json()["team_id"] == TEAM
    assert response.json()["agent_count"] == len(env.actors)
    assert response.json()["online_agents"] == ["alice"]


@pytest.mark.asyncio
async def test_authenticated_presence_read_refuses_a_missing_serving_client(
    privacy_app,
):
    # Startup/resource configuration, not an authentication override.
    del privacy_app.app.state.awid_registry_client
    response = await privacy_app.client.get(
        f"/v1/teams/{TEAM}/agents", headers={"X-Dashboard-Token": _make_jwt([TEAM])}
    )
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "registry_client_unavailable"


@pytest.mark.asyncio
async def test_private_team_jwt_read_does_not_require_public_visibility_lookup(
    privacy_app,
):
    import socket
    from awid.registry import RegistryClient

    env = privacy_app
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    original = env.app.state.awid_registry_client
    unavailable = RegistryClient(registry_url=f"http://127.0.0.1:{port}")
    try:
        env.app.state.awid_registry_client = unavailable
        try:
            anonymous = await env.client.get(f"/v1/teams/{TEAM}/agents")
            assert anonymous.status_code == 503, anonymous.text
            assert "ConnectError" in anonymous.json()["detail"]
            authenticated = await env.client.get(
                f"/v1/teams/{TEAM}/agents",
                headers={"X-Dashboard-Token": _make_jwt([TEAM])},
            )
            assert authenticated.status_code == 200, authenticated.text
            assert {row["alias"] for row in authenticated.json()["agents"]} == set(
                env.actors
            )
        finally:
            env.app.state.awid_registry_client = original
    finally:
        await unavailable.aclose()
