"""Tests for dashboard read endpoints (JWT-authenticated)."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from aweb.routes.dashboard import router as dashboard_router

_JWT_SECRET = "test-dashboard-secret-at-least-32bytes!"
_DEFAULT_REGISTRY = object()


def _make_jwt(team_ids: list[str], user_id: str = "user-123") -> str:
    return jwt.encode(
        {"user_id": user_id, "team_ids": team_ids, "exp": int(time.time()) + 3600},
        _JWT_SECRET,
        algorithm="HS256",
    )


class _FakeRegistryClient:
    def __init__(self, *, visibility: str = "private") -> None:
        self.visibility = visibility
        self.calls: list[tuple[str, str]] = []

    async def get_team(self, domain: str, name: str):
        self.calls.append((domain, name))
        return SimpleNamespace(
            team_id="team-1",
            domain=domain,
            name=name,
            display_name="",
            team_did_key="did:key:z6Mkteam",
            visibility=self.visibility,
            created_at="2026-04-08T00:00:00Z",
        )


class _FailingRegistryClient:
    async def get_team(self, domain: str, name: str):
        raise RuntimeError(f"registry unavailable for {domain}/{name}")


def _build_app(aweb_db, *, registry_client=_DEFAULT_REGISTRY):
    app = FastAPI()
    app.include_router(dashboard_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    app.state.db = _DbShim()
    app.state.dashboard_jwt_secret = _JWT_SECRET
    if registry_client is _DEFAULT_REGISTRY:
        registry_client = _FakeRegistryClient(visibility="private")
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
            agent_id, team_id, did_key, did_aw, address, alias, lifetime, role, status, human_name, agent_type
        )
        VALUES
            ($1, 'backend:acme.com', 'did:key:z6Mkalice', 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'developer', 'active', 'Alice', 'coder'),
            ($2, 'backend:acme.com', 'did:key:z6Mkbob', NULL, NULL, 'bob', 'ephemeral', 'reviewer', 'active', 'Bob', 'reviewer')
        """,
        alice_id, bob_id,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (from_did, to_did, from_alias, to_alias, subject, body, team_id, from_agent_id, to_agent_id)
        VALUES ('did:key:z6Mkalice', 'did:key:z6Mkbob', 'alice', 'bob', 'Hello', 'Hi Bob!', 'backend:acme.com', $1, $2)
        """,
        alice_id, bob_id,
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

    return str(alice_id), str(bob_id)


@pytest.mark.asyncio
async def test_list_agents(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    alice_id, bob_id = await _seed(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path, last_seen_at
        )
        VALUES (
            $1, 'backend:acme.com', $2, 'alice', '/Users/alice/project', $3
        )
        """,
        uuid.uuid4(),
        uuid.UUID(alice_id),
        datetime(2026, 4, 8, 12, 0, 0, tzinfo=timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path, last_seen_at, deleted_at
        )
        VALUES (
            $1, 'backend:acme.com', $2, 'bob', '/Users/bob/stale', $3, $4
        )
        """,
        uuid.uuid4(),
        uuid.UUID(bob_id),
        datetime(2026, 4, 8, 13, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 8, 13, 5, 0, tzinfo=timezone.utc),
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["agents"]) == 2
    agents = {a["alias"]: a for a in data["agents"]}
    assert set(agents) == {"alice", "bob"}
    assert agents["alice"]["workspace_path"] == "/Users/alice/project"
    assert agents["alice"]["last_seen"] == "2026-04-08T12:00:00+00:00"
    assert agents["alice"]["address"] == "acme.com/alice"
    assert agents["alice"]["agent_type"] == "coder"
    assert agents["bob"]["workspace_path"] is None
    assert agents["bob"]["last_seen"] is None
    assert agents["bob"]["address"] is None
    assert agents["bob"]["agent_type"] == "reviewer"


@pytest.mark.asyncio
async def test_list_agents_prefers_active_workspace_over_newer_deleted_workspace(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    alice_id, bob_id = await _seed(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path, last_seen_at
        )
        VALUES (
            $1, 'backend:acme.com', $2, 'alice', '/Users/alice/project', $3
        )
        """,
        uuid.uuid4(),
        uuid.UUID(alice_id),
        datetime(2026, 4, 8, 12, 0, 0, tzinfo=timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path, last_seen_at, deleted_at
        )
        VALUES
            ($1, 'backend:acme.com', $2, 'bob', '/Users/bob/stale', $3, $4),
            ($5, 'backend:acme.com', $2, 'bob', '/Users/bob/active', $6, NULL)
        """,
        uuid.uuid4(),
        uuid.UUID(bob_id),
        datetime(2026, 4, 8, 13, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 8, 13, 5, 0, tzinfo=timezone.utc),
        uuid.uuid4(),
        datetime(2026, 4, 8, 11, 0, 0, tzinfo=timezone.utc),
    )
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    agents = {a["alias"]: a for a in resp.json()["agents"]}
    assert agents["bob"]["workspace_path"] == "/Users/bob/active"
    assert agents["bob"]["last_seen"] == "2026-04-08T11:00:00+00:00"


@pytest.mark.asyncio
async def test_agent_detail(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents/alice",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["alias"] == "alice"
    assert data["role"] == "developer"
    assert data["address"] == "acme.com/alice"
    assert data["agent_type"] == "coder"


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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/claims",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_claims_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/backend:acme.com/claims")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_messages(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/messages",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["messages"]) == 1
    assert data["messages"][0]["subject"] == "Hello"


@pytest.mark.asyncio
async def test_tasks(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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
    assert data["has_more"] is False
    assert data["next_cursor"] is None


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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.get(
            "/v1/teams/backend:acme.com/tasks",
            params={"limit": 2},
            headers={"X-Dashboard-Token": token},
        )
        assert first.status_code == 200
        first_data = first.json()
        assert [task["title"] for task in first_data["tasks"]] == ["Second task", "Third task"]
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
async def test_unauthorized_team_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = _make_jwt(["team:other.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_public_team_allows_anonymous_dashboard_reads(aweb_cloud_db):
    registry_client = _FakeRegistryClient(visibility="public")
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=registry_client)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 200
    assert len(resp.json()["agents"]) == 2
    assert registry_client.calls == [("acme.com", "backend")]


@pytest.mark.asyncio
async def test_private_team_with_valid_jwt_does_not_fail_on_registry_lookup_error(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=_FailingRegistryClient())
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_anonymous_request_fails_closed_when_registry_lookup_errors(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=_FailingRegistryClient())
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_anonymous_request_returns_503_during_partial_init_without_registry_client(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=None)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/backend:acme.com/agents")

    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_authenticated_request_succeeds_during_partial_init_without_registry_client(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=None)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_usage_endpoint(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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
async def test_status_endpoint(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/status",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["team_id"] == "backend:acme.com"
    assert data["agent_count"] == 2


@pytest.mark.asyncio
async def test_roles_active_empty(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["backend:acme.com"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents/nonexistent",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_expired_jwt_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = jwt.encode(
        {"user_id": "user-123", "team_ids": ["backend:acme.com"], "exp": int(time.time()) - 3600},
        _JWT_SECRET,
        algorithm="HS256",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/backend:acme.com/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 401
