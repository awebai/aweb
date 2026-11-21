"""Tests for dashboard read endpoints (JWT-authenticated)."""

from __future__ import annotations

import asyncio
import json
import time
import socket

import httpx
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
import pytest
import pytest_asyncio
from awid.registry import RegistryClient
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from aweb.events import (
    TeamAgentOfflineEvent,
    TeamAgentOnlineEvent,
    TeamTaskCreatedEvent,
    publish_team_event,
)
from aweb.presence import update_agent_presence
from aweb.routes import dashboard as dashboard_routes
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


class _FakeRedisPipeline:
    def __init__(self, redis) -> None:
        self.redis = redis
        self.ops: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name):
        def enqueue(*args, **kwargs):
            self.ops.append((name, args, kwargs))
            return self

        return enqueue

    async def execute(self):
        results = []
        for op, args, kwargs in self.ops:
            results.append(await getattr(self.redis, op)(*args, **kwargs))
        self.ops.clear()
        return results


class _FakePubSub:
    def __init__(self, redis) -> None:
        self.redis = redis
        self.queue: asyncio.Queue = asyncio.Queue()
        self.channels: set[str] = set()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    async def subscribe(self, *channels):
        for channel in channels:
            self.channels.add(channel)
            self.redis.subscribers.setdefault(channel, set()).add(self.queue)

    async def unsubscribe(self, *channels):
        targets = channels or tuple(self.channels)
        for channel in targets:
            self.redis.subscribers.get(channel, set()).discard(self.queue)
            self.channels.discard(channel)

    async def get_message(self, ignore_subscribe_messages=True, timeout=0):
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def aclose(self):
        await self.unsubscribe(*tuple(self.channels))


class _FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.sets: dict[str, set[str]] = {}
        self.strings: dict[str, str] = {}
        self.subscribers: dict[str, set[asyncio.Queue]] = {}

    def pubsub(self):
        return _FakePubSub(self)

    def pipeline(self, transaction=True):
        return _FakeRedisPipeline(self)

    async def publish(self, channel, message):
        queues = list(self.subscribers.get(channel, set()))
        for queue in queues:
            await queue.put({"type": "message", "channel": channel, "data": message})
        return len(queues)

    async def hset(self, key, mapping):
        current = self.hashes.setdefault(key, {})
        current.update({str(k): str(v) for k, v in mapping.items()})
        return len(mapping)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def expire(self, key, ttl):
        return True

    async def persist(self, key):
        return True

    async def sadd(self, key, *values):
        bucket = self.sets.setdefault(key, set())
        bucket.update(str(v) for v in values)
        return len(values)

    async def smembers(self, key):
        return set(self.sets.get(key, set()))

    async def exists(self, key):
        return int(
            key in self.hashes
            and bool(self.hashes[key])
            or key in self.sets
            and bool(self.sets[key])
            or key in self.strings
        )

    async def set(self, key, value, ex=None):
        self.strings[key] = str(value)
        return True

    async def get(self, key):
        return self.strings.get(key)

    async def srem(self, key, value):
        bucket = self.sets.get(key)
        if bucket is None:
            return 0
        existed = str(value) in bucket
        bucket.discard(str(value))
        return 1 if existed else 0

    async def delete(self, key):
        removed = 0
        removed += 1 if self.hashes.pop(key, None) is not None else 0
        removed += 1 if self.sets.pop(key, None) is not None else 0
        removed += 1 if self.strings.pop(key, None) is not None else 0
        return removed


def _build_app(aweb_db, *, registry_client=_DEFAULT_REGISTRY, redis=None):
    app = FastAPI()
    app.include_router(dashboard_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    app.state.db = _DbShim()
    app.state.dashboard_jwt_secret = _JWT_SECRET
    app.state.redis = redis
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


class _FakeStreamRequest:
    async def is_disconnected(self) -> bool:
        return False


def _parse_sse_chunk(chunk: str):
    event_name = None
    data_lines: list[str] = []
    for line in chunk.splitlines():
        if line.startswith(":"):
            continue
        if line.startswith("event: "):
            event_name = line[7:]
            continue
        if line.startswith("data: "):
            data_lines.append(line[6:])
    payload = json.loads("".join(data_lines)) if data_lines else {}
    return event_name, payload


@pytest.mark.asyncio
async def test_list_agents(dashboard_stack):
    env = dashboard_stack
    await _seed_dashboard_directory(env)
    alice, bob = env.actors["alice"], env.actors["bob"]
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/Users/alice/project',last_seen_at=$1 WHERE workspace_id=$2",
        datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc),
        alice.workspace,
    )
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/Users/bob/stale',last_seen_at=$1,deleted_at=$2 WHERE agent_id=$3",
        datetime(2026, 4, 8, 13, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 8, 13, 5, tzinfo=timezone.utc),
        bob.id,
    )
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/agents",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["agents"]) == 2
    agents = {a["alias"]: a for a in data["agents"]}
    assert set(agents) == {"alice", "bob"}
    assert agents["alice"]["workspace_path"] == "/Users/alice/project"
    assert agents["alice"]["last_seen"] == "2026-04-08T12:00:00+00:00"
    assert agents["alice"]["human_name"] == "Alice"
    assert agents["alice"]["address"] == "example.test/alice"
    assert agents["alice"]["agent_type"] == "coder"
    assert agents["bob"]["workspace_path"] is None
    assert agents["bob"]["last_seen"] is None
    assert agents["bob"]["human_name"] == "Bob"
    assert agents["bob"]["address"] is None
    assert agents["bob"]["agent_type"] == "reviewer"


@pytest.mark.asyncio
async def test_list_agents_prefers_active_workspace_over_newer_deleted_workspace(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed_dashboard_directory(env)
    bob = env.actors["bob"]
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/Users/bob/active',last_seen_at=$1 WHERE workspace_id=$2",
        datetime(2026, 4, 8, 11, 0, tzinfo=timezone.utc),
        bob.workspace,
    )
    await env.db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias,workspace_path,last_seen_at,deleted_at) VALUES ($1,$2,$3,'bob-stale','/Users/bob/stale',$4,$5)",
        uuid.uuid4(),
        env.team_id,
        bob.id,
        datetime(2026, 4, 8, 13, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 8, 13, 5, tzinfo=timezone.utc),
    )
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/agents",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 200, resp.text
    agents = {a["alias"]: a for a in resp.json()["agents"]}
    assert agents["bob"]["workspace_path"] == "/Users/bob/active"
    assert agents["bob"]["last_seen"] == "2026-04-08T11:00:00+00:00"


@pytest.mark.asyncio
async def test_list_agents_excludes_human_typed_action_attribution_rows(
    dashboard_stack,
):
    from awid.identity_observation import IdentityKind
    from messaging_actor_support import admit_messaging_actor

    env = dashboard_stack
    await _seed_dashboard_stack(env)
    await admit_messaging_actor(
        env, alias="cowork-gzo3o2loh252", team_id=env.team_id, kind=IdentityKind.HUMAN
    )
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/agents",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 200, resp.text
    aliases = {a["alias"] for a in resp.json()["agents"]}
    assert aliases == {"alice", "bob"}, (
        f"human-typed attribution row leaked into agent list: {aliases}"
    )
    assert "cowork-gzo3o2loh252" not in aliases


@pytest.mark.asyncio
async def test_agent_detail(dashboard_stack):
    env = dashboard_stack
    await _seed_dashboard_directory(env)
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/agents/alice",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["alias"] == "alice"
    assert data["role"] == "developer"
    assert data["address"] == "example.test/alice"
    assert data["agent_type"] == "coder"


@pytest.mark.asyncio
async def test_claims(dashboard_stack):
    alice_id, _ = await _seed_dashboard_stack(dashboard_stack)
    workspace_id = dashboard_stack.actors["alice"].workspace
    assert workspace_id != uuid.UUID(alice_id)
    await dashboard_stack.db.execute(
        "UPDATE {{tables.workspaces}} SET workspace_path='/Users/alice/project' WHERE workspace_id=$1",
        workspace_id,
    )
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.task_claims}}}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES (
            '{dashboard_stack.team_id}', $1, 'alice', 'Alice', '{dashboard_stack.team_name}-aaaa',
            TIMESTAMPTZ '2026-04-08T12:15:00Z'
        )
        """,
        workspace_id,
    )
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/claims",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "claims": [
            {
                "task_ref": f"{dashboard_stack.team_name}-aaaa",
                "workspace_id": str(workspace_id),
                "alias": "alice",
                "claimed_at": "2026-04-08T12:15:00+00:00",
            }
        ]
    }


@pytest.mark.asyncio
async def test_claims_unauthorized_returns_403(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt(["team:other.com"])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/claims",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_claims_missing_token_returns_401(dashboard_stack):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    resp = await env.client.get(f"/v1/teams/{env.team_id}/claims")
    assert resp.status_code == 401, resp.text


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
async def test_tasks(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["tasks"]) == 1
    assert data["tasks"][0]["title"] == "Fix bug"
    assert data["has_more"] is False
    assert data["next_cursor"] is None


@pytest.mark.asyncio
async def test_tasks_filters_and_paginates(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    parent_task_id = uuid.uuid4()
    blocked_task_id = uuid.uuid4()
    blocker_task_id = uuid.uuid4()
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.tasks}}}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            status, priority, task_type, labels, assignee_alias, parent_task_id, created_at, updated_at
        )
        VALUES
            ($1, '{dashboard_stack.team_id}', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', $2,
             TIMESTAMPTZ '2026-04-08T12:05:00Z', TIMESTAMPTZ '2026-04-08T12:06:00Z'),
            ($2, '{dashboard_stack.team_id}', 3, 3, 'aaac', 'Parent task', 'Parent for dashboard task',
             'open', 1, 'epic', ARRAY['backend']::text[], NULL, NULL,
             TIMESTAMPTZ '2026-04-08T12:04:30Z', TIMESTAMPTZ '2026-04-08T12:04:45Z'),
            ($3, '{dashboard_stack.team_id}', 4, 4, 'aaad', 'Blocked task', 'Blocked by dashboard task',
             'open', 1, 'chore', ARRAY['docs']::text[], NULL, NULL,
             TIMESTAMPTZ '2026-04-08T12:04:00Z', TIMESTAMPTZ '2026-04-08T12:04:10Z')
        """,
        blocked_task_id,
        parent_task_id,
        blocker_task_id,
    )
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.task_dependencies}}}} (task_id, depends_on_id, team_id)
        VALUES ($1, $2, '{dashboard_stack.team_id}')
        """,
        blocked_task_id,
        blocker_task_id,
    )
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
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
async def test_tasks_empty_result_set(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"status": "closed"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_unknown_assignee_returns_empty_results(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"assignee_alias": "someone-who-left"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_invalid_cursor_returns_422(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"cursor": "not-base64"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 422
    assert resp.json()["detail"] == "Invalid cursor"


@pytest.mark.asyncio
async def test_tasks_filters_in_isolation(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.tasks}}}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            status, priority, task_type, labels, assignee_alias, created_at
        )
        VALUES
            ($1, '{dashboard_stack.team_id}', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, '{dashboard_stack.team_id}', 3, 3, 'aaac', 'Document claims', 'Write pagination docs',
             'open', 1, 'chore', ARRAY['docs']::text[], NULL, TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    status_resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"status": "in_progress"},
        headers={"X-Dashboard-Token": token},
    )
    assignee_resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"assignee_alias": "alice"},
        headers={"X-Dashboard-Token": token},
    )
    priority_resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"priority": "P0"},
        headers={"X-Dashboard-Token": token},
    )
    q_resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
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
async def test_tasks_cursor_pagination(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.tasks}}}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at
        )
        VALUES
            ($1, '{dashboard_stack.team_id}', 2, 2, 'aaab', 'Second task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, '{dashboard_stack.team_id}', 3, 3, 'aaac', 'Third task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    first = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
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
        f"/v1/teams/{dashboard_stack.team_id}/tasks",
        params={"limit": 2, "cursor": first_data["next_cursor"]},
        headers={"X-Dashboard-Token": token},
    )

    assert second.status_code == 200
    second_data = second.json()
    assert [task["title"] for task in second_data["tasks"]] == ["Fix bug"]
    assert second_data["has_more"] is False
    assert second_data["next_cursor"] is None


@pytest.mark.asyncio
async def test_events_stream_emits_snapshot_and_team_events(aweb_cloud_db):
    redis = _FakeRedis()
    alice_id, _ = await _seed(aweb_cloud_db.aweb_db)
    workspace_id = str(uuid.uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, workspace_path
        )
        VALUES (
            $1, 'backend:acme.com', $2, 'alice', '/Users/alice/project'
        )
        """,
        uuid.UUID(workspace_id),
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
        uuid.UUID(workspace_id),
    )
    await update_agent_presence(
        redis,
        workspace_id=workspace_id,
        alias="alice",
        team_id="backend:acme.com",
    )
    stream = dashboard_routes._sse_dashboard_events(
        request=_FakeStreamRequest(),
        db=_build_app(aweb_cloud_db.aweb_db, redis=redis).state.db,
        redis=redis,
        team_id="backend:acme.com",
    )
    assert await anext(stream) == ": keepalive\n\n"

    event_name, payload = _parse_sse_chunk(await anext(stream))
    assert event_name == "connected"
    assert payload["team_id"] == "backend:acme.com"

    event_name, payload = _parse_sse_chunk(await anext(stream))
    assert event_name == "snapshot"
    assert payload["team_id"] == "backend:acme.com"
    assert payload["online_aliases"] == ["alice"]
    assert payload["active_claims"] == [
        {
            "task_ref": "backend-aaaa",
            "workspace_id": workspace_id,
            "alias": "alice",
            "claimed_at": "2026-04-08T12:15:00+00:00",
        }
    ]

    await publish_team_event(
        redis,
        TeamTaskCreatedEvent(
            team_id="backend:acme.com",
            task_ref="backend-aaab",
            title="Build dashboard stream",
            status="open",
        ),
    )

    event_name, payload = _parse_sse_chunk(
        await asyncio.wait_for(anext(stream), timeout=1)
    )
    assert event_name == "task.created"
    assert payload == {
        "type": "task.created",
        "team_id": "backend:acme.com",
        "task_ref": "backend-aaab",
        "alias": "",
        "title": "Build dashboard stream",
        "status": "open",
        "assignee_alias": None,
        "timestamp": payload["timestamp"],
    }
    await stream.aclose()


@pytest.mark.asyncio
async def test_events_stream_emits_presence_diffs(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(dashboard_routes, "DASHBOARD_PRESENCE_POLL_SECONDS", 0.01)
    monkeypatch.setattr(dashboard_routes, "DASHBOARD_PUBSUB_POLL_SECONDS", 0.01)
    redis = _FakeRedis()
    await _seed(aweb_cloud_db.aweb_db)
    stream = dashboard_routes._sse_dashboard_events(
        request=_FakeStreamRequest(),
        db=_build_app(aweb_cloud_db.aweb_db, redis=redis).state.db,
        redis=redis,
        team_id="backend:acme.com",
    )
    assert await anext(stream) == ": keepalive\n\n"
    await anext(stream)
    event_name, payload = _parse_sse_chunk(await anext(stream))
    assert event_name == "snapshot"
    assert payload["online_aliases"] == []

    workspace_id = str(uuid.uuid4())
    await update_agent_presence(
        redis,
        workspace_id=workspace_id,
        alias="bob",
        team_id="backend:acme.com",
    )

    event_name, payload = _parse_sse_chunk(
        await asyncio.wait_for(anext(stream), timeout=1)
    )
    assert event_name == "agent.online"
    assert payload == {
        "type": "agent.online",
        "team_id": "backend:acme.com",
        "alias": "bob",
        "timestamp": payload["timestamp"],
    }

    await redis.delete(f"presence:{workspace_id}")

    event_name, payload = _parse_sse_chunk(
        await asyncio.wait_for(anext(stream), timeout=1)
    )
    assert event_name == "agent.offline"
    assert payload == {
        "type": "agent.offline",
        "team_id": "backend:acme.com",
        "alias": "bob",
        "timestamp": payload["timestamp"],
    }
    await stream.aclose()


@pytest.mark.asyncio
async def test_team_presence_events_publish_to_shared_channel(aweb_cloud_db):
    redis = _FakeRedis()
    stream = dashboard_routes._sse_dashboard_events(
        request=_FakeStreamRequest(),
        db=_build_app(aweb_cloud_db.aweb_db, redis=redis).state.db,
        redis=redis,
        team_id="backend:acme.com",
    )
    assert await anext(stream) == ": keepalive\n\n"
    await anext(stream)
    await anext(stream)

    await publish_team_event(
        redis,
        TeamAgentOnlineEvent(team_id="backend:acme.com", alias="alice"),
    )
    event_name, payload = _parse_sse_chunk(
        await asyncio.wait_for(anext(stream), timeout=1)
    )
    assert event_name == "agent.online"
    assert payload == {
        "type": "agent.online",
        "team_id": "backend:acme.com",
        "alias": "alice",
        "timestamp": payload["timestamp"],
    }

    await publish_team_event(
        redis,
        TeamAgentOfflineEvent(team_id="backend:acme.com", alias="alice"),
    )
    event_name, payload = _parse_sse_chunk(
        await asyncio.wait_for(anext(stream), timeout=1)
    )
    assert event_name == "agent.offline"
    assert payload == {
        "type": "agent.offline",
        "team_id": "backend:acme.com",
        "alias": "alice",
        "timestamp": payload["timestamp"],
    }
    await stream.aclose()


@pytest.mark.asyncio
async def test_events_stream_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, redis=_FakeRedis())
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/teams/backend:acme.com/events/stream")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_events_stream_unauthorized_team_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, redis=_FakeRedis())
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
async def test_unauthorized_team_returns_403(dashboard_stack):
    token = _make_jwt(["team:other.com"])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/agents",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_token_returns_401(dashboard_stack):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    resp = await env.client.get(f"/v1/teams/{env.team_id}/agents")
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_public_team_allows_anonymous_dashboard_reads(dashboard_stack):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    registry = env.app.state.awid_registry_client
    await registry.set_team_visibility("example.test", env.team_name, "public", env.team_sk)
    resp = await env.client.get(f"/v1/teams/{env.team_id}/agents")
    assert resp.status_code == 200, resp.text
    assert {agent["alias"] for agent in resp.json()["agents"]} == {"alice", "bob"}
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_anonymous_request_reports_upstream_registry_connect_errors_as_503(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    original = env.app.state.awid_registry_client
    unavailable = RegistryClient(registry_url=f"http://127.0.0.1:{port}")
    try:
        env.app.state.awid_registry_client = unavailable
        resp = await env.client.get(f"/v1/teams/{dashboard_stack.team_id}/agents")
    finally:
        env.app.state.awid_registry_client = original
        await unavailable.aclose()
    assert resp.status_code == 503
    assert (
        "AWID dashboard team visibility lookup upstream unavailable (ConnectError)"
        in resp.json()["detail"]
    )


@pytest.mark.asyncio
async def test_private_team_with_valid_jwt_does_not_fail_on_registry_lookup_error(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed_dashboard_stack(env)

    async def fail_at_transport(request):
        raise RuntimeError("registry visibility transport failed")

    original = env.app.state.awid_registry_client
    failing = RegistryClient(
        registry_url="http://registry.test",
        transport=httpx.MockTransport(fail_at_transport),
        service_token=original.service_token,
        domain_verifier=env.registry.namespace_authority,
    )
    try:
        env.app.state.awid_registry_client = failing
        resp = await env.client.get(
            f"/v1/teams/{env.team_id}/agents",
            headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
        )
    finally:
        env.app.state.awid_registry_client = original
        await failing.aclose()
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_anonymous_request_surfaces_unexpected_registry_lookup_errors(
    dashboard_stack, caplog
):
    env = dashboard_stack
    await _seed_dashboard_stack(env)

    async def fail_at_transport(request):
        raise RuntimeError("registry visibility transport failed")

    original = env.app.state.awid_registry_client
    failing = RegistryClient(
        registry_url="http://registry.test",
        transport=httpx.MockTransport(fail_at_transport),
        service_token=original.service_token,
        domain_verifier=env.registry.namespace_authority,
    )
    try:
        env.app.state.awid_registry_client = failing
        resp = await env.client.get(f"/v1/teams/{dashboard_stack.team_id}/agents")
    finally:
        env.app.state.awid_registry_client = original
        await failing.aclose()
    assert resp.status_code == 500
    assert (
        "Unexpected AWID dashboard team visibility lookup dependency error (RuntimeError)"
        in resp.json()["detail"]
    )
    assert "registry visibility transport failed" in caplog.text


@pytest.mark.asyncio
async def test_anonymous_request_returns_503_during_partial_init_without_registry_client(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    del env.app.state.awid_registry_client
    resp = await env.client.get(f"/v1/teams/{dashboard_stack.team_id}/agents")
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["code"] == "registry_client_unavailable"
    assert detail["message"] == 'Registry client is unavailable. Configure the serving registry client and start the application before retrying.'


@pytest.mark.asyncio
async def test_authenticated_presence_read_refuses_a_missing_serving_client(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed_dashboard_stack(env)
    del env.app.state.awid_registry_client
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/agents",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["code"] == "registry_client_unavailable"
    assert resp.json()["detail"]["message"] == 'Registry client is unavailable. Configure the serving registry client and start the application before retrying.'


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
async def test_status_endpoint(dashboard_stack):
    from aweb.presence import clear_workspace_presence

    env = dashboard_stack
    await _seed_dashboard_stack(env)
    await clear_workspace_presence(
        env.redis, [str(actor.workspace) for actor in env.actors.values()]
    )
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '2 hours'"
    )
    resp = await env.client.get(
        f"/v1/teams/{env.team_id}/status",
        headers={"X-Dashboard-Token": _make_jwt([env.team_id])},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["team_id"] == env.team_id
    assert data["agent_count"] == 2
    assert data["online_agents"] == []


@pytest.mark.asyncio
async def test_roles_active_empty(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/roles/active",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json()["roles"] is None


@pytest.mark.asyncio
async def test_instructions_active_empty(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/instructions/active",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json()["instructions"] is None


@pytest.mark.asyncio
async def test_agent_not_found_returns_404(dashboard_stack):
    await _seed_dashboard_stack(dashboard_stack)
    token = _make_jwt([dashboard_stack.team_id])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/agents/nonexistent",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_expired_jwt_returns_401(dashboard_stack):
    token = jwt.encode(
        {
            "user_id": "user-123",
            "team_ids": [dashboard_stack.team_id],
            "exp": int(time.time()) - 3600,
        },
        _JWT_SECRET,
        algorithm="HS256",
    )

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{dashboard_stack.team_id}/agents",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 401


@pytest_asyncio.fixture
async def dashboard_stack(shared_test_pool, monkeypatch):
    from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_stack

    async with privacy_stack(
        shared_test_pool, monkeypatch, aliases=("alice", "bob"), team_visibility="private"
    ) as env:
        env.team_id, env.team_name = TEAM, TEAM_NAME
        yield env


async def _seed_dashboard_stack(env):
    """Only real registry/native admission supplies the converted readers' member facts."""
    from test_dashboard_privacy import _request
    from test_team_room import admit_room_member

    for alias in ("alice", "bob"):
        await admit_room_member(env, alias=alias)
    alice, bob = env.actors["alice"], env.actors["bob"]
    sent = await _request(
        env,
        "alice",
        "POST",
        "/v1/messages",
        {"to_did": bob.did, "subject": "Hello", "body": "Hi Bob!"},
    )
    assert sent.status_code == 200, sent.text
    await env.db.execute(
        """INSERT INTO {{tables.tasks}}
           (team_id,task_number,root_task_seq,task_ref_suffix,title,status,priority,task_type,created_at)
           VALUES ($1,1,1,'aaaa','Fix bug','open',2,'task',TIMESTAMPTZ '2026-04-08T12:03:00Z')""",
        env.team_id,
    )
    return str(alice.id), str(bob.id)


async def _seed_dashboard_directory(env):
    from test_agents_suggest_alias_http import _global_actor, request_as

    await _seed_dashboard_stack(env)
    await _global_actor(env, "alice", address="example.test/alice")
    for alias, agent_type in (("alice", "coder"), ("bob", "reviewer")):
        connected = await request_as(
            env, alias=alias, method="POST", path="/v1/connect",
            payload={"human_name": alias.title(), "role": "developer", "agent_type": agent_type},
        )
        assert connected.status_code == 200, connected.text
