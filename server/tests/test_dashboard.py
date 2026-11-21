"""Dashboard reads through actual native, registry, PostgreSQL and Redis resources."""

from __future__ import annotations

import socket
import time
import uuid
from datetime import timedelta

import httpx
import jwt
import pytest
import pytest_asyncio
from awid.registry import RegistryClient

from aweb.embedding import OutboxRecoveryOwnership
from aweb.lifecycle import LifecycleActor, LifecycleCascadeRequest, apply_lifecycle_cascade
from dashboard_test_support import _JWT_SECRET as _JWT_SECRET, _make_jwt as _make_jwt
from test_dashboard_privacy import TEAM, TEAM_NAME, _request, privacy_stack
from test_dashboard_privacy import privacy_app
from test_team_room import admit_room_member
from test_workspace_liveness_http import _send_member_request

__all__ = ["privacy_app"]


@pytest_asyncio.fixture
async def dashboard_stack(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool,
        monkeypatch,
        team_visibility="private",
        aliases=("alice", "bob"),
        outbox_recovery=OutboxRecoveryOwnership.HOST,
    ) as env:
        yield env


async def _seed(env):
    """Actual member admission/mail write; fixed task rows are pagination inputs."""
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
        TEAM,
    )
    return str(alice.id), str(bob.id)


@pytest.mark.asyncio
async def test_claims(dashboard_stack):
    alice_id, _ = await _seed(dashboard_stack)
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
            '{TEAM}', $1, 'alice', 'Alice', '{TEAM_NAME}-aaaa',
            TIMESTAMPTZ '2026-04-08T12:15:00Z'
        )
        """,
        workspace_id,
    )
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/claims",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "claims": [
            {
                "task_ref": f"{TEAM_NAME}-aaaa",
                "workspace_id": str(workspace_id),
                "alias": "alice",
                "claimed_at": "2026-04-08T12:15:00+00:00",
            }
        ]
    }


@pytest.mark.asyncio
async def test_claims_unauthorized_returns_403(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt(["team:other.com"])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/claims",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_claims_missing_token_returns_401(privacy_app):
    env = privacy_app
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET visibility='private' WHERE domain='example.test' AND name=$1",
        TEAM.split(":", 1)[0],
    )
    response = await env.client.get(f"/v1/teams/{TEAM}/claims")
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_dashboard_messages_route_is_removed(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/messages",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
async def test_tasks(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
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
    await _seed(dashboard_stack)
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
            ($1, '{TEAM}', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', $2,
             TIMESTAMPTZ '2026-04-08T12:05:00Z', TIMESTAMPTZ '2026-04-08T12:06:00Z'),
            ($2, '{TEAM}', 3, 3, 'aaac', 'Parent task', 'Parent for dashboard task',
             'open', 1, 'epic', ARRAY['backend']::text[], NULL, NULL,
             TIMESTAMPTZ '2026-04-08T12:04:30Z', TIMESTAMPTZ '2026-04-08T12:04:45Z'),
            ($3, '{TEAM}', 4, 4, 'aaad', 'Blocked task', 'Blocked by dashboard task',
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
        VALUES ($1, $2, '{TEAM}')
        """,
        blocked_task_id,
        blocker_task_id,
    )
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
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
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"status": "closed"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_unknown_assignee_returns_empty_results(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"assignee_alias": "someone-who-left"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json() == {"tasks": [], "has_more": False, "next_cursor": None}


@pytest.mark.asyncio
async def test_tasks_invalid_cursor_returns_422(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"cursor": "not-base64"},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 422
    assert resp.json()["detail"] == "Invalid cursor"


@pytest.mark.asyncio
async def test_tasks_filters_in_isolation(dashboard_stack):
    await _seed(dashboard_stack)
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.tasks}}}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            status, priority, task_type, labels, assignee_alias, created_at
        )
        VALUES
            ($1, '{TEAM}', 2, 2, 'aaab', 'Build dashboard', 'Add dashboard filters',
             'in_progress', 0, 'feature', ARRAY['dashboard','backend']::text[], 'alice', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, '{TEAM}', 3, 3, 'aaac', 'Document claims', 'Write pagination docs',
             'open', 1, 'chore', ARRAY['docs']::text[], NULL, TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    status_resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"status": "in_progress"},
        headers={"X-Dashboard-Token": token},
    )
    assignee_resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"assignee_alias": "alice"},
        headers={"X-Dashboard-Token": token},
    )
    priority_resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
        params={"priority": "P0"},
        headers={"X-Dashboard-Token": token},
    )
    q_resp = await client.get(
        f"/v1/teams/{TEAM}/tasks",
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
    await _seed(dashboard_stack)
    await dashboard_stack.db.execute(
        f"""
        INSERT INTO {{{{tables.tasks}}}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at
        )
        VALUES
            ($1, '{TEAM}', 2, 2, 'aaab', 'Second task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:05:00Z'),
            ($2, '{TEAM}', 3, 3, 'aaac', 'Third task', 'open', 2, 'task', TIMESTAMPTZ '2026-04-08T12:04:00Z')
        """,
        uuid.uuid4(),
        uuid.uuid4(),
    )
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    first = await client.get(
        f"/v1/teams/{TEAM}/tasks",
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
        f"/v1/teams/{TEAM}/tasks",
        params={"limit": 2, "cursor": first_data["next_cursor"]},
        headers={"X-Dashboard-Token": token},
    )

    assert second.status_code == 200
    second_data = second.json()
    assert [task["title"] for task in second_data["tasks"]] == ["Fix bug"]
    assert second_data["has_more"] is False
    assert second_data["next_cursor"] is None


@pytest.mark.asyncio
async def test_events_stream_missing_token_returns_401(privacy_app):
    env = privacy_app
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET visibility='private' WHERE domain='example.test' AND name=$1",
        TEAM.split(":", 1)[0],
    )
    response = await env.client.get(f"/v1/teams/{TEAM}/events/stream")
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_events_stream_unauthorized_team_returns_403(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt(["team:other.com"])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/events/stream",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthorized_team_returns_403(dashboard_stack):
    token = _make_jwt(["team:other.com"])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/agents",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_token_returns_401(dashboard_stack):
    env = dashboard_stack
    await _seed(env)
    resp = await env.client.get(f"/v1/teams/{TEAM}/agents")
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_public_team_allows_anonymous_dashboard_reads(dashboard_stack):
    env = dashboard_stack
    await _seed(env)
    registry = env.app.state.awid_registry_client
    await registry.set_team_visibility("example.test", TEAM_NAME, "public", env.team_sk)
    resp = await env.client.get(f"/v1/teams/{TEAM}/agents")
    assert resp.status_code == 200, resp.text
    assert {agent["alias"] for agent in resp.json()["agents"]} == {"alice", "bob"}
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_anonymous_request_reports_upstream_registry_connect_errors_as_503(
    dashboard_stack,
):
    env = dashboard_stack
    await _seed(env)
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    original = env.app.state.awid_registry_client
    unavailable = RegistryClient(registry_url=f"http://127.0.0.1:{port}")
    try:
        env.app.state.awid_registry_client = unavailable
        resp = await env.client.get(f"/v1/teams/{TEAM}/agents")
    finally:
        env.app.state.awid_registry_client = original
        await unavailable.aclose()
    assert resp.status_code == 503
    assert (
        "AWID dashboard team visibility lookup upstream unavailable (ConnectError)"
        in resp.json()["detail"]
    )


@pytest.mark.asyncio
async def test_anonymous_request_surfaces_unexpected_registry_lookup_errors(
    dashboard_stack, caplog
):
    env = dashboard_stack
    await _seed(env)

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
        resp = await env.client.get(f"/v1/teams/{TEAM}/agents")
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
    await _seed(env)
    del env.app.state.awid_registry_client
    resp = await env.client.get(f"/v1/teams/{TEAM}/agents")
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["code"] == "registry_client_unavailable"
    assert (
        detail["message"]
        == "Registry client is unavailable. Configure the serving registry client and start the application before retrying."
    )


@pytest.mark.asyncio
async def test_usage_endpoint(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        "/v1/usage",
        params={"team_id": TEAM},
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["team_id"] == TEAM
    assert data["messages_sent"] >= 1
    assert data["active_agents"] >= 2


@pytest.mark.asyncio
async def test_roles_active_empty(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/roles/active",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json()["roles"] is None


@pytest.mark.asyncio
async def test_instructions_active_empty(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/instructions/active",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 200
    assert resp.json()["instructions"] is None


@pytest.mark.asyncio
async def test_agent_not_found_returns_404(dashboard_stack):
    await _seed(dashboard_stack)
    token = _make_jwt([TEAM])

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/agents/nonexistent",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_expired_jwt_returns_401(dashboard_stack):
    token = jwt.encode(
        {
            "user_id": "user-123",
            "team_ids": [TEAM],
            "exp": int(time.time()) - 3600,
        },
        _JWT_SECRET,
        algorithm="HS256",
    )

    client = dashboard_stack.client
    resp = await client.get(
        f"/v1/teams/{TEAM}/agents",
        headers={"X-Dashboard-Token": token},
    )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_agents_and_detail_keep_workspace_and_identity_fields(privacy_app):
    from test_agents_suggest_alias_http import _global_actor

    env = privacy_app
    alice = env.actors["alice"]
    await _global_actor(env, "alice", address="example.test/alice")
    connected = await _send_member_request(
        env, alias="alice", method="POST", path="/v1/connect",
        body={"workspace_path": "/workspace/alice", "human_name": "Alice",
              "role": "developer", "agent_type": "coder"},
    )
    assert connected.status_code == 200, connected.text
    seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        alice.workspace,
    )
    assert seen is not None
    headers = {"X-Dashboard-Token": _make_jwt([TEAM])}
    response = await env.client.get(f"/v1/teams/{TEAM}/agents", headers=headers)
    assert response.status_code == 200, response.text
    agents = {agent["alias"]: agent for agent in response.json()["agents"]}
    assert set(agents) == set(env.actors)
    assert agents["alice"]["workspace_path"] == "/workspace/alice"
    assert agents["alice"]["last_seen"] == seen.isoformat()
    assert agents["alice"]["address"] == "example.test/alice"
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
    await admit_room_member(env, alias="bob")
    removed = await apply_lifecycle_cascade(
        env.db,
        env.redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(actor_id="test-host", actor_type="system", authority="embedding"),
            team_id=TEAM,
            target_workspace_ids=(str(bob.workspace),),
        ),
        registry_client=env.app.state.awid_registry_client,
    )
    assert removed.errors == ()
    assert not removed.identity_deleted
    assert [change.workspace_id for change in removed.workspace_changes] == [str(bob.workspace)]
    connected = await _send_member_request(
        env,
        alias="bob",
        method="POST",
        path="/v1/connect",
        body={"workspace_path": "/workspace/live"},
    )
    assert connected.status_code == 200, connected.text
    assert connected.json()["agent_id"] == str(bob.id)
    live_workspace = uuid.UUID(connected.json()["workspace_id"])
    assert live_workspace != bob.workspace
    seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        bob.workspace,
    )
    assert seen is not None
    live_seen = seen - timedelta(seconds=1)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
        live_seen,
        live_workspace,
    )
    response = await env.client.get(
        f"/v1/teams/{TEAM}/agents", headers={"X-Dashboard-Token": _make_jwt([TEAM])}
    )
    assert response.status_code == 200, response.text
    bob_row = next(row for row in response.json()["agents"] if row["alias"] == "bob")
    assert bob_row["workspace_path"] == "/workspace/live"
    assert bob_row["last_seen"] == live_seen.isoformat()


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
