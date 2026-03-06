"""Tests for unified /v1/tasks endpoints with beads fallback.

The /v1/tasks endpoints serve native aweb tasks and, for projects that use
beads, also return beads issues mapped to the aweb task shape. Native tasks
take priority; beads issues fill in for projects that haven't migrated yet.
"""

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis

from beadhub.api import create_app

TEST_REDIS_URL = "redis://localhost:6379/15"


async def _setup_project(client):
    """Create a project with one agent and return setup dict."""
    project_slug = f"utask-{uuid.uuid4().hex[:8]}"
    repo_origin = f"git@github.com:test/unified-{project_slug}.git"

    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": project_slug,
            "project_name": project_slug,
            "alias": f"agent-{uuid.uuid4().hex[:4]}",
            "human_name": "Test Agent",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    api_key = resp.json()["api_key"]

    reg = await client.post(
        "/v1/workspaces/register",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"repo_origin": repo_origin, "role": "developer"},
    )
    assert reg.status_code == 200, reg.text

    return {
        "project_slug": project_slug,
        "workspace_id": reg.json()["workspace_id"],
        "api_key": api_key,
        "repo_origin": repo_origin,
    }


async def _upload_beads_issues(client, api_key, issues, repo="github.com/test/repo", branch="main"):
    """Upload beads issues via the beads upload endpoint."""
    resp = await client.post(
        "/v1/beads/upload",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"repo": repo, "branch": branch, "issues": issues},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_tasks_list_includes_beads_issues(db_infra):
    """GET /v1/tasks returns beads issues mapped to task shape."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        try:
            await redis.ping()
        except Exception:
            pytest.skip("Redis is not available")
        await redis.flushdb()
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                setup = await _setup_project(client)
                headers = {"Authorization": f"Bearer {setup['api_key']}"}

                # Upload a beads issue
                await _upload_beads_issues(
                    client,
                    setup["api_key"],
                    [
                        {
                            "id": "bd-1",
                            "title": "Beads bug report",
                            "status": "open",
                            "priority": 1,
                            "issue_type": "bug",
                            "created_by": "alice",
                        },
                    ],
                )

                # GET /v1/tasks should include the beads issue
                resp = await client.get("/v1/tasks", headers=headers)
                assert resp.status_code == 200, resp.text
                tasks = resp.json()["tasks"]
                matching = [t for t in tasks if t["task_ref"] == "bd-1"]
                assert len(matching) == 1, f"Expected beads issue in task list, got {tasks}"
                task = matching[0]
                assert task["title"] == "Beads bug report"
                assert task["task_type"] == "bug"
                assert task["priority"] == 1
                assert task["status"] == "open"
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_tasks_detail_falls_back_to_beads(db_infra):
    """GET /v1/tasks/{ref} returns beads issue when no native task matches."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        try:
            await redis.ping()
        except Exception:
            pytest.skip("Redis is not available")
        await redis.flushdb()
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                setup = await _setup_project(client)
                headers = {"Authorization": f"Bearer {setup['api_key']}"}

                await _upload_beads_issues(
                    client,
                    setup["api_key"],
                    [
                        {
                            "id": "bd-42",
                            "title": "Legacy beads issue",
                            "status": "in_progress",
                            "priority": 2,
                            "issue_type": "feature",
                            "created_by": "bob",
                            "description": "A detailed description",
                            "labels": ["backend", "api"],
                        },
                    ],
                )

                # GET /v1/tasks/bd-42 should resolve from beads
                resp = await client.get("/v1/tasks/bd-42", headers=headers)
                assert resp.status_code == 200, resp.text
                task = resp.json()
                assert task["task_ref"] == "bd-42"
                assert task["title"] == "Legacy beads issue"
                assert task["task_type"] == "feature"
                assert task["priority"] == 2
                assert task["status"] == "in_progress"
                assert task["description"] == "A detailed description"
                assert task["labels"] == ["backend", "api"]
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_tasks_detail_prefers_native_over_beads(db_infra):
    """Native aweb tasks take priority when ref matches both sources."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        try:
            await redis.ping()
        except Exception:
            pytest.skip("Redis is not available")
        await redis.flushdb()
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                setup = await _setup_project(client)
                headers = {"Authorization": f"Bearer {setup['api_key']}"}

                # Create a native task
                task_resp = await client.post(
                    "/v1/tasks",
                    headers=headers,
                    json={"title": "Native task", "task_type": "bug", "priority": 1},
                )
                assert task_resp.status_code == 200, task_resp.text
                task_ref = task_resp.json()["task_ref"]

                # Upload a beads issue with the same ID (unlikely but tests priority)
                await _upload_beads_issues(
                    client,
                    setup["api_key"],
                    [
                        {
                            "id": task_ref,
                            "title": "Beads version of same issue",
                            "status": "open",
                            "priority": 3,
                            "issue_type": "task",
                            "created_by": "charlie",
                        },
                    ],
                )

                # Native should win
                resp = await client.get(f"/v1/tasks/{task_ref}", headers=headers)
                assert resp.status_code == 200, resp.text
                task = resp.json()
                assert task["title"] == "Native task", "Native task should take priority over beads"
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_tasks_list_merges_native_and_beads(db_infra):
    """GET /v1/tasks returns both native tasks and beads issues."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        try:
            await redis.ping()
        except Exception:
            pytest.skip("Redis is not available")
        await redis.flushdb()
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                setup = await _setup_project(client)
                headers = {"Authorization": f"Bearer {setup['api_key']}"}

                # Create a native task
                task_resp = await client.post(
                    "/v1/tasks",
                    headers=headers,
                    json={"title": "Native task", "task_type": "task", "priority": 1},
                )
                assert task_resp.status_code == 200, task_resp.text
                native_ref = task_resp.json()["task_ref"]

                # Upload a beads issue
                await _upload_beads_issues(
                    client,
                    setup["api_key"],
                    [
                        {
                            "id": "bd-99",
                            "title": "Beads issue",
                            "status": "open",
                            "priority": 2,
                            "issue_type": "bug",
                            "created_by": "alice",
                        },
                    ],
                )

                # Both should appear
                resp = await client.get("/v1/tasks", headers=headers)
                assert resp.status_code == 200, resp.text
                tasks = resp.json()["tasks"]
                refs = {t["task_ref"] for t in tasks}
                assert native_ref in refs, f"Expected native task {native_ref} in {refs}"
                assert "bd-99" in refs, f"Expected beads issue bd-99 in {refs}"
    finally:
        await redis.aclose()
