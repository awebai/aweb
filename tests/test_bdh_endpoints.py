import json
import logging
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis

from beadhub.api import create_app
from beadhub.routes.bdh import _parse_command_line

logger = logging.getLogger(__name__)

TEST_REDIS_URL = "redis://localhost:6379/15"
TEST_REPO_ORIGIN = "git@github.com:anthropic/beadhub.git"


def auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _jsonl(*rows: dict) -> str:
    return "\n".join(json.dumps(r) for r in rows) + "\n"


@pytest.mark.asyncio
async def test_bdh_command_requires_workspace_and_returns_claims(db_infra, init_workspace):
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        logger.warning("Redis is not available; skipping test", exc_info=True)
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                init = await init_workspace(
                    client,
                    project_slug=f"bdh-{uuid.uuid4().hex[:8]}",
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice-agent",
                    human_name="Alice",
                    role="agent",
                )

                resp = await client.post(
                    "/v1/bdh/command",
                    headers=auth_headers(init["api_key"]),
                    json={
                        "workspace_id": init["workspace_id"],
                        "repo_id": init["repo_id"],
                        "alias": init["alias"],
                        "human_name": init["human_name"],
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "command_line": "ready",
                    },
                )
                assert resp.status_code == 200, resp.text
                data = resp.json()
                assert data["approved"] is True
                assert data["context"]["beads_in_progress"] == []
    except Exception:
        logger.exception("test_bdh_command_requires_workspace_and_returns_claims failed")
        raise
    finally:
        await redis.flushdb()
        await redis.aclose()


@pytest.mark.asyncio
async def test_bdh_sync_sets_and_clears_claims(db_infra, init_workspace):
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        logger.warning("Redis is not available; skipping test", exc_info=True)
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                init = await init_workspace(
                    client,
                    project_slug=f"bdh-{uuid.uuid4().hex[:8]}",
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice-agent",
                    human_name="Alice",
                    role="agent",
                )

                # Full sync after claiming a bead (bdh does full on first run).
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(init["api_key"]),
                    json={
                        "workspace_id": init["workspace_id"],
                        "repo_id": init["repo_id"],
                        "alias": init["alias"],
                        "human_name": init["human_name"],
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "sync_mode": "full",
                        "issues_jsonl": _jsonl(
                            {"id": "bd-1", "title": "t", "status": "in_progress"}
                        ),
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text

                claims = await client.get("/v1/claims", headers=auth_headers(init["api_key"]))
                assert claims.status_code == 200
                claim_list = claims.json()["claims"]
                assert len(claim_list) == 1
                assert claim_list[0]["bead_id"] == "bd-1"
                assert claim_list[0]["workspace_id"] == init["workspace_id"]

                # Incremental sync clears claim when closing.
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(init["api_key"]),
                    json={
                        "workspace_id": init["workspace_id"],
                        "repo_id": init["repo_id"],
                        "alias": init["alias"],
                        "human_name": init["human_name"],
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "sync_mode": "incremental",
                        "changed_issues": _jsonl({"id": "bd-1", "title": "t", "status": "closed"}),
                        "deleted_ids": [],
                        "command_line": "close bd-1",
                    },
                )
                assert resp.status_code == 200, resp.text

                claims = await client.get("/v1/claims", headers=auth_headers(init["api_key"]))
                assert claims.status_code == 200
                assert claims.json()["claims"] == []
    except Exception:
        logger.exception("test_bdh_sync_sets_and_clears_claims failed")
        raise
    finally:
        await redis.flushdb()
        await redis.aclose()


@pytest.mark.asyncio
async def test_bdh_command_returns_401_when_workspace_deleted(db_infra, init_workspace):
    """Workspace deletion cascades to agent soft-delete, deactivating API keys."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        logger.warning("Redis is not available; skipping test", exc_info=True)
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                init = await init_workspace(
                    client,
                    project_slug=f"bdh-{uuid.uuid4().hex[:8]}",
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice-agent",
                    human_name="Alice",
                    role="agent",
                )

                # Soft-delete workspace (cascades to agent soft-delete).
                delete_resp = await client.delete(
                    f"/v1/workspaces/{init['workspace_id']}",
                    headers=auth_headers(init["api_key"]),
                )
                assert delete_resp.status_code == 200, delete_resp.text

                resp = await client.post(
                    "/v1/bdh/command",
                    headers=auth_headers(init["api_key"]),
                    json={
                        "workspace_id": init["workspace_id"],
                        "repo_id": init["repo_id"],
                        "alias": init["alias"],
                        "human_name": init["human_name"],
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "command_line": "ready",
                    },
                )
                assert resp.status_code == 401, resp.text
    except Exception:
        logger.exception("test_bdh_command_returns_401_when_workspace_deleted failed")
        raise
    finally:
        await redis.flushdb()
        await redis.aclose()


@pytest.mark.asyncio
async def test_bdh_command_rejects_claim_when_already_claimed(db_infra, init_workspace):
    """Command should return approved=False when another workspace already claims the bead."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                slug = f"bdh-{uuid.uuid4().hex[:8]}"

                # Create two workspaces in the same project
                alice = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice-dev",
                    human_name="Alice",
                    role="developer",
                )
                bob = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="bob-dev",
                    human_name="Bob",
                    role="developer",
                )

                # Alice claims bd-1 via sync
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(alice["api_key"]),
                    json={
                        "workspace_id": alice["workspace_id"],
                        "alias": alice["alias"],
                        "human_name": "Alice",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "sync_mode": "full",
                        "issues_jsonl": _jsonl(
                            {"id": "bd-1", "title": "Fix bug", "status": "in_progress"}
                        ),
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text

                # Bob tries to claim the same bead via command
                resp = await client.post(
                    "/v1/bdh/command",
                    headers=auth_headers(bob["api_key"]),
                    json={
                        "workspace_id": bob["workspace_id"],
                        "alias": bob["alias"],
                        "human_name": "Bob",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text
                data = resp.json()
                assert data["approved"] is False
                assert "alice-dev" in data["reason"]

                # Bob's non-claim command should still be approved
                resp = await client.post(
                    "/v1/bdh/command",
                    headers=auth_headers(bob["api_key"]),
                    json={
                        "workspace_id": bob["workspace_id"],
                        "alias": bob["alias"],
                        "human_name": "Bob",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "command_line": "ready",
                    },
                )
                assert resp.status_code == 200, resp.text
                assert resp.json()["approved"] is True

                # Alice claiming her own bead again should be approved
                resp = await client.post(
                    "/v1/bdh/command",
                    headers=auth_headers(alice["api_key"]),
                    json={
                        "workspace_id": alice["workspace_id"],
                        "alias": alice["alias"],
                        "human_name": "Alice",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text
                assert resp.json()["approved"] is True
    finally:
        await redis.flushdb()
        await redis.aclose()


@pytest.mark.asyncio
async def test_sync_rejects_claim_when_already_claimed_by_another(db_infra, init_workspace):
    """Sync should skip the claim upsert when another workspace already holds it."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                slug = f"bdh-{uuid.uuid4().hex[:8]}"

                alice = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice-dev",
                    human_name="Alice",
                    role="developer",
                )
                bob = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="bob-dev",
                    human_name="Bob",
                    role="developer",
                )

                # Alice claims bd-1 via sync
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(alice["api_key"]),
                    json={
                        "workspace_id": alice["workspace_id"],
                        "alias": alice["alias"],
                        "human_name": "Alice",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "sync_mode": "full",
                        "issues_jsonl": _jsonl(
                            {"id": "bd-1", "title": "Fix bug", "status": "in_progress"}
                        ),
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text
                assert resp.json().get("claim_rejected") is not True

                # Bob tries to claim bd-1 via sync — issues should sync but claim should be skipped
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(bob["api_key"]),
                    json={
                        "workspace_id": bob["workspace_id"],
                        "alias": bob["alias"],
                        "human_name": "Bob",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "developer",
                        "sync_mode": "full",
                        "issues_jsonl": _jsonl(
                            {"id": "bd-1", "title": "Fix bug", "status": "in_progress"}
                        ),
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text
                data = resp.json()
                assert data["synced"] is True  # Issues still sync
                assert data["claim_rejected"] is True
                assert "alice-dev" in data["claim_rejected_reason"]

                # Only Alice's claim should exist
                claims = await client.get("/v1/claims", headers=auth_headers(alice["api_key"]))
                assert claims.status_code == 200
                claim_list = claims.json()["claims"]
                assert len(claim_list) == 1
                assert claim_list[0]["alias"] == "alice-dev"
    finally:
        await redis.flushdb()
        await redis.aclose()


class TestParseCommandLine:
    def test_update_in_progress(self):
        cmd, bead_id, status = _parse_command_line("update bd-1 --status in_progress")
        assert (cmd, bead_id, status) == ("update", "bd-1", "in_progress")

    def test_update_with_equals(self):
        cmd, bead_id, status = _parse_command_line("update bd-1 --status=in_progress")
        assert (cmd, bead_id, status) == ("update", "bd-1", "in_progress")

    def test_close(self):
        cmd, bead_id, status = _parse_command_line("close bd-42")
        assert (cmd, bead_id, status) == ("close", "bd-42", None)

    def test_ready(self):
        cmd, bead_id, status = _parse_command_line("ready")
        assert (cmd, bead_id, status) == ("ready", None, None)

    def test_empty(self):
        cmd, bead_id, status = _parse_command_line("")
        assert (cmd, bead_id, status) == (None, None, None)

    def test_bead_id_starting_with_dashes_ignored(self):
        """update --status in_progress (no bead_id) should not set bead_id to '--status'."""
        cmd, bead_id, status = _parse_command_line("update --status in_progress")
        assert bead_id is None

    def test_delete(self):
        cmd, bead_id, status = _parse_command_line("delete bd-5")
        assert (cmd, bead_id, status) == ("delete", "bd-5", None)


@pytest.mark.asyncio
async def test_close_releases_claims_from_all_workspaces(db_infra, init_workspace):
    """Closing a bead should release claims held by ANY workspace, not just the closer."""
    redis = await Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:
        pytest.skip("Redis is not available")
    await redis.flushdb()

    try:
        app = create_app(db_infra=db_infra, redis=redis, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                slug = f"bdh-{uuid.uuid4().hex[:8]}"
                # Two workspaces in the same project.
                ws_a = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="alice",
                    human_name="Alice",
                    role="agent",
                )
                ws_b = await init_workspace(
                    client,
                    project_slug=slug,
                    repo_origin=TEST_REPO_ORIGIN,
                    alias="bob",
                    human_name="Bob",
                    role="agent",
                )

                # Alice claims bd-1 via sync.
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(ws_a["api_key"]),
                    json={
                        "workspace_id": ws_a["workspace_id"],
                        "repo_id": ws_a["repo_id"],
                        "alias": "alice",
                        "human_name": "Alice",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "sync_mode": "full",
                        "issues_jsonl": _jsonl(
                            {"id": "bd-1", "title": "Fix bug", "status": "in_progress"},
                        ),
                        "command_line": "update bd-1 --status in_progress",
                    },
                )
                assert resp.status_code == 200, resp.text

                # Verify Alice's claim exists.
                claims = await client.get("/v1/claims", headers=auth_headers(ws_a["api_key"]))
                assert len(claims.json()["claims"]) == 1

                # Bob closes the same bead via sync.
                resp = await client.post(
                    "/v1/bdh/sync",
                    headers=auth_headers(ws_b["api_key"]),
                    json={
                        "workspace_id": ws_b["workspace_id"],
                        "repo_id": ws_b["repo_id"],
                        "alias": "bob",
                        "human_name": "Bob",
                        "repo_origin": TEST_REPO_ORIGIN,
                        "role": "agent",
                        "sync_mode": "incremental",
                        "changed_issues": _jsonl(
                            {"id": "bd-1", "title": "Fix bug", "status": "closed"},
                        ),
                        "deleted_ids": [],
                        "command_line": "close bd-1",
                    },
                )
                assert resp.status_code == 200, resp.text

                # Alice's claim should be gone — the close released ALL claims.
                claims = await client.get("/v1/claims", headers=auth_headers(ws_a["api_key"]))
                assert (
                    claims.json()["claims"] == []
                ), "Closing a bead from another workspace should release all claims"
    finally:
        await redis.flushdb()
        await redis.aclose()
