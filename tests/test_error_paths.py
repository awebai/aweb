"""Tests for error paths and edge cases."""

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


async def _init_workspace_and_auth(client) -> str:
    project_slug = "test-errors"
    repo_origin = "git@github.com:anthropic/beadhub.git"
    aweb_resp = await client.post(
        "/v1/init",
        json={
            "project_slug": project_slug,
            "project_name": project_slug,
            "alias": f"error-agent-{uuid.uuid4().hex[:8]}",
            "human_name": "Test",
            "agent_type": "agent",
        },
    )
    assert aweb_resp.status_code == 200, aweb_resp.text
    api_key = aweb_resp.json()["api_key"]
    client.headers["Authorization"] = f"Bearer {api_key}"

    reg = await client.post(
        "/v1/workspaces/register",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"repo_origin": repo_origin, "role": "agent"},
    )
    assert reg.status_code == 200, reg.text
    return reg.json()["workspace_id"]


@pytest.mark.asyncio
async def test_mcp_invalid_json(db_infra, redis_client_async):
    """MCP endpoint rejects malformed JSON."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/mcp",
                content="not valid json",
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 422
            error = resp.json()
            assert "detail" in error


@pytest.mark.asyncio
async def test_mcp_unknown_tool(db_infra, redis_client_async):
    """MCP endpoint returns error for unknown tool."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "nonexistent_tool",
                    "arguments": {},
                },
            }
            resp = await client.post("/mcp", json=req)
            assert resp.status_code == 200
            body = resp.json()
            assert "error" in body
            assert body["error"]["code"] == -32601
            assert "Unknown tool" in body["error"]["message"]


@pytest.mark.asyncio
async def test_task_patch_nonexistent_returns_404(db_infra, redis_client_async):
    """PATCH /v1/tasks/{ref} returns 404 for non-numeric bead refs (not 500)."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            await _init_workspace_and_auth(client)
            resp = await client.patch(
                "/v1/tasks/beadhub-xbdk",
                json={"status": "closed"},
            )
            assert resp.status_code == 404
            assert resp.json()["detail"] == "Task not found"


@pytest.mark.asyncio
async def test_escalation_not_found(db_infra, redis_client_async):
    """Fetching a nonexistent escalation returns 404."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            await _init_workspace_and_auth(client)
            # Use a valid UUID that doesn't exist
            resp = await client.get("/v1/escalations/00000000-0000-0000-0000-000000000000")
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_escalation_respond_not_found(db_infra, redis_client_async):
    """Responding to a nonexistent escalation returns 404."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            await _init_workspace_and_auth(client)
            resp = await client.post(
                "/v1/escalations/00000000-0000-0000-0000-000000000000/respond",
                json={
                    "response": "approved",
                    "note": "looks good",
                },
            )
            assert resp.status_code == 404
