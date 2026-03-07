"""Tests for MCP discovery methods: tools/list, resources/list, resources/read."""

import json

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _rpc(client, api_key, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    resp = await client.post("/mcp", json=body, headers=_auth_headers(api_key))
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_tools_list_returns_all_tools(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-discovery",
                repo_origin="git@github.com:test/mcp-discovery.git",
                alias="disco-agent",
            )
            result = await _rpc(client, init["api_key"], "tools/list")

            assert "result" in result, f"Expected result, got: {result}"
            tools = result["result"]["tools"]
            assert isinstance(tools, list)
            assert len(tools) >= 10

            tool_names = {t["name"] for t in tools}
            assert "register_agent" in tool_names
            assert "list_agents" in tool_names
            assert "status" in tool_names
            assert "get_ready_issues" in tool_names
            assert "get_issue" in tool_names
            assert "subscribe_to_bead" in tool_names
            assert "list_subscriptions" in tool_names
            assert "unsubscribe" in tool_names
            assert "escalate" in tool_names
            assert "get_escalation" in tool_names

            # Each tool must have name, description, and inputSchema
            for tool in tools:
                assert "name" in tool
                assert "description" in tool
                assert "inputSchema" in tool
                schema = tool["inputSchema"]
                assert schema.get("type") == "object"


@pytest.mark.asyncio
async def test_tools_list_existing_tools_call_still_works(db_infra, async_redis, init_workspace):
    """Verify tools/call still works after adding tools/list."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-compat",
                repo_origin="git@github.com:test/mcp-compat.git",
                alias="compat-agent",
            )
            # tools/call should still work
            result = await _rpc(
                client,
                init["api_key"],
                "tools/call",
                {
                    "name": "register_agent",
                    "arguments": {
                        "workspace_id": init["workspace_id"],
                        "alias": "compat-agent",
                        "human_name": "Test",
                    },
                },
            )
            payload = json.loads(result["result"]["content"][0]["text"])
            assert payload["ok"] is True


@pytest.mark.asyncio
async def test_resources_list(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-resources",
                repo_origin="git@github.com:test/mcp-resources.git",
                alias="res-agent",
            )
            result = await _rpc(client, init["api_key"], "resources/list")

            assert "result" in result, f"Expected result, got: {result}"
            resources = result["result"]["resources"]
            assert isinstance(resources, list)
            assert len(resources) >= 1

            # Each resource must have uri and name
            for res in resources:
                assert "uri" in res
                assert "name" in res

            uris = {r["uri"] for r in resources}
            assert "beadhub://status" in uris


@pytest.mark.asyncio
async def test_resources_read_status(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-read",
                repo_origin="git@github.com:test/mcp-read.git",
                alias="read-agent",
            )
            # First register presence so status has data
            await _rpc(
                client,
                init["api_key"],
                "tools/call",
                {
                    "name": "register_agent",
                    "arguments": {
                        "workspace_id": init["workspace_id"],
                        "alias": "read-agent",
                        "human_name": "Test",
                    },
                },
            )

            result = await _rpc(
                client,
                init["api_key"],
                "resources/read",
                {"uri": "beadhub://status"},
            )

            assert "result" in result, f"Expected result, got: {result}"
            contents = result["result"]["contents"]
            assert isinstance(contents, list)
            assert len(contents) == 1
            assert contents[0]["uri"] == "beadhub://status"
            assert contents[0]["mimeType"] == "application/json"
            # Should be valid JSON
            data = json.loads(contents[0]["text"])
            assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_resources_read_unknown_uri(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-read-err",
                repo_origin="git@github.com:test/mcp-read-err.git",
                alias="err-agent",
            )
            result = await _rpc(
                client,
                init["api_key"],
                "resources/read",
                {"uri": "beadhub://nonexistent"},
            )

            assert "error" in result
            assert result["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_resources_read_missing_uri(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await init_workspace(
                client,
                project_slug="mcp-read-nouri",
                repo_origin="git@github.com:test/mcp-read-nouri.git",
                alias="nouri-agent",
            )
            result = await _rpc(
                client,
                init["api_key"],
                "resources/read",
                {},
            )

            assert "error" in result
            assert result["error"]["code"] == -32602
