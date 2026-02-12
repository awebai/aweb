"""Tests for the aweb MCP server module."""

from __future__ import annotations

import json

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.mcp import create_mcp_app


async def _init_agent(client: AsyncClient, slug: str, alias: str) -> dict:
    """Bootstrap a project + agent + API key via /v1/init."""
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": slug,
            "alias": alias,
            "human_name": f"Human {alias}",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

_PROTOCOL_VERSION = "2025-03-26"
_REQ_ID = 0


def _next_id() -> int:
    global _REQ_ID
    _REQ_ID += 1
    return _REQ_ID


def _jsonrpc(method: str, params: dict | None = None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": _next_id()}
    if params is not None:
        msg["params"] = params
    return msg


_MCP_ACCEPT = "application/json, text/event-stream"


async def _mcp_initialize(mc: AsyncClient, headers: dict | None = None) -> tuple[dict, str]:
    """Send MCP initialize + initialized, return (result, session_id)."""
    h = {"Accept": _MCP_ACCEPT, **(headers or {})}
    resp = await mc.post(
        "/mcp",
        json=_jsonrpc(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "0.1"},
            },
        ),
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.headers.get("mcp-session-id", "")

    # Send initialized notification
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    await mc.post(
        "/mcp",
        json=notif,
        headers={"Accept": _MCP_ACCEPT, "mcp-session-id": session_id, **(headers or {})},
    )
    return resp.json(), session_id


async def _mcp_call(
    mc: AsyncClient, method: str, params: dict, session_id: str, headers: dict | None = None
) -> dict:
    """Send a JSON-RPC request to the MCP endpoint and return the response."""
    h = {"Accept": _MCP_ACCEPT, "mcp-session-id": session_id, **(headers or {})}
    resp = await mc.post(
        "/mcp",
        json=_jsonrpc(method, params),
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Scaffold tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_app_can_be_created(aweb_db_infra):
    """create_mcp_app returns an ASGI app."""
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    assert mcp_app is not None


@pytest.mark.asyncio
async def test_mcp_initialize_without_auth_rejected(aweb_db_infra):
    """Unauthenticated requests are rejected."""
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            resp = await mc.post(
                "/mcp",
                json=_jsonrpc(
                    "initialize",
                    {
                        "protocolVersion": _PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0.1"},
                    },
                ),
            )
            assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mcp_initialize_with_auth(aweb_db_infra):
    """Authenticated MCP initialization succeeds and returns tools."""
    # Bootstrap an agent via the REST API first
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            agent = await _init_agent(rc, "mcp-test", "alice")
            api_key = agent["api_key"]

    # Now test the MCP app
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    auth = {"Authorization": f"Bearer {api_key}"}

    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            result, session_id = await _mcp_initialize(mc, headers=auth)
            assert "result" in result
            assert result["result"]["serverInfo"]["name"] == "aweb"


@pytest.mark.asyncio
async def test_mcp_lists_tools(aweb_db_infra):
    """tools/list returns the registered aweb tools."""
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            agent = await _init_agent(rc, "mcp-tools", "alice")
            api_key = agent["api_key"]

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    auth = {"Authorization": f"Bearer {api_key}"}

    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, session_id = await _mcp_initialize(mc, headers=auth)
            result = await _mcp_call(mc, "tools/list", {}, session_id, headers=auth)

            tools = result["result"]["tools"]
            tool_names = {t["name"] for t in tools}
            assert "whoami" in tool_names


# ---------------------------------------------------------------------------
# whoami tool test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_whoami(aweb_db_infra):
    """whoami tool returns the authenticated agent's identity."""
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            agent = await _init_agent(rc, "mcp-whoami", "alice")
            api_key = agent["api_key"]

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    auth = {"Authorization": f"Bearer {api_key}"}

    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, session_id = await _mcp_initialize(mc, headers=auth)
            result = await _mcp_call(
                mc, "tools/call", {"name": "whoami", "arguments": {}}, session_id, headers=auth
            )

            content = result["result"]["content"]
            assert len(content) == 1
            assert content[0]["type"] == "text"
            data = json.loads(content[0]["text"])
            assert data["alias"] == "alice"
            assert data["project_id"] == agent["project_id"]
            assert data["agent_id"] == agent["agent_id"]
