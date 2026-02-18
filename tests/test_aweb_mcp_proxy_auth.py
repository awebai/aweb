"""Tests for MCP proxy auth: tampered headers must be rejected, not fall back to Bearer."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import (
    INTERNAL_ACTOR_ID_HEADER,
    INTERNAL_BEADHUB_AUTH_HEADER,
    INTERNAL_PROJECT_HEADER,
    INTERNAL_USER_HEADER,
    _internal_auth_header_value,
)
from aweb.db import DatabaseInfra
from aweb.mcp import create_mcp_app

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


async def _init_agent(client: AsyncClient, slug: str, alias: str) -> dict:
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


def _tampered_proxy_headers(project_id: str, actor_id: str) -> dict:
    """Build proxy headers with a wrong HMAC signature."""
    principal_id = str(uuid.uuid4())
    # Use a wrong secret to produce an invalid signature.
    bad_auth = _internal_auth_header_value(
        secret="wrong-secret",
        project_id=project_id,
        principal_type="u",
        principal_id=principal_id,
        actor_id=actor_id,
    )
    return {
        INTERNAL_BEADHUB_AUTH_HEADER: bad_auth,
        INTERNAL_PROJECT_HEADER: project_id,
        INTERNAL_USER_HEADER: principal_id,
        INTERNAL_ACTOR_ID_HEADER: actor_id,
    }


@pytest.mark.asyncio
async def test_tampered_proxy_headers_rejected_without_bearer_fallback(
    aweb_db_infra: DatabaseInfra,
    monkeypatch,
):
    """When proxy headers are trusted and HMAC is invalid, MCP must return 401
    even if no Bearer token is provided — it must NOT fall through to Bearer auth."""
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

    project_id = str(uuid.uuid4())
    actor_id = str(uuid.uuid4())
    headers = _tampered_proxy_headers(project_id, actor_id)

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
                headers={"Accept": "application/json, text/event-stream", **headers},
            )
            assert (
                resp.status_code == 401
            ), f"Expected 401 for tampered proxy headers, got {resp.status_code}"


@pytest.mark.asyncio
async def test_tampered_proxy_headers_rejected_even_with_valid_bearer(
    aweb_db_infra: DatabaseInfra,
    monkeypatch,
):
    """When proxy headers are trusted and HMAC is invalid, MCP must return 401
    even when a valid Bearer token is also present — proxy mode must not fall back."""
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

    # Create a valid agent with a Bearer key.
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            agent = await _init_agent(rc, "proxy-test", "alice")

    api_key = agent["api_key"]
    project_id = agent["project_id"]
    actor_id = agent["agent_id"]

    # Build tampered proxy headers + valid Bearer.
    headers = _tampered_proxy_headers(project_id, actor_id)
    headers["Authorization"] = f"Bearer {api_key}"

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
                headers={"Accept": "application/json, text/event-stream", **headers},
            )
            assert resp.status_code == 401, (
                f"Expected 401 for tampered proxy headers even with valid Bearer, "
                f"got {resp.status_code}"
            )
