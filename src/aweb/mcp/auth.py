"""MCP authentication middleware.

Extracts Bearer tokens from incoming requests, validates them against the aweb
API key store, and makes the resolved auth context available to MCP tool
handlers via a contextvar.
"""

from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from aweb.auth import verify_bearer_token_details

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Resolved identity for the current MCP request."""

    project_id: str
    agent_id: str
    api_key_id: str


_auth_context: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar(
    "aweb_mcp_auth", default=None
)


def get_auth() -> AuthContext:
    """Return the auth context for the current request.

    Raises RuntimeError if called outside an authenticated request.
    """
    ctx = _auth_context.get()
    if ctx is None:
        raise RuntimeError("No MCP auth context — request was not authenticated")
    return ctx


class MCPAuthMiddleware:
    """ASGI middleware that enforces Bearer token auth on every MCP request.

    Also manages the MCP session manager lifespan when provided.
    """

    def __init__(self, app: ASGIApp, db_infra: Any) -> None:
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            response = JSONResponse(
                {"error": "Authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        token = auth_header[7:]
        try:
            details = await verify_bearer_token_details(self.db_infra, token, manager_name="aweb")
        except HTTPException:
            response = JSONResponse(
                {"error": "Invalid API key"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        except Exception:
            logger.exception("Unexpected error validating API key")
            raise

        agent_id = (details.get("agent_id") or "").strip()
        if not agent_id:
            response = JSONResponse(
                {"error": "API key is not bound to an agent"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        ctx = AuthContext(
            project_id=details["project_id"],
            agent_id=agent_id,
            api_key_id=details["api_key_id"],
        )
        cv_token = _auth_context.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _auth_context.reset(cv_token)
