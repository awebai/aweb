"""MCP authentication middleware.

Resolves the calling agent's identity and makes it available to MCP tool
handlers via a contextvar.  Supports two auth modes:

1. **Direct mode** (OSS / standalone): Bearer token validated against the aweb
   API key store.
2. **Proxy mode** (claweb / embedded): Signed internal headers injected by the
   outer auth middleware (requires ``AWEB_TRUST_PROXY_HEADERS=1``).
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

from aweb.auth import (
    _parse_internal_auth_context,
    _trust_aweb_proxy_headers,
    verify_bearer_token_details,
)

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
    """ASGI middleware that resolves agent identity for MCP requests.

    Supports proxy-header auth (for claweb) and direct Bearer token auth (OSS).
    """

    def __init__(self, app: ASGIApp, db_infra: Any) -> None:
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        # Try proxy-header auth first (claweb sets signed internal headers).
        ctx = self._resolve_proxy_auth(request)
        if ctx is None:
            ctx = await self._resolve_bearer_auth(request, scope, receive, send)
        if ctx is None:
            return  # Response already sent by _resolve_bearer_auth.

        cv_token = _auth_context.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _auth_context.reset(cv_token)

    @staticmethod
    def _resolve_proxy_auth(request: Request) -> AuthContext | None:
        """Resolve auth from signed proxy headers (claweb mode)."""
        if not _trust_aweb_proxy_headers():
            return None
        try:
            internal = _parse_internal_auth_context(request)
        except HTTPException:
            return None
        if internal is None:
            return None
        actor_id = (internal.get("actor_id") or "").strip()
        if not actor_id:
            return None
        return AuthContext(
            project_id=internal["project_id"],
            agent_id=actor_id,
            api_key_id=internal.get("principal_id") or "",
        )

    async def _resolve_bearer_auth(
        self, request: Request, scope: Scope, receive: Receive, send: Send
    ) -> AuthContext | None:
        """Resolve auth from Bearer token (OSS mode). Sends error response on failure."""
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            response = JSONResponse(
                {"error": "Authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return None

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
            return None
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
            return None

        return AuthContext(
            project_id=details["project_id"],
            agent_id=agent_id,
            api_key_id=details["api_key_id"],
        )
