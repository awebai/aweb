"""MCP authentication middleware.

Resolves the calling agent's identity and makes it available to MCP tool
handlers via a contextvar.  Supports two auth modes:

1. **Certificate mode** (OSS / standalone): DIDKey signature + team certificate,
   same as the HTTP route authentication.
2. **Proxy mode** (embedded / hosted): Signed internal headers injected by the
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

from aweb.internal_auth import _trust_aweb_proxy_headers, parse_internal_auth_context
from aweb.team_auth_deps import verify_request_certificate, resolve_team_identity

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Resolved identity for the current MCP request."""

    team_address: str
    agent_id: str
    alias: str
    did_key: str


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

    Supports certificate auth (OSS) and proxy-header auth (hosted).
    """

    def __init__(self, app: ASGIApp, db_infra: Any) -> None:
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        if _trust_aweb_proxy_headers():
            try:
                ctx = self._resolve_proxy_auth(request)
            except HTTPException as exc:
                response = JSONResponse(
                    {"error": exc.detail},
                    status_code=exc.status_code,
                    headers=exc.headers,
                )
                await response(scope, receive, send)
                return
            if ctx is None:
                response = JSONResponse(
                    {"error": "Authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return
        else:
            ctx = await self._resolve_certificate_auth(request, scope, receive, send)
            if ctx is None:
                return  # Response already sent.

        cv_token = _auth_context.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _auth_context.reset(cv_token)

    @staticmethod
    def _resolve_proxy_auth(request: Request) -> AuthContext | None:
        """Resolve auth from signed proxy headers (proxy mode).

        Raises HTTPException on invalid signatures — callers must not swallow it.
        Returns None only when no proxy headers are present at all.

        Note: proxy mode is a transitional path for aweb-cloud. The proxy
        headers must provide team_address and alias alongside actor_id.
        """
        internal = parse_internal_auth_context(request)
        if internal is None:
            return None
        actor_id = (internal.get("actor_id") or "").strip()
        if not actor_id:
            return None
        team_address = (internal.get("team_address") or "").strip()
        alias = (internal.get("alias") or "").strip()
        did_key = (internal.get("did_key") or "").strip()
        if not team_address:
            raise HTTPException(status_code=403, detail="Proxy headers must include team_address")
        return AuthContext(
            team_address=team_address,
            agent_id=actor_id,
            alias=alias,
            did_key=did_key,
        )

    async def _resolve_certificate_auth(
        self, request: Request, scope: Scope, receive: Receive, send: Send
    ) -> AuthContext | None:
        """Resolve auth from DIDKey signature + team certificate (OSS mode)."""
        try:
            cert_info = await verify_request_certificate(request, self.db_infra)
        except HTTPException as exc:
            response = JSONResponse(
                {"error": exc.detail},
                status_code=exc.status_code,
                headers=getattr(exc, "headers", None),
            )
            await response(scope, receive, send)
            return None
        except Exception:
            logger.exception("Unexpected error verifying certificate")
            response = JSONResponse({"error": "Internal error"}, status_code=500)
            await response(scope, receive, send)
            return None

        try:
            aweb_db = self.db_infra.get_manager("aweb")
            identity = await resolve_team_identity(aweb_db, cert_info)
        except ValueError:
            response = JSONResponse(
                {"error": "Agent not connected — use POST /v1/connect first"},
                status_code=403,
            )
            await response(scope, receive, send)
            return None

        return AuthContext(
            team_address=identity.team_address,
            agent_id=identity.agent_id,
            alias=identity.alias,
            did_key=identity.did_key,
        )
