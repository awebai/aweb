"""MCP authentication middleware."""

from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from aweb.identity_auth_deps import resolve_identity_auth
from aweb.team_auth_deps import _aweb_db, verify_request_certificate

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Resolved identity for the current MCP request."""

    team_id: str | None
    agent_id: str | None
    alias: str | None
    did_key: str
    did_aw: str | None = None
    address: str | None = None
    workspace_id: str | None = None


def auth_dids(auth: AuthContext) -> list[str]:
    """Return the authenticated routing DIDs in preference order."""
    dids: list[str] = []
    for value in ((auth.did_aw or "").strip(), (auth.did_key or "").strip()):
        if value and value not in dids:
            dids.append(value)
    return dids


def primary_auth_did(auth: AuthContext) -> str:
    """Return the preferred routing DID for the authenticated caller."""
    dids = auth_dids(auth)
    return dids[0] if dids else ""


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
    """ASGI middleware that resolves identity for MCP requests."""

    def __init__(self, app: ASGIApp, db_infra: Any) -> None:
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        try:
            ctx = await self._resolve_auth(request)
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
            )
            await response(scope, receive, send)
            return

        cv_token = _auth_context.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _auth_context.reset(cv_token)

    async def _resolve_auth(self, request: Request) -> AuthContext | None:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("DIDKey "):
            return None

        cert_header = request.headers.get("x-awid-team-certificate", "")
        if not cert_header:
            identity = await resolve_identity_auth(request)
            return AuthContext(
                team_id=None,
                agent_id=None,
                workspace_id=None,
                alias=None,
                did_key=identity.did_key,
                did_aw=identity.did_aw,
                address=identity.address,
            )

        cert_info = await verify_request_certificate(request, self.db_infra)

        aweb_db = _aweb_db(self.db_infra)
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias, did_aw, address FROM {{tables.agents}}
            WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
            """,
            cert_info["team_id"],
            cert_info["did_key"],
        )
        if not row:
            raise HTTPException(status_code=403, detail="Agent not connected")

        workspace = await aweb_db.fetch_one(
            """
            SELECT workspace_id
            FROM {{tables.workspaces}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            ORDER BY updated_at DESC, workspace_id DESC
            LIMIT 1
            """,
            row["agent_id"],
            cert_info["team_id"],
        )

        return AuthContext(
            team_id=cert_info["team_id"],
            agent_id=str(row["agent_id"]),
            workspace_id=(str(workspace["workspace_id"]) if workspace else None),
            alias=row["alias"],
            did_key=cert_info["did_key"],
            did_aw=(cert_info.get("member_did_aw") or row.get("did_aw") or "").strip() or None,
            address=(cert_info.get("member_address") or row.get("address") or "").strip() or None,
        )
