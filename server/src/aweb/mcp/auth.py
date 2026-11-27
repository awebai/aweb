"""MCP authentication middleware."""

from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.agent_wake import agent_wake_publisher
from aweb.identity_binding import refresh_projection_binding, verify_identity_binding
from aweb.identity_address import AddressResolution
from aweb.service_errors import IdentityBindingError
from aweb.application_state import RegistryClientUnavailable
from aweb.auth_error_transport import mcp_auth_error_response
from aweb.internal_auth import (
    InternalAuthContext,
    ProxyVerificationConfig,
    parse_internal_auth_context,
    read_internal_actor_projection,
)
from aweb.mcp.mutations import (
    mutation_callback_from_scope,
    reset_mutation_callback,
    set_mutation_callback,
)
from aweb.team_registry import native_database_manager

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
    request: Request | None = None
    trusted_proxy: bool = False
    identity_scope: str | None = None
    # Evidence from get_team_identity verifying the presented certificate,
    # never from the agent projection's stored certificate_id.
    certificate_id: str | None = None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)
    # The native adapter retains the original credential, scope, chain and
    # address observation rather than reconstructing authority from metadata.
    messaging_auth: MessagingAuth | None = None

    @classmethod
    def from_messaging_auth(
        cls, *, identity: MessagingAuth, workspace_id: str | None = None
    ) -> AuthContext:
        """Adapt the shared HTTP principal without selecting another membership.

        Global And Local Identities (docs/identity-messaging-contract.md:68-94) keeps
        DID-scoped messaging
        independent of team selection. Transport metadata adds no authority.
        """
        return cls(
            team_id=identity.team_id,
            agent_id=identity.agent_id,
            workspace_id=workspace_id,
            alias=identity.alias,
            did_key=identity.did_key,
            did_aw=identity.did_aw,
            address=identity.address,
            identity_scope=identity.identity_scope,
            certificate_id=identity.certificate_id,
            address_resolution=identity.address_resolution,
            messaging_auth=identity,
        )


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


def current_agent_wake_publisher():
    """The serving application's agent wake publisher for this MCP request."""
    ctx = _auth_context.get()
    request = getattr(ctx, "request", None)
    if request is None:
        return None
    return agent_wake_publisher(request.app.state)


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

    def __init__(
        self,
        app: ASGIApp,
        db_infra: Any,
        *,
        proxy_verification: ProxyVerificationConfig | None = None,
    ) -> None:
        self.proxy_verification = ProxyVerificationConfig.capture(proxy_verification)
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        try:
            ctx = await self._resolve_auth(request)
        except (IdentityBindingError, RegistryClientUnavailable) as exc:
            await mcp_auth_error_response(exc)(scope, receive, send)
            return
        except HTTPException as exc:
            response = JSONResponse(
                {"error": exc.detail}, status_code=exc.status_code, headers=exc.headers
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

        # The mounted inner Starlette app mutates scope["app"]. Keep the
        # authenticated parent policy/registry context stable for tool reads.
        ctx.request = Request(dict(request.scope))
        cv_token = _auth_context.set(ctx)
        mutation_token = set_mutation_callback(mutation_callback_from_scope(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            reset_mutation_callback(mutation_token)
            _auth_context.reset(cv_token)

    async def _resolve_auth(self, request: Request) -> AuthContext | None:
        internal = parse_internal_auth_context(
            request, proxy_verification=self.proxy_verification
        )
        if internal is not None:
            return await self._resolve_proxy_auth(internal, request=request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("DIDKey "):
            return None

        identity = await get_messaging_auth(request, self.db_infra)
        workspace = None
        if identity.certificate_id and identity.agent_id:
            workspace = await native_database_manager(self.db_infra).fetch_one(
                """
                SELECT workspace_id
                FROM {{tables.workspaces}}
                WHERE agent_id = $1::uuid AND team_id = $2 AND deleted_at IS NULL
                ORDER BY updated_at DESC, workspace_id DESC
                LIMIT 1
                """,
                identity.agent_id,
                identity.team_id,
            )
        return AuthContext.from_messaging_auth(
            identity=identity,
            workspace_id=str(workspace["workspace_id"]) if workspace else None,
        )

    async def _resolve_proxy_auth(
        self, internal: InternalAuthContext, *, request: Request
    ) -> AuthContext:
        aweb_db = native_database_manager(self.db_infra)
        team_id = internal["team_id"]
        row = await read_internal_actor_projection(aweb_db, internal)
        if not row:
            raise HTTPException(status_code=403, detail="Agent not connected")

        binding = await verify_identity_binding(
            request,
            did_key=row["did_key"],
            did_aw=row.get("did_aw") or "",
            address=row.get("address") or "",
        )
        await refresh_projection_binding(
            aweb_db, agent_id=row["agent_id"], did_key=row["did_key"], binding=binding
        )

        workspace = await aweb_db.fetch_one(
            """
            SELECT workspace_id
            FROM {{tables.workspaces}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            ORDER BY updated_at DESC, workspace_id DESC
            LIMIT 1
            """,
            row["agent_id"],
            team_id,
        )

        return AuthContext(
            team_id=team_id,
            agent_id=str(row["agent_id"]),
            workspace_id=(str(workspace["workspace_id"]) if workspace else None),
            alias=row["alias"],
            did_key=str(row["did_key"]),
            did_aw=binding.did_aw or None,
            address=binding.address or None,
            trusted_proxy=True,
            identity_scope=row.get("identity_scope") or None,
        )
