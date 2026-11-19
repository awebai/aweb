"""aweb MCP server factory.

Creates an MCP-over-Streamable-HTTP ASGI app that exposes aweb coordination
primitives as MCP tools. Designed to be mounted alongside the REST API::

    from aweb.mcp import create_mcp_app
    mcp_app = create_mcp_app(db_infra=infra, redis=redis)
    fastapi_app.mount("/mcp", mcp_app)
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from awid.registry import RegistryClient
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from redis.asyncio import Redis

from aweb.config import get_awid_registry_url
from aweb.db import DatabaseInfrastructure
from aweb.federation.transport import delivery_transport
from aweb.internal_auth import ProxyVerificationConfig
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.mcp.compatibility import observe_compatibility_tool_call
from aweb.mcp.notifications import append_pending_nudge
from aweb.mcp.registration import (
    agents,
    chat,
    contacts,
    identity,
    instructions,
    mail,
    roles,
    room,
    tasks,
    work,
    workspace,
)
from aweb.mcp.registration.dependencies import ToolDependencies
from aweb.mcp.signing import (
    HostedMessageDecryptor,
    HostedMessageEncryptor,
    HostedMessageSigner,
)


class NormalizeMountedMCPPathMiddleware:
    """Rewrite exact /mcp requests to /mcp/ before FastAPI routing.

    Some browser MCP clients normalize the advertised resource URL by dropping
    the trailing slash, then send requests to ``/mcp``. FastAPI/Starlette will
    otherwise redirect or mount the sub-app with an empty inner path, which
    breaks FastMCP's expectation that the streamable endpoint lives at ``/``.
    """

    def __init__(self, app: Any, *, mount_path: str = "/mcp") -> None:
        self.app = app
        self.mount_path = mount_path.rstrip("/") or "/mcp"

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path") or ""
            if path == self.mount_path:
                scope = dict(scope)
                normalized = f"{self.mount_path}/"
                scope["path"] = normalized
                scope["raw_path"] = normalized.encode("utf-8")
        await self.app(scope, receive, send)


class ManagedMCPApp:
    """ASGI wrapper that lets a mounted FastMCP app manage its own lifecycle.

    Mounted ASGI sub-applications do not have their lifespan handlers invoked by
    the parent FastAPI app, but FastMCP's Streamable HTTP transport depends on
    its session manager running. The parent app must therefore call
    ``startup()`` and ``shutdown()`` explicitly.
    """

    def __init__(self, app: Any, session_manager: Any) -> None:
        self.app = app
        self._session_manager = session_manager
        self._runner_task: asyncio.Task[None] | None = None
        self._started = asyncio.Event()
        self._shutdown = asyncio.Event()

    @property
    def is_running(self) -> bool:
        """Whether this resource has an active serving task."""
        return self._started.is_set() and self._runner_task is not None and not self._runner_task.done()

    async def startup(self) -> None:
        """Start the mounted MCP session manager and wait until it can serve."""
        if self._runner_task is not None:
            return

        async def _runner() -> None:
            async with self._session_manager.run():
                self._started.set()
                await self._shutdown.wait()

        self._started.clear()
        self._shutdown.clear()
        self._runner_task = asyncio.create_task(_runner())
        while not self._started.is_set():
            if self._runner_task.done():
                await self._runner_task
            await asyncio.sleep(0)

    async def shutdown(self) -> None:
        """Stop and await the mounted MCP session manager owned by this wrapper."""
        if self._runner_task is None:
            return
        self._shutdown.set()
        await self._runner_task
        self._runner_task = None

    async def __call__(self, scope, receive, send) -> None:
        normalized_scope = scope
        path = scope.get("path")
        if not path:
            # When mounted at /mcp, some clients hit the exact mount path
            # (/mcp without a trailing slash). Starlette passes that through to
            # the mounted app with an empty inner path, but FastMCP expects the
            # streamable HTTP endpoint at "/". Normalize the empty inner path so
            # /mcp and /mcp/ behave identically.
            normalized_scope = dict(scope)
            normalized_scope["path"] = "/"
            normalized_scope["raw_path"] = b"/"
        await self.app(normalized_scope, receive, send)


def register_tools(
    mcp: FastMCP,
    db_infra: DatabaseInfrastructure,
    redis: Optional[Redis],
    registry_client: RegistryClient,
    federation_authority=None,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    federation_mail_transport=None,
    federation_chat_transport=None,
    public_origin: str | None = None,
) -> None:
    """Register all aweb MCP tools on *mcp*.

    Call this on your own :class:`FastMCP` instance to compose aweb tools
    alongside additional tools.  Pass ``redis=None`` if Redis is unavailable;
    presence-related tools will degrade gracefully.

    Federated mail and chat are delivered through the federation authority's
    transport unless the host passes one.
    """
    federation_mail_transport = delivery_transport(federation_authority, federation_mail_transport)
    federation_chat_transport = delivery_transport(federation_authority, federation_chat_transport)

    dependencies = ToolDependencies(
        db_infra=db_infra,
        redis=redis,
        registry_client=registry_client,
        federation_authority=federation_authority,
        hosted_signer=hosted_signer,
        hosted_encryptor=hosted_encryptor,
        hosted_decryptor=hosted_decryptor,
        federation_mail_transport=federation_mail_transport,
        federation_chat_transport=federation_chat_transport,
        public_origin=public_origin,
    )
    identity.register_tools(mcp, dependencies)
    room.register_tools(mcp, dependencies)
    mail.register_tools(mcp, dependencies)
    agents.register_tools(mcp, dependencies)
    chat.register_tools(mcp, dependencies)
    tasks.register_tools(mcp, dependencies)
    instructions.register_tools(mcp, dependencies)
    roles.register_tools(mcp, dependencies)
    work.register_tools(mcp, dependencies)
    workspace.register_tools(mcp, dependencies)
    contacts.register_tools(mcp, dependencies)

class _NudgingFastMCP(FastMCP):
    def __init__(self, *args, db_infra, **kwargs):
        self._nudge_db = db_infra
        super().__init__(*args, **kwargs)

    async def call_tool(self, name, arguments):
        """Execute the registered tool and append the current pending-notice hint."""
        observe_compatibility_tool_call(tool_name=name)
        result = await super().call_tool(name, arguments)
        return await append_pending_nudge(result, self._nudge_db)


def create_mcp_app(
    *,
    db_infra: DatabaseInfrastructure,
    redis: Optional[Redis] = None,
    registry_client: RegistryClient | None = None,
    federation_authority=None,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    federation_mail_transport=None,
    federation_chat_transport=None,
    public_origin: str | None = None,
    streamable_http_path: str = "/",
    proxy_verification: ProxyVerificationConfig | None = None,
) -> Any:
    """Create an MCP ASGI app for aweb tools.

    The returned app handles Streamable HTTP transport and can be mounted on
    any ASGI framework (FastAPI, Starlette, etc.)::

        fastapi_app.mount("/mcp", create_mcp_app(db_infra=infra))

    When mounted at ``/mcp`` with the default ``streamable_http_path="/"``,
    the external MCP endpoint is ``/mcp/``.
    """
    proxy_configuration = ProxyVerificationConfig.capture(proxy_verification)
    normalized_path = streamable_http_path.strip() or "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    if normalized_path != "/" and normalized_path.endswith("/"):
        normalized_path = normalized_path.rstrip("/")

    mcp = _NudgingFastMCP(
        "aweb",
        db_infra=db_infra,
        stateless_http=True,
        json_response=True,
        streamable_http_path=normalized_path,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )

    if registry_client is None:
        registry_client = RegistryClient(registry_url=get_awid_registry_url())

    register_tools(
        mcp,
        db_infra,
        redis,
        registry_client,
        federation_authority=federation_authority,
        hosted_signer=hosted_signer,
        hosted_encryptor=hosted_encryptor,
        hosted_decryptor=hosted_decryptor,
        federation_mail_transport=federation_mail_transport,
        federation_chat_transport=federation_chat_transport,
        public_origin=public_origin,
    )

    # streamable_http_app() returns a Starlette app with its own lifespan, but
    # mounted sub-applications do not receive lifespan events from FastAPI.
    # Wrap the app so the parent can start/stop the session manager explicitly.
    inner = mcp.streamable_http_app()
    return ManagedMCPApp(MCPAuthMiddleware(inner, db_infra, proxy_verification=proxy_configuration), mcp.session_manager)
