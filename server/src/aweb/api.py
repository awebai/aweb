import hashlib
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Optional, TypedDict
from uuid import uuid4

import httpx
from awid.dns_verify import DomainVerifier
from awid.external_authority import SystemTXTOutcomeResolver
from awid.federation_errors import FederationAuthorityError
from awid.log import canonical_server_origin
from awid.log_config import configure_logging
from awid.registry import CachedRegistryClient, RegistryClient
from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from redis.asyncio import from_url as async_redis_from_url
from starlette.exceptions import HTTPException as ASGIHTTPException
from starlette.routing import Mount

from .application_state import RegistryClientUnavailable
from .attachments import AttachmentBackend
from .certificate_error_transport import install_certificate_error_handlers
from .team_control_error_transport import install_team_control_error_handlers
from .config import get_public_origin, get_settings
from .connection_scope import ConnectionScopeMiddleware
from .coordination.routes.repos import router as repos_router
from .coordination.routes.tasks import router as tasks_router
from .coordination.routes.team_instructions import instructions_router
from .coordination.routes.team_roles import roles_router
from .coordination.routes.workspaces import router as workspaces_router
from .db import DatabaseInfrastructure
from .db import db_infra as default_db_infra
from .federation.errors import authority_error_body
from .install_admins import install_admin_setup_message
from .internal_auth import ProxyVerificationConfig
from .mcp.server import NormalizeMountedMCPPathMiddleware
from .messaging.chat_policy import HumanChatRefused
from .outbox_recovery import OutboxRecoveryStarter
from .request_compression import RequestDecompressionFastAPI
from .resource_startup import start_agent_wakes as start_agent_wakes
from .resource_startup import stop_agent_wakes as stop_agent_wakes
from .routes.agents import router as agents_router
from .routes.app_hooks import router as app_hooks_router
from .routes.apps import router as apps_router
from .routes.chat import router as chat_router
from .routes.claims import router as claims_router
from .routes.connect import router as connect_router
from .routes.contacts import router as contacts_router
from .routes.conversations import router as conversations_router
from .routes.dashboard import router as dashboard_router
from .routes.events import router as events_router
from .routes.federation import router as federation_router
from .routes.hook_bindings import router as hook_bindings_router
from .routes.identity_grants import router as identity_grants_router
from .routes.messages import router as messages_router
from .routes.reservations import router as reservations_router
from .routes.room import router as room_router
from .routes.service_registration import router as service_registration_router
from .routes.session_leases import router as session_leases_router
from .routes.status import router as status_router
from .routing_utils import move_mount_before_spa_fallback
from .error_responses import install_service_error_handlers

logger = logging.getLogger(__name__)


def _cached_body_receive(body: bytes):
    """Return an ASGI receive callable that replays a cached request body.

    After the cached body has been replayed, subsequent reads must terminate
    immediately with an empty request-body event. Waiting on the original
    receive callable here can hang POST error responses under Uvicorn because
    Starlette may poll the request stream after the endpoint has already raised.
    A non-GET route must not return a streaming response, and MCP must keep
    json_response=True: a disconnect listener would spin on this receive.
    """
    replayed = False

    async def _receive():
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return _receive


# Above the largest body a released client sends: aw reads a --body-file
# of up to 10 MiB, which end-to-end encryption carries as about 13.4 MiB of
# base64. Every route's tighter bound still applies on top of this one.
DEFAULT_MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024


def _max_request_body_bytes() -> int:
    """The deployment's request-body cap, from AWEB_MAX_REQUEST_BODY_BYTES."""
    raw = os.getenv("AWEB_MAX_REQUEST_BODY_BYTES")
    if raw is None:
        return DEFAULT_MAX_REQUEST_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(
            "AWEB_MAX_REQUEST_BODY_BYTES must be a positive whole number of bytes"
        )
    return value


class RequestBodyCacheMiddleware:
    """Cache each HTTP request's body and its SHA-256 for signature verification.

    Sets ``request.state.cached_body`` and ``request.state.body_sha256``. A
    GET, HEAD or OPTIONS request has an empty body and keeps its receive. Any
    other request is read whole before the app runs and replayed to it, so
    FastAPI still parses it. A body over ``max_body_bytes`` is refused with
    413 as soon as it is declared or read past the cap, before the app runs,
    so no request buffers more than the cap. An embedding host can enforce a
    tighter limit by raising a Starlette HTTPException(413) from receive.
    Pure ASGI: unlike a BaseHTTPMiddleware, it holds no tasks of its own for
    a long-lived streaming response.
    """

    def __init__(
        self, app, *, max_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _refuse(self, scope, receive, send) -> None:
        await JSONResponse({"detail": "Request body too large"}, status_code=413)(
            scope, receive, send
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = scope.setdefault("state", {})
        if scope.get("method") in {"GET", "HEAD", "OPTIONS"}:
            state["cached_body"] = b""
            state["body_sha256"] = hashlib.sha256(b"").hexdigest()
            await self.app(scope, receive, send)
            return
        declared = next(
            (
                value
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ),
            None,
        )
        if (
            declared is not None
            and declared.isdigit()
            and int(declared) > self.max_body_bytes
        ):
            await self._refuse(scope, receive, send)
            return
        chunks, received = [], 0
        while True:
            try:
                message = await receive()
            except ASGIHTTPException as exc:
                if exc.status_code != 413:
                    raise
                # The mounted app's error middleware would send a 500 before
                # the host could handle the receive-side refusal.
                await self._refuse(scope, receive, send)
                return
            if message["type"] == "http.disconnect":
                return  # The client left before sending its body; nobody to answer.
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > self.max_body_bytes:
                await self._refuse(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        state["cached_body"] = body
        state["body_sha256"] = hashlib.sha256(body).hexdigest()
        await self.app(scope, _cached_body_receive(body), send)


async def _mount_mcp_app(
    app: FastAPI,
    mcp_app,
) -> None:
    previous = getattr(app.state, "native_mcp_mount", None)
    if previous in app.router.routes:
        app.router.routes.remove(previous)
    if any(isinstance(r, Mount) and r.path == "/mcp" for r in app.router.routes):
        return
    app.mount("/mcp", mcp_app)
    app.state.native_mcp_mount = next(
        r for r in app.router.routes if isinstance(r, Mount) and r.path == "/mcp"
    )
    move_mount_before_spa_fallback(app, "/mcp")
    logger.info("MCP endpoint mounted at /mcp/")


class _RegistryClientOptions(TypedDict):
    registry_url: str
    service_token: str | None
    member_signing_keys: dict[str, bytes]
    transport: httpx.AsyncBaseTransport | None
    domain_verifier: DomainVerifier | None


def _build_awid_registry_client(
    app: FastAPI,
    redis: Redis | None,
    transport: httpx.AsyncBaseTransport | None = None,
    domain_verifier: DomainVerifier | None = None,
) -> RegistryClient:
    settings = get_settings()
    registry_url = settings.awid_registry_url
    service_token = settings.awid_service_token
    client_kwargs: _RegistryClientOptions = {
        "registry_url": registry_url,
        "service_token": service_token,
        "member_signing_keys": settings.awid_member_signing_keys,
        "transport": transport,
        "domain_verifier": domain_verifier,
    }
    if redis is not None:
        return CachedRegistryClient(redis_client=redis, **client_kwargs)
    return RegistryClient(**client_kwargs)


def _make_standalone_lifespan(*, host_runs_outbox_recovery: bool = False):
    """Own standalone connections; share the native serving-resource owner."""
    # API module construction also creates the default app; defer this import
    # until the lifecycle factory to avoid an API/embedding initialization cycle.
    from .embedding import (
        OutboxRecoveryOwnership,
        default_mcp_factory,
        start_native_resources,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run the shared native resource owner for this application lifespan."""
        settings = get_settings()
        configure_logging(
            log_level=settings.log_level,
            json_format=os.getenv("AWEB_LOG_JSON", "true").lower() == "true",
        )
        logger.info("Starting aweb coordination server (standalone mode)")
        async with AsyncExitStack() as cleanup:
            redis = await async_redis_from_url(
                settings.redis_url, decode_responses=True
            )
            cleanup.push_async_callback(redis.aclose)
            await redis.ping()
            cleanup.push_async_callback(default_db_infra.close)
            await default_db_infra.initialize()
            if getattr(app.state, "install_admin_policy", None) is None:
                setup_message = await install_admin_setup_message(
                    default_db_infra.get_manager()
                )
                if setup_message:
                    logger.info(setup_message)
            registry = _build_awid_registry_client(app, redis)
            cleanup.push_async_callback(registry.aclose)
            async with start_native_resources(
                api_app=app,
                db_infra=default_db_infra,
                redis=redis,
                registry_client=registry,
                mcp_factory=default_mcp_factory,
                outbox_recovery=OutboxRecoveryOwnership.HOST
                if host_runs_outbox_recovery
                else OutboxRecoveryOwnership.NATIVE,
            ) as resources:
                await _mount_mcp_app(app, resources.mcp_app)
                yield

    return lifespan


def _make_library_lifespan(
    db_infra: DatabaseInfrastructure,
    redis: Redis,
    awid_transport: httpx.AsyncBaseTransport | None,
    domain_verifier: DomainVerifier | None,
    *,
    host_runs_outbox_recovery: bool = False,
):
    """Borrow host connections; close only this lifespan's registry client."""
    # API module construction also creates the default app; defer this import
    # until the lifecycle factory to avoid an API/embedding initialization cycle.
    from .embedding import (
        OutboxRecoveryOwnership,
        default_mcp_factory,
        start_native_resources,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run the shared native resource owner for this application lifespan."""
        logger.info("Starting aweb coordination server (library mode)")
        async with AsyncExitStack() as cleanup:
            registry = _build_awid_registry_client(
                app, redis, awid_transport, domain_verifier
            )
            cleanup.push_async_callback(registry.aclose)
            async with start_native_resources(
                api_app=app,
                db_infra=db_infra,
                redis=redis,
                registry_client=registry,
                mcp_factory=default_mcp_factory,
                outbox_recovery=OutboxRecoveryOwnership.HOST
                if host_runs_outbox_recovery
                else OutboxRecoveryOwnership.NATIVE,
            ) as resources:
                await _mount_mcp_app(app, resources.mcp_app)
                yield

    return lifespan


def create_app(
    *,
    db_infra: Optional[DatabaseInfrastructure] = None,
    redis: Optional[Redis] = None,
    attachment_backend: AttachmentBackend | None = None,
    public_origin: str | None = None,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    domain_verifier: DomainVerifier | None = None,
    host_runs_outbox_recovery: bool = False,
    proxy_verification: ProxyVerificationConfig | None = None,
) -> FastAPI:
    """Create the aweb coordination FastAPI application.

    Args:
        proxy_verification: App-owned proxy trust/secret; omitted captures environment once.
        db_infra: External DatabaseInfra instance (library mode).
                  If None, creates own connections (standalone mode).
        redis: External async Redis client (library mode).
               If None, creates own connection (standalone mode).
        public_origin: Configured external origin for request signature checks.
                       Defaults to public-origin settings captured at construction.
        awid_transport: The transport the AWID registry client uses (library
                        mode only), such as a host's in-process AWID. The
                        startup health check and every AWID call go through it.
        domain_verifier: The `_awid` DNS lookup the AWID registry client uses
                        for namespace authority (library mode only), such as
                        a host's in-process AWID's own; real DNS otherwise.
        host_runs_outbox_recovery: The host runs aweb.outbox_recovery's
                        recover_outboxes on its own scheduler. Otherwise an app
                        that receives no lifespan (a mount) starts the recovery
                        loop on its first request.

    Library mode requires both db_infra and redis to be provided.
    Standalone mode requires neither (will create its own).
    A mounted child must have its lifespan run explicitly, or use the public
    aweb.embedding.embedded_aweb context. Mounting alone does not start native
    resources or its MCP session manager.

    Examples:
        Standalone mode (simple deployment)::

            app = create_app()
            # Run with: uvicorn aweb.api:create_app --factory

        Library mode (embedding in another FastAPI app)::

            from aweb.api import create_app
            from aweb.db import DatabaseInfra
            from redis.asyncio import Redis

            # Initialize shared infrastructure
            db_infra = DatabaseInfra()
            await db_infra.initialize()
            redis = await Redis.from_url("redis://localhost:6379")

            # Create the coordination app with shared connections
            coordination_app = create_app(db_infra=db_infra, redis=redis)

            # Mount under your main app
            # Keep this context open for the host's serving lifetime.
            async with coordination_app.router.lifespan_context(coordination_app):
                main_app.mount("/coordination", coordination_app)
                # Serve main_app while this context remains open.
    """
    proxy_configuration = ProxyVerificationConfig.capture(proxy_verification)
    # Validate mode consistency
    if (db_infra is None) != (redis is None):
        raise ValueError(
            "Library mode requires both db_infra and redis, or neither for standalone mode"
        )

    library_mode = db_infra is not None
    if awid_transport is not None and not library_mode:
        raise ValueError("awid_transport is available in library mode only")
    if domain_verifier is not None and not library_mode:
        raise ValueError("domain_verifier is available in library mode only")

    # Validate db_infra is initialized in library mode
    if library_mode:
        assert db_infra is not None  # Type narrowing for mypy
        if not db_infra.is_initialized:
            raise ValueError(
                "db_infra must be initialized before passing to create_app() in library mode. "
                "Call 'await db_infra.initialize()' before creating the app."
            )
        assert redis is not None  # Required when db_infra is provided
        lifespan = _make_library_lifespan(
            db_infra,
            redis,
            awid_transport,
            domain_verifier,
            host_runs_outbox_recovery=host_runs_outbox_recovery,
        )
    else:
        lifespan = _make_standalone_lifespan(
            host_runs_outbox_recovery=host_runs_outbox_recovery
        )

    from aweb.attachment_service import router as attachment_router

    app = RequestDecompressionFastAPI(
        title="aweb coordination core", version="0.1.0", lifespan=lifespan
    )
    proxy_configuration.install(app)
    app.state.attachment_backend = attachment_backend
    # DNS names the namespace controller whose act may move a pinned team key
    # (aweb.team_key_pins); an embedding host may replace the resolver.
    app.state.awid_txt_resolver = SystemTXTOutcomeResolver()
    app.state.public_origin = (
        canonical_server_origin(public_origin)
        if public_origin is not None
        else get_public_origin()
    )
    app.include_router(attachment_router)
    app.add_middleware(NormalizeMountedMCPPathMiddleware, mount_path="/mcp")

    app.add_middleware(
        RequestBodyCacheMiddleware, max_body_bytes=_max_request_body_bytes()
    )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error_handler(
        request: Request, exc: RequestValidationError
    ):
        matched_route_path = getattr(request.scope.get("route"), "path", "")
        if (
            matched_route_path
            in {
                "/v1/messages",
                "/v1/chat/sessions",
                "/v1/chat/sessions/{session_id}/messages",
            }
            and isinstance(exc.body, dict)
            and ({"attachments", "attachment_refs"} & exc.body.keys())
        ):
            return JSONResponse(
                status_code=422, content={"detail": {"code": "request_invalid"}}
            )
        if isinstance(matched_route_path, str) and matched_route_path.startswith(
            "/v1/federation/"
        ):
            reason = (
                "federation_timestamp_invalid"
                if any("timestamp" in error.get("loc", ()) for error in exc.errors())
                else "federation_envelope_invalid"
            )
            error = FederationAuthorityError(reason)
            return JSONResponse(
                status_code=error.http_status,
                content=authority_error_body(
                    error,
                    correlation_id=request.headers.get("X-Correlation-ID")
                    or str(uuid4()),
                ),
            )
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(FederationAuthorityError)
    async def _federation_authority_error_handler(
        request: Request, exc: FederationAuthorityError
    ):

        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
        headers = {"Retry-After": "1"} if exc.retry_after_required else None
        return JSONResponse(
            status_code=exc.http_status,
            content=authority_error_body(exc, correlation_id=correlation_id),
            headers=headers,
        )

    @app.exception_handler(HumanChatRefused)
    async def _human_chat_refused_handler(request: Request, exc: HumanChatRefused):
        return JSONResponse(
            status_code=422,
            content=exc.body(
                correlation_id=request.headers.get("X-Correlation-ID"),
            ),
        )

    install_service_error_handlers(app)

    @app.exception_handler(RegistryClientUnavailable)
    async def _registry_client_unavailable_handler(
        request: Request, exc: RegistryClientUnavailable
    ):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    install_certificate_error_handlers(app)
    install_team_control_error_handlers(app)

    @app.get("/live", tags=["internal"])
    async def live() -> dict:
        # Checks no dependency: a Redis or database outage must not make an
        # orchestrator restart a process that is serving requests.
        """Report whether this server process can answer requests."""
        return {"status": "ok"}

    @app.get("/health", tags=["internal"])
    @app.get("/ready", tags=["internal"])
    async def health(request: Request) -> JSONResponse:
        """Report native dependency readiness, refusing when a required resource failed."""
        checks = {}
        healthy = True
        resources = getattr(request.app.state, "native_resources", None)
        resource_readiness = resources.readiness if resources is not None else None
        if resource_readiness is not None:
            checks["native_resources"] = (
                "ok" if resource_readiness.ready else "unavailable"
            )
            healthy = resource_readiness.ready

        # Check Redis
        try:
            redis: Redis = request.app.state.redis
            await redis.ping()
            checks["redis"] = "ok"
        except Exception:
            logger.error("Health check failed for Redis", exc_info=True)
            checks["redis"] = "error"
            healthy = False

        # Check Database
        try:
            db_infra: DatabaseInfrastructure = request.app.state.db
            db = db_infra.get_manager("server")
            await db.fetch_value("SELECT 1")
            checks["database"] = "ok"
        except Exception:
            logger.error("Health check failed for database", exc_info=True)
            checks["database"] = "error"
            healthy = False

        content = {"status": "ok" if healthy else "unhealthy", "checks": checks}
        if resource_readiness is not None and not resource_readiness.ready:
            content["message"] = resource_readiness.message
        return JSONResponse(
            status_code=200 if healthy else 503,
            content=content,
        )

    app.include_router(agents_router)
    app.include_router(apps_router)
    app.include_router(hook_bindings_router)
    app.include_router(app_hooks_router)
    app.include_router(connect_router)
    app.include_router(chat_router)
    app.include_router(dashboard_router)
    app.include_router(claims_router)
    app.include_router(contacts_router)
    app.include_router(conversations_router)
    app.include_router(events_router)
    app.include_router(federation_router)
    app.include_router(identity_grants_router)
    from aweb.routes.messaging import router as messaging_router

    app.include_router(messaging_router)
    app.include_router(messages_router)
    app.include_router(room_router)
    app.include_router(reservations_router)
    app.include_router(session_leases_router)
    app.include_router(service_registration_router)
    app.include_router(status_router)
    app.include_router(instructions_router)
    app.include_router(roles_router)
    app.include_router(tasks_router)
    app.include_router(workspaces_router)
    app.include_router(repos_router)

    if not host_runs_outbox_recovery:
        app.add_middleware(OutboxRecoveryStarter)
    # Added last, so it is outermost: one connection for every statement a
    # request runs before its response starts, middleware included.
    app.add_middleware(ConnectionScopeMiddleware)

    return app


# Module-level app for uvicorn: `uvicorn aweb.api:app`
app = create_app()
