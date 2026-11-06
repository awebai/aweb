import hashlib
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from redis.asyncio import from_url as async_redis_from_url
from starlette.routing import Mount

from awid.registry import CachedRegistryClient, RegistryClient
from awid.federation_errors import FederationAuthorityError
from .config import get_public_origin, get_settings
from awid.log import canonical_server_origin
from .connection_scope import ConnectionScopeMiddleware
from .db import DatabaseInfra
from .db import db_infra as default_db_infra
from awid.log_config import configure_logging
from .federation.activation import build_federation_authority_activation
from .federation.errors import authority_error_body
from .agent_wake import AgentWakeHub, AgentWakePublisher
from .mutation_hooks import create_mutation_handler
from .outbox_recovery import OutboxRecoveryStarter, start_outbox_recovery, stop_outbox_recovery
from awid.ratelimit import build_rate_limiter
from .routing_utils import move_mount_before_spa_fallback
from .service_errors import ServiceError
from .messaging.chat_policy import HumanChatRefused
from .install_admins import install_admin_setup_message
from .mcp.server import NormalizeMountedMCPPathMiddleware
from .request_compression import RequestDecompressionFastAPI
from .routes.agent_activity import router as agent_activity_router
from .routes.agent_status import router as agent_status_router
from .routes.agents import router as agents_router
from .routes.app_hooks import router as app_hooks_router
from .routes.apps import router as apps_router
from .routes.hook_bindings import router as hook_bindings_router
from .routes.connect import router as connect_router
from .routes.dashboard import router as dashboard_router
from .routes.chat import router as chat_router
from .routes.claims import router as claims_router
from .routes.contacts import router as contacts_router
from .routes.conversations import router as conversations_router
from .routes.events import router as events_router
from .routes.federation import router as federation_router
from .routes.identity_grants import router as identity_grants_router
from .routes.messages import router as messages_router
from .routes.room import router as room_router
from .routes.reservations import router as reservations_router
from .routes.session_leases import router as session_leases_router
from .routes.service_registration import router as service_registration_router
from .routes.status import router as status_router
from .coordination.routes.team_instructions import instructions_router
from .coordination.routes.team_roles import roles_router
from .coordination.routes.repos import router as repos_router
from .coordination.routes.tasks import router as tasks_router
from .coordination.routes.workspaces import router as workspaces_router

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
        raise ValueError("AWEB_MAX_REQUEST_BODY_BYTES must be a positive whole number of bytes")
    return value


class RequestBodyCacheMiddleware:
    """Cache each HTTP request's body and its SHA-256 for signature verification.

    Sets ``request.state.cached_body`` and ``request.state.body_sha256``. A
    GET, HEAD or OPTIONS request has an empty body and keeps its receive. Any
    other request is read whole before the app runs and replayed to it, so
    FastAPI still parses it. A body over ``max_body_bytes`` is refused with
    413 as soon as it is declared or read past the cap, before the app runs,
    so no request buffers more than the cap. Pure ASGI: unlike a
    BaseHTTPMiddleware, it holds no tasks of its own for a long-lived
    streaming response.
    """

    def __init__(self, app, *, max_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _refuse(self, scope, receive, send) -> None:
        await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)

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
        declared = next((value for name, value in scope.get("headers", []) if name.lower() == b"content-length"), None)
        if declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes:
            await self._refuse(scope, receive, send)
            return
        chunks, received = [], 0
        while True:
            message = await receive()
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
    db_infra: DatabaseInfra,
    redis: Redis,
    registry_client: RegistryClient,
    federation_authority=None,
) -> None:
    if any(isinstance(r, Mount) and r.path == "/mcp" for r in app.router.routes):
        return

    from .mcp import create_mcp_app

    mcp_app = create_mcp_app(
        db_infra=db_infra,
        redis=redis,
        registry_client=registry_client,
        federation_authority=federation_authority,
        streamable_http_path="/",
    )
    await mcp_app.startup()
    app.state.mcp_app = mcp_app
    app.mount("/mcp", mcp_app)
    move_mount_before_spa_fallback(app, "/mcp")
    logger.info("MCP endpoint mounted at /mcp/")


async def _shutdown_mcp_app(app: FastAPI) -> None:
    mcp_app = getattr(app.state, "mcp_app", None)
    if mcp_app is None:
        return
    await mcp_app.shutdown()
    app.state.mcp_app = None


async def start_agent_wakes(app: FastAPI, redis: Redis) -> None:
    """Start the process's agent wake publisher and subscriber on ``app.state``.

    Both lifespans call this. A host that mounts the app as a sub-application,
    whose lifespan never runs, must call it at mount (and ``stop_agent_wakes``
    at shutdown); without it, writes publish no wakes and streams fall back to
    their 15 s reconcile from Postgres.
    """
    app.state.agent_wake_publisher = AgentWakePublisher(redis)
    app.state.agent_wake_hub = AgentWakeHub(redis)
    await app.state.agent_wake_hub.start()


async def stop_agent_wakes(app: FastAPI) -> None:
    hub = getattr(app.state, "agent_wake_hub", None)
    if hub is not None:
        await hub.close()
    publisher = getattr(app.state, "agent_wake_publisher", None)
    if publisher is not None:
        await publisher.close()


async def _shutdown_federation_authority(app: FastAPI) -> None:
    authority = getattr(app.state, "federation_authority", None)
    if authority is None:
        return
    await authority.aclose()
    app.state.federation_authority = None


async def _shutdown_awid_registry_client(app: FastAPI) -> None:
    registry_client = getattr(app.state, "awid_registry_client", None)
    if registry_client is None:
        return
    await registry_client.aclose()
    app.state.awid_registry_client = None


def _build_awid_registry_client(
    app: FastAPI, redis: Redis | None, transport: httpx.AsyncBaseTransport | None = None
) -> RegistryClient:
    settings = get_settings()
    registry_url = settings.awid_registry_url
    service_token = settings.awid_service_token
    client_class = CachedRegistryClient if redis is not None else RegistryClient
    client_kwargs = {"registry_url": registry_url, "service_token": service_token, "transport": transport}
    if redis is not None:
        return client_class(redis_client=redis, **client_kwargs)
    return client_class(**client_kwargs)


async def _validate_awid_registry_client(registry_client: RegistryClient) -> None:
    try:
        await registry_client.health()
    except Exception as exc:
        raise RuntimeError(
            f"Failed to reach AWID registry at {registry_client.registry_url}: {exc}"
        ) from exc


def _make_standalone_lifespan():
    """Create lifespan for standalone mode (creates own DB and Redis connections)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("AWEB_LOG_JSON", "true").lower() == "true"
        settings = get_settings()
        configure_logging(log_level=settings.log_level, json_format=json_format)
        logger.info("Starting aweb coordination server (standalone mode)")

        redis: Redis | None = None
        redis_connected = False
        db_initialized = False

        try:
            # Phase 1: Initialize all resources (don't set app.state yet)
            redis = await async_redis_from_url(settings.redis_url, decode_responses=True)
            await redis.ping()
            redis_connected = True
            logger.info("Connected to Redis")

            await default_db_infra.initialize()
            db_initialized = True
            logger.info("Database initialized")
            if getattr(app.state, "install_admin_policy", None) is None:
                setup_message = await install_admin_setup_message(default_db_infra.get_manager())
                if setup_message:
                    logger.info(setup_message)

            # Phase 2: Only assign to app.state after ALL initialization succeeds
            app.state.redis = redis
            app.state.db = default_db_infra
            app.state.rate_limiter = build_rate_limiter(redis=redis)
            app.state.on_mutation = create_mutation_handler(redis, default_db_infra)
            app.state.awid_registry_client = _build_awid_registry_client(app, redis)
            app.state.federation_authority = build_federation_authority_activation(
                default_db_infra,
                public_origin=app.state.public_origin,
            )
            await _validate_awid_registry_client(app.state.awid_registry_client)
            await _mount_mcp_app(
                app,
                default_db_infra,
                redis,
                app.state.awid_registry_client,
                app.state.federation_authority,
            )
            await start_agent_wakes(app, redis)
            start_outbox_recovery(app)

        except Exception:
            # Log which phase failed
            if not redis_connected:
                logger.exception("Failed to connect to Redis")
            elif not db_initialized:
                logger.exception("Failed to initialize database")

            # Clean up any initialized resources on failure
            if db_initialized:
                await default_db_infra.close()
            if redis is not None:
                await redis.aclose()
            raise

        try:
            yield
        finally:
            logger.info("Shutting down aweb coordination server")
            await _shutdown_mcp_app(app)
            await stop_outbox_recovery(app)
            await _shutdown_federation_authority(app)
            await _shutdown_awid_registry_client(app)
            await stop_agent_wakes(app)
            await redis.aclose()
            await default_db_infra.close()

    return lifespan


def _make_library_lifespan(
    db_infra: DatabaseInfra, redis: Redis, awid_transport: httpx.AsyncBaseTransport | None
):
    """Create lifespan for library mode (uses externally provided connections)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("AWEB_LOG_JSON", "true").lower() == "true"
        log_level = os.getenv("AWEB_LOG_LEVEL", "info")
        configure_logging(log_level=log_level, json_format=json_format)
        logger.info("Starting aweb coordination server (library mode)")

        # Use externally provided connections - no initialization needed
        app.state.redis = redis
        app.state.db = db_infra
        app.state.rate_limiter = build_rate_limiter(redis=redis)
        app.state.on_mutation = create_mutation_handler(redis, db_infra)
        app.state.awid_registry_client = _build_awid_registry_client(app, redis, awid_transport)
        app.state.federation_authority = build_federation_authority_activation(
            db_infra,
            public_origin=app.state.public_origin,
        )
        await _validate_awid_registry_client(app.state.awid_registry_client)
        await _mount_mcp_app(
            app,
            db_infra,
            redis,
            app.state.awid_registry_client,
            app.state.federation_authority,
        )
        await start_agent_wakes(app, redis)
        start_outbox_recovery(app)

        try:
            yield
        finally:
            # Don't close connections in library mode - caller manages them
            await _shutdown_mcp_app(app)
            await stop_outbox_recovery(app)
            await _shutdown_federation_authority(app)
            await _shutdown_awid_registry_client(app)
            await stop_agent_wakes(app)
            logger.info("Aweb coordination server stopping (library mode)")

    return lifespan


def create_app(
    *,
    db_infra: Optional[DatabaseInfra] = None,
    redis: Optional[Redis] = None,
    attachment_backend=None,
    public_origin: str | None = None,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    host_runs_outbox_recovery: bool = False,
) -> FastAPI:
    """Create the aweb coordination FastAPI application.

    Args:
        db_infra: External DatabaseInfra instance (library mode).
                  If None, creates own connections (standalone mode).
        redis: External async Redis client (library mode).
               If None, creates own connection (standalone mode).
        public_origin: Configured external origin for request signature checks.
                       Defaults to public-origin settings captured at construction.
        awid_transport: The transport the AWID registry client uses (library
                        mode only), such as a host's in-process AWID. The
                        startup health check and every AWID call go through it.
        host_runs_outbox_recovery: The host runs aweb.outbox_recovery's
                        recover_outboxes on its own scheduler. Otherwise an app
                        that receives no lifespan (a mount) starts the recovery
                        loop on its first request.

    Library mode requires both db_infra and redis to be provided.
    Standalone mode requires neither (will create its own).

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
            main_app.mount("/coordination", coordination_app)
    """
    # Validate mode consistency
    if (db_infra is None) != (redis is None):
        raise ValueError(
            "Library mode requires both db_infra and redis, or neither for standalone mode"
        )

    library_mode = db_infra is not None
    if awid_transport is not None and not library_mode:
        raise ValueError("awid_transport is available in library mode only")

    # Validate db_infra is initialized in library mode
    if library_mode:
        assert db_infra is not None  # Type narrowing for mypy
        if not db_infra.is_initialized:
            raise ValueError(
                "db_infra must be initialized before passing to create_app() in library mode. "
                "Call 'await db_infra.initialize()' before creating the app."
            )
        assert redis is not None  # Required when db_infra is provided
        lifespan = _make_library_lifespan(db_infra, redis, awid_transport)
    else:
        lifespan = _make_standalone_lifespan()

    from aweb.attachment_service import router as attachment_router

    app = RequestDecompressionFastAPI(title="aweb coordination core", version="0.1.0", lifespan=lifespan)
    app.state.attachment_backend = attachment_backend
    app.state.public_origin = (
        canonical_server_origin(public_origin) if public_origin is not None else get_public_origin()
    )
    app.include_router(attachment_router)
    app.add_middleware(NormalizeMountedMCPPathMiddleware, mount_path="/mcp")

    app.add_middleware(RequestBodyCacheMiddleware, max_body_bytes=_max_request_body_bytes())

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error_handler(
        request: Request, exc: RequestValidationError
    ):
        matched_route_path = getattr(request.scope.get("route"), "path", "")
        if (matched_route_path in {"/v1/messages", "/v1/chat/sessions", "/v1/chat/sessions/{session_id}/messages"}
                and isinstance(exc.body, dict) and ({"attachments", "attachment_refs"} & exc.body.keys())):
            return JSONResponse(status_code=422, content={"detail": {"code": "request_invalid"}})
        if isinstance(matched_route_path, str) and matched_route_path.startswith(
            "/v1/federation/"
        ):
            from uuid import uuid4

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
                    correlation_id=request.headers.get("X-Correlation-ID") or str(uuid4()),
                ),
            )
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(FederationAuthorityError)
    async def _federation_authority_error_handler(
        request: Request, exc: FederationAuthorityError
    ):
        from uuid import uuid4

        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
        headers = {"Retry-After": "1"} if exc.retry_after_required else None
        return JSONResponse(
            status_code=exc.http_status,
            content=authority_error_body(exc, correlation_id=correlation_id),
            headers=headers,
        )

    @app.exception_handler(HumanChatRefused)
    async def _human_chat_refused_handler(request: Request, exc: HumanChatRefused):
        return JSONResponse(status_code=422, content=exc.body(
            correlation_id=request.headers.get("X-Correlation-ID"),
        ))

    @app.exception_handler(ServiceError)
    async def _service_error_handler(request: Request, exc: ServiceError):
        if exc.status_code >= 500:
            logger.exception("Unhandled ServiceError", exc_info=exc)
            return JSONResponse(status_code=500, content={"detail": "Internal server error"})
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.get("/health", tags=["internal"])
    async def health(request: Request) -> dict:
        checks = {}
        healthy = True

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
            db_infra: DatabaseInfra = request.app.state.db
            db = db_infra.get_manager("server")
            await db.fetch_value("SELECT 1")
            checks["database"] = "ok"
        except Exception:
            logger.error("Health check failed for database", exc_info=True)
            checks["database"] = "error"
            healthy = False

        return {"status": "ok" if healthy else "unhealthy", "checks": checks}

    app.include_router(agents_router)
    app.include_router(agent_status_router)
    app.include_router(agent_activity_router)
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
