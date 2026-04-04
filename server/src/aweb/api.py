import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport
from redis.asyncio import Redis
from redis.asyncio import from_url as async_redis_from_url
from starlette.routing import Mount

from .awid import CachedRegistryClient, RegistryClient
from .config import get_settings, is_local_awid_registry_url
from .db import DatabaseInfra
from .db import db_infra as default_db_infra
from .logging import configure_logging
from .mutation_hooks import create_mutation_handler
from .ratelimit import build_rate_limiter
from .routing_utils import move_mount_before_spa_fallback
from .service_errors import ServiceError
from .mcp.server import NormalizeMountedMCPPathMiddleware
from .routes.auth import router as auth_router
from .routes.agents import router as agents_router
from .routes.chat import router as chat_router
from .routes.claims import router as claims_router
from .routes.contacts import router as contacts_router
from .routes.conversations import router as conversations_router
from .routes.did import router as did_router
from .routes.dns_addresses import router as dns_addresses_router
from .routes.dns_namespaces import router as dns_namespaces_router
from .routes.events import router as events_router
from .routes.init import bootstrap_router, router as init_router
from .routes.messages import router as messages_router
from .routes.projects import router as projects_router
from .routes.reservations import router as reservations_router
from .routes.scopes import router as scopes_router
from .routes.spawn import router as spawn_router
from .routes.status import router as status_router
from .coordination.routes.project_instructions import instructions_router
from .coordination.routes.project_roles import roles_router
from .coordination.routes.repos import router as repos_router
from .coordination.routes.tasks import router as tasks_router
from .coordination.routes.workspaces import router as workspaces_router

logger = logging.getLogger(__name__)

_MISSING_CUSTODY_KEY_WARNING = (
    "AWEB_CUSTODY_KEY not configured — custodial agent signing disabled. "
    "Set AWEB_CUSTODY_KEY to a 64-char hex string to enable."
)


async def _mount_mcp_app(app: FastAPI, db_infra: DatabaseInfra, redis: Redis) -> None:
    if any(isinstance(r, Mount) and r.path == "/mcp" for r in app.router.routes):
        return

    from .mcp import create_mcp_app

    mcp_app = create_mcp_app(db_infra=db_infra, redis=redis, streamable_http_path="/")
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


def _build_awid_registry_client(app: FastAPI, redis: Redis | None) -> RegistryClient:
    settings = get_settings()
    registry_url = settings.awid_registry_url
    client_class = CachedRegistryClient if redis is not None else RegistryClient
    client_kwargs = {"registry_url": registry_url}
    if is_local_awid_registry_url(registry_url):
        client_kwargs["transport"] = ASGITransport(app=app)
    if redis is not None:
        return client_class(redis_client=redis, **client_kwargs)
    return client_class(**client_kwargs)


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

            if not os.environ.get("AWEB_CUSTODY_KEY"):
                logger.warning(_MISSING_CUSTODY_KEY_WARNING)

            # Phase 2: Only assign to app.state after ALL initialization succeeds
            app.state.redis = redis
            app.state.db = default_db_infra
            app.state.rate_limiter = build_rate_limiter(redis=redis)
            app.state.on_mutation = create_mutation_handler(redis, default_db_infra)
            app.state.awid_registry_client = _build_awid_registry_client(app, redis)
            await _mount_mcp_app(app, default_db_infra, redis)

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
            await redis.aclose()
            await default_db_infra.close()

    return lifespan


def _make_library_lifespan(db_infra: DatabaseInfra, redis: Redis):
    """Create lifespan for library mode (uses externally provided connections)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("AWEB_LOG_JSON", "true").lower() == "true"
        log_level = os.getenv("AWEB_LOG_LEVEL", "info")
        configure_logging(log_level=log_level, json_format=json_format)
        logger.info("Starting aweb coordination server (library mode)")

        if not os.environ.get("AWEB_CUSTODY_KEY"):
            logger.warning(
                "AWEB_CUSTODY_KEY not configured — custodial agent signing disabled. "
                "Set AWEB_CUSTODY_KEY to a 64-char hex string to enable."
            )

        # Use externally provided connections - no initialization needed
        app.state.redis = redis
        app.state.db = db_infra
        app.state.rate_limiter = build_rate_limiter(redis=redis)
        app.state.on_mutation = create_mutation_handler(redis, db_infra)
        app.state.awid_registry_client = _build_awid_registry_client(app, redis)
        await _mount_mcp_app(app, db_infra, redis)

        try:
            yield
        finally:
            # Don't close connections in library mode - caller manages them
            await _shutdown_mcp_app(app)
            logger.info("Aweb coordination server stopping (library mode)")

    return lifespan


def create_app(
    *,
    db_infra: Optional[DatabaseInfra] = None,
    redis: Optional[Redis] = None,
    enable_bootstrap_routes: bool = True,
) -> FastAPI:
    """Create the aweb coordination FastAPI application.

    Args:
        db_infra: External DatabaseInfra instance (library mode).
                  If None, creates own connections (standalone mode).
        redis: External async Redis client (library mode).
               If None, creates own connection (standalone mode).
        enable_bootstrap_routes: If True, expose bootstrap routes such as `/v1/workspaces/init`.
                                 Embedded/proxy deployments should set this to False.

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

    # Validate db_infra is initialized in library mode
    if library_mode:
        assert db_infra is not None  # Type narrowing for mypy
        if not db_infra.is_initialized:
            raise ValueError(
                "db_infra must be initialized before passing to create_app() in library mode. "
                "Call 'await db_infra.initialize()' before creating the app."
            )
        assert redis is not None  # Required when db_infra is provided
        lifespan = _make_library_lifespan(db_infra, redis)
    else:
        lifespan = _make_standalone_lifespan()

    app = FastAPI(title="aweb coordination core", version="0.1.0", lifespan=lifespan)
    app.add_middleware(NormalizeMountedMCPPathMiddleware, mount_path="/mcp")
    mount_local_registry_routes = is_local_awid_registry_url()

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
        except Exception as e:
            checks["redis"] = f"error: {e}"
            healthy = False

        # Check Database
        try:
            db_infra: DatabaseInfra = request.app.state.db
            db = db_infra.get_manager("server")
            await db.fetch_value("SELECT 1")
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = f"error: {e}"
            healthy = False

        return {"status": "ok" if healthy else "unhealthy", "checks": checks}

    app.include_router(bootstrap_router)
    if enable_bootstrap_routes:
        app.include_router(init_router)
        app.include_router(spawn_router)
    app.include_router(auth_router)
    app.include_router(agents_router)
    app.include_router(chat_router)
    app.include_router(claims_router)
    app.include_router(contacts_router)
    app.include_router(conversations_router)
    if mount_local_registry_routes:
        app.include_router(did_router)
        app.include_router(dns_addresses_router)
        app.include_router(dns_namespaces_router)
    app.include_router(events_router)
    app.include_router(messages_router)
    app.include_router(projects_router)
    app.include_router(reservations_router)
    app.include_router(scopes_router)
    app.include_router(status_router)
    app.include_router(instructions_router)
    app.include_router(roles_router)
    app.include_router(tasks_router)
    app.include_router(workspaces_router)
    app.include_router(repos_router)

    return app


# Module-level app for uvicorn: `uvicorn aweb.api:app`
app = create_app()
