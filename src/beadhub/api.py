import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from aweb.routes.agents import router as aweb_agents_router
from aweb.routes.auth import router as aweb_auth_router
from aweb.routes.chat import router as aweb_chat_router
from aweb.routes.messages import router as aweb_messages_router
from aweb.routes.projects import router as aweb_projects_router
from aweb.routes.reservations import router as aweb_reservations_router
from aweb.routes.tasks import router as aweb_tasks_router
from aweb.service_errors import ServiceError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis
from redis.asyncio import from_url as async_redis_from_url

from .config import get_settings
from .db import DatabaseInfra
from .db import db_infra as default_db_infra
from .logging import configure_logging
from .mutation_hooks import create_mutation_handler
from .routes.agents import router as agents_router
from .routes.bdh import router as bdh_router
from .routes.beads import router as beads_router
from .routes.claims import router as claims_router
from .routes.escalations import router as escalations_router
from .routes.init import router as init_router
from .routes.mcp import router as mcp_router
from .routes.policies import router as policies_router
from .routes.repos import router as repos_router
from .routes.status import router as status_router
from .routes.subscriptions import router as subscriptions_router
from .routes.tasks import router as tasks_router
from .routes.workspaces import router as workspaces_router

logger = logging.getLogger(__name__)

_MISSING_CUSTODY_KEY_WARNING = (
    "AWEB_CUSTODY_KEY not configured — custodial agent signing disabled. "
    "Set AWEB_CUSTODY_KEY to a 64-char hex string to enable."
)


def _make_standalone_lifespan():
    """Create lifespan for standalone mode (creates own DB and Redis connections)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("BEADHUB_LOG_JSON", "true").lower() == "true"
        settings = get_settings()
        configure_logging(log_level=settings.log_level, json_format=json_format)
        logger.info("Starting BeadHub server (standalone mode)")

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
            app.state.on_mutation = create_mutation_handler(redis, default_db_infra)

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
            logger.info("Shutting down BeadHub server")
            await redis.aclose()
            await default_db_infra.close()

    return lifespan


def _make_library_lifespan(db_infra: DatabaseInfra, redis: Redis):
    """Create lifespan for library mode (uses externally provided connections)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("BEADHUB_LOG_JSON", "true").lower() == "true"
        log_level = os.getenv("BEADHUB_LOG_LEVEL", "info")
        configure_logging(log_level=log_level, json_format=json_format)
        logger.info("Starting BeadHub server (library mode)")

        if not os.environ.get("AWEB_CUSTODY_KEY"):
            logger.warning(
                "AWEB_CUSTODY_KEY not configured — custodial agent signing disabled. "
                "Set AWEB_CUSTODY_KEY to a 64-char hex string to enable."
            )

        # Use externally provided connections - no initialization needed
        app.state.redis = redis
        app.state.db = db_infra
        app.state.on_mutation = create_mutation_handler(redis, db_infra)

        try:
            yield
        finally:
            # Don't close connections in library mode - caller manages them
            logger.info("BeadHub server stopping (library mode)")

    return lifespan


def create_app(
    *,
    db_infra: Optional[DatabaseInfra] = None,
    redis: Optional[Redis] = None,
    serve_frontend: bool = True,
    enable_bootstrap_routes: bool = True,
) -> FastAPI:
    """Create BeadHub FastAPI application.

    Args:
        db_infra: External DatabaseInfra instance (library mode).
                  If None, creates own connections (standalone mode).
        redis: External async Redis client (library mode).
               If None, creates own connection (standalone mode).
        serve_frontend: If True, serve the dashboard frontend from /frontend/dist.
                        Set to False when embedding in another app that serves its own UI.
        enable_bootstrap_routes: If True, expose bootstrap routes such as `/v1/init`.
                                 Embedded/proxy deployments should set this to False.

    Library mode requires both db_infra and redis to be provided.
    Standalone mode requires neither (will create its own).

    Examples:
        Standalone mode (simple deployment)::

            app = create_app()
            # Run with: uvicorn beadhub.api:create_app --factory

        Library mode (embedding in another FastAPI app)::

            from beadhub.api import create_app
            from beadhub.db import DatabaseInfra
            from redis.asyncio import Redis

            # Initialize shared infrastructure
            db_infra = DatabaseInfra()
            await db_infra.initialize()
            redis = await Redis.from_url("redis://localhost:6379")

            # Create BeadHub app with shared connections
            beadhub_app = create_app(db_infra=db_infra, redis=redis)

            # Mount under your main app
            main_app.mount("/beadhub", beadhub_app)
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

    app = FastAPI(title="BeadHub OSS Core", version="0.1.0", lifespan=lifespan)

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

    # aweb protocol routes (BeadHub is an aweb server).
    # Note: BeadHub overrides `/v1/init` with an extended init endpoint.
    if enable_bootstrap_routes:
        app.include_router(init_router)
    app.include_router(aweb_auth_router)
    app.include_router(aweb_chat_router)
    app.include_router(aweb_messages_router)
    app.include_router(aweb_projects_router)
    app.include_router(aweb_reservations_router)
    # beadhub tasks router overrides GET endpoints to add beads fallback.
    # Mounted before aweb_tasks_router so GET routes take priority;
    # aweb_tasks_router still handles POST, PATCH, DELETE, deps, comments.
    app.include_router(tasks_router)
    app.include_router(aweb_tasks_router)

    # beadhub endpoints.
    app.include_router(bdh_router)
    app.include_router(agents_router)
    # aweb agent lifecycle routes. beadhub's agents_router (above) takes precedence on
    # GET "" (list) and POST /suggest-alias-prefix, masking the aweb versions of those
    # two routes. All other aweb lifecycle routes (rotate, retire, deregister, log,
    # resolve, heartbeat, access mode) are not duplicated and route to aweb normally.
    app.include_router(aweb_agents_router)
    app.include_router(beads_router)
    app.include_router(claims_router)
    app.include_router(escalations_router)
    app.include_router(policies_router)
    app.include_router(status_router)
    app.include_router(subscriptions_router)
    app.include_router(workspaces_router)
    app.include_router(repos_router)
    app.include_router(mcp_router)

    # Serve frontend dashboard if available and enabled
    if serve_frontend:
        # Look for frontend dist relative to this file's location
        frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
        if frontend_dist.exists():
            # Serve static assets
            app.mount(
                "/assets",
                StaticFiles(directory=frontend_dist / "assets"),
                name="assets",
            )

            # Serve index.html for all unmatched routes (SPA routing)
            from fastapi.responses import FileResponse

            @app.get("/{full_path:path}", include_in_schema=False)
            async def serve_spa(full_path: str):
                # API routes are handled by routers registered before this catch-all
                # This only catches non-API paths for SPA routing
                index_path = frontend_dist / "index.html"
                if index_path.exists():
                    return FileResponse(index_path)
                raise HTTPException(status_code=404, detail="Frontend not found")

            logger.info("Frontend dashboard enabled at /")
        else:
            logger.debug("Frontend not found at %s, skipping", frontend_dist)

    return app


# Module-level app for uvicorn: `uvicorn beadhub.api:app`
app = create_app()
