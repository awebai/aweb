"""aweb FastAPI application entrypoints.

Important: `aweb` MUST NOT import from `beadhub`. This module is intentionally
minimal until the aweb routes and storage are implemented per
`docs/aweb.md`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from aweb.auth import validate_auth_config
from aweb.db import DatabaseInfra
from aweb.routes.agents import router as agents_router
from aweb.routes.auth import router as auth_router
from aweb.routes.chat import router as chat_router
from aweb.routes.contacts import router as contacts_router
from aweb.routes.conversations import router as conversations_router
from aweb.routes.init import router as init_router
from aweb.routes.messages import router as messages_router
from aweb.routes.projects import router as projects_router
from aweb.routes.reservations import router as reservations_router


def include_aweb_routers(app: FastAPI) -> None:
    """Install aweb routers into an existing FastAPI app."""
    app.include_router(init_router)
    app.include_router(auth_router)
    app.include_router(agents_router)
    app.include_router(chat_router)
    app.include_router(contacts_router)
    app.include_router(conversations_router)
    app.include_router(messages_router)
    app.include_router(projects_router)
    app.include_router(reservations_router)


def create_app(
    *,
    db_infra: Optional[DatabaseInfra] = None,
    redis: Optional[Redis] = None,
) -> FastAPI:
    """Create an aweb FastAPI app.

    For now this is a minimal skeleton; full behavior will land when `aweb`
    routes/storage are implemented.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Validate auth configuration before starting
        validate_auth_config()

        if db_infra is None:
            # Standalone mode: initialize our own infra.
            infra = DatabaseInfra()
            await infra.initialize()
            app.state.db = infra
        else:
            if not db_infra.is_initialized:
                raise ValueError(
                    "db_infra must be initialized before passing to create_app() in library mode. "
                    "Call 'await db_infra.initialize()' before creating the app."
                )
            app.state.db = db_infra

        if redis is None:
            # Redis is optional for now; keep placeholder for future coordination features.
            app.state.redis = None
        else:
            app.state.redis = redis

        yield

        # Only close infra if we created it in standalone mode.
        if db_infra is None:
            await app.state.db.close()

    app = FastAPI(title="aweb (Agent Web)", version="0.0.0", lifespan=lifespan)

    @app.get("/health", tags=["internal"])
    async def health(_: Request) -> dict:
        return {"status": "ok", "mode": "library" if db_infra is not None else "standalone"}

    # Convert domain service exceptions to HTTP responses so routes
    # don't need try/except around every service call.
    # (Deferred import avoids circular dependency with route modules.)
    from aweb.service_errors import ServiceError

    @app.exception_handler(ServiceError)
    async def _service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    include_aweb_routers(app)
    return app
