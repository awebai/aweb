from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from redis.asyncio import Redis
from redis.asyncio import from_url as async_redis_from_url

from aweb.logging import configure_logging
from aweb.ratelimit import MemoryFixedWindowRateLimiter, RedisFixedWindowRateLimiter
from aweb.routes.did import router as did_router
from aweb.routes.dns_addresses import router as dns_addresses_router
from aweb.routes.dns_namespaces import router as dns_namespaces_router

from .config import get_settings
from .db import AwidDatabaseInfra

logger = logging.getLogger(__name__)


def _public_health_error(*, component: str, exc: Exception, checks: dict[str, str]) -> None:
    logger.warning("awid health check failed for %s", component, exc_info=exc)
    checks[component] = "error"


def _make_standalone_lifespan():
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("AWID_LOG_JSON", "true").lower() == "true"
        settings = get_settings()
        configure_logging(log_level=settings.log_level, json_format=json_format)
        logger.info("Starting awid registry service (standalone mode)")

        redis: Redis | None = None
        db_infra = AwidDatabaseInfra(schema=settings.db_schema)

        try:
            redis = await async_redis_from_url(settings.redis_url, decode_responses=True)
            await redis.ping()
            await db_infra.initialize()

            app.state.redis = redis
            app.state.db = db_infra
            app.state.rate_limiter = _build_rate_limiter(
                redis=redis,
                backend=settings.rate_limit_backend,
            )
            app.state.db_schema = settings.db_schema
            yield
        finally:
            if redis is not None:
                await redis.aclose()
            await db_infra.close()
            logger.info("Awid registry service stopped")

    return lifespan


def _make_library_lifespan(
    db_infra: AwidDatabaseInfra,
    redis: Redis,
    rate_limiter=None,
):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        json_format = os.getenv("AWID_LOG_JSON", "true").lower() == "true"
        settings = get_settings()
        configure_logging(log_level=settings.log_level, json_format=json_format)
        logger.info("Starting awid registry service (library mode)")

        app.state.redis = redis
        app.state.db = db_infra
        app.state.rate_limiter = rate_limiter or _build_rate_limiter(
            redis=redis,
            backend=settings.rate_limit_backend,
        )
        app.state.db_schema = db_infra.schema
        try:
            yield
        finally:
            logger.info("Awid registry service stopping (library mode)")

    return lifespan


def _build_rate_limiter(*, redis, backend: str):
    if backend == "memory":
        return MemoryFixedWindowRateLimiter()
    return RedisFixedWindowRateLimiter(redis=redis)


def create_app(
    *,
    db_infra: Optional[AwidDatabaseInfra] = None,
    redis: Optional[Redis] = None,
    rate_limiter=None,
) -> FastAPI:
    if (db_infra is None) != (redis is None):
        raise ValueError("Library mode requires both db_infra and redis, or neither for standalone mode")
    if db_infra is not None and not db_infra.is_initialized:
        raise ValueError("db_infra must be initialized before passing to create_app()")

    if db_infra is None:
        lifespan = _make_standalone_lifespan()
    else:
        assert redis is not None
        lifespan = _make_library_lifespan(db_infra, redis, rate_limiter)

    app = FastAPI(title="awid.ai registry", version="0.1.0", lifespan=lifespan)

    @app.get("/", tags=["ops"])
    async def root() -> dict:
        return {"service": "awid", "status": "ok"}

    async def _health_payload(request: Request) -> dict:
        checks: dict[str, str] = {}
        healthy = True

        try:
            redis_client: Redis = request.app.state.redis
            await redis_client.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            _public_health_error(component="redis", exc=exc, checks=checks)
            healthy = False

        try:
            db = request.app.state.db.get_manager("aweb")
            await db.fetch_value("SELECT 1")
            checks["database"] = "ok"
        except Exception as exc:
            _public_health_error(component="database", exc=exc, checks=checks)
            healthy = False

        checks["schema"] = str(getattr(request.app.state, "db_schema", "awid"))
        checks["rate_limiter"] = type(request.app.state.rate_limiter).__name__
        return {"status": "ok" if healthy else "unhealthy", "checks": checks}

    @app.get("/health", tags=["ops"])
    async def health(request: Request) -> dict:
        return await _health_payload(request)

    @app.get("/ops/health", tags=["ops"])
    async def ops_health(request: Request) -> dict:
        return await _health_payload(request)

    app.include_router(did_router)
    app.include_router(dns_namespaces_router)
    app.include_router(dns_addresses_router)
    return app


app = create_app()
