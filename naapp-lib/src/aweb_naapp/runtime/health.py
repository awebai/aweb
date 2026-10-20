"""The naapp ``/health``, ``/live`` and ``/ready`` routes."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from aweb_naapp.runtime.build_identity import (
    resolve_build_identity,
    resolve_render_deployment_identity,
)
from aweb_naapp.runtime.settings import NaappSettings

logger = logging.getLogger(__name__)

# A dependency that does not answer within this bound is reported as failing.
HEALTH_CHECK_TIMEOUT_SECONDS = 5.0
# The health routes are unauthenticated, and a check may cost a database scan
# or a KMS call, so one run's result is served to every request in this window.
HEALTH_CHECK_CACHE_SECONDS = 10.0
_monotonic = time.monotonic


@dataclass(frozen=True)
class CheckResult:
    """One dependency's state. ``detail`` is served as it is, so it carries
    only public facts, never an error message or a credential."""

    ok: bool
    detail: Mapping[str, object] = field(default_factory=dict)


HealthCheck = Callable[[], Awaitable[CheckResult]]


async def _run(name: str, check: HealthCheck) -> CheckResult:
    try:
        return await asyncio.wait_for(check(), timeout=HEALTH_CHECK_TIMEOUT_SECONDS)
    except Exception:
        logger.exception("Health check %s failed", name)
        return CheckResult(ok=False)


def mount_health(
    app: FastAPI, settings: NaappSettings, checks: Mapping[str, HealthCheck] | None = None
) -> None:
    """Serve the app's id and build identity, plus Render's deployment identity
    when the platform injects one.

    The identity is resolved once, here, so an invalid injected value stops the
    app from starting rather than being served. The non-Render build commit is
    read from the app's own ``<env_prefix>GIT_SHA``.

    ``checks`` are the app's dependencies, reported by name on ``/health`` and
    ``/ready``. They run at most once per ``HEALTH_CHECK_CACHE_SECONDS``:
    concurrent requests wait for the one run in flight, and later ones get its
    result until it expires. ``/ready`` answers 503 when any of them fails;
    ``/health`` reports the same and always answers 200; ``/live`` runs none.
    """
    fallback_sha_env = f"{settings.model_config.get('env_prefix', '')}GIT_SHA"
    payload: dict[str, object] = {
        "status": "ok",
        "service": settings.app_id,
        "build": resolve_build_identity(fallback_sha_env),
    }
    deployment = resolve_render_deployment_identity()
    if deployment is not None:
        payload["deployment"] = deployment
    checks = dict(checks or {})
    lock = asyncio.Lock()
    cached: list[tuple[float, tuple[bool, dict[str, object]]]] = []

    async def checked() -> tuple[bool, dict[str, object]]:
        if not checks:
            return True, payload
        async with lock:
            if cached and cached[0][0] > _monotonic():
                return cached[0][1]
            result = await run_checks()
            cached[:] = [(_monotonic() + HEALTH_CHECK_CACHE_SECONDS, result)]
            return result

    async def run_checks() -> tuple[bool, dict[str, object]]:
        results = await asyncio.gather(*(_run(name, check) for name, check in checks.items()))
        ready = all(result.ok for result in results)
        return ready, {
            **payload,
            "status": "ok" if ready else "unavailable",
            "checks": {
                name: {"ok": result.ok, **result.detail}
                for name, result in zip(checks, results, strict=True)
            },
        }

    @app.get("/live")
    async def live() -> dict[str, object]:
        return payload

    @app.get("/health")
    async def health() -> dict[str, object]:
        return (await checked())[1]

    @app.get("/ready")
    async def ready() -> JSONResponse:
        is_ready, body = await checked()
        return JSONResponse(body, status_code=200 if is_ready else 503)
