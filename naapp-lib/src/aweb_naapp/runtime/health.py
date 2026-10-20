"""The naapp ``/health``, ``/live`` and ``/ready`` routes."""

from __future__ import annotations

from fastapi import FastAPI

from aweb_naapp.runtime.build_identity import (
    resolve_build_identity,
    resolve_render_deployment_identity,
)
from aweb_naapp.runtime.settings import NaappSettings


def mount_health(app: FastAPI, settings: NaappSettings) -> None:
    """Serve the app's id and build identity, plus Render's deployment identity
    when the platform injects one.

    The identity is resolved once, here, so an invalid injected value stops the
    app from starting rather than being served. The non-Render build commit is
    read from the app's own ``<env_prefix>GIT_SHA``.
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

    @app.get("/health")
    @app.get("/live")
    @app.get("/ready")
    async def health() -> dict[str, object]:
        return payload
