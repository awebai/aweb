from __future__ import annotations

from fastapi import FastAPI
from starlette.routing import Mount


def move_mount_before_spa_fallback(app: FastAPI, mount_path: str) -> None:
    """Ensure mounted sub-app routes win over the catch-all SPA fallback."""
    mounts = [
        route
        for route in app.router.routes
        if isinstance(route, Mount) and route.path == mount_path
    ]
    if not mounts:
        return

    routes_wo_mounts = [route for route in app.router.routes if route not in mounts]
    fallback_path = "/{full_path:path}"
    try:
        fallback_idx = next(
            idx
            for idx, route in enumerate(routes_wo_mounts)
            if getattr(route, "path", None) == fallback_path
        )
    except StopIteration:
        fallback_idx = len(routes_wo_mounts)

    app.router.routes = (
        routes_wo_mounts[:fallback_idx] + mounts + routes_wo_mounts[fallback_idx:]
    )
