"""Anonymous toolkit assets for a console served on its own human origin."""

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from aweb_naapp.asset_responses import (
    IMMUTABLE_CACHE_CONTROL,
    font_response,
    stylesheet_response,
)
from aweb_naapp.css import CSS_SHA256


def console_assets_router() -> APIRouter:
    """Mount once at the human-origin root, including before passkey sign-in.

    Assets use the public mount's bytes, MIME and immutable cache policy, with
    ConsoleRoute's CSP/referrer headers. No session or app-owned font fallback.
    """
    from aweb_naapp.console import ConsoleRoute

    class AssetRoute(ConsoleRoute):
        def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
            handler = super().get_route_handler()

            async def asset_handler(request: Request) -> Response:
                response = await handler(request)
                # Only these content-addressed/allowlisted static successes are cacheable.
                # Refusals and every other ConsoleRoute keep their no-store policy.
                if response.status_code == 200:
                    response.headers["Cache-Control"] = IMMUTABLE_CACHE_CONTROL
                return response

            return asset_handler

    router = APIRouter(route_class=AssetRoute)

    @router.get(f"/css/aweb.{CSS_SHA256[:12]}.css")
    async def stylesheet() -> Response:
        return stylesheet_response(immutable=True)

    @router.get("/fonts/{name}")
    async def font(name: str) -> Response:
        return font_response(name)

    return router
