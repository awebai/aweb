"""Shared toolkit bytes for the human console, under its existing route headers."""

import aweb_naapp as naapp
from aweb_naapp.console import ConsoleRoute
from aweb_naapp.css import font_bytes
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

STYLESHEET = f"/css/aweb.{naapp.CSS_SHA256[:12]}.css"


def console_assets_router() -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.get(STYLESHEET)
    async def stylesheet() -> Response:
        return Response(naapp.aweb_css(), media_type="text/css")

    @router.get("/fonts/{name}")
    async def font(name: str) -> Response:
        content = font_bytes(name)
        if content is None:
            raise HTTPException(status_code=404)
        return Response(content, media_type="font/woff2")

    return router
