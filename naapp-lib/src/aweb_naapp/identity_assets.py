"""Public identity assets, packaged with the shared chrome and served locally."""

from __future__ import annotations

from importlib.resources import files
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

ASSET_PREFIX = "/brand/field-v1"
_ASSETS = {
    "favicon.svg": "image/svg+xml",
    **{f"icon-{size}.png": "image/png" for size in (16, 32, 48, 180, 192, 512)},
    **{f"{brand}-card.png": "image/png" for brand in ("aweb", "folio", "library")},
}


def identity_asset(name: str) -> tuple[bytes, str] | None:
    if name not in _ASSETS:
        return None
    return files("aweb_naapp").joinpath("assets/identity", name).read_bytes(), _ASSETS[name]


def mount_identity_routes(app: FastAPI) -> None:
    # Keep HTTP imports out of the toolkit's dependency-free docs surface.
    from fastapi import HTTPException
    from fastapi.responses import Response

    @app.get(ASSET_PREFIX + "/{name}")
    async def asset(name: str) -> Response:
        result = identity_asset(name)
        if result is None:
            raise HTTPException(404, "Asset not found")
        content, media_type = result
        return Response(content, media_type=media_type, headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "public, max-age=31536000, immutable",
        })
