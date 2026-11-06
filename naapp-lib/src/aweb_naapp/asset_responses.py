"""One serving path for toolkit CSS and allowlisted WOFF2 bytes."""

from collections.abc import Mapping

from fastapi import HTTPException
from fastapi.responses import Response

from aweb_naapp.css import aweb_css, font_bytes

IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"


def stylesheet_response(*, immutable: bool) -> Response:
    return Response(
        content=aweb_css(),
        media_type="text/css",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": IMMUTABLE_CACHE_CONTROL if immutable else "public, max-age=3600",
        },
    )


def font_response(name: str, *, app_fonts: Mapping[str, bytes] | None = None) -> Response:
    font = font_bytes(name)
    if font is None and app_fonts is not None:
        font = app_fonts.get(name)
    if font is None:
        raise HTTPException(status_code=404, detail="Font not found")
    return Response(
        content=font,
        media_type="font/woff2",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": IMMUTABLE_CACHE_CONTROL},
    )
