"""HTTP refusal mapping for collection-link host routes."""

from aweb_naapp.runtime.capability_links.routes import LINK_RESPONSE_HEADERS
from fastapi import HTTPException
from fastapi.responses import JSONResponse


def link_http_refusal(refused: HTTPException) -> JSONResponse:
    headers = {name.lower(): value for name, value in (refused.headers or {}).items()}
    headers.update({name.lower(): value for name, value in LINK_RESPONSE_HEADERS.items()})
    return JSONResponse(
        {"detail": refused.detail}, status_code=refused.status_code,
        headers=headers,
    )
