"""HTTP routes for capability links (docs/page-links.md §2).

Every link response carries ``Cache-Control: no-store`` and
``Referrer-Policy: no-referrer``. A refusal carries only the contract's code;
its reason stays in the app's log. The exchange route's body holds the link
secret, so nothing here logs or echoes it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links import LinkAuthority, LinkRefused, exchange

logger = logging.getLogger(__name__)

LINK_RESPONSE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def refusal_response(refused: LinkRefused) -> JSONResponse:
    """The response for a refused link request: its code, with the link headers."""
    headers = dict(LINK_RESPONSE_HEADERS)
    if refused.retry_after_s is not None:
        headers["Retry-After"] = str(refused.retry_after_s)
    return JSONResponse(
        {"detail": {"code": refused.code}}, status_code=refused.status, headers=headers
    )


def mount_link_exchange(
    app: FastAPI,
    *,
    db: AsyncDatabaseManager,
    authority: LinkAuthority,
    client_address: Callable[[Request], str],
    clock: Callable[[], datetime],
) -> None:
    """Serve ``POST /v1/links/{link_id}/session``.

    ``client_address`` keys the per-client exchange bucket, as the deployment
    resolves its callers (the peer, or a proxy header it trusts).
    """

    @app.post("/v1/links/{link_id}/session", include_in_schema=False)
    async def exchange_route(link_id: str, request: Request) -> JSONResponse:
        try:
            session = await exchange(
                db,
                authority,
                link_id=link_id,
                body=await request.body(),
                client=client_address(request),
                now=clock(),
            )
        except LinkRefused as refused:
            logger.info("link exchange refused: %s (%s)", refused.code, refused.reason)
            return refusal_response(refused)
        return JSONResponse(
            {
                "session_id": session.session_id,
                "csrf_token": session.csrf_token,
                "expires_at": _timestamp(session.expires_at),
                "link": dict(session.link),
            },
            headers=LINK_RESPONSE_HEADERS,
        )
