"""HTTP routes for capability links (docs/page-links.md §2).

Every link response carries ``Cache-Control: no-store`` and
``Referrer-Policy: no-referrer``. A refusal carries only the contract's code;
its reason stays in the app's log. The exchange route's body holds the link
secret, so nothing here logs or echoes it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links import (
    LinkAuthority,
    LinkCreator,
    LinkRefused,
    _exchange_request,
    exchange,
    load_link_creator,
)
from aweb_naapp.runtime.team_auth import MembershipProof

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
    check_current_member: Callable[[LinkCreator], Awaitable[MembershipProof]],
    client_address: Callable[[Request], str],
    clock: Callable[[], datetime],
) -> None:
    """Serve ``POST /v1/links/{link_id}/session``.

    ``client_address`` keys the per-client exchange bucket, as the deployment
    resolves its callers (the peer, or a proxy header it trusts).
    ``check_current_member`` calls the shared runtime with this internal evidence
    before any transaction; never refresh membership in the authority callback.
    """

    @app.post("/v1/links/{link_id}/session", include_in_schema=False)
    async def exchange_route(link_id: str, request: Request) -> JSONResponse:
        try:
            body = await request.body()
            _exchange_request(body)
            creator = await load_link_creator(db, link_id=link_id)
            # Phase 1 may reach AWID. It MUST finish before exchange opens its
            # transaction; phase 2 reloads evidence and checks expiry under lock.
            proof = await check_current_member(creator)
            session = await exchange(
                db,
                authority,
                link_id=link_id,
                body=body,
                client=client_address(request),
                now=clock(),
                proof=proof,
            )
        except LinkRefused as refused:
            logger.info("link exchange refused: %s (%s)", refused.code, refused.reason)
            return refusal_response(refused)
        except HTTPException as refused:
            # Preserve the shared runtime's public membership code/status and
            # any retry header, with the same privacy headers as every link response.
            return JSONResponse(
                {"detail": refused.detail},
                status_code=refused.status_code,
                headers={**(refused.headers or {}), **LINK_RESPONSE_HEADERS},
            )
        return JSONResponse(
            {
                "session_id": session.session_id,
                "csrf_token": session.csrf_token,
                "expires_at": _timestamp(session.expires_at),
                "link": dict(session.link),
            },
            headers=LINK_RESPONSE_HEADERS,
        )
