"""One browser page for both purposes of the shared loopback handoff.

The page selects only the stored purpose. The existing JSON routes admit the
browser, bind its CSRF token and verify every ceremony and effect.
"""

from importlib.resources import files

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_naapp.console import ConsoleRoute, LoginLimiter, console_assets_router
from aweb_naapp.console.handoff_credential import _id
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.css import CSS_SHA256

_ASSETS = files("aweb_naapp.console.browser")


def _unavailable(error: HTTPException) -> HTMLResponse:
    # Fixed copy only: do not echo an id, scope, exception detail or redirect.
    guidance = (
        "Please wait before starting a new request from your terminal."
        if error.status_code == 429
        else "Return to your terminal and start a new request."
    )
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Request unavailable</title>"
        f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">'
        '<link rel="stylesheet" href="/handoff-assets/handoff.css"></head>'
        '<body><main class="handoff" aria-labelledby="handoff-unavailable">'
        '<h1 id="handoff-unavailable">Request unavailable</h1>'
        '<p role="status">This request cannot be completed.</p>'
        f"<p>{guidance}</p></main></body></html>",
        status_code=error.status_code,
        headers=error.headers,
    )


def handoff_page_router(*, store: HandoffStore, limiter: LoginLimiter) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)
    # A factory mounted by itself serves the same shared toolkit assets as
    # ConsoleShell; no app-specific stylesheet, font or script is required.
    router.include_router(console_assets_router())

    @router.get("/handoff-assets/handoff.js")
    async def script() -> Response:
        return Response(_ASSETS.joinpath("handoff.js").read_text(), media_type="text/javascript")

    @router.get("/handoff-assets/handoff.css")
    async def stylesheet() -> Response:
        return Response(_ASSETS.joinpath("handoff.css").read_text(), media_type="text/css")

    @router.get("/handoff/{handoff_id}")
    async def page(handoff_id: str, request: Request) -> HTMLResponse:
        # UUID and purpose are the only dynamic HTML inputs. Scope and CSRF
        # arrive through the existing admitted state route, never this lookup.
        try:
            await limiter.admit(request, "console.handoff")
            identifier = _id(handoff_id)
            purpose = await store.db.fetch_value(
                "SELECT purpose FROM {{tables.console_handoffs}} WHERE handoff_id=$1 "
                "AND expires_at>clock_timestamp() AND completed_at IS NULL AND released_at IS NULL",
                identifier,
            )
            if purpose not in ("credential", "session"):
                raise HTTPException(403, "handoff_refused")
        except HTTPException as error:
            if error.status_code not in (403, 429):
                raise
            return _unavailable(error)
        credential = purpose == "credential"
        title = "Create a passkey" if credential else "Sign in with a passkey"
        explanation = (
            "Create a passkey for the identity below. This step alone does not grant access."
            if credential
            else "Sign in for the identity below. You will review the request before allowing "
            "the terminal to continue."
        )
        action = "Create passkey" if credential else "Sign in with passkey"
        return HTMLResponse(
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{title}</title>"
            f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">'
            '<link rel="stylesheet" href="/handoff-assets/handoff.css">'
            '<script src="/handoff-assets/handoff.js" defer></script></head>'
            f'<body data-handoff-id="{identifier}" data-purpose="{purpose}" data-handoff-state="loading">'
            '<main class="handoff"><p class="handoff-eyebrow">Terminal request</p>'
            f"<h1>{title}</h1><p>{explanation}</p>"
            '<p class="handoff-origin">On <span id="handoff-origin"></span></p>'
            '<section id="handoff-scope" class="card" aria-label="Requested identity and role" hidden>'
            '<dl><dt>Identity</dt><dd id="handoff-principal"></dd>'
            '<dt>Role</dt><dd id="handoff-role"></dd>'
            '<dt>Installation</dt><dd id="handoff-installation"></dd></dl></section>'
            '<p id="handoff-status" role="status" aria-live="polite">Preparing your request…</p>'
            f'<button id="handoff-action" class="btn" type="button" disabled>{action}</button>'
            '<section id="handoff-allow" aria-labelledby="handoff-allow-title" hidden>'
            '<h2 id="handoff-allow-title" tabindex="-1">Allow this terminal session?</h2>'
            "<p>The terminal will be able to act as this identity in this role for up to 15 minutes.</p>"
            '<button id="handoff-confirm" class="btn" type="button">Allow</button>'
            "<p>Close this page to decline.</p></section>"
            "<noscript><p>JavaScript is required to use your passkey. Enable it and reload this page.</p></noscript>"
            "</main></body></html>"
        )

    return router
