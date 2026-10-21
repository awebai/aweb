"""Human-origin browser shell; authentication and mutations stay with S4/B3.

Mount alongside owner_console_router on the human app only. The scope in a
setup/sign-in link is a locator, never authority. Custody owns the destination
pages and app composition owns the mount.
"""

from html import escape
from pathlib import Path

from aweb_naapp.console import ConsoleRoute, ConsoleSessions
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

_ASSETS = Path(__file__).parent


def _page(title: str, body: str) -> HTMLResponse:
    # body is a local, trusted template. Escape every locator inserted into it.
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)} · Secrets</title>"
        '<link rel="stylesheet" href="/console-ui/style.css">'
        '<script src="/console-ui/console.js" defer></script></head>'
        '<body><header><a href="/">Secrets</a></header><main>'
        f"{body}</main></body></html>"
    )


def _login_redirect(error: HTTPException) -> RedirectResponse:
    if error.status_code != 401:
        raise error
    # Preserve S4's clearing cookie when a session has expired or been revoked.
    return RedirectResponse("/login", status_code=303, headers=error.headers)


def console_ui_router(*, sessions: ConsoleSessions) -> APIRouter:
    """GET shell/login and static assets; mount only on the human origin.

    Login uses the existing /login/options and /login POST ceremonies. Browser
    forms share only the CSRF token in tab sessionStorage under
    aweb.secrets.console.csrf; credentials and form values are never stored.
    """
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        try:
            await sessions.current(request)
        except HTTPException as error:
            return _login_redirect(error)
        return _page(
            "Console",
            '<div class="heading"><h1>Secrets console</h1>'
            '<form id="logout" action="/logout" method="post">'
            '<button type="submit" class="secondary">Sign out</button></form></div>'
            "<p>Manage your team’s secrets and the people and agents who can use them.</p>"
            '<nav aria-label="Console"><a href="/secrets/new">Create a secret</a>'
            '<a href="/grants/new">Grant access to a role</a>'
            '<a href="/approvals">Review approvals</a>'
            '<a href="/activity">View activity</a></nav>'
            '<p id="notice" role="status" aria-live="polite"></p>',
        )

    @router.get("/login", response_class=HTMLResponse)
    async def login(request: Request, scope: str = "") -> Response:
        if scope:
            return _page(
                "Sign in",
                "<h1>Sign in to Secrets</h1><p>Use your passkey to continue.</p>"
                f'<form id="login" data-scope="{escape(scope, quote=True)}">'
                '<button type="submit">Sign in with a passkey</button></form>'
                '<p id="notice" role="status" aria-live="polite"></p>',
            )
        try:
            await sessions.current(request)
        except HTTPException as error:
            if error.status_code != 401:
                raise
            response = _page(
                "Sign in",
                "<h1>Sign in to Secrets</h1>"
                "<p>Open your owner or approver sign-in link to continue.</p>",
            )
            # Keep refusal headers, including the clearing session cookie.
            response.headers.update(error.headers or {})
            return response
        return RedirectResponse("/", status_code=303)

    @router.get("/console-ui/console.js")
    async def script() -> Response:
        return Response((_ASSETS / "console.js").read_text(), media_type="text/javascript")

    @router.get("/console-ui/style.css")
    async def style() -> Response:
        return Response((_ASSETS / "style.css").read_text(), media_type="text/css")

    return router
