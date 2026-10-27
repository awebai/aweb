"""Human-origin browser shell; authentication and mutations stay with S4/B3.

Mount alongside owner_console_router on the human app only. The scope in a
setup/sign-in link is a locator, never authority. Custody owns the destination
pages and app composition owns the mount.
"""

from html import escape
from pathlib import Path
from urllib.parse import quote

from aweb_naapp.console import ConsoleRoute, ConsoleSession, ConsoleSessions
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


def console_page(*, title: str, body_html: str, session: ConsoleSession) -> HTMLResponse:
    """Render an authenticated page with a per-tab CSRF availability guard.

    body_html is trusted developer-authored HTML, never a submitted value.
    Pass the session returned by S4.current and serve through ConsoleRoute.
    Custody pages use this same wrapper and assets so a new tab with only a
    cookie gets a scoped passkey sign-in link instead of unusable actions.
    """
    scope = escape(session.scope, quote=True)
    href = "/login?scope=" + quote(session.scope, safe="")
    return _page(
        title,
        f'<section data-console-scope="{scope}" hidden>{body_html}</section>'
        '<section id="console-reauth-notice"><h1>Sign in to make changes</h1>'
        "<p>Sign in again in this tab to make changes.</p>"
        f'<a id="console-reauth" href="{escape(href, quote=True)}">Sign in with your passkey</a>'
        "</section>",
    )


def recovery_page(
    error: HTTPException, *, message: str, action_href: str, action_label: str
) -> HTMLResponse:
    """A browser GET refusal as a page: its own status and headers, one sentence, one way on.

    message, action_href and action_label are fixed by the caller, never request values.
    The page sits outside console_page's per-tab guard, so it shows without a CSRF token,
    and it shows nothing the refused read would have shown. Serve through ConsoleRoute.
    A 401 goes to _login_redirect instead.
    """
    response = _page(
        message,
        f'<section id="console-recovery"><h1>{escape(message)}</h1>'
        f'<p><a id="console-recovery-action" href="{escape(action_href, quote=True)}">'
        f"{escape(action_label)}</a></p></section>",
    )
    response.status_code = error.status_code
    response.headers.update(error.headers or {})
    return response


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
            session = await sessions.current(request)
        except HTTPException as error:
            return _login_redirect(error)
        return console_page(
            title="Console",
            session=session,
            body_html='<div class="heading"><h1>Secrets console</h1>'
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
