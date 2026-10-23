"""Human token-entry and frozen change review pages on the shared console shell."""

import json
from html import escape
from pathlib import Path

from aweb_naapp.console import ConsoleRoute
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.console_changes import ConsoleChanges, _errors
from aweb_secrets.console_ui import _login_redirect, _page, console_page

_ASSETS = Path(__file__).parent
_SCRIPT = (
    '<link rel="stylesheet" href="/console-forms/forms.css">'
    '<script src="/console-forms/forms.js" defer></script>'
)
_STATUS = '<p id="form-status" role="status" aria-live="polite"></p>'
_REVIEW = (
    "<h1>Review the 1Password connection</h1>"
    '<p id="approval-instructions">Open the approval link sent to your registered contact.</p>'
    '<section id="change-summary" hidden><h2>Frozen change</h2>'
    '<dl id="change-facts"></dl>'
    "<p><strong>Activating a new service-account token invalidates existing 1Password item bindings. "
    "Those items need to be linked and confirmed again. Disabled secrets stay disabled.</strong></p>"
    '<h2>Reason supplied by the drafter (untrusted)</h2><pre id="change-reason"></pre>'
    '<button id="confirm-change" type="button" disabled>Confirm with your passkey</button></section>'
)


def console_forms_router(*, changes: ConsoleChanges) -> APIRouter:
    """Mount on the human app with the same ConsoleChanges and value routers.

    No values go into page templates, URLs, browser storage or returned results.
    The forms use only the shared POST and WebAuthn assertion helpers.
    """
    router = APIRouter(route_class=ConsoleRoute)

    async def session(request: Request):
        return await changes.console.sessions.current(request)

    @router.get("/backend-credentials/onepassword/new", response_class=HTMLResponse)
    async def token_page(request: Request) -> Response:
        try:
            current = await session(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _errors(changes.console, current):
            installation = await changes.installation_for_session(current)
        path = "/installations/" + installation + "/backend-credentials/onepassword/versions"
        return console_page(
            title="Connect 1Password",
            session=current,
            body_html="<h1>Connect 1Password</h1>"
            "<p>Use a read-only service-account token limited to your team’s vault. "
            "The token is sealed and is never shown again.</p>"
            f'<form id="backend-token" method="post" action="{escape(path, quote=True)}" '
            f'data-installation="{escape(installation, quote=True)}">'
            '<label for="service-account-token">1Password service-account token</label>'
            '<input id="service-account-token" type="password" name="value" '
            'autocomplete="off" spellcheck="false" required>'
            '<button type="submit">Save a draft</button></form>' + _STATUS + _SCRIPT,
        )

    @router.get("/approvals", response_class=HTMLResponse)
    async def approval_page(request: Request) -> Response:
        try:
            current = await session(request)
        except HTTPException as refused:
            if refused.status_code != 401:
                raise
            response = _page(
                "Sign in to review",
                "<h1>Sign in to review an approval</h1>"
                "<p>The approval link selects your sign-in. Your passkey is required to continue.</p>"
                '<form id="approval-login" method="post" action="/login">'
                '<button type="submit" disabled>Sign in with your passkey</button></form>'
                + _STATUS
                + _SCRIPT,
            )
            response.headers.update(refused.headers or {})
            return response
        async with _errors(changes.console, current):
            await changes.installation_for_session(current)
        return console_page(
            title="Review approval", session=current, body_html=_REVIEW + _STATUS + _SCRIPT
        )

    @router.get(
        "/installations/{installation_id}/change-sets/{change_id}/review",
        response_class=HTMLResponse,
    )
    async def review_page(installation_id: str, change_id: str, request: Request) -> Response:
        try:
            current = await session(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _errors(changes.console, current):
            frozen = await changes.read(current, installation_id, change_id)
        # HTML escaping protects even </pre>/<script> in an untrusted reason.
        # The script reads textContent, and every displayed field uses textContent.
        projection = '<pre id="frozen-change" hidden>' + escape(json.dumps(frozen)) + "</pre>"
        return console_page(
            title="Review approval",
            session=current,
            body_html=_REVIEW + projection + _STATUS + _SCRIPT,
        )

    @router.get("/console-forms/forms.css")
    async def style() -> Response:
        return Response((_ASSETS / "forms.css").read_text(), media_type="text/css")

    @router.get("/console-forms/forms.js")
    async def script() -> Response:
        return Response((_ASSETS / "forms.js").read_text(), media_type="text/javascript")

    return router
