"""Human configuration entry and frozen change review pages on the shared console shell."""

import json
from html import escape
from pathlib import Path

from aweb_naapp.console import ConsoleRoute
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.console_changes import ConsoleChanges, _errors
from aweb_secrets.console_ui import _login_redirect, _page, console_page
from aweb_secrets.operation import CAPTURE_FIELDS
from aweb_secrets.secret import KINDS, mint_secret_id

_ASSETS = Path(__file__).parent
_SCRIPT = (
    '<link rel="stylesheet" href="/console-forms/forms.css">'
    '<script src="/console-forms/forms.js" defer></script>'
)
_STATUS = '<p id="form-status" role="status" aria-live="polite"></p>'
_REVIEW = (
    "<h1>Review changes</h1>"
    '<p id="approval-instructions">Open the approval link sent to your registered contact.</p>'
    '<section id="change-summary" hidden><h2>Frozen change</h2>'
    '<dl id="change-facts"></dl>'
    '<p id="backend-replacement-notice" hidden><strong>Activating a new service-account token invalidates existing 1Password item bindings. '
    "Those items need to be linked and confirmed again. Disabled secrets stay disabled.</strong></p>"
    '<h2>Reason supplied by the drafter (untrusted)</h2><pre id="change-reason"></pre>'
    '<button id="confirm-change" type="button" disabled>Confirm with your passkey</button></section>'
)

_KIND_NAMES = {
    "bearer": "Bearer token",
    "basic": "Basic credentials",
    "header": "Custom header",
    "query": "Query parameter",
    "oauth2-client-credentials": "OAuth2 client credentials",
    "aws-sigv4": "AWS Signature Version 4",
}


def _reference_kinds() -> str:
    fields = []
    params = {
        "header": (("name", "Header name", True), ("prefix", "Header prefix", False)),
        "query": (("param", "Query parameter name", True),),
        "oauth2-client-credentials": (
            ("token_endpoint", "Token endpoint URL", True),
            ("scope", "OAuth scopes", False),
        ),
        "aws-sigv4": (("region", "AWS region", True), ("service", "AWS service", True)),
    }
    for kind in KINDS:
        inactive = " hidden disabled" if kind != "bearer" else ""
        fields.append(
            f'<fieldset data-kind="{kind}"{inactive}><legend>{_KIND_NAMES[kind]}</legend>'
        )
        for name, label, needed in params.get(kind, ()):
            identity = f"reference-{kind}-{name}"
            fields.append(
                f'<label for="{identity}">{label}</label><input id="{identity}" '
                f'data-param="{name}" autocomplete="off" spellcheck="false"'
                + (" required" if needed else "")
                + ">"
            )
        if kind == "oauth2-client-credentials":
            fields.append(
                '<label for="reference-client-auth">Client authentication</label>'
                '<select id="reference-client-auth" data-param="client_auth">'
                '<option value="client_secret_basic">HTTP Basic authentication</option>'
                '<option value="client_secret_post">Form body</option></select>'
            )
        required, optional = CAPTURE_FIELDS[kind]
        for name in sorted(required | optional):
            identity = f"reference-{kind}-{name}-field"
            label = name.replace("_", " ").capitalize() + " field ID"
            if name in optional:
                label += " (optional)"
            fields.append(
                f'<label for="{identity}">{label}</label><input id="{identity}" '
                f'data-field="{name}" autocomplete="off" spellcheck="false" '
                'pattern="[A-Za-z0-9_-]{1,128}" maxlength="128"'
                + (" required" if name in required else "")
                + ">"
            )
        fields.append("</fieldset>")
    return "".join(fields)


def _reference_form(installation_id: str, credential_version: int) -> str:
    action = "/installations/" + installation_id + "/onepassword/references"
    options = "".join(
        f'<option value="{kind}" data-auth-kind>{_KIND_NAMES[kind]}</option>' for kind in KINDS
    )
    return (
        "<p>Select the item and field IDs from your connected vault. Enter references here; "
        "the field values stay in 1Password. Review and confirm the draft before agents can use it.</p>"
        f'<form id="onepassword-reference" method="post" action="{escape(action, quote=True)}" '
        f'data-installation="{escape(installation_id, quote=True)}">'
        f'<input type="hidden" name="secret_id" value="{mint_secret_id()}">'
        f'<input type="hidden" name="credential_version" value="{credential_version}">'
        '<label for="reference-name">Secret name</label>'
        '<input id="reference-name" name="ref" pattern="[a-z0-9][a-z0-9_-]{0,63}" '
        'maxlength="64" autocomplete="off" required>'
        '<label for="reference-description">Description (optional)</label>'
        '<textarea id="reference-description" name="description" maxlength="512" rows="2"></textarea>'
        '<label for="reference-kind">Authentication kind</label>'
        f'<select id="reference-kind" name="kind">{options}</select>'
        '<label for="reference-sensitivity">Sensitivity</label>'
        '<select id="reference-sensitivity" name="sensitivity">'
        '<option value="standard">Standard</option><option value="sensitive">Sensitive</option></select>'
        '<label class="check"><input type="checkbox" name="approve_only">Require approval for every use</label>'
        '<label for="reference-vault">Vault ID</label>'
        '<input id="reference-vault" name="vault_id" autocomplete="off" spellcheck="false" '
        'pattern="[a-z0-9]{26}" minlength="26" maxlength="26" required>'
        '<label for="reference-item">Item ID</label>'
        '<input id="reference-item" name="item_id" autocomplete="off" spellcheck="false" '
        'pattern="[a-z0-9]{26}" minlength="26" maxlength="26" required>'
        + _reference_kinds()
        + '<label for="reference-reason">Reason for this change (optional)</label>'
        '<input id="reference-reason" name="reason" autocomplete="off">'
        '<button type="submit">Save a reference draft</button></form>'
    )


def console_forms_router(*, changes: ConsoleChanges) -> APIRouter:
    """Mount on the human app with the same ConsoleChanges and value routers.

    No values go into page templates, URLs, browser storage or returned results.
    The forms use only the shared POST and WebAuthn assertion helpers.
    """
    router = APIRouter(route_class=ConsoleRoute)

    async def session(request: Request):
        return await changes.console.sessions.current(request)

    async def reference_page(request: Request, installation_id: str | None = None) -> Response:
        try:
            current = await session(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _errors(changes.console, current):
            if installation_id is None:
                installation_id = await changes.installation_for_session(current)
            admitted = await changes._installation(installation_id)
            async with changes.console.db.transaction() as tx:
                await changes._owner(tx, current, admitted)
                version = await tx.fetch_value(
                    "SELECT active_version FROM {{tables.onepassword_credentials}} "
                    "WHERE installation_id=$1 AND team_id=$2",
                    admitted.installation_id,
                    admitted.team_id,
                )
                await changes.console.fence.check(tx, admitted)
                changes._unexpired(current)
        body = (
            _reference_form(installation_id, version)
            if version is not None
            else "<p>Connect and confirm your team’s 1Password service account first.</p>"
            '<p><a href="/backend-credentials/onepassword/new">Connect 1Password</a></p>'
        )
        return console_page(
            title="Link a 1Password secret",
            session=current,
            body_html="<h1>Link a 1Password secret</h1>" + body + _STATUS + _SCRIPT,
        )

    @router.get("/secrets/new", response_class=HTMLResponse)
    @router.get("/onepassword/references/new", response_class=HTMLResponse)
    async def reference_entry(request: Request) -> Response:
        return await reference_page(request)

    @router.get(
        "/installations/{installation_id}/onepassword/references/new", response_class=HTMLResponse
    )
    async def scoped_reference_entry(installation_id: str, request: Request) -> Response:
        return await reference_page(request, installation_id)

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
