"""Native value entry on the owner console (secrets.md §6.1, lines596-606)."""

from enum import StrEnum
from html import escape
from pathlib import Path

from aweb_naapp.console import ConsoleRoute
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from aweb_secrets.console_changes import ConsoleChanges, _errors
from aweb_secrets.console_forms.kinds import CONSOLE_KINDS, KIND_NAMES, kind_parameter_controls
from aweb_secrets.console_ui import _login_redirect, console_page
from aweb_secrets.console_values import native_value_refusals
from aweb_secrets.operation import CAPTURE_FIELDS
from aweb_secrets.secret import SecretBackend, SecretKind, SecretSensitivity, mint_secret_id

_SCRIPT = Path(__file__).with_name("native.js")


class NativeValueField(StrEnum):
    VALUE = "value"
    USERNAME = "username"
    PASSWORD = "password"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    ACCESS_KEY_ID = "access_key_id"
    SECRET_ACCESS_KEY = "secret_access_key"
    SESSION_TOKEN = "session_token"


_VALUE_LABELS = {
    NativeValueField.VALUE: "Value",
    NativeValueField.USERNAME: "Username (leave empty if the service uses only a password)",
    NativeValueField.PASSWORD: "Password",
    NativeValueField.CLIENT_ID: "Client ID",
    NativeValueField.CLIENT_SECRET: "Client secret",
    NativeValueField.ACCESS_KEY_ID: "Access key ID",
    NativeValueField.SECRET_ACCESS_KEY: "Secret access key",
    NativeValueField.SESSION_TOKEN: "Session token (optional)",
}


def _native_value_fields(kind: SecretKind) -> str:
    required, optional = CAPTURE_FIELDS[kind]
    fields = []
    for name in sorted(required | optional):
        field = NativeValueField(name)
        identity = f"native-{kind}-{field}"
        label = KIND_NAMES[kind] if kind is SecretKind.BEARER else _VALUE_LABELS[field]
        attributes = (
            ' data-optional=""'
            if name in optional
            else " required"
            if field is not NativeValueField.USERNAME
            else ""
        )
        fields.append(
            f'<label for="{identity}">{label}</label>'
            f'<input id="{identity}" type="password" data-value-field="{field}"'
            f' autocomplete="off" spellcheck="false"{attributes}>'
        )
    return "".join(fields)


def _native_kind_controls() -> str:
    fields = []
    for kind in CONSOLE_KINDS:
        inactive = " hidden disabled" if kind is not SecretKind.BEARER else ""
        fields.append(
            f'<fieldset data-kind="{kind}"{inactive}><legend>{KIND_NAMES[kind]}</legend>'
            + kind_parameter_controls(kind, prefix="native")
            + _native_value_fields(kind)
            + "</fieldset>"
        )
    return "".join(fields)


def native_value_form(*, installation_id: str) -> str:
    options = "".join(
        f'<option value="{kind}">{KIND_NAMES[kind]}</option>' for kind in CONSOLE_KINDS
    )
    installation = escape(installation_id, quote=True)
    return (
        "<h1>Store a secret in Secrets</h1>"
        "<p>The value is encrypted and kept by this Secrets service. "
        "Enter it once; it is never shown again. "
        "Agents cannot use it until you confirm the draft with your passkey and grant access.</p>"
        f'<form id="native-value" method="post" action="/installations/{installation}/native/versions" '
        f'data-installation="{installation}" data-backend="{SecretBackend.NATIVE}" '
        f'data-standard="{SecretSensitivity.STANDARD}" data-sensitive="{SecretSensitivity.SENSITIVE}">'
        f'<input type="hidden" name="secret_id" value="{mint_secret_id()}">'
        '<label for="native-name">Secret name</label>'
        '<input id="native-name" name="ref" pattern="[a-z0-9][a-z0-9_-]{0,63}" '
        'maxlength="64" autocomplete="off" required aria-describedby="native-name-hint" '
        'title="Lowercase letters, digits, - and _; up to 64 characters">'
        '<p id="native-name-hint">Lowercase letters, digits, - and _; up to 64 characters.</p>'
        '<label for="native-description">Description (optional)</label>'
        '<textarea id="native-description" name="description" maxlength="512" rows="2"></textarea>'
        '<label for="native-kind">Authentication kind</label>'
        f'<select id="native-kind" name="kind">{options}</select>'
        '<label for="native-sensitivity">Sensitivity</label>'
        '<select id="native-sensitivity" name="sensitivity">'
        f'<option value="{SecretSensitivity.STANDARD}">Standard</option>'
        f'<option value="{SecretSensitivity.SENSITIVE}">Sensitive</option></select>'
        '<label class="check"><input type="checkbox" name="approve_only">Require approval for every use</label>'
        + _native_kind_controls()
        + '<label for="native-reason">Reason for this change (optional)</label>'
        '<input id="native-reason" name="reason" autocomplete="off">'
        '<button type="submit">Save the value and draft</button></form>'
        '<p id="form-status" role="status" aria-live="polite"></p>'
        '<link rel="stylesheet" href="/console-forms/forms.css">'
        '<script src="/console-forms/native.js" defer></script>'
    )


def native_value_forms_router(*, changes: ConsoleChanges) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/secrets/native/new")
    async def entry(request: Request) -> Response:
        try:
            current = await changes.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with native_value_refusals(), _errors(changes.console, current):
            installation_id = await changes.installation_for_session(current)
            admitted = await changes._installation(current, installation_id)
            async with changes.console.db.transaction() as tx:
                await changes._owner(tx, current, admitted)
                await changes.console.fence.check(tx, admitted)
                changes._unexpired(current)
        return console_page(
            title="Store a secret in Secrets",
            session=current,
            body_html=native_value_form(installation_id=installation_id),
        )

    @router.get("/console-forms/native.js")
    async def script() -> Response:
        return Response(_SCRIPT.read_bytes(), media_type="application/javascript")

    return router
