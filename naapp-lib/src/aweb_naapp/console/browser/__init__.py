"""The human origin's browser shell, shared by every app with a console.

The shell renders pages and serves the login and ceremony scripts; S4
sessions and B3's ceremonies keep all authority. Everything a person reads is
the app's: its name, its copy and its stylesheet arrive as trusted inputs in
a :class:`ConsoleBrand` and a :class:`CeremonyCopy`, and the shell escapes
each value it inserts. Mount the routers on the human app only, beside
``console_login_router`` and ``credential_router``.

The scripts read their configuration from the page's ``body``: the tab's
CSRF storage key and the copy they show. ``console.js`` exports
``window.awebConsole = {post, assertion, csrfKey}`` for an app's own forms.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from importlib.resources import files
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from aweb_naapp.console import ConsoleRoute, ConsoleSession, ConsoleSessions

_ASSETS = files(__package__)


@dataclass(frozen=True)
class SignInCopy:
    """What the shell's login, re-authentication and sign-out say."""

    title: str
    heading: str
    scoped_hint: str
    unscoped_hint: str
    button: str
    waiting: str
    failed: str
    sign_out_failed: str
    reauth_heading: str
    reauth_text: str
    reauth_link: str


@dataclass(frozen=True)
class Ceremony:
    """One link ceremony's page: its title, explanation, button and outcome."""

    title: str
    explanation: str
    action: str
    done: str


@dataclass(frozen=True)
class CeremonyCopy:
    """What the enrolment and contact-proof pages say."""

    enrolment: Ceremony
    contact_proof: Ceremony
    missing_link: str
    completing: str
    failed: str
    continue_link: str


@dataclass(frozen=True)
class ConsoleBrand:
    """An app's console: its name, its tab CSRF storage key, its stylesheet
    and its sign-in copy, all trusted app inputs."""

    product: str
    csrf_key: str
    stylesheet: str
    sign_in: SignInCopy


def login_redirect(error: HTTPException) -> RedirectResponse:
    """A 401 from S4 as a redirect to ``/login`` that keeps S4's clearing
    cookie; any other refusal is raised again."""
    if error.status_code != 401:
        raise error
    return RedirectResponse("/login", status_code=303, headers=error.headers)


def _attributes(values: dict[str, str]) -> str:
    return "".join(f' {name}="{escape(value, quote=True)}"' for name, value in values.items())


class ConsoleShell:
    """The pages and routes of one app's console, in that app's brand."""

    def __init__(self, brand: ConsoleBrand) -> None:
        self.brand = brand

    def _document(
        self, title: str, body_html: str, *, assets: str, script: str, data: dict[str, str]
    ) -> HTMLResponse:
        copy = self.brand.sign_in
        body = _attributes(
            {
                **data,
                "data-console-csrf-key": self.brand.csrf_key,
                "data-copy-waiting": copy.waiting,
                "data-copy-failed": copy.failed,
                "data-copy-sign-out-failed": copy.sign_out_failed,
            }
        )
        product = escape(self.brand.product)
        return HTMLResponse(
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{escape(title)} · {product}</title>"
            f'<link rel="stylesheet" href="/{assets}/style.css">'
            f'<script src="/{assets}/{script}" defer></script></head>'
            f'<body{body}><header><a href="/">{product}</a></header><main>'
            f"{body_html}</main></body></html>"
        )

    def page(self, title: str, body_html: str) -> HTMLResponse:
        """A page without a session. ``body_html`` is trusted, developer-authored
        HTML; escape every value inserted into it."""
        return self._document(title, body_html, assets="console-ui", script="console.js", data={})

    def console_page(self, *, title: str, body_html: str, session: ConsoleSession) -> HTMLResponse:
        """A session's page, its content hidden until this tab holds a CSRF token.

        ``body_html`` is trusted, developer-authored HTML, never a submitted
        value. Pass the session from S4's ``current`` and serve through
        ``ConsoleRoute``. A tab with only the cookie gets the scoped passkey
        sign-in instead of actions it could not take.
        """
        copy = self.brand.sign_in
        scope = escape(session.scope, quote=True)
        href = "/login?scope=" + quote(session.scope, safe="")
        return self.page(
            title,
            f'<section data-console-scope="{scope}" hidden>{body_html}</section>'
            f'<section id="console-reauth-notice"><h1>{escape(copy.reauth_heading)}</h1>'
            f"<p>{escape(copy.reauth_text)}</p>"
            f'<a id="console-reauth" href="{escape(href, quote=True)}">'
            f"{escape(copy.reauth_link)}</a></section>",
        )

    def recovery_page(
        self, error: HTTPException, *, message: str, action_href: str, action_label: str
    ) -> HTMLResponse:
        """A browser GET refusal as a page: its own status and headers, one sentence, one way on.

        message, action_href and action_label are fixed by the caller, never request values.
        The page sits outside console_page's per-tab guard, so it shows without a CSRF token,
        and it shows nothing the refused read would have shown. Serve through ConsoleRoute.
        A 401 goes to login_redirect instead.
        """
        response = self.page(
            message,
            f'<section id="console-recovery"><h1>{escape(message)}</h1>'
            f'<p><a id="console-recovery-action" href="{escape(action_href, quote=True)}">'
            f"{escape(action_label)}</a></p></section>",
        )
        response.status_code = error.status_code
        response.headers.update(error.headers or {})
        return response

    def router(self, *, sessions: ConsoleSessions, home_title: str, home_html: str) -> APIRouter:
        """``GET /`` (the session's home), ``GET /login`` and the shell's assets.

        Login uses the existing ``/login/options`` and ``/login`` ceremonies.
        The CSRF token lives only in the tab's sessionStorage under the
        brand's key; credentials and form values are never stored.
        """
        router = APIRouter(route_class=ConsoleRoute)
        copy = self.brand.sign_in

        @router.get("/", response_class=HTMLResponse)
        async def home(request: Request) -> Response:
            try:
                session = await sessions.current(request)
            except HTTPException as error:
                return login_redirect(error)
            return self.console_page(title=home_title, body_html=home_html, session=session)

        @router.get("/login", response_class=HTMLResponse)
        async def login(request: Request, scope: str = "") -> Response:
            if scope:
                return self.page(
                    copy.title,
                    f"<h1>{escape(copy.heading)}</h1><p>{escape(copy.scoped_hint)}</p>"
                    f'<form id="login" data-scope="{escape(scope, quote=True)}">'
                    f'<button type="submit">{escape(copy.button)}</button></form>'
                    '<p id="notice" role="status" aria-live="polite"></p>',
                )
            try:
                await sessions.current(request)
            except HTTPException as error:
                if error.status_code != 401:
                    raise
                response = self.page(
                    copy.title,
                    f"<h1>{escape(copy.heading)}</h1><p>{escape(copy.unscoped_hint)}</p>",
                )
                # Keep refusal headers, including the clearing session cookie.
                response.headers.update(error.headers or {})
                return response
            return RedirectResponse("/", status_code=303)

        @router.get("/console-ui/console.js")
        async def script() -> Response:
            return Response(_asset("console.js"), media_type="text/javascript")

        @router.get("/console-ui/style.css")
        async def style() -> Response:
            return Response(self.brand.stylesheet, media_type="text/css")

        return router

    def bootstrap_router(self, copy: CeremonyCopy) -> APIRouter:
        """``GET /enrolment`` and ``GET /contact-proof``: anonymous pages that
        take the one-use token from the link's fragment and complete B3's
        existing POST ceremony. They create no console session."""
        router = APIRouter(route_class=ConsoleRoute)

        def ceremony_page(name: str, ceremony: Ceremony) -> HTMLResponse:
            return self._document(
                ceremony.title,
                f"<h1>{escape(ceremony.title)}</h1><p>{escape(ceremony.explanation)}</p>"
                f'<button id="complete" type="button" disabled>{escape(ceremony.action)}</button>'
                '<p id="notice" role="status" aria-live="polite"></p>'
                f"<p><a id=\"continue\" hidden>{escape(copy.continue_link)}</a></p>",
                assets="console-bootstrap",
                script="bootstrap.js",
                data={
                    "data-ceremony": name,
                    "data-copy-done": ceremony.done,
                    "data-copy-missing-link": copy.missing_link,
                    "data-copy-completing": copy.completing,
                    "data-copy-ceremony-failed": copy.failed,
                },
            )

        @router.get("/enrolment", response_class=HTMLResponse)
        async def enrolment() -> HTMLResponse:
            return ceremony_page("enrolment", copy.enrolment)

        @router.get("/contact-proof", response_class=HTMLResponse)
        async def contact_proof() -> HTMLResponse:
            return ceremony_page("contact-proof", copy.contact_proof)

        @router.get("/console-bootstrap/bootstrap.js")
        async def script() -> Response:
            return Response(_asset("bootstrap.js"), media_type="text/javascript")

        @router.get("/console-bootstrap/style.css")
        async def style() -> Response:
            return Response(self.brand.stylesheet, media_type="text/css")

        return router


def _asset(name: str) -> str:
    return _ASSETS.joinpath(name).read_text(encoding="utf-8")
