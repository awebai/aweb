"""Anonymous fragment locators for the existing B3 POST ceremonies.

Mount on the human origin alongside owner_console_router. These pages create
no console session; completion authority remains in the service's ceremony.
"""

from importlib.resources import files

from aweb_naapp.console import ConsoleRoute
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response


def _page(*, ceremony: str, title: str, explanation: str, action: str) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title} · Secrets</title>"
        '<link rel="stylesheet" href="/console-bootstrap/style.css">'
        '<script src="/console-bootstrap/bootstrap.js" defer></script></head>'
        f'<body data-ceremony="{ceremony}"><header><a href="/">Secrets</a></header>'
        f"<main><h1>{title}</h1><p>{explanation}</p>"
        f'<button id="complete" type="button" disabled>{action}</button>'
        '<p id="notice" role="status" aria-live="polite"></p>'
        '<p><a id="continue" hidden>Continue to sign in</a></p></main></body></html>'
    )


def console_bootstrap_router() -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/enrolment", response_class=HTMLResponse)
    async def enrolment() -> HTMLResponse:
        return _page(
            ceremony="enrolment",
            title="Set up your passkey",
            explanation="Use the link from your email to create your passkey for Secrets.",
            action="Set up passkey",
        )

    @router.get("/contact-proof", response_class=HTMLResponse)
    async def contact_proof() -> HTMLResponse:
        return _page(
            ceremony="contact-proof",
            title="Confirm your email address",
            explanation="Confirm that you can receive email here. The waiting period still applies.",
            action="Confirm email address",
        )

    @router.get("/console-bootstrap/bootstrap.js")
    async def script() -> Response:
        return Response(
            files(__package__).joinpath("bootstrap.js").read_text(encoding="utf-8"),
            media_type="text/javascript",
        )

    @router.get("/console-bootstrap/style.css")
    async def style() -> Response:
        return Response(
            files("aweb_secrets.console_ui").joinpath("style.css").read_text(encoding="utf-8"),
            media_type="text/css",
        )

    return router
