"""The shared console browser shell over HTTP, with real B3 passkeys, console
sessions and PostgreSQL: its pages carry only the app's copy and stylesheet,
escape everything they insert, and live on the human origin alone."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from aweb_naapp.console import CONSOLE_HEADERS, COOKIE_NAME, ConsoleRoute
from aweb_naapp.console.browser import ConsoleBrand, ConsoleShell, login_redirect
from tests.console.shell_support import BRAND, CEREMONIES, CSRF_KEY, SIGN_IN, STYLESHEET, shell_app
from tests.runtime.credential_audit.support import (
    World,
    bind,
    designate,
    enrol,
)

HUMAN = "https://console.example.test"
AGENT = "https://api.example.test"
PAGES = ("/", "/login", "/enrolment", "/contact-proof")
ASSETS = (
    "/console-ui/console.js",
    "/console-ui/style.css",
    "/console-bootstrap/bootstrap.js",
    "/console-bootstrap/style.css",
)


class Elements(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def first(self, tag: str, **attrs: str) -> dict[str, str | None]:
        return next(
            found
            for name, found in self.tags
            if name == tag and all(found.get(k) == v for k, v in attrs.items())
        )

    def body(self) -> dict[str, str | None]:
        return self.first("body")


def console_headed(response: httpx.Response) -> bool:
    return all(response.headers.get(name) == value for name, value in CONSOLE_HEADERS.items())


def refusals(shell: ConsoleShell) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/refused")
    async def refused() -> HTMLResponse:
        return shell.recovery_page(
            HTTPException(status_code=403, headers={"X-Refusal": "kept"}),
            message="That record is not yours",
            action_href="/",
            action_label="Back to the console",
        )

    return router


@asynccontextmanager
async def origins(world: World) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    composed = await shell_app(world, human_origin=HUMAN, agent_origin=AGENT)
    composed.human.include_router(refusals(composed.shell))
    app = composed.app
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=HUMAN) as browser,
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=AGENT) as agent,
    ):
        yield browser, agent


async def signed_in(world: World, browser: httpx.AsyncClient) -> str:
    scope = await bind(world)
    await designate(world, scope)
    device = await enrol(world)
    options = await browser.post("/login/options", json={"scope": scope})
    login = await browser.post(
        "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert login.status_code == 200
    return scope


async def test_every_page_carries_the_apps_stylesheet_csrf_key_and_copy(world: World):
    async with origins(world) as (browser, _):
        for path in ("/login", "/enrolment", "/contact-proof", "/refused"):
            response = await browser.get(path)
            page = Elements(response.text)
            assert console_headed(response), path
            # No page issues a session; at most it forwards S4's clearing cookie.
            for cookie in response.headers.get_list("set-cookie"):
                assert SimpleCookie(cookie)[COOKIE_NAME].value == "", path
            body = page.body()
            assert body["data-console-csrf-key"] == CSRF_KEY, path
            assert body["data-copy-waiting"] == SIGN_IN.waiting, path
            assert body["data-copy-failed"] == SIGN_IN.failed, path
            assert body["data-copy-sign-out-failed"] == SIGN_IN.sign_out_failed, path
            stylesheet = page.first("link", rel="stylesheet")["href"]
            assert (await browser.get(stylesheet)).text == STYLESHEET, path
            assert BRAND.product in "".join(page.text), path


async def test_both_stylesheets_are_the_apps_and_every_asset_is_human_origin_only(world: World):
    async with origins(world) as (browser, agent):
        for path in ("/console-ui/style.css", "/console-bootstrap/style.css"):
            response = await browser.get(path)
            assert response.headers["content-type"].startswith("text/css")
            assert response.text == STYLESHEET
        for path in ("/console-ui/console.js", "/console-bootstrap/bootstrap.js"):
            response = await browser.get(path)
            assert response.headers["content-type"].startswith("text/javascript")
            assert console_headed(response)
        for path in PAGES + ASSETS:
            assert (await agent.get(path)).status_code == 404, path


async def test_home_without_a_session_redirects_to_login_and_login_offers_the_unscoped_hint(
    world: World,
):
    async with origins(world) as (browser, _):
        home = await browser.get("/")
        assert (home.status_code, home.headers["location"]) == (303, "/login")
        login = Elements((await browser.get("/login")).text)
    assert SIGN_IN.unscoped_hint in login.text
    assert not [tag for tag, attrs in login.tags if attrs.get("id") == "login"]


async def test_a_scoped_login_link_is_a_locator_escaped_as_data(world: World):
    scope = 'example.reader."><script>alert(1)</script>'
    async with origins(world) as (browser, _):
        response = await browser.get("/login?" + urlencode({"scope": scope}))
    page = Elements(response.text)
    assert page.first("form", id="login")["data-scope"] == scope
    assert "<script>alert(1)" not in response.text
    assert SIGN_IN.scoped_hint in page.text
    assert SIGN_IN.button in page.text


async def test_a_session_gets_home_with_its_actions_hidden_behind_the_tab_guard(world: World):
    async with origins(world) as (browser, _):
        scope = await signed_in(world, browser)
        response = await browser.get("/")
        assert (await browser.get("/login")).status_code == 303
    page = Elements(response.text)
    guarded = page.first("section", **{"data-console-scope": scope})
    assert "hidden" in guarded
    assert page.first("h1", id="home") is not None
    reauth = page.first("a", id="console-reauth")
    assert reauth["href"] == "/login?" + urlencode({"scope": scope})
    assert SIGN_IN.reauth_heading in page.text
    assert SIGN_IN.reauth_link in page.text


async def test_the_bootstrap_pages_offer_each_ceremonys_copy_without_a_session(world: World):
    async with origins(world) as (browser, _):
        for path, ceremony in (
            ("/enrolment", CEREMONIES.enrolment),
            ("/contact-proof", CEREMONIES.contact_proof),
        ):
            response = await browser.get(path)
            page = Elements(response.text)
            body = page.body()
            assert body["data-ceremony"] == path.lstrip("/")
            assert body["data-copy-done"] == ceremony.done
            assert body["data-copy-missing-link"] == CEREMONIES.missing_link
            assert body["data-copy-completing"] == CEREMONIES.completing
            assert body["data-copy-ceremony-failed"] == CEREMONIES.failed
            assert ceremony.title in page.text and ceremony.action in page.text
            assert "disabled" in page.first("button", id="complete")
            assert CEREMONIES.continue_link in page.text


async def test_a_refusal_page_keeps_its_status_and_headers_outside_the_tab_guard(world: World):
    async with origins(world) as (browser, _):
        response = await browser.get("/refused")
    assert (response.status_code, response.headers["x-refusal"]) == (403, "kept")
    page = Elements(response.text)
    assert page.first("section", id="console-recovery") is not None
    assert page.first("a", id="console-recovery-action")["href"] == "/"
    assert not [tag for tag, attrs in page.tags if "data-console-scope" in attrs]


def test_login_redirect_keeps_the_clearing_cookie_and_reraises_other_refusals():
    cleared = login_redirect(
        HTTPException(status_code=401, headers={"Set-Cookie": "__Host-session=; Max-Age=0"})
    )
    assert (cleared.status_code, cleared.headers["location"]) == (303, "/login")
    assert cleared.headers["set-cookie"] == "__Host-session=; Max-Age=0"
    forbidden = HTTPException(status_code=403)
    try:
        login_redirect(forbidden)
    except HTTPException as raised:
        assert raised is forbidden
    else:
        raise AssertionError("a 403 is not a login redirect")


def test_the_brand_escapes_what_it_inserts():
    shell = ConsoleShell(
        ConsoleBrand(
            product='<b>"Example"</b>',
            csrf_key='key"><x',
            stylesheet=STYLESHEET,
            sign_in=SIGN_IN,
        )
    )
    html = shell.page("A <title>", "<p>trusted</p>").body.decode()
    assert "<b>" not in html and 'key"><x' not in html
    assert "<p>trusted</p>" in html
    assert Elements(html).body()["data-console-csrf-key"] == 'key"><x'
