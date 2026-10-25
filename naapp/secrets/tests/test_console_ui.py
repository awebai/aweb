"""The browser shell mounts with real S4/B3 sessions and PostgreSQL."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from html.parser import HTMLParser
from urllib.parse import urlencode

import httpx
from aweb_naapp.console import CONSOLE_HEADERS, apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.origins import split_origins
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import ALICE, ORIGIN, World, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API, login

world = _world


class Elements(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


@asynccontextmanager
async def pages(world: World) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    app = await application(world)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as browser,
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=API) as agent,
    ):
        yield browser, agent


async def application(world: World, *, human_origin: str = ORIGIN, agent_origin: str = API):
    await apply_console_migrations(world.db)

    async def installation(installation_id: str, *, team_id: str | None = None):
        assert installation_id == world.admitted.installation_id
        return world.admitted

    services = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        directory=world.directory,
        fence=world.fence,
        verifier=world.owner.verifier,
        installation=installation,
    )
    human = FastAPI()
    human.include_router(owner_console_router(services))
    human.include_router(console_ui_router(sessions=services.sessions))
    return split_origins(FastAPI(), human, agent_origin=agent_origin, human_origin=human_origin)


def safe(response: httpx.Response) -> None:
    for header, value in CONSOLE_HEADERS.items():
        assert response.headers[header] == value


async def test_home_requires_a_current_passkey_session_and_links_to_owner_pages(world: World):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with pages(world) as (browser, _):
        refused = await browser.get("/")
        assert refused.status_code == 303
        assert refused.headers["location"] == "/login"
        safe(refused)
        signed_in = await login(world, browser, scope)
        assert signed_in.status_code == 200
        home = await browser.get("/")
        assert home.status_code == 200
        safe(home)
        links = {attrs.get("href") for tag, attrs in Elements(home.text).tags if tag == "a"}
        assert {"/secrets/new", "/grants/new", "/approvals", "/activity"} <= links
        assert (await browser.get("/login")).headers["location"] == "/"
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        assert (await browser.get("/")).status_code == 303


async def test_login_requires_a_setup_locator_and_escapes_it_as_data(world: World):
    async with pages(world) as (browser, _):
        missing = await browser.get("/login")
        assert missing.status_code == 200
        safe(missing)
        assert not any(tag == "form" for tag, _ in Elements(missing.text).tags)
        locator = '"><script src="https://untrusted.invalid/x.js"></script>'
        response = await browser.get("/login?" + urlencode({"scope": locator}))
        assert response.status_code == 200
        safe(response)
        tags = Elements(response.text).tags
        assert [attrs["data-scope"] for tag, attrs in tags if tag == "form"] == [locator]
        assert all(attrs.get("src", "").startswith("/") for tag, attrs in tags if tag == "script")


async def test_shell_assets_stay_on_the_human_origin_and_refuse_team_auth(world: World):
    async with pages(world) as (browser, agent):
        page = await browser.get("/login?scope=locator")
        assets = [
            attrs.get("src") if tag == "script" else attrs.get("href")
            for tag, attrs in Elements(page.text).tags
            if tag in {"script", "link"}
        ]
        assert assets
        for path in ["/", "/login", *assets]:
            assert path is not None
            assert (await agent.get(path)).status_code == 404
            response = await browser.get(path)
            safe(response)
            denied = await browser.get(path, headers={"X-AWEB-Signature": "invalid"})
            assert denied.status_code == 403
        assert (await browser.get("/login", params={"scope": "locator"})).status_code == 200
