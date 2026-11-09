"""The reader's viewer in a real browser at phone and desktop widths: a
designated reader enrols its passkey from its mailed link with a virtual
authenticator, signs in, and reads, filters, follows and checks its team's
log on the console origin logs composes."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from datetime import timedelta
from urllib.parse import urlencode

import pytest
import uvicorn
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
)
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from fastapi import FastAPI
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Route,
    async_playwright,
    expect,
)
from playwright.async_api import Error as PlaywrightError

from aweb_logs.reader_service import ReaderService

from .reader_world import CONTACT, World, designated_reader, world_fixture  # noqa: F401
from .test_reader_viewer import recorded


@pytest.fixture
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as playwright:
        try:
            running = await playwright.chromium.launch()
        except PlaywrightError as error:
            if "Executable doesn't exist" not in str(error):
                raise
            pytest.fail("Install the locked Chromium with uv run playwright install chromium")
        try:
            yield running
        finally:
            await running.close()


@pytest.fixture
async def service(world: World) -> AsyncIterator[str]:
    """logs' console origin as :class:`ReaderService` composes it, served on
    an ephemeral local port the browser can reach."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    # The real verifier, for this ephemeral origin, before anyone enrols.
    world.passkeys.rp = RelyingParty(origin=origin, name="Logs")
    await apply_console_migrations(world.db)
    reader_service = ReaderService(
        db=world.db,
        directory=world.directory,
        fence=world.fence,
        designations=world.designations,
        passkeys=world.passkeys,
        recorder=world.recorder,
        sessions=ConsoleSessions(
            world.db, passkeys=world.passkeys, scopes=world.directory.is_current_reader
        ),
        limiter=LoginLimiter(
            world.db, client_identity=ClientIdentity(), limit=12, window=timedelta(minutes=1)
        ),
        chain_keys=frozenset({world.signer.did_key}),
    )
    human = FastAPI()
    human.include_router(reader_service.console_router)
    app = split_origins(
        FastAPI(), human, agent_origin=f"http://127.0.0.1:{port}", human_origin=origin
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


async def signed_in_page(world: World, context: BrowserContext, service: str) -> Page:
    """A tab of a designated reader that enrolled its passkey from its mailed
    link and signed in with it."""
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    await cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    scope, _ = await designated_reader(world)
    await page.goto(service + "/login?" + urlencode({"scope": scope}))
    status = await page.evaluate(
        """async link_token => {
      const response = await fetch('/enrolment/options', {method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({link_token})});
      const credential = await navigator.credentials.create({publicKey:
        PublicKeyCredential.parseCreationOptionsFromJSON(await response.json())});
      return (await fetch('/enrolment', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({link_token, credential:credential.toJSON()})})).status;
    }""",
        world.inbox.enrolments[CONTACT][-1],
    )
    assert status == 200
    await page.locator("#login button[type=submit]").click()
    await page.wait_for_url(service + "/")
    return page


async def fits(page: Page) -> bool:
    return await page.evaluate("document.documentElement.scrollWidth <= innerWidth")


@pytest.mark.parametrize("width", [375, 1440])
async def test_a_reader_reads_filters_follows_and_checks_its_log_in_a_browser(
    world: World, browser: Browser, service: str, width: int, tmp_path
):
    async with await browser.new_context(viewport={"width": width, "height": 900}) as context:
        page = await signed_in_page(world, context, service)
        client = await recorded(world, "client")
        core = await recorded(world, "core")

        await page.locator('.home-links a[href="/events"]').click()
        await page.wait_for_url(service + "/events")
        reported = page.locator(f'article[data-event-id="{client}"]')
        await expect(reported).to_be_visible()
        await expect(reported.locator(".mediation[data-agent-reported]")).to_be_visible()
        await expect(page.locator(f'article[data-event-id="{core}"]')).to_be_visible()
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"events-{width}.png", full_page=True)

        await page.locator("#filters summary").click()
        await page.locator("#filter-mediation").select_option("client")
        await page.locator("#filters button[type=submit]").click()
        await page.wait_for_url(service + "/events?*mediation=client*")
        await expect(page.locator("article[data-event-id]")).to_have_count(1)
        await expect(reported).to_be_visible()
        assert await fits(page)

        await page.goto(service + "/follow")
        await expect(page.locator("#follow-status")).to_be_visible()
        followed = await recorded(world, "client")
        arrived = page.locator(f'#followed article[data-event-id="{followed}"]')
        await expect(arrived).to_be_visible(timeout=10_000)
        await expect(arrived.locator("[data-agent-reported]").first).to_be_visible()
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"follow-{width}.png", full_page=True)

        await page.goto(service + "/integrity")
        await expect(page.locator("section#chain[data-intact=true]")).to_be_visible()
        await expect(page.locator("section#observed")).to_be_visible()
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"integrity-{width}.png", full_page=True)
        await page.emulate_media(color_scheme="dark")
        await page.screenshot(path=tmp_path / f"integrity-{width}-dark.png", full_page=True)
        await page.goto(service + "/events")
        await page.screenshot(path=tmp_path / f"events-{width}-dark.png", full_page=True)
        await page.goto(service + "/")
        await page.screenshot(path=tmp_path / f"home-{width}-dark.png", full_page=True)
        await page.emulate_media(color_scheme="light")
        await page.screenshot(path=tmp_path / f"home-{width}.png", full_page=True)


async def test_the_follow_page_stops_and_offers_sign_in_when_the_session_ends(
    world: World, browser: Browser, service: str
):
    async with await browser.new_context() as context:
        page = await signed_in_page(world, context, service)
        await page.goto(service + "/follow")
        await context.clear_cookies()
        await expect(page.locator("#follow-ended")).to_be_visible(timeout=10_000)
        await expect(page.locator("#followed article")).to_have_count(0)


@pytest.fixture
async def cut_off() -> AsyncIterator[str]:
    """A local server that starts an HTML response and closes the connection
    before its body is complete: the network failing while a page is read."""

    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4096\r\n\r\n<ol"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}/follow/events"
    finally:
        server.close()
        await server.wait_closed()


async def test_follow_keeps_following_when_a_response_is_cut_off(
    world: World, browser: Browser, service: str, cut_off: str
):
    async with await browser.new_context() as context:
        page = await signed_in_page(world, context, service)
        polls: list[str] = []

        async def first_cut_off(route: Route) -> None:
            polls.append(route.request.url)
            if len(polls) == 1:
                await route.continue_(url=cut_off)
            else:
                await route.continue_()

        await page.route("**/follow/events*", first_cut_off)
        await page.goto(service + "/follow")
        followed = await recorded(world, "client")
        arrived = page.locator(f'#followed article[data-event-id="{followed}"]')
        await expect(arrived).to_be_visible(timeout=10_000)
        assert len(polls) >= 2
        await expect(page.locator("#follow-failed")).to_be_hidden()
        await expect(page.locator("#follow-ended")).to_be_hidden()


async def test_follow_stops_on_a_response_that_is_not_a_list_of_events(
    world: World, browser: Browser, service: str
):
    async with await browser.new_context() as context:
        page = await signed_in_page(world, context, service)

        async def malformed(route: Route) -> None:
            await route.fulfill(
                status=200,
                content_type="text/html",
                body='<ol class="events" data-after="MS45OQ"><li>event</li>'
                '<div id="injected">not an event</div></ol>',
            )

        await page.route("**/follow/events*", malformed)
        await page.goto(service + "/follow")
        await expect(page.locator("#follow-failed")).to_be_visible(timeout=10_000)
        await expect(page.locator("#followed > *")).to_have_count(0)
        await expect(page.locator("#injected")).to_have_count(0)
