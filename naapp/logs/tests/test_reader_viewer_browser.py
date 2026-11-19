"""The reader's viewer in a real browser at phone and desktop widths: a
designated reader enrols its passkey from its mailed link with a virtual
authenticator, signs in, and reads, filters, follows and checks its team's
log on the console origin logs composes."""

from __future__ import annotations

import asyncio
import base64
import socket
import ssl
from collections.abc import AsyncIterator
from urllib.parse import urlencode

import pytest
import uvicorn
from aweb_naapp.console import (
    apply_console_migrations,
)
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.network import Certificates, make_certificates
from cryptography.hazmat.primitives import serialization
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

from .reader_world import World, held_reader, world_fixture  # noqa: F401
from .test_reader_viewer import recorded, viewer_service


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
def console_tls(tmp_path) -> Certificates:
    """A private CA's certificate for the local HTTPS console."""
    return make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])


@pytest.fixture
async def service(world: World, console_tls: Certificates) -> AsyncIterator[str]:
    """logs' console origin as :class:`ReaderService` composes it, served over
    HTTPS on an ephemeral local port the browser can reach. An owner act's
    audience is an HTTPS origin, and the credential's relying party is that
    same origin."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        origin = f"https://localhost:{port}"
        # The real verifier, for this ephemeral origin, before anyone enrols.
        world.passkeys.rp = RelyingParty(origin=origin, name="Logs")
        await apply_console_migrations(world.db)
        reader_service = viewer_service(world)
        human = FastAPI()
        human.include_router(reader_service.console_router)
        app = split_origins(
            FastAPI(), human, agent_origin=f"http://127.0.0.1:{port}", human_origin=origin
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                log_level="warning",
                lifespan="off",
                ssl_certfile=str(console_tls.cert_file),
                ssl_keyfile=str(console_tls.key_file),
            )
        )
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


async def signed_in_page(world: World, context: BrowserContext, service: str) -> Page:
    """A tab of a reader the owner named, whose authenticator holds the
    credential the owner's act bound, signed in with it."""
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    authenticator = await cdp.send(
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
    scope, _ = await held_reader(world)
    (credential,) = world.devices[scope].credentials.values()
    await cdp.send(
        "WebAuthn.addCredential",
        {
            "authenticatorId": authenticator["authenticatorId"],
            "credential": {
                "credentialId": base64.b64encode(credential.credential_id).decode(),
                "isResidentCredential": True,
                "rpId": credential.rp_id,
                "privateKey": base64.b64encode(
                    credential.key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                ).decode(),
                "userHandle": base64.b64encode(credential.user_handle).decode(),
                "signCount": 0,
            },
        },
    )
    await page.goto(service + "/login?" + urlencode({"scope": scope}))
    await page.locator("#login button[type=submit]").click()
    await page.wait_for_url(service + "/")
    return page


async def fits(page: Page) -> bool:
    return await page.evaluate("document.documentElement.scrollWidth <= innerWidth")


@pytest.mark.parametrize("width", [375, 1440])
async def test_a_reader_reads_filters_follows_and_checks_its_log_in_a_browser(
    world: World, browser: Browser, service: str, width: int, tmp_path
):
    async with await browser.new_context(
        viewport={"width": width, "height": 900}, ignore_https_errors=True
    ) as context:
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

        await page.goto(service + "/events?" + urlencode({"occurred_from": "yesterday"}))
        await expect(page.locator("#filter-occurred_from")).to_be_focused()
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"refused-{width}.png", full_page=True)

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
    async with await browser.new_context(ignore_https_errors=True) as context:
        page = await signed_in_page(world, context, service)
        await page.goto(service + "/follow")
        await context.clear_cookies()
        await expect(page.locator("#follow-ended")).to_be_visible(timeout=10_000)
        await expect(page.locator("#followed article")).to_have_count(0)


@pytest.fixture
async def cut_off(console_tls: Certificates) -> AsyncIterator[str]:
    """A local HTTPS server that starts an HTML response and closes the
    connection before its body is complete: the network failing while a page
    is read."""

    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4096\r\n\r\n<ol"
        )
        await writer.drain()
        writer.close()

    tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    tls.load_cert_chain(console_tls.cert_file, console_tls.key_file)
    server = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=tls)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"https://127.0.0.1:{port}/follow/events"
    finally:
        server.close()
        await server.wait_closed()


async def test_follow_keeps_following_when_a_response_is_cut_off(
    world: World, browser: Browser, service: str, cut_off: str
):
    async with await browser.new_context(ignore_https_errors=True) as context:
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
    async with await browser.new_context(ignore_https_errors=True) as context:
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


async def test_follow_shows_it_is_retrying_while_the_server_cannot_be_reached(
    world: World, browser: Browser, service: str
):
    async with await browser.new_context(ignore_https_errors=True) as context:
        page = await signed_in_page(world, context, service)
        unreachable = {"remaining": 2}

        async def first_unreachable(route: Route) -> None:
            if unreachable["remaining"] > 0:
                unreachable["remaining"] -= 1
                await route.abort("connectionrefused")
            else:
                await route.continue_()

        await page.route("**/follow/events*", first_unreachable)
        await page.goto(service + "/follow")
        follow = page.locator("#follow")
        await expect(follow).to_have_attribute("data-state", "retrying", timeout=10_000)
        followed = await recorded(world, "client")
        await expect(page.locator(f'#followed article[data-event-id="{followed}"]')).to_have_count(
            1, timeout=10_000
        )
        await expect(follow).to_have_attribute("data-state", "live")
        await expect(page.locator("#follow-failed")).to_be_hidden()
        await page.wait_for_timeout(2_500)
        await expect(page.locator(f'#followed article[data-event-id="{followed}"]')).to_have_count(
            1
        )


# The contrast of what `element` shows against what is behind it, as the page
# renders it in either scheme: colours are resolved through a canvas, so any
# CSS colour syntax measures the same.
_CONTRAST = """([selector, property, against]) => {
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 1;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  const rgba = (colour) => {
    context.clearRect(0, 0, 1, 1);
    context.fillStyle = colour;
    context.fillRect(0, 0, 1, 1);
    return Array.from(context.getImageData(0, 0, 1, 1).data);
  };
  const behind = (element) => {
    for (let at = element; at; at = at.parentElement) {
      const colour = rgba(getComputedStyle(at).backgroundColor);
      if (colour[3] === 255) return colour;
    }
    return rgba(getComputedStyle(document.documentElement).backgroundColor);
  };
  const luminance = ([r, g, b]) => {
    const linear = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
  };
  const element = document.querySelector(selector);
  const shown = rgba(getComputedStyle(element)[property]);
  const back = against === "self" ? rgba(getComputedStyle(element).backgroundColor)
    : behind(element.parentElement);
  const [light, dark] = [luminance(shown), luminance(back)].sort((a, b) => b - a);
  return (light + 0.05) / (dark + 0.05);
}"""


@pytest.mark.parametrize("scheme", ["light", "dark"])
async def test_the_viewer_s_controls_and_verdicts_have_readable_contrast(
    world: World, browser: Browser, service: str, scheme: str
):
    async with await browser.new_context(color_scheme=scheme, ignore_https_errors=True) as context:  # type: ignore[arg-type]
        page = await signed_in_page(world, context, service)
        await page.goto(service + "/events")
        await page.locator("#filters summary").click()
        for control in ("#filter-event_type", "#filter-mediation"):
            for against in ("behind", "self"):
                ratio = await page.evaluate(_CONTRAST, [control, "borderTopColor", against])
                assert ratio >= 3, (control, against, ratio)
        await page.goto(service + "/events?occurred_from=yesterday")
        assert await page.evaluate(_CONTRAST, [".field-error", "color", "behind"]) >= 4.5
        for against in ("behind", "self"):
            ratio = await page.evaluate(
                _CONTRAST, ["#filter-occurred_from", "borderTopColor", against]
            )
            assert ratio >= 3, (against, ratio)
        await page.goto(service + "/integrity")
        assert await page.evaluate(_CONTRAST, [".verdict", "color", "behind"]) >= 4.5
