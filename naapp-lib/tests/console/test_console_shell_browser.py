"""The shared console shell in Chromium, under its own CSP, with the virtual
WebAuthn authenticator, real B3 passkeys on the shared credential recorder,
real console sessions and PostgreSQL. Nothing in the browser is stubbed.

A designated holder opens its enrolment link, creates its passkey from the
shell's ceremony page, signs in, sees the app's home only in the tab that
holds its CSRF token, and signs out; at a phone's width and a desktop's."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import pytest
import uvicorn
from playwright.async_api import Browser, BrowserContext, Page, async_playwright, expect
from playwright.async_api import Error as PlaywrightError

from aweb_naapp.runtime.passkeys import RelyingParty
from tests.console.shell_support import CEREMONIES, CSRF_KEY, SIGN_IN, shell_app
from tests.runtime.credential_audit.support import (
    CONTACT,
    World,
    bind,
    designate,
)

VIEWPORTS = {"phone": (375, 812), "desktop": (1440, 900)}
AUTHENTICATOR = {
    "options": {
        "protocol": "ctap2",
        "transport": "internal",
        "hasResidentKey": True,
        "hasUserVerification": True,
        "isUserVerified": True,
        "automaticPresenceSimulation": True,
    }
}


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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    # The real verifier, for this test's browser origin, before anyone enrols.
    world.passkeys.rp = RelyingParty(origin=origin, name="Example")
    composed = await shell_app(world, human_origin=origin, agent_origin=f"http://127.0.0.1:{port}")
    server = uvicorn.Server(uvicorn.Config(composed.app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("the console server stopped before it started")
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


async def holder(context: BrowserContext) -> Page:
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    await cdp.send("WebAuthn.addVirtualAuthenticator", AUTHENTICATOR)
    return page


async def fits(page: Page) -> bool:
    return await page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")


@pytest.mark.parametrize("viewport", list(VIEWPORTS))
async def test_a_holder_enrols_from_its_link_signs_in_and_signs_out(
    world: World, browser: Browser, service: str, tmp_path: Path, viewport: str
):
    width, height = VIEWPORTS[viewport]
    scope = await bind(world)
    await designate(world, scope)
    token = world.inbox.enrolments[CONTACT][-1]
    async with await browser.new_context(viewport={"width": width, "height": height}) as context:
        page = await holder(context)
        await page.goto(service + "/enrolment#token=" + quote(token, safe=""))
        await expect(page.get_by_role("button", name=CEREMONIES.enrolment.action)).to_be_enabled()
        assert urlsplit(page.url).fragment == ""
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"enrolment-{viewport}.png")

        await page.get_by_role("button", name=CEREMONIES.enrolment.action).click()
        await expect(page.locator("#notice")).to_have_text(CEREMONIES.enrolment.done)
        assert await context.cookies() == []
        continue_link = page.get_by_role("link", name=CEREMONIES.continue_link)
        await expect(continue_link).to_be_visible()
        href = await continue_link.get_attribute("href")
        assert href is not None and parse_qs(urlsplit(href).query) == {"scope": [scope]}

        await continue_link.click()
        await page.get_by_role("button", name=SIGN_IN.button).click()
        await page.wait_for_url(service + "/")
        await expect(page.locator("#home")).to_be_visible()
        await expect(page.locator("#console-reauth-notice")).to_be_hidden()
        assert await page.evaluate("key => !!sessionStorage.getItem(key)", CSRF_KEY)
        assert await fits(page)
        await page.screenshot(path=tmp_path / f"home-{viewport}.png")

        # Another tab with the cookie but none of this tab's CSRF token is
        # offered a sign-in, never actions it could not take.
        async with await browser.new_context(viewport={"width": width, "height": height}) as fresh:
            await fresh.add_cookies(await context.cookies())
            other = await fresh.new_page()
            await other.goto(service + "/")
            await expect(other.get_by_role("link", name=SIGN_IN.reauth_link)).to_be_visible()
            await expect(other.locator("#home")).to_be_hidden()
            assert await fits(other)
            await other.screenshot(path=tmp_path / f"reauth-{viewport}.png")

        await page.get_by_role("button", name="Sign out of Example").click()
        await page.wait_for_url(service + "/login")
        assert await page.evaluate("key => sessionStorage.getItem(key)", CSRF_KEY) is None
        assert await context.cookies() == []


async def test_a_page_without_its_link_starts_no_ceremony(
    world: World, browser: Browser, service: str
):
    async with await browser.new_context() as context:
        page = await holder(context)
        requests: list[str] = []
        page.on("request", lambda request: requests.append(request.url))
        await page.goto(service + "/enrolment")
        await expect(page.locator("#notice")).to_have_text(CEREMONIES.missing_link)
        await expect(page.get_by_role("button", name=CEREMONIES.enrolment.action)).to_be_disabled()
    assert not [url for url in requests if url.endswith("/enrolment/options")]


async def test_a_spent_link_shows_the_apps_failure_and_can_be_retried(
    world: World, browser: Browser, service: str
):
    scope = await bind(world)
    await designate(world, scope)
    async with await browser.new_context() as context:
        page = await holder(context)
        await page.goto(service + "/enrolment#token=not-a-delivered-token")
        await page.get_by_role("button", name=CEREMONIES.enrolment.action).click()
        await expect(page.locator("#notice")).to_have_text(CEREMONIES.failed)
        await expect(page.get_by_role("button", name=CEREMONIES.enrolment.action)).to_be_enabled()
