"""Production login JS, real S4/B3/PG and Chromium's WebAuthn authenticator."""

import asyncio
import base64
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import uvicorn
from aweb_naapp.runtime.passkeys import RelyingParty, contact_sha256
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import Browser, async_playwright, expect
from playwright.async_api import Error as PlaywrightError

from aweb_secrets.owners import owner_scope
from tests.test_change_sets import ALICE, TEAM, World
from tests.test_change_sets import world as _world
from tests.test_console_ui import application

world = _world
CSRF_KEY = "aweb.secrets.console.csrf"


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
    # Configure this fixture's real verifier for its ephemeral browser origin,
    # before designating or enrolling anyone. No WebAuthn method is replaced.
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    app = await application(world, human_origin=origin, agent_origin=f"http://127.0.0.1:{port}")
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("Console server stopped before startup")
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


@pytest.mark.parametrize("user_verified", [True, False])
async def test_browser_login_and_bodiless_csrf_logout(
    world: World, browser: Browser, service: str, tmp_path: Path, user_verified: bool
):
    async with await browser.new_context() as context:
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")
        result = await cdp.send(
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
        scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
        contact = "alice@acme.com"
        subject = {
            "app_id": world.admitted.app_id,
            "installation_id": INSTALLATION_ID,
            "role": scope,
            "contact_sha256": contact_sha256(contact),
        }
        signing, signature = world.owner.sign("app-role.designate", subject)
        response = await context.request.post(
            service + f"/installations/{INSTALLATION_ID}/owner-acts",
            data={
                "signing": base64.b64encode(signing).decode(),
                "signature": signature,
                "team_id": TEAM,
                "principal": ALICE.principal_did,
                "contact": contact,
            },
        )
        assert response.status == 200
        await page.goto(service + "/login?" + urlencode({"scope": scope}))
        # Only registration is test-driven here. The sign-in/logout actions
        # below click the production UI and run its actual script under CSP.
        status = await page.evaluate(
            """async token => {
              const options = await fetch('/enrolment/options', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({link_token: token})
              });
              if (!options.ok) return options.status;
              const credential = await navigator.credentials.create({
                publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(await options.json())
              });
              return (await fetch('/enrolment', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({link_token: token, credential: credential.toJSON()})
              })).status;
            }""",
            world.inbox.enrolments[contact][-1],
        )
        assert status == 200
        await cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": result["authenticatorId"], "isUserVerified": user_verified},
        )
        await page.get_by_role("button", name="Sign in with a passkey").click()
        if not user_verified:
            await expect(page.get_by_role("button", name="Sign in with a passkey")).to_be_enabled()
            assert await context.cookies() == []
            assert await page.evaluate("key => sessionStorage.getItem(key)", CSRF_KEY) is None
            assert (await context.request.get(service + "/session")).status == 401
            return
        await page.wait_for_url(service + "/")
        assert (await context.request.get(service + "/session")).status == 200
        assert await page.evaluate("key => !!sessionStorage.getItem(key)", CSRF_KEY)
        assert await page.evaluate("localStorage.length") == 0
        [cookie] = await context.cookies()
        assert (cookie["httpOnly"], cookie["secure"], cookie["sameSite"]) == (True, True, "Strict")
        assert (await context.request.post(service + "/logout")).status == 403
        assert (await context.request.get(service + "/session")).status == 200
        assert (
            await page.get_by_role("link", name="View activity").get_attribute("href")
            == "/activity"
        )
        # A new browser context can have the session cookie but no tab CSRF.
        # It must offer re-authentication rather than unusable mutation actions.
        async with await browser.new_context() as fresh:
            await fresh.add_cookies(await context.cookies())
            other = await fresh.new_page()
            await other.goto(service + "/")
            assert (await fresh.request.get(service + "/session")).status == 200
            await expect(other.locator("#console-reauth")).to_be_visible(timeout=2000)
            await expect(other.locator("[data-console-scope]")).to_be_hidden()
            href = await other.locator("#console-reauth").get_attribute("href")
            assert href is not None
            assert parse_qs(urlsplit(href).query) == {"scope": [scope]}
            await other.screenshot(path=tmp_path / "console-fresh-tab.png")
        await page.screenshot(path=tmp_path / "console-home.png")
        await page.get_by_role("button", name="Sign out").click()
        await page.wait_for_url(service + "/login")
        assert (await context.request.get(service + "/session")).status == 401
        assert await page.evaluate("key => sessionStorage.getItem(key)", CSRF_KEY) is None
        assert await context.cookies() == []
