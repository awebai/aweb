"""Toolkit tokens reach real owner pages, including the create-secret controls."""

import asyncio
import socket
from datetime import UTC, datetime

import pytest
import uvicorn
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI
from playwright.async_api import expect

from aweb_secrets.activity_service import ActivityReads
from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_activity import ConsoleActivity, console_activity_router
from aweb_secrets.console_bootstrap import console_bootstrap_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_forms import console_forms_router
from aweb_secrets.console_jobs import console_jobs_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.jobs import apply_job_migrations
from aweb_secrets.runners import apply_runner_migrations
from aweb_secrets.use_context import apply_use_context_migrations
from tests.test_change_sets import world as _world
from tests.test_console_activity import recorded
from tests.test_console_changes import Registrations
from tests.test_console_forms import enrolled_page
from tests.test_console_reference_forms import connect_backend
from tests.test_console_ui_browser import browser as _browser

world = _world
browser = _browser


@pytest.fixture
async def token_service(world):
    # Compose the real routers/services used by these pages; no HTML or asset responses replaced.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    await apply_console_migrations(world.db)
    await apply_dispatch_migrations(world.db)
    await apply_use_context_migrations(world.db)

    async def installation(installation_id, *, team_id=None):
        assert installation_id == INSTALLATION_ID
        return world.admitted

    world.console = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        credential_audit=world.credential_audit,
        directory=world.directory,
        fence=world.fence,
        verifier=world.owner.verifier,
        installation=installation,
    )
    changes = ConsoleChanges(
        console=world.console,
        changes=world.change_sets,
        approvals=world.approvals,
        registrations=Registrations(),
        approval_kind=approval_kind,
        after_commit=world.containment.evict,
    )
    await apply_job_migrations(world.db)
    await apply_runner_migrations(world.db)
    human = FastAPI()
    human.include_router(owner_console_router(world.console))
    human.include_router(console_ui_router(sessions=world.console.sessions))
    human.include_router(console_changes_router(changes))
    human.include_router(console_forms_router(changes=changes))
    human.include_router(
        console_values_router(ConsoleValues(console=world.console, custody=world.custody))
    )
    human.include_router(console_bootstrap_router())
    human.include_router(console_jobs_router(changes=changes))
    human.include_router(
        console_activity_router(
            services=ConsoleActivity(console=world.console, reads=ActivityReads())
        )
    )
    app = split_origins(
        FastAPI(), human, human_origin=origin, agent_origin=f"http://127.0.0.1:{port}"
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    running = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if running.done():
                    await running
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(running, 10)
        sock.close()


async def prepared_owner(world, browser, origin):
    context = await browser.new_context()
    page, cdp, authenticator = await enrolled_page(world, context, origin)
    await connect_backend(world, page, origin)
    await recorded(world, datetime.now(UTC))
    return context, page, cdp, authenticator


@pytest.mark.parametrize("scheme", ["light", "dark"])
async def test_create_secret_uses_shared_type_color_and_focus_tokens(
    world, browser, token_service, scheme
):
    context, page, _, _ = await prepared_owner(world, browser, token_service)
    try:
        await page.emulate_media(color_scheme=scheme)
        await page.goto(token_service + "/secrets/new")
        await expect(page.locator("#onepassword-reference")).to_be_visible()
        await page.evaluate("document.fonts.ready")
        for width in (320, 390, 768, 1440):
            await page.set_viewport_size({"width": width, "height": 900})
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            metrics = await page.evaluate("""() => {
              const root = getComputedStyle(document.documentElement);
              const token = name => root.getPropertyValue(name).trim();
              const elements = [...document.querySelectorAll('main h1, #onepassword-reference label, #onepassword-reference input, #onepassword-reference select, #onepassword-reference textarea, #onepassword-reference button')].filter(e => e.getClientRects().length);
              const probe = document.createElement('span'); document.body.append(probe);
              const resolve = (property, value) => { probe.style[property] = value; return getComputedStyle(probe)[property]; };
              const result = {
                sans: token('--font-sans'), fonts: elements.map(e => getComputedStyle(e).fontFamily),
                bg: getComputedStyle(document.body).backgroundColor, expectedBg: resolve('backgroundColor', 'var(--bg)'),
                ink: getComputedStyle(document.body).color, expectedInk: resolve('color', 'var(--ink)'),
                input: getComputedStyle(document.querySelector('#reference-name')).backgroundColor,
                expectedInput: resolve('backgroundColor', 'var(--surface)'),
              };
              probe.remove(); return result;
            }""")
            assert metrics["sans"] and all(font == metrics["sans"] for font in metrics["fonts"])
            assert metrics["bg"] == metrics["expectedBg"]
            assert metrics["ink"] == metrics["expectedInk"]
            assert metrics["input"] == metrics["expectedInput"]
        # A runtime token change must propagate to controls, rather than a copied palette.
        await page.evaluate(
            "document.documentElement.style.setProperty('--accent', 'rgb(101, 31, 121)')"
        )
        await page.locator("#reference-name").focus()
        assert (
            await page.locator("#reference-name").evaluate("e => getComputedStyle(e).outlineColor")
            == "rgb(101, 31, 121)"
        )
    finally:
        await context.close()
