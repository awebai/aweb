"""The DB-write agent is obvious at mobile and desktop sizes, and revoking it needs no passkey."""

import asyncio
import socket

import pytest
import uvicorn
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.approvals import Approvals, PgApprovalStore
from aweb_naapp.runtime.passkeys import RelyingParty
from playwright.async_api import expect

from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from tests.test_change_sets import Installations
from tests.test_change_sets import world as _world
from tests.test_console_access import (
    DB_AGENT,
    DB_WRITE,
    INSERT,
    OPEN_AGENT,
    ORDERS_DB,
    READ,
    READER,
    READERS,
    READING,
    admission,
    application,
    seed,
)
from tests.test_console_forms import enrolled_page
from tests.test_console_ui_browser import browser as _browser
from tests.test_use_approvals import Clock, Uses

world = _world
browser = _browser


def apart(a, b, gap=4):
    """Two controls neither overlap nor touch, side by side or stacked."""
    return (
        a["x"] + a["width"] + gap <= b["x"]
        or b["x"] + b["width"] + gap <= a["x"]
        or a["y"] + a["height"] + gap <= b["y"]
        or b["y"] + b["height"] + gap <= a["y"]
    )


@pytest.fixture
async def service(world):
    await apply_idempotency_migrations(world.db)
    await apply_ratelimit_migrations(world.db)
    clock = Clock()
    approvals = Approvals(
        store=PgApprovalStore(world.db),
        policies=UsePolicies(world.db),
        approvers=UseApprovers(world.db, world.passkeys, world.directory),
        delivery=world.inbox,
        authenticators=[world.passkeys.authenticator()],
        audit=world.approvals._audit,
        clock=clock,
    )
    context = Uses(world, approvals, clock, Installations().grant)
    await seed(world)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    app = await application(context, origin=origin, agent_origin=f"http://127.0.0.1:{port}")
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield context, origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


@pytest.mark.parametrize("width", [375, 1440])
async def test_the_db_write_agent_is_flagged_first_and_revoked_without_a_passkey(
    world, browser, service, tmp_path, width
):
    uses, origin = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, cdp, authenticator = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")
        first = page.locator(".access-agent").first
        await expect(first).to_have_attribute("data-principal-did", DB_AGENT.did_aw)
        await expect(first.locator(".access-flags .flag-write")).to_be_visible()
        await expect(first.locator(".access-flags .flag-sensitive")).to_be_visible()
        write = first.locator(f'.access-use[data-operation-id="{INSERT.operation_id}"]')
        await expect(write.locator(".flag-write")).to_be_visible()
        await expect(first).to_contain_text("db-agent")
        await expect(first).to_contain_text(DB_AGENT.did_aw)
        role_grant = first.locator(f'.access-grant[data-grant-id="{READING.grant_id}"]')
        await expect(role_grant).to_contain_text("secrets.role.readers")
        opened = page.locator(f'.access-agent[data-principal-did="{OPEN_AGENT.did_aw}"]')
        await expect(opened.locator(".access-flags .flag-write")).to_be_visible()
        await expect(opened.locator(".access-use .flag-write")).to_be_visible()
        await page.screenshot(path=tmp_path / f"access-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")

        # Narrowing uses only the session and CSRF: remove the authenticator first.
        await cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
        page.once("dialog", lambda dialog: asyncio.ensure_future(dialog.accept()))
        await first.locator(
            f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] .access-revoke'
        ).click()
        await expect(
            page.locator(f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"]')
        ).to_have_count(0)
        await expect(
            page.locator(f'[data-principal-did="{DB_AGENT.did_aw}"] .access-flags .flag-write')
        ).to_have_count(0)
        await page.screenshot(path=tmp_path / f"access-{width}-revoked.png", full_page=True)
    assert await admission(uses, DB_AGENT, ORDERS_DB, INSERT.operation_id, 1) == (
        "operation_not_allowed"
    )
    assert await admission(uses, DB_AGENT, ORDERS_DB, READ.operation_id, 2) is None


@pytest.mark.parametrize("width", [375, 1440])
async def test_one_agent_is_removed_from_its_role_without_a_passkey(
    world, browser, service, tmp_path, width
):
    uses, origin = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, cdp, authenticator = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")
        reader = page.locator(f'.access-agent[data-principal-did="{READER.did_aw}"]')
        remove = reader.locator(f'.access-remove-member[data-role="{READERS}"]')
        await expect(remove).to_be_visible()
        revoke = reader.locator(f'.access-grant[data-grant-id="{READING.grant_id}"] .access-revoke')
        assert apart(await revoke.bounding_box(), await remove.bounding_box())
        await page.screenshot(path=tmp_path / f"access-role-{width}.png", full_page=True)
        await cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
        page.once("dialog", lambda dialog: asyncio.ensure_future(dialog.accept()))
        await remove.click()
        await expect(reader).to_have_count(0)
        survivor = page.locator(
            f'.access-grant[data-principal-did="{DB_AGENT.did_aw}"][data-grant-id="{READING.grant_id}"]'
        )
        await expect(survivor).to_be_visible()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert await admission(uses, READER, ORDERS_DB, READ.operation_id, 1) == "grant_missing"
    assert await admission(uses, DB_AGENT, ORDERS_DB, READ.operation_id, 2) is None
