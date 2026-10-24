"""Real Chromium passkeys review frozen uses through the shipped UI."""

import asyncio
import socket

import pytest
import uvicorn
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.approvals import Approvals, ApprovalState, PgApprovalStore
from aweb_naapp.runtime.passkeys import RelyingParty
from playwright.async_api import expect

from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from tests.test_change_sets import ALICE, Installations
from tests.test_change_sets import world as _world
from tests.test_console_forms import enrolled_page
from tests.test_console_ui_browser import browser as _browser
from tests.test_console_use_approvals import application
from tests.test_use_approvals import Clock, Uses, install, request

world = _world
browser = _browser


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


@pytest.mark.parametrize("width,user_verified", [(375, True), (1440, True), (375, False)])
async def test_browser_frozen_review_fresh_decision_and_no_dispatch(
    world, browser, service, tmp_path, width, user_verified
):
    uses, origin = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, cdp, authenticator = await enrolled_page(world, context, origin)
        await install(uses, approvers=["owner:" + ALICE.principal_did])
        _, _, pending = await request(uses, reason='</pre><img src=x onerror="alert(1)">')
        approval_id = pending.pending.approval.approval_id
        token = next(t for a, t in world.inbox.links["alice@acme.com"] if a == approval_id)
        # Include signed-out login in the real page; no token goes into diagnostics.
        await context.clear_cookies()
        await page.goto(origin + "/use-approvals#token=" + token)
        await page.get_by_role("button", name="Sign in with your passkey", exact=True).click()
        await expect(page.get_by_role("button", name="Review with your passkey")).to_be_enabled()
        await page.get_by_role("button", name="Review with your passkey").click()
        await expect(page.locator("#request-review")).to_be_visible()
        assert (
            await page.locator("#request-reason").text_content()
            == '</pre><img src=x onerror="alert(1)">'
        )
        assert await page.locator("#request-review img").count() == 0
        assert not await page.evaluate(
            "token => JSON.stringify({...sessionStorage,...localStorage}).includes(token)", token
        )
        assert not await page.evaluate("location.hash")
        await page.screenshot(path=tmp_path / f"use-review-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
        await cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": authenticator, "isUserVerified": user_verified},
        )
        await page.get_by_role("button", name="Approve with your passkey", exact=True).click()
        if user_verified:
            await expect(page.locator("#use-approval")).to_have_attribute("data-state", "approved")
            assert (await uses.approvals.get(approval_id)).state is ApprovalState.APPROVED
        else:
            await expect(page.locator("#approval-status")).to_contain_text("could not be confirmed")
            assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
        assert (await uses.approvals.get(approval_id)).consumed_operation_id is None
        await page.reload()
        assert (await uses.approvals.get(approval_id)).consumed_operation_id is None
