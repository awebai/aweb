"""The delivered common email entry reaches the actual typed approval page."""

import asyncio
import secrets
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
import uvicorn
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.smtp import SmtpServer
from fastapi import FastAPI
from playwright.async_api import Error as BrowserError
from playwright.async_api import expect

from aweb_secrets.approval_email import ApprovalEmailDelivery
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_forms import console_forms_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_use_approvals import (
    ConsoleUseApprovals,
    console_run_approvals_router,
    console_use_approvals_router,
)
from tests.console_use_world import audit_for, mint
from tests.test_approval_email import contents, mailer
from tests.test_change_sets import ALICE, TEAM, Installations
from tests.test_change_sets import world as _world
from tests.test_console_changes import Registrations
from tests.test_console_forms import enrolled_page
from tests.test_console_ui_browser import browser as _browser
from tests.test_use_approvals import Clock, Uses, install
from tests.test_use_audit import targets

world = _world
browser = _browser


@pytest.fixture
async def entry_service(world, tmp_path):
    w = world
    await apply_console_migrations(w.db)
    await apply_idempotency_migrations(w.db)
    await apply_ratelimit_migrations(w.db)
    uses = Uses(w, w.approvals, Clock(), Installations().grant)
    audit, _ = audit_for(uses)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    w.passkeys.rp = RelyingParty(origin=origin, name="Secrets")

    async def installation(installation_id, *, team_id=None):
        assert installation_id == w.admitted.installation_id
        assert team_id in (None, w.admitted.team_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        credential_audit=w.credential_audit,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    changes = ConsoleChanges(
        console=console,
        changes=w.change_sets,
        approvals=uses.approvals,
        registrations=Registrations(),
        after_commit=w.containment.evict,
    )

    async def registration_view(team_id):
        assert team_id == TEAM
        return targets(uses.clock())

    typed = ConsoleUseApprovals(
        console=console,
        approvals=uses.approvals,
        use_audit=audit,
        registration_view=registration_view,
    )
    human = FastAPI()
    human.include_router(owner_console_router(console))
    human.include_router(console_ui_router(sessions=console.sessions))
    human.include_router(console_changes_router(changes))
    human.include_router(console_forms_router(changes=changes))
    human.include_router(console_use_approvals_router(services=typed))
    human.include_router(console_run_approvals_router(services=typed))
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
        with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
            uses.approvals._delivery = ApprovalEmailDelivery(
                mailer=mailer(smtp, tmp_path), approval_url=origin + "/approvals"
            )
            yield uses, origin, smtp
    finally:
        server.should_exit = True
        await asyncio.wait_for(running, 10)
        sock.close()


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("signed_out", [False, True])
async def test_broker_email_entry_reaches_the_use_page_and_keeps_fresh_ceremonies(
    world, browser, entry_service, width, signed_out
):
    uses, origin, smtp = entry_service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        await install(uses, approvers=["owner:" + ALICE.principal_did])
        pending = await mint(uses)
        approval_id = pending.pending.approval.approval_id
        [received] = smtp.received
        _, _, _, url = contents(received)
        assert urlsplit(url).path == "/approvals"
        [token] = parse_qs(urlsplit(url).fragment)["token"]
        if signed_out:
            await context.clear_cookies()
        requests = []
        page.on("request", lambda request: requests.append(request.url))
        try:
            await page.goto(url)
        except BrowserError:
            raise AssertionError("delivered approval entry failed") from None
        # The assertion deliberately precedes any typed-page request: the
        # actual email entry must select this page, rather than a test deep link.
        await expect(page.locator("#use-approval")).to_be_visible()
        assert urlsplit(page.url).path == "/use-approvals"
        assert not urlsplit(page.url).fragment
        if await page.evaluate(
            "token => JSON.stringify({...sessionStorage,...localStorage}).includes(token)", token
        ):
            raise AssertionError("personal locator persisted in browser storage")
        assert all(not urlsplit(request).fragment for request in requests)
        await expect(page.locator("#request-review")).to_be_hidden()
        if signed_out:
            await page.get_by_role("button", name="Sign in with your passkey", exact=True).click()
        await page.get_by_role("button", name="Review with your passkey", exact=True).click()
        await expect(page.locator("#request-review")).to_be_visible()
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
        await page.get_by_role("button", name="Approve with your passkey", exact=True).click()
        await expect(page.locator("#use-approval")).to_have_attribute("data-state", "approved")
        approval = await uses.approvals.get(approval_id)
        assert approval.state is ApprovalState.APPROVED
        assert approval.consumed_operation_id is None
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
