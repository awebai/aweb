"""The delivered common email entry reaches the actual typed approval page."""

import asyncio
import base64
import secrets
import socket
from functools import partial
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import uvicorn
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.smtp import SmtpServer
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import FastAPI
from playwright.async_api import Error as BrowserError
from playwright.async_api import expect

from aweb_secrets.approval_email import ApprovalEmailDelivery
from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_forms import console_forms_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_use_approvals import (
    ConsoleUseApprovals,
    console_run_approvals_router,
    console_use_approvals_router,
)
from aweb_secrets.owners import owner_scope
from tests.console_use_world import audit_for, mint
from tests.test_approval_email import contents, mailer
from tests.test_change_sets import ALICE, TEAM, Installations, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console_changes import Registrations
from tests.test_console_forms import enrolled_page
from tests.test_console_ui_browser import browser as _browser
from tests.test_run_dispatch_service import setup as run_setup
from tests.test_use_approvals import Clock, Uses, install
from tests.test_use_audit import targets

world = _world
browser = _browser


@pytest.fixture
def script_delivery():
    requested, release = asyncio.Event(), asyncio.Event()
    release.set()
    return requested, release


@pytest.fixture
async def entry_service(world, tmp_path, request, script_delivery):
    w = world
    await apply_console_migrations(w.db)
    await apply_idempotency_migrations(w.db)
    await apply_ratelimit_migrations(w.db)
    uses = Uses(w, w.approvals, Clock(), Installations().grant)
    run = None
    if getattr(request, "param", "use") == "run":
        await enrol_owner(w, ALICE, "alice@acme.com")
        run = await run_setup(uses, approval_required=True)
        uses.approvals = run.arguments["approvals"]
        audit = run.arguments["use_audit"]
    else:
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
        approval_kind=partial(approval_kind, enable_runs=run is not None),
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

    async def slow_script(scope, receive, send):
        # Delay delivery, without replacing the production asset or browser JS.
        if scope["type"] == "http" and scope["path"] == "/console-use-approvals/approvals.js":
            requested, release = script_delivery
            requested.set()
            await release.wait()
        await app(scope, receive, send)

    server = uvicorn.Server(uvicorn.Config(slow_script, log_level="warning", lifespan="off"))
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
            yield uses, origin, smtp, run
    finally:
        server.should_exit = True
        await asyncio.wait_for(running, 10)
        sock.close()


async def open_email_entry(page, url, script_delivery):
    requested, release = script_delivery
    requested.clear()
    release.clear()
    navigation = asyncio.create_task(page.goto(url))
    try:
        async with asyncio.timeout(10):
            await requested.wait()
        panel = page.locator("#use-approval")
        await expect(panel).to_be_attached()
        scoped = page.locator("[data-console-scope]")
        if await scoped.count():
            await expect(scoped).to_have_js_property("hidden", False)
        assert bool(urlsplit(page.url).fragment)
        # The browser has parsed the real page but has not received its script.
        # It must not expose a ready approval panel while the locator is in URL/history.
        if await panel.is_visible():
            raise AssertionError("approval panel visible before personal locator removal")
    finally:
        release.set()
        try:
            await navigation
        except BrowserError:
            raise AssertionError("delivered approval entry failed") from None


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("signed_out", [False, True])
async def test_broker_email_entry_reaches_the_use_page_and_keeps_fresh_ceremonies(
    world, browser, entry_service, script_delivery, width, signed_out
):
    uses, origin, smtp, _ = entry_service
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
        await open_email_entry(page, url, script_delivery)
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


async def existing_owner_page(world, context, origin):
    """Import the real setup key; LOGIN still uses the browser and B3/S4."""
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    auth = await cdp.send(
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
    [credential] = world.devices["alice@acme.com"].credentials.values()
    try:
        await cdp.send(
            "WebAuthn.addCredential",
            {
                "authenticatorId": auth["authenticatorId"],
                "credential": {
                    "credentialId": base64.b64encode(credential.credential_id).decode(),
                    "isResidentCredential": True,
                    "rpId": "localhost",
                    "privateKey": base64.b64encode(
                        credential.key.private_bytes(
                            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
                        )
                    ).decode(),
                    "userHandle": base64.b64encode(credential.user_handle).decode(),
                    "signCount": credential.sign_count,
                },
            },
        )
    except BrowserError:
        raise AssertionError("generated browser authenticator could not be prepared") from None
    scope = owner_scope(world.admitted.installation_id, TEAM, ALICE.principal_did)
    await page.goto(origin + "/login?" + urlencode({"scope": scope}))
    await page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
    await page.wait_for_url(origin + "/")
    return page


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("entry_service", ["run"], indirect=True)
async def test_run_email_entry_selects_run_page_without_releasing_terms_to_another_candidate(
    world, browser, entry_service, script_delivery, width
):
    uses, origin, smtp, run = entry_service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page = await existing_owner_page(world, context, origin)
        reply = await run.service.submit(job=run.job.job_id, submission=run.submission)
        assert reply.status == 202
        [received] = smtp.received
        _, _, _, url = contents(received)
        assert urlsplit(url).path == "/approvals"
        [token] = parse_qs(urlsplit(url).fragment)["token"]
        approval_id = await world.db.fetch_value(
            "SELECT approval_id FROM {{tables.run_slot_approvals}} WHERE approval_ref=$1",
            reply.body["approval_ref"],
        )
        await open_email_entry(page, url, script_delivery)
        await expect(page.locator("#use-approval")).to_be_visible()
        await expect(page.locator("#use-approval")).to_have_attribute("data-root", "/run-approvals")
        assert urlsplit(page.url).path == "/run-approvals" and not urlsplit(page.url).fragment
        assert not await page.evaluate(
            "token => JSON.stringify({...sessionStorage,...localStorage}).includes(token)", token
        )
        await expect(page.locator("#request-review")).to_be_hidden()
        # The email's finance candidate is distinct from this owner session.
        # Dispatch may select a page, but cannot authorize its VIEW or decision.
        async with page.expect_response(origin + "/run-approvals/view-options") as viewed:
            await page.get_by_role("button", name="Review with your passkey", exact=True).click()
        assert (await viewed.value).status == 403
        await expect(page.locator("#request-review")).to_be_hidden()
        approval = await uses.approvals.get(approval_id)
        assert approval.state is ApprovalState.PENDING and approval.consumed_operation_id is None
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
