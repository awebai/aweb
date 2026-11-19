"""The actual production approval page discloses frozen agent header values."""

import asyncio

import pytest
import uvicorn
from aweb_naapp.dispatch import State as DispatchState
from aweb_naapp.runtime.approvals import ApprovalState
from playwright.async_api import Error as BrowserError
from playwright.async_api import expect

from tests.human_owner import install_virtual_credential
from tests.test_console_ui_browser import browser as browser
from tests.test_production_approval_headers import RequestKind, header_request
from tests.test_production_bootstrap import root as root


@pytest.fixture
def production_settings(console_listener):
    return {"console_origin": console_listener.origin}


@pytest.fixture
async def production_console(root, console_listener, console_tls):
    service, _, configured, *_ = root
    assert configured.console_origin == console_listener.origin
    server = uvicorn.Server(
        uvicorn.Config(
            service,
            log_level="warning",
            lifespan="off",  # root already owns the real production lifespan.
            ssl_certfile=str(console_tls.cert_file),
            ssl_keyfile=str(console_tls.key_file),
        )
    )
    running = asyncio.create_task(server.serve(sockets=[console_listener.socket]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if running.done():
                    await running
                    raise RuntimeError("production console stopped before startup")
                await asyncio.sleep(0.01)
        yield configured.console_origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(running, 10)


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize(
    "request_kind",
    [RequestKind.OPEN, RequestKind.NAMED_OPERATION],
    ids=lambda request_kind: request_kind.value,
)
async def test_production_page_shows_submitted_header_values_before_approval(
    root,
    production_console,
    browser,
    tmp_path,
    request_kind: RequestKind,
    width,
    *,
    onepassword_values,
):
    pending = await header_request(
        root, request_kind=request_kind, onepassword_values=onepassword_values
    )
    service, *_ = root
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
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
        try:
            await install_virtual_credential(cdp, authenticator["authenticatorId"], pending.device)
            await page.goto(production_console + "/use-approvals#token=" + pending.token)
            await page.get_by_role("button", name="Sign in with your passkey", exact=True).click()
        except BrowserError:
            # Browser diagnostics must not print a personal locator or fixture key.
            raise AssertionError("production approval sign-in did not complete") from None
        view = page.get_by_role("button", name="Review with your passkey", exact=True)
        await expect(view).to_be_enabled()
        await view.click()
        await expect(page.locator("#request-review")).to_be_visible()
        if pending.credential in await page.locator("body").inner_text():
            raise AssertionError("the approval page disclosed the stored credential")
        # Both signed production requests allow X-Project then X-Account;
        # show their exact values and submitted order before the human decides.
        await expect(page.locator("#request-action")).to_contain_text("account-A")
        headers = page.get_by_role("heading", name="Headers", exact=True).locator(
            "xpath=following-sibling::pre[1]"
        )
        await expect(headers).to_have_text("x-project: project-A\nx-account: account-A")
        await expect(
            page.get_by_role("button", name="Approve with your passkey", exact=True)
        ).to_be_enabled()
        db = service.runtime.db()
        assert await db.fetch_value("SELECT state FROM approvals") == ApprovalState.PENDING.value
        assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is None
        assert (
            await db.fetch_value("SELECT state FROM dispatches")
            == DispatchState.AWAITING_APPROVAL.value
        )
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(
            path=tmp_path / f"approval-headers-{request_kind.value}-{width}.png", full_page=True
        )
