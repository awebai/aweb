"""Real Chromium signatures traverse the explicit owner settlement pages."""

import asyncio
import base64
import socket
from urllib.parse import urlencode

import pytest
import uvicorn
from aweb_naapp.console import LOGIN_BUCKET
from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.passkeys import RelyingParty
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from playwright.async_api import Error as BrowserError
from playwright.async_api import expect

from tests.test_console_reconciliation import application, repeated_broker
from tests.test_console_ui_browser import browser as browser
from tests.test_reconciliation_service import snapshot
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


@pytest.fixture
async def service(uses):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    # The service fixture first enrols an actual B3 owner and produces a real
    # uncertain run. Import that generated authenticator key into Chromium;
    # all subsequent LOGIN/VIEW/APPROVE assertions use the shipped browser UI.
    app, run, original, current = await application(
        uses, origin=origin, agent_origin=f"http://127.0.0.1:{port}"
    )
    uses.world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield origin, run, original, current
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


async def signed_in_page(uses, context, origin, current):
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
    [credential] = uses.world.devices["alice@acme.com"].credentials.values()
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
    await page.goto(origin + "/login?" + urlencode({"scope": current.scope}))
    await page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
    await page.wait_for_url(origin + "/")
    return page, cdp, auth


@pytest.mark.parametrize("width,verified", [(375, True), (768, True), (1440, True), (375, False)])
async def test_browser_frozen_outcome_fresh_approve_and_explicit_settlement(
    uses, browser, service, tmp_path, width, verified
):
    origin, run, original, current = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, cdp, auth = await signed_in_page(uses, context, origin, current)
        await page.goto(origin + "/activity")
        await page.get_by_role("link", name="Resolve uncertain outcome", exact=True).click()
        await expect(
            page.get_by_role("heading", name="Resolve an uncertain outcome", exact=True)
        ).to_be_visible()
        before = await snapshot(uses.world.db)
        await page.reload()
        assert await snapshot(uses.world.db) == before
        await page.screenshot(path=tmp_path / f"settlement-choice-{width}.png", full_page=True)
        await page.get_by_label("Outcome to record").select_option("failed")
        stage = "submit chosen outcome"
        try:
            await page.get_by_role("button", name="Review this outcome", exact=True).click()
            stage = "open minted personal review"
            await expect(page.locator("#view-outcome")).to_be_enabled()
            approval_id, token = uses.world.inbox.links["alice@acme.com"][-1]
            await context.clear_cookies()
            await page.evaluate("sessionStorage.clear()")
            # Mint already opened this path. Leave it first so opening the
            # delivered link loads a new signed-out document, not just a hash.
            await page.goto("about:blank")
            stage = "navigate signed-out personal link"
            await page.goto(origin + "/reconciliation-approvals#token=" + token)
            stage = "offer personal-link sign-in"
            await page.get_by_role("button", name="Sign in with your passkey", exact=True).click()
            stage = "complete personal-link sign-in"
            await expect(page.locator("#view-outcome")).to_be_enabled()
        except (BrowserError, AssertionError):
            # Navigation diagnostics can otherwise contain the personal link.
            raise AssertionError("personal review failed at: " + stage) from None
        await page.get_by_role("button", name="Review with your passkey", exact=True).click()
        await expect(page.locator("#outcome-review")).to_be_visible()
        await expect(page.locator("#outcome-facts")).to_contain_text("failed")
        await expect(page.locator("#reconciliation-status")).to_be_focused()
        assert not await page.evaluate("location.hash")
        if await page.evaluate(
            "token => JSON.stringify({...sessionStorage,...localStorage}).includes(token)", token
        ):
            raise AssertionError("personal approval token reached browser storage")
        await page.screenshot(path=tmp_path / f"settlement-review-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": auth["authenticatorId"], "isUserVerified": verified},
        )
        before_decision = await snapshot(uses.world.db)
        await page.get_by_role("button", name="Approve with your passkey", exact=True).click()
        if not verified:
            await expect(page.locator("#approve-outcome")).to_be_enabled()
            await expect(page.locator("#reconciliation-status")).to_be_focused()
            assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
            assert await snapshot(uses.world.db) == before_decision
            return
        await expect(page.locator("#settlement-link")).to_be_focused()
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.APPROVED
        await page.get_by_role("link", name="View settlement status", exact=True).click()
        await expect(page.locator("#settle-outcome")).to_be_visible()
        before = await snapshot(uses.world.db)
        await page.reload()
        assert await snapshot(uses.world.db) == before
        await page.screenshot(path=tmp_path / f"settlement-approved-{width}.png", full_page=True)
        run.available[0] = False
        await page.get_by_role("button", name="Confirm settlement", exact=True).click()
        await expect(page.locator("#settlement-receipt")).to_have_attribute(
            "data-state", "reconciled_failed"
        )
        await expect(page.locator("#reconciliation-status")).to_be_focused()
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.CONSUMED
        await page.screenshot(path=tmp_path / f"settlement-recorded-{width}.png", full_page=True)
        summary = page.locator("#settlement-summary")
        await expect(summary).to_contain_text("reconciled_failed")
        await expect(summary).to_contain_text("consumed")
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        before = await snapshot(uses.world.db)
        await page.reload()
        assert await snapshot(uses.world.db) == before
        assert await page.locator("#settle-outcome").count() == 0


@pytest.mark.parametrize("width", [375, 1440])
async def test_cookie_only_failed_passkey_reauthentication_shows_feedback(
    uses, browser, service, tmp_path, width
):
    origin, _, original, current = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, cdp, auth = await signed_in_page(uses, context, origin, current)
        # Keep the real S4 cookie while removing this tab's CSRF token.
        await page.evaluate("sessionStorage.clear()")
        await page.goto(origin + "/reconciliations/" + original.original.reconcile_ref)
        await expect(page.locator("[data-console-scope]")).to_be_hidden()
        await expect(page.locator("#console-reauth-notice")).to_be_visible()
        before = await snapshot(uses.world.db)
        await cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": auth["authenticatorId"], "isUserVerified": False},
        )
        login = page.locator("#reconciliation-sign-in")
        await login.click()
        await expect(login).to_be_enabled()
        await page.screenshot(
            path=tmp_path / f"settlement-reauth-refused-{width}.png", full_page=True
        )
        feedback = page.locator("#reconciliation-status")
        await expect(feedback).to_be_visible()
        await expect(feedback).not_to_be_empty()
        await expect(feedback).to_be_focused()
        await expect(page.locator("[data-console-scope]")).to_be_hidden()
        after = await snapshot(uses.world.db)
        # A real failed LOGIN is metered by S4. Preserve complete comparisons
        # of every domain/audit table and all non-login rate buckets.
        changed_buckets = {
            row["bucket"]
            for left, right in ((before, after), (after, before))
            for row in left["rate_buckets"]
            if row not in right["rate_buckets"]
        }
        assert changed_buckets == {LOGIN_BUCKET}, "unexpected reauthentication rate changes"
        for observation in (before, after):
            observation["rate_buckets"] = [
                row for row in observation["rate_buckets"] if row["bucket"] != LOGIN_BUCKET
            ]
        for table in before:
            assert after[table] == before[table], "unexpected settlement effect in " + table


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize(
    "repeat_state,settled",
    [(State.ADMITTED, False), (State.OUTCOME_UNKNOWN, False), (State.OUTCOME_UNKNOWN, True)],
)
async def test_browser_repeat_observation_keeps_original_and_repeat_distinct(
    uses, browser, service, tmp_path, width, repeat_state, settled
):
    origin, _, _, current = service
    ref = await repeated_broker(uses, repeat_state, settled=settled)
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await signed_in_page(uses, context, origin, current)
        await page.goto(origin + "/reconciliations/" + ref)
        notice = page.locator("#repeat-status")
        await expect(notice).to_be_visible()
        await expect(notice).to_have_attribute("data-repeat-state", repeat_state.value)
        await expect(notice).to_have_attribute("data-pair-state", "closed" if settled else "open")
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(
            path=tmp_path / f"repeat-{repeat_state.value}-{settled}-{width}.png", full_page=True
        )
        before = await snapshot(uses.world.db)
        await page.reload()
        assert await snapshot(uses.world.db) == before
