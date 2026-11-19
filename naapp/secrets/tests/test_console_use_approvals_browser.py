"""The production console reviews and decides real member approval requests."""

import json
from enum import StrEnum
from functools import partial

import pytest
from aweb_naapp.dispatch import State as DispatchState
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.webauthn import from_b64url, without_user_verification
from playwright.async_api import BrowserContext, Page, Route, expect
from playwright.async_api import Error as BrowserError

from tests.human_owner import install_virtual_credential
from tests.production_approvals import requester_receipt, stored_approval
from tests.test_production_approval_headers_browser import (
    browser as browser,
)
from tests.test_production_approval_headers_browser import (
    production_console as production_console,
)
from tests.test_production_approval_headers_browser import (
    production_settings as production_settings,
)
from tests.test_production_bootstrap import ApprovalAction, ProductionRequest, approval_request
from tests.test_production_bootstrap import root as root

REASON = '</pre><img src=x onerror="alert(1)">'


class DecisionInput(StrEnum):
    VERIFIED = "verified"
    SIGNED_WITHOUT_UV = "signed-without-uv"


async def remove_decision_uv(route: Route, *, pending: ProductionRequest) -> None:
    """Send the enrolled key's real assertion without UV to the actual verifier."""
    body = route.request.post_data_json
    if route.request.method != "POST" or not isinstance(body, dict):
        raise ValueError("expected the console's decision POST")
    assertion = body.get("assertion")
    if not isinstance(assertion, dict) or not isinstance(assertion.get("rawId"), str):
        raise ValueError("decision POST has no credential assertion")
    credential = pending.device.credentials.get(from_b64url(assertion["rawId"]))
    if credential is None:
        raise ValueError("decision assertion did not use the enrolled fixture credential")
    changed = without_user_verification(assertion, credential.key)
    await route.continue_(post_data=json.dumps({**body, "assertion": changed}))


async def open_production_review(
    context: BrowserContext, *, pending: ProductionRequest, origin: str
) -> tuple[Page, dict]:
    """Authenticate the enrolled holder, then perform the separate production VIEW."""
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
        await page.goto(origin + "/use-approvals#token=" + pending.token)
        await page.get_by_role("button", name="Sign in with your passkey", exact=True).click()
    except BrowserError:
        raise AssertionError("production approval sign-in did not complete") from None
    async with page.expect_response(origin + "/use-approvals/view-options") as viewed:
        await page.get_by_role("button", name="Review with your passkey", exact=True).click()
    response = await viewed.value
    assert response.status == 200
    view_options = await response.json()
    return page, view_options


async def assert_private_escaped_review(page: Page, *, pending: ProductionRequest) -> None:
    """The real review escapes the requester's text and does not persist its locator."""
    await expect(page.locator("#request-review")).to_be_visible()
    if pending.credential in await page.locator("body").inner_text():
        raise AssertionError("the approval page disclosed the stored credential")
    assert await page.locator("#request-reason").text_content() == REASON
    assert await page.locator("#request-review img").count() == 0
    assert not await page.evaluate(
        "token => JSON.stringify({...sessionStorage,...localStorage}).includes(token)",
        pending.token,
    )
    assert not await page.evaluate("location.hash")
    assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")


@pytest.mark.parametrize(
    "width,decision_input",
    [
        (375, DecisionInput.VERIFIED),
        (1440, DecisionInput.VERIFIED),
        (375, DecisionInput.SIGNED_WITHOUT_UV),
    ],
)
async def test_browser_frozen_review_fresh_decision_and_no_dispatch(
    root,
    browser,
    production_console,
    tmp_path,
    width,
    decision_input: DecisionInput,
    *,
    onepassword_values,
):
    pending = await approval_request(
        root, kind=ApprovalAction.USE, onepassword_values=onepassword_values, reason=REASON
    )
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, view_options = await open_production_review(
            context, pending=pending, origin=production_console
        )
        await assert_private_escaped_review(page, pending=pending)
        await page.screenshot(
            path=tmp_path / f"use-review-{width}-{decision_input.value}.png", full_page=True
        )
        approval = await stored_approval(root, pending=pending)
        assert approval.state is ApprovalState.PENDING
        assert approval.consumed_operation_id is None
        decision_url = production_console + "/use-approvals/decide"
        if decision_input is DecisionInput.SIGNED_WITHOUT_UV:
            await page.route(decision_url, partial(remove_decision_uv, pending=pending))
        async with (
            page.expect_response(
                production_console + "/use-approvals/decision-options"
            ) as prepared,
            page.expect_response(decision_url) as decided,
        ):
            await page.get_by_role("button", name="Approve with your passkey", exact=True).click()
        options_response = await prepared.value
        assert options_response.status == 200
        decision_options = await options_response.json()
        assert (
            view_options["userVerification"] == decision_options["userVerification"] == "required"
        )
        assert view_options["challenge"] != decision_options["challenge"]
        response = await decided.value
        expected_state = ApprovalState.PENDING
        if decision_input is DecisionInput.VERIFIED:
            assert response.status == 200
            await expect(page.locator("#use-approval")).to_have_attribute("data-state", "approved")
            expected_state = ApprovalState.APPROVED
        else:
            assert response.status == 409
            assert await response.json() == {"detail": "approval_refused"}
            await expect(page.locator("#approval-status")).to_contain_text("could not be confirmed")
        approval = await stored_approval(root, pending=pending)
        assert approval.state is expected_state
        assert approval.consumed_operation_id is None
        await page.reload()
        approval = await stored_approval(root, pending=pending)
        assert approval.state is expected_state
        assert approval.consumed_operation_id is None
        receipt = await requester_receipt(root, pending=pending)
        assert receipt["state"] == (
            ApprovalState.APPROVED.value
            if expected_state is ApprovalState.APPROVED
            else DispatchState.AWAITING_APPROVAL.value
        )
