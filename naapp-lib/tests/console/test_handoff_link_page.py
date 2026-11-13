"""The mailed personal link in real Chromium: one passkey touch approves or
denies, with no sign-in (human-assurance-contract.md, "Mailed approval links")."""

import re

import pytest
from playwright.async_api import expect

from tests.console.test_handoff_governance_page import governance_server, open_page
from tests.runtime.approvals.test_passkeys import Contacts
from tests.runtime.test_protected_signer import CONTACT
from tests.runtime.test_protected_signer import world as world
from tests.runtime.test_protected_signer_link import mailing_signer


@pytest.fixture
async def link_service(world, tmp_path):
    contacts = Contacts()
    async with governance_server(world, tmp_path, signer=mailing_signer(world, contacts)) as service:
        yield replace_signer(service, contacts)


def replace_signer(service, contacts):
    service.token = contacts.last(CONTACT)
    service.link = f"{service.origin}/handoff/{service.prepared.handoff_id}#k={service.token}"
    return service


def watch_posts(page, origin):
    posts = []
    page.on("request", lambda r: posts.append(r.url.removeprefix(origin)) if r.method == "POST" else None)
    return posts


@pytest.mark.parametrize("width", [375, 1440])
async def test_one_touch_from_the_mailed_link_approves(link_service, width):
    s = link_service
    context, page, _, _ = await open_page(s, width)
    async with context:
        posts = watch_posts(page, s.origin)
        assert (await page.goto(s.link)).status == 200
        approve, deny = page.locator("#handoff-action"), page.locator("#handoff-deny")
        await expect(approve).to_be_enabled()
        await expect(deny).to_be_enabled()
        # The token leaves the address bar and history at once.
        assert "#" not in page.url and s.token not in page.url
        await expect(page.locator("#handoff-choice-note")).to_have_text("Both choices ask for your passkey.")
        await expect(page.locator("#handoff-fingerprint")).to_be_visible()
        # Who asked and until when are in sight; identifiers are in details.
        await expect(page.locator("#handoff-requested")).to_contain_text("Requested by")
        await expect(page.locator("#handoff-expires")).to_have_text(re.compile(r"^Expires .+$"))
        await expect(page.locator("#handoff-act")).to_be_hidden()
        await expect(page.locator("#handoff-target")).to_be_hidden()
        await expect(page.locator("#handoff-fingerprint")).to_have_text(
            " ".join(s.prepared.digest[i : i + 4] for i in range(0, 16, 4)))
        # The full digest is one step away, in Technical details.
        await expect(page.locator("#handoff-digest")).to_be_hidden()
        await page.get_by_text("Technical details", exact=True).click()
        await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert "terminal" not in (await page.locator("main").inner_text()).lower()
        await approve.click()
        outcome = page.locator("#handoff-title")
        await expect(outcome).to_have_text("Approved")
        await expect(outcome).to_be_focused()
        assert await page.title() == "Approved"
        await expect(page.locator("#handoff-outcome-text")).to_have_text("Done. There is nothing else to do here.")
        await expect(approve).to_be_hidden()
        await expect(deny).to_be_hidden()
        assert posts == [f"/handoff/{s.prepared.handoff_id}/link", f"/handoff/{s.prepared.handoff_id}/link/options",
            f"/handoff/{s.prepared.handoff_id}/link/decide"]
        assert await context.cookies() == []
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert receipt.state == "committed"
        # The page never goes to the requester's own callback.
        assert not s.callback.done()


async def test_one_touch_from_the_mailed_link_denies(link_service):
    s = link_service
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await page.goto(s.link)
        await page.locator("#handoff-deny").click()
        await expect(page.locator("#handoff-title")).to_have_text("Denied")
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert (receipt.state, receipt.code) == ("refused", "human_refused")


async def test_a_cancelled_passkey_prompt_decides_nothing(link_service):
    s = link_service
    context, page, cdp, device = await open_page(s, 375)
    async with context:
        posts = watch_posts(page, s.origin)
        await page.goto(s.link)
        await expect(page.locator("#handoff-action")).to_be_enabled()
        await cdp.send("WebAuthn.setUserVerified", {"authenticatorId": device, "isUserVerified": False})
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-status")).to_have_text(
            "Nothing was decided. If your passkey is on another device, open this link there.")
        await expect(page.locator("#handoff-action")).to_be_enabled()
        await expect(page.locator("#handoff-action")).to_be_focused()
        await expect(page.locator("#handoff-deny")).to_be_enabled()
        assert not any(url.endswith("/link/decide") for url in posts)
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert receipt.state == "pending"


@pytest.mark.parametrize("link", ["spent", "wrong"])
async def test_a_link_that_no_longer_works_says_so_and_offers_nothing(link_service, link):
    s = link_service
    target = s.link if link == "spent" else s.link[:-2] + "xx"
    context, page, _, _ = await open_page(s, 375)
    async with context:
        if link == "spent":
            await page.goto(s.link)
            await page.locator("#handoff-action").click()
            await expect(page.locator("#handoff-title")).to_have_text("Approved")
            # Opening the mail link again is a fresh load, not a fragment change.
            await page.goto("about:blank")
        await page.goto(target)
        await expect(page.locator("#handoff-status")).to_have_text(
            "This link is not valid any more. Requests still waiting for you are on your owner page.")
        await expect(page.locator("#handoff-title")).to_have_text("This link no longer works")
        await expect(page.locator("#handoff-action")).to_be_hidden()
        await expect(page.locator("#handoff-deny")).to_be_hidden()
        await expect(page.get_by_role("link", name="owner page")).to_have_attribute("href", "/")
        assert s.prepared.digest not in await page.content()


async def test_a_link_opened_after_its_request_expired_says_so(link_service):
    from datetime import timedelta

    s = link_service
    s.world.clock.advance(timedelta(hours=25))
    context, page, _, _ = await open_page(s, 390)
    async with context:
        await page.goto(s.link)
        await expect(page.locator("#handoff-title")).to_have_text("Request expired")
        await expect(page.locator("#handoff-status")).to_have_text("This request expired without a decision. Nothing was signed.")
        await expect(page.locator("#handoff-action")).to_be_hidden()
        assert s.prepared.digest not in await page.content()


async def test_a_request_that_expires_while_open_turns_into_expired(link_service):
    s = link_service
    context, page, _, _ = await open_page(s, 390)
    async with context:
        await page.clock.install()
        await page.goto(s.link)
        await expect(page.locator("#handoff-action")).to_be_enabled()
        await page.clock.fast_forward("25:00:00")
        await expect(page.locator("#handoff-title")).to_have_text("Request expired")
        await expect(page.locator("#handoff-status")).to_contain_text("without a decision. Nothing was signed.")
        await expect(page.locator("#handoff-action")).to_be_hidden()


@pytest.fixture
async def signed_in_service(world, tmp_path):
    async with governance_server(world, tmp_path, redirect=False) as service:
        yield service


async def sign_in(page, s):
    await page.goto(f"{s.origin}/handoff/{s.prepared.handoff_id}")
    # One instruction before sign-in, gone once the request shows.
    await expect(page.locator("#handoff-explanation")).to_have_text("Sign in with your passkey to see the request.")
    await expect(page.locator("#handoff-status")).to_have_text("")
    await page.locator("#handoff-action").click()
    await expect(page.locator("#handoff-explanation")).to_be_hidden()
    await expect(page.locator("#handoff-deny")).to_be_enabled()


async def test_a_tab_that_signed_in_approves_with_one_touch(signed_in_service):
    s = signed_in_service
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await sign_in(page, s)
        # Coming back to the request in the same tab (as from the owner page)
        # needs no second sign-in: the next touch is the approval itself.
        await page.goto("about:blank")
        posts = watch_posts(page, s.origin)
        await page.goto(f"{s.origin}/handoff/{s.prepared.handoff_id}")
        await expect(page.locator("#handoff-action")).to_have_text("Approve")
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-title")).to_have_text("Approved")
        await expect(page.locator("#handoff-title")).to_be_focused()
        await expect(page.locator("#handoff-outcome-text")).to_have_text("Done. There is nothing else to do here.")
        await expect(page.locator("#handoff-action")).to_be_hidden()
        await expect(page.locator("#handoff-deny")).to_be_hidden()
        assert posts == [f"/handoff/{s.prepared.handoff_id}/governance/options",
            f"/handoff/{s.prepared.handoff_id}/governance/execute"]
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert receipt.state == "committed"


async def test_a_signed_in_approver_denies_with_one_touch(signed_in_service):
    s = signed_in_service
    context, page, _, _ = await open_page(s, 1440)
    async with context:
        await sign_in(page, s)
        await page.locator("#handoff-deny").click()
        await expect(page.locator("#handoff-title")).to_have_text("Denied")
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert (receipt.state, receipt.code) == ("refused", "human_refused")


@pytest.mark.parametrize("status, sentence", [
    (429, "Too many attempts from this browser. Wait a minute, then open the page again."),
    (403, "If it came by email, the link is no longer valid; if a terminal started it, start a new request there."),
])
def test_a_refused_page_says_what_to_do_for_email_and_terminal_alike(status, sentence):
    from fastapi import HTTPException

    from aweb_naapp.console.handoff_page import _unavailable

    page = _unavailable(HTTPException(status, "handoff_refused"))
    assert page.status_code == status
    assert sentence in page.body.decode()
    # A rate limit is not final, so it does not say the request cannot be completed.
    assert ("This request cannot be completed." in page.body.decode()) == (status == 403)


async def test_a_session_that_ends_mid_page_asks_to_sign_in_again(signed_in_service):
    s = signed_in_service
    context, page, _, _ = await open_page(s, 390)
    async with context:
        await sign_in(page, s)
        await context.clear_cookies()
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-status")).to_have_text("You were signed out. Sign in again to decide.")
        await expect(page.locator("#handoff-action")).to_have_text("Sign in with passkey")
        await expect(page.locator("#handoff-action")).to_be_enabled()
        await expect(page.locator("#handoff-action")).to_be_focused()
        await expect(page.locator("#handoff-deny")).to_be_hidden()
        receipt = await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        assert receipt.state == "pending"


async def test_a_click_after_the_server_expired_the_request_says_expired(link_service):
    from datetime import timedelta

    s = link_service
    context, page, _, _ = await open_page(s, 390)
    async with context:
        await page.goto(s.link)
        await expect(page.locator("#handoff-action")).to_be_enabled()
        s.world.clock.advance(timedelta(hours=25))
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-title")).to_have_text("Request expired")


async def test_times_read_in_the_readers_own_zone(link_service):
    s = link_service
    context, page, _, _ = await open_page(s, 390, timezone_id="America/New_York", locale="en-US")
    async with context:
        await page.goto(s.link)
        expires = page.locator("#handoff-expires")
        await expect(expires).to_have_text(re.compile(r"^Expires .+ E[SD]T$"))
        assert "UTC" not in await expires.inner_text()
