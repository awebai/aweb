"""aweb-adbb D2c in real Chromium: one current-authority read fails right
after the approver's touch. The page says the act is not completed yet and
offers to try again; reopening the page (mailed link or signed-in tab) and
pressing Approve finishes the same act with no second passkey check, and the
act is signed once."""

from playwright.async_api import expect

from aweb_naapp.runtime.protected_signer import SignerRefused
from tests.console.test_handoff_governance_page import open_page
from tests.console.test_handoff_link_page import link_service as link_service  # noqa: F401
from tests.console.test_handoff_link_page import sign_in, watch_posts  # noqa: F401
from tests.console.test_handoff_link_page import signed_in_service as signed_in_service
from tests.runtime.protected_signer_support import world as world  # noqa: F401


def fail_the_read_after_the_touch(s, monkeypatch):
    """The second current-authority read of an execute is the one after the
    recorded decision; it fails once."""
    authority = s.world.signer.authority
    observe = authority.observe
    reads = {"execute": 0}

    async def once(context, *, purpose):
        if purpose == "execute":
            reads["execute"] += 1
            if reads["execute"] == 2:
                raise SignerRefused("evidence_unavailable")
        return await observe(context, purpose=purpose)

    monkeypatch.setattr(authority, "observe", once)


async def signed(s):
    return await s.world.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}} "
        "WHERE operation_id=$1 AND (result IS NOT NULL OR signed_result IS NOT NULL)", s.prepared.operation_id)


async def test_a_mailed_link_reopened_after_a_failed_read_finishes_the_approval(link_service, monkeypatch):  # noqa: F811
    s = link_service
    fail_the_read_after_the_touch(s, monkeypatch)
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await page.goto(s.link)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "retry")
        await expect(page.locator("#handoff-action")).to_be_enabled()
        assert (await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)).state == "pending"
        assert await signed(s) == 0
        # The approver opens the mailed link again: a new page load, not a
        # fragment change within the page that already stripped its token.
        await page.goto("about:blank")
        posts = watch_posts(page, s.origin)
        await page.goto(s.link)
        await expect(page.locator("#handoff-action")).to_be_enabled()
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-title")).to_have_text("Approved")
        handoff = f"/handoff/{s.prepared.handoff_id}/link"
        assert posts == [handoff, handoff + "/options", handoff + "/decide"]
        assert (await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)).state == "committed"
        assert await signed(s) == 1


async def test_a_signed_in_tab_tries_again_and_finishes_the_approval(signed_in_service, monkeypatch):  # noqa: F811
    s = signed_in_service
    fail_the_read_after_the_touch(s, monkeypatch)
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await sign_in(page, s)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "retry")
        posts = watch_posts(page, s.origin)
        # Try again, in the same tab: no second passkey check.
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-title")).to_have_text("Approved")
        governance = f"/handoff/{s.prepared.handoff_id}/governance"
        assert posts == [governance + "/options", governance + "/execute"]
        assert (await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)).state == "committed"
        assert await signed(s) == 1


async def test_a_mailed_link_deny_that_fails_after_the_touch_never_turns_into_approve(link_service, monkeypatch):  # noqa: F811
    s = link_service
    fail_the_read_after_the_touch(s, monkeypatch)
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await page.goto(s.link)
        await page.locator("#handoff-deny").click()
        # A rejection the signer could not finish is unconfirmed, as a lost
        # answer is: the page never offers to approve instead.
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "unconfirmed")
        await expect(page.locator("#handoff-action")).to_be_hidden()
        assert await signed(s) == 0


async def test_a_mailed_link_answer_lost_after_signing_tries_again_into_not_confirmed(link_service, monkeypatch):  # noqa: F811
    s = link_service
    # The page's signer is the fixture's own instance: patch its class.
    service = type(s.world.signer)
    decide = service.link_decide

    async def lose_the_answer(self, *args, **kwargs):
        await decide(self, *args, **kwargs)
        raise SignerRefused("evidence_unavailable")  # Lose only the already applied answer.

    monkeypatch.setattr(service, "link_decide", lose_the_answer)
    context, page, _, _ = await open_page(s, 375)
    async with context:
        await page.goto(s.link)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "retry")
        assert await signed(s) == 1
        # Trying again cannot sign twice; the page says it cannot confirm
        # and points to History rather than calling the link unusable.
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-title")).to_have_text("Not confirmed")
        await expect(page.locator("#handoff-action")).to_be_hidden()
        await expect(page.locator("#handoff-deny")).to_be_hidden()
        owner_page = page.locator("#handoff-outcome-text").get_by_role("link", name="owner page", exact=True)
        await expect(owner_page).to_have_attribute("href", "/")
        assert await signed(s) == 1
