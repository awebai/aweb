"""Juan's guided walk of the acxy.16 screens, on the real composed signer.

Not part of any suite (the name does not match test_*.py); run it by path:

    cd server
    # Capture mode: clicks through by itself and saves every screen.
    AWEB_WALK_SHOTS=/tmp/acxy16-walk uv run pytest -q -s tests/walks/walk_acxy16.py
    # Live mode: a visible browser; the person presses every button.
    AWEB_WALK=live uv run pytest -q -s tests/walks/walk_acxy16.py

Live mode waits up to 15 minutes at each step for the person's click. A
virtual authenticator holds the fixture's enrolled passkeys and answers every
passkey prompt at once: no Touch ID or phone prompt appears. Everything else
(TLS origins, PostgreSQL, the AWID registry, the signer, the owner session,
exact-act approval, retained delivery) is the real composition the native
tests use. The run prints each step's instruction.
"""

import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from playwright.async_api import expect

from tests.test_independent_protected_signer import DOMAIN, did
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_endorse_page_browser import endorse_page, open_with_passkey
from tests.test_protected_owner_initiation_native import independent_reader
from tests.test_protected_owner_page_removal_browser import owner_origin
from tests.test_protected_owner_removal_native import legacy_member

pytest_plugins = ("tests.test_independent_protected_signer",)

LIVE = os.environ.get("AWEB_WALK") == "live"
SHOTS = os.environ.get("AWEB_WALK_SHOTS")
WAIT = 15 * 60 * 1000 if LIVE else 10_000


class Walk:
    def __init__(self):
        self.number = 0

    async def screen(self, page, name, check):
        """One screen of the walk: what to look at, saved in capture mode."""
        self.number += 1
        print(f"\n[{self.number:02d}] {name}: {check}")
        if SHOTS:
            Path(SHOTS).mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=Path(SHOTS) / f"{self.number:02d}-{name}.png", full_page=True)

    async def press(self, locator, instruction):
        """The person presses it in live mode; capture mode presses it."""
        await expect(locator).to_be_visible(timeout=WAIT)
        if LIVE:
            print(f"     -> {instruction}")
        else:
            await locator.click()


@pytest.mark.asyncio
async def test_walk(admissions, tmp_path, monkeypatch):
    a = admissions
    walk = Walk()
    viewport = {"width": 1280, "height": 900}
    for directory in ("endorse", "owner"):
        (tmp_path / directory).mkdir()

    # 1. The root endorsement, from the approver's mailed personal link.
    async with endorse_page(a, tmp_path / "endorse", headless=not LIVE) as s:
        link = f"{s.origin}/handoff/{s.prepared['handoff_id']}#k={a.w.delivery.approval_links[-1]}"
        context, page = await open_with_passkey(a, s.browser, viewport["width"])
        async with context:
            await page.goto(link)
            await expect(page.locator("#handoff-action")).to_have_text("Approve", timeout=WAIT)
            await walk.screen(page, "endorse-mailed-link",
                "The question names the root agent and the team; its responsibility and limits read plainly; "
                "Requested by names the root, with when it asked.")
            await walk.press(page.get_by_text("Technical details", exact=True), "Open Technical details.")
            await walk.screen(page, "endorse-technical-details",
                "Identifiers (root, keys, policy, full digest) only here; the fingerprint above matches.")
            await walk.press(page.locator("#handoff-action"), "Press Approve.")
            await expect(page.locator("#handoff-title")).to_have_text("Approved", timeout=WAIT)
            await walk.screen(page, "endorse-approved",
                "Approved, nothing else to do; the card now says what was asked.")

    # 2. The team owner's page: members, Remove, approve, deny, lost answer.
    await legacy_member(a, "local", alias="build-1")
    await legacy_member(a, "unknown", alias="legacy-bot")
    rows = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
    root = next(row for row in rows if row.member_did_key == did(a.w.root))
    async with independent_reader(a), owner_origin(a, tmp_path / "owner", headless=not LIVE) as (origin, browser):
        from aweb_naapp.runtime.protected_signer import SignerRefused

        custody = a.w.app.authority.custody
        deliver = custody.deliver_retained

        async def release(operation, retained):
            # Only the root's removal loses its answer, after it was applied.
            await deliver(operation, retained)
            if operation.intent()["subject"]["certificate_id"] == root.certificate_id:
                raise SignerRefused("receipt_unavailable")

        monkeypatch.setattr(custody, "deliver_retained", release)
        context, page = await open_with_passkey(SimpleNamespace(device=a.w.device), browser, viewport["width"])
        async with context:
            await page.goto(origin + "/login?scope=" + quote(a.w.human.b3_scope, safe=""))
            await walk.press(page.locator("#login button"), "Press Sign in.")
            await page.wait_for_url(origin + "/", timeout=WAIT)
            await walk.screen(page, "owner-page",
                "Signed in as the owner; Team members say what each is in plain words; Remove only beside "
                "agents and members not confirmed as agent or person.")

            # Approve a removal.
            await walk.press(page.locator('[data-remove-certificate]').filter(has_text="Remove build-1"),
                "Press Remove build-1.")
            await expect(page.locator("#handoff-action")).to_have_text("Approve", timeout=WAIT)
            await walk.screen(page, "remove-approval-page",
                "Remove build-1 from engineering?; Kind: agent; Requested by you, with when; nothing removed yet.")
            await walk.press(page.locator("#handoff-action"), "Press Approve.")
            await expect(page.locator("#handoff-title")).to_have_text("Approved", timeout=WAIT)
            await walk.screen(page, "remove-approved", "Approved; the member is removed.")

            # Deny one.
            await page.goto(origin + "/")
            await walk.press(page.locator('[data-remove-certificate]').filter(has_text="Remove legacy-bot"),
                "Press Remove legacy-bot.")
            await expect(page.locator("#handoff-deny")).to_be_visible(timeout=WAIT)
            await walk.screen(page, "remove-unverified-kind",
                "Kind: agent or person not confirmed, shown before deciding.")
            await walk.press(page.locator("#handoff-deny"), "Press Deny.")
            await expect(page.locator("#handoff-title")).to_have_text("Denied", timeout=WAIT)
            await walk.screen(page, "remove-denied", "Denied; legacy-bot stays a member.")

            # An applied removal whose answer is lost, recovered from History.
            await page.goto(origin + "/")
            await walk.press(page.locator(f'[data-remove-certificate="{root.certificate_id}"]'),
                f"Press Remove {root.alias}.")
            await expect(page.locator("#handoff-action")).to_have_text("Approve", timeout=WAIT)
            await walk.press(page.locator("#handoff-action"), "Press Approve (its answer will be lost).")
            await expect(page.locator("#handoff-title")).to_have_text("Not confirmed", timeout=WAIT)
            await walk.screen(page, "lost-answer",
                "Not confirmed: no buttons, what was asked still shown, and a link to the owner page.")
            await walk.press(page.locator("#handoff-outcome-text").get_by_role("link", name="owner page"),
                "Follow the owner page link.")
            await page.wait_for_url(origin + "/", timeout=WAIT)
            await walk.screen(page, "owner-history",
                f"{root.alias} has left the members; History: Approved, not confirmed yet, the decision time, "
                "Check this request; Denied by you with its time; Approved by you.")
            await walk.press(page.get_by_role("link", name="Check this request", exact=True),
                "Follow Check this request.")
            await expect(page.locator("#handoff-title")).to_have_text("Approved", timeout=WAIT)
            await walk.screen(page, "lost-answer-recovered",
                "The same request, now Approved; delivered once, nothing sent again.")
