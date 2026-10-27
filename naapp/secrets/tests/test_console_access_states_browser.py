"""The Access page's other states as an owner sees them: one secret's view and its terms, jobs,
an empty page, errors, a failed action and keyboard-only use."""

import asyncio
import json

import pytest
from aweb_naapp.roles import unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import expect

from aweb_secrets import records
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.policy import Policy
from tests.test_admission import POLICY_BODY
from tests.test_change_sets import ALICE, TEAM
from tests.test_console_access import (
    DB_AGENT,
    DB_WRITE,
    INSERT,
    OPEN,
    OPEN_AGENT,
    ORDERS_DB,
    PAYMENTS,
    READ,
    READER,
    READERS,
    READING,
    admission,
    job_using,
    run_grant,
)
from tests.test_console_access_browser import browser as _browser
from tests.test_console_access_browser import service as _service
from tests.test_console_access_browser import world as _world
from tests.test_console_forms import enrolled_page

world = _world
browser = _browser
service = _service

TERMS = Policy.from_body(
    {
        **POLICY_BODY,
        "rate": [{"per": "principal_secret", "capacity": 30, "window_s": 3600}],
        "windows": {
            "time_zone": "Europe/Madrid",
            "ranges": [
                {"days": ["mon", "tue", "wed", "thu", "fri"], "from": "09:00", "to": "18:00"}
            ],
        },
    }
)
NO_OVERFLOW = "document.documentElement.scrollWidth <= innerWidth"


async def jobs_on_terms(w):
    """READER may supply orders-db to two jobs, under rate and time terms: one job also needs
    payments-api, and the other names a credential that does not exist."""
    syncing = await job_using(w, [ORDERS_DB.ref, PAYMENTS.ref], job_id="orders-sync")
    archive = await job_using(w, [ORDERS_DB.ref, "retired-key"], job_id="orders-archive")
    async with w.db.transaction() as tx:
        await records.create_policy(tx, INSTALLATION_ID, TERMS)
        for grant_id, job in (("grt_runsync1", syncing), ("grt_runarch1", archive)):
            await records.create_grant(
                tx, INSTALLATION_ID, TEAM, run_grant(grant_id, ORDERS_DB, READER, job, TERMS)
            )


async def tab_to(page, selector: str) -> None:
    for _ in range(80):
        await page.keyboard.press("Tab")
        if await page.evaluate("s => document.activeElement.matches(s)", selector):
            return
    pytest.fail(f"keyboard focus never reached {selector}")


async def focus_ring_visible(page) -> bool:
    return await page.evaluate(
        "() => { const s = getComputedStyle(document.activeElement);"
        " return s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0; }"
    )


@pytest.mark.parametrize(
    ("width", "scheme"),
    [(375, "light"), (768, "light"), (1440, "light"), (375, "dark"), (1440, "dark")],
)
async def test_one_secrets_view_shows_who_can_use_it_on_what_terms(
    world, browser, service, tmp_path, width, scheme
):
    _, origin = service
    await jobs_on_terms(world)
    viewport = {"width": width, "height": 1000}
    async with await browser.new_context(viewport=viewport, color_scheme=scheme) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")
        await page.screenshot(path=tmp_path / f"list-{width}-{scheme}.png", full_page=True)
        assert await page.evaluate(NO_OVERFLOW)
        await page.locator(f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] h3 a').click()
        await expect(page).to_have_url(origin + f"/access/secrets/{ORDERS_DB.ref}")
        # Only this secret's access: the payments-api agent is not listed.
        await expect(
            page.locator(f'.access-agent[data-principal-did="{OPEN_AGENT.did_aw}"]')
        ).to_have_count(0)
        await expect(
            page.locator(f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] .access-origin')
        ).to_contain_text("directly")
        await expect(
            page.locator(
                f'.access-grant[data-principal-did="{READER.did_aw}"]'
                f'[data-grant-id="{READING.grant_id}"] .access-origin'
            )
        ).to_contain_text(READERS)
        syncing = page.locator('.access-run[data-job-id="orders-sync"]')
        await expect(syncing).to_contain_text("2 credentials")
        await expect(syncing).not_to_contain_text("can run")
        await expect(page.locator('.access-run[data-job-id="orders-archive"]')).to_contain_text(
            "not usable"
        )
        terms = page.locator('.access-grant[data-grant-id="grt_runsync1"] .access-conditions')
        await expect(terms).to_contain_text("Rate limit")
        await expect(terms).to_contain_text("Allowed times")
        await page.screenshot(path=tmp_path / f"secret-{width}-{scheme}.png", full_page=True)
        assert await page.evaluate(NO_OVERFLOW)
        await page.get_by_role("link", name="All access").click()
        await expect(page).to_have_url(origin + "/access")


@pytest.mark.parametrize("width", [375, 1440])
async def test_once_every_grant_is_revoked_the_page_says_no_agent_has_access(
    world, browser, service, tmp_path, width
):
    _, origin = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")
        for grant in (DB_WRITE, READING, OPEN):
            controls = page.locator(
                f'.access-grant[data-grant-id="{grant.grant_id}"] .access-revoke'
            )
            page.once("dialog", lambda dialog: asyncio.ensure_future(dialog.accept()))
            await controls.first.click()
            await expect(controls).to_have_count(0)
        await expect(page.locator("#access-empty")).to_be_visible()
        await expect(page.locator(".access-agent")).to_have_count(0)
        await page.screenshot(path=tmp_path / f"empty-{width}.png", full_page=True)


async def test_an_unknown_secret_and_changed_access_as_the_browser_shows_them(
    world, browser, service, tmp_path
):
    _, origin = service
    async with await browser.new_context(viewport={"width": 375, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        unknown = await page.goto(origin + "/access/secrets/no-such-secret")
        assert unknown.status == 404
        await page.screenshot(path=tmp_path / "unknown-secret-375.png", full_page=True)

        holding, release = asyncio.Event(), asyncio.Event()

        async def withdraw():
            async with world.db.transaction() as tx:
                await unassign(tx, ALICE, OWNER_ROLE)
                holding.set()
                await release.wait()

        withdrawal = asyncio.create_task(withdraw())
        await holding.wait()
        navigation = asyncio.create_task(page.goto(origin + "/access"))
        for _ in range(500):
            if await world.db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()"
                " AND wait_event_type='Lock' AND query LIKE '%role_assignments%FOR SHARE%')"
            ):
                break
            await asyncio.sleep(0.01)
        else:
            release.set()
            await asyncio.gather(withdrawal, navigation, return_exceptions=True)
            pytest.fail("the view did not reach the owner role hold")
        release.set()
        await withdrawal
        changed = await asyncio.wait_for(navigation, 10)
        assert changed.status == 409
        await page.screenshot(path=tmp_path / "access-changed-375.png", full_page=True)


async def test_a_failed_revoke_far_down_the_page_is_reported_where_the_owner_is(
    world, browser, service, tmp_path
):
    uses, origin = service
    async with await browser.new_context(viewport={"width": 375, "height": 800}) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")
        # The connection drops: the request never reaches the service, so nothing is revoked.
        await page.route("**/containment", lambda route: route.abort())
        control = page.locator(f'.access-grant[data-grant-id="{OPEN.grant_id}"] .access-revoke')
        await control.scroll_into_view_if_needed()
        page.once("dialog", lambda dialog: asyncio.ensure_future(dialog.accept()))
        await control.click()
        await expect(control).to_be_enabled()
        focused = await page.evaluate("() => document.activeElement.outerHTML.slice(0, 160)")
        (tmp_path / "failed-revoke-focus.json").write_text(json.dumps({"focused": focused}))
        await page.screenshot(path=tmp_path / "failed-revoke-375.png")
        assert await admission(uses, OPEN_AGENT, PAYMENTS, "", 1) is None
        # The owner learns what happened where they acted, and keeps their place.
        failure = page.locator(f'.access-grant[data-grant-id="{OPEN.grant_id}"] [role="alert"]')
        await expect(failure).not_to_be_empty()
        await expect(failure).to_be_in_viewport()
        await expect(control).to_be_focused()


async def test_keyboard_only_list_secret_return_and_cancelled_narrowing(
    world, browser, service, tmp_path
):
    uses, origin = service
    asked: list[str] = []
    async with await browser.new_context(viewport={"width": 1440, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, origin)
        await page.goto(origin + "/access")

        def cancel(dialog):
            asked.append(dialog.message)
            asyncio.ensure_future(dialog.dismiss())

        page.on("dialog", cancel)
        await tab_to(page, f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] h3 a')
        assert await focus_ring_visible(page)
        await page.screenshot(path=tmp_path / "keyboard-link-1440.png")
        await page.keyboard.press("Enter")
        await expect(page).to_have_url(origin + f"/access/secrets/{ORDERS_DB.ref}")
        await tab_to(page, 'a[href="/access"]')
        assert await focus_ring_visible(page)
        await page.keyboard.press("Enter")
        await expect(page).to_have_url(origin + "/access")
        await tab_to(page, f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] .access-revoke')
        assert await focus_ring_visible(page)
        await page.screenshot(path=tmp_path / "keyboard-revoke-1440.png")
        await page.keyboard.press("Enter")
        await tab_to(
            page,
            f'.access-agent[data-principal-did="{READER.did_aw}"]'
            f' .access-remove-member[data-role="{READERS}"]',
        )
        assert await focus_ring_visible(page)
        await page.keyboard.press("Enter")
        await expect(page.locator(".access-agent")).to_have_count(3)
    (tmp_path / "confirm-dialogs.json").write_text(json.dumps(asked))
    assert asked == [
        "Revoke this grant?",
        f"Remove this agent from the role {READERS}?",
    ]
    # Cancelling either confirmation changes nothing.
    assert await admission(uses, DB_AGENT, ORDERS_DB, INSERT.operation_id, 1) is None
    assert await admission(uses, READER, ORDERS_DB, READ.operation_id, 2) is None
