"""Navigation refusals offer recovery without changing JSON/API refusals."""

import asyncio
from uuid import uuid4

import pytest
from aweb_naapp.console import CONSOLE_HEADERS, COOKIE_NAME
from playwright.async_api import expect

from tests.test_console_reconciliation_browser import browser as browser
from tests.test_console_reconciliation_browser import service as service
from tests.test_console_reconciliation_browser import signed_in_page
from tests.test_reconciliation_service import snapshot
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("case", ["pagination", "authority", "record", "control"])
async def test_refused_navigation_is_an_inert_recovery_page(
    uses, browser, service, tmp_path, width, case
):
    origin, _, _, current = service
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await signed_in_page(uses, context, origin, current)
        if case == "pagination":
            path, api, status, code = (
                "/activity?before=bad",
                "/activity/events?before=bad",
                400,
                "activity_cursor_invalid",
            )
        elif case == "authority":
            await uses.world.db.execute(
                "UPDATE {{tables.installation_fences}}"
                " SET fresh_until=clock_timestamp()-interval '1 second'"
            )
            path, api, status, code = "/activity", "/activity/events", 503, "authority_unavailable"
        else:
            ref = str(uuid4())
            root, suffix = (
                ("/reconciliations/", "/record")
                if case == "record"
                else ("/reconciliation-controls/", "/status")
            )
            path, api, status, code = (
                root + ref,
                root + ref + suffix,
                404,
                "reconciliation_not_found",
            )

        before = await snapshot(uses.world.db)
        api_response = await context.request.get(origin + api)
        assert api_response.status == status
        assert await api_response.json() == {"detail": code}

        response = await page.goto(origin + path)
        assert response is not None and response.status == status
        for name, value in CONSOLE_HEADERS.items():
            assert await response.header_value(name) == value
        await page.screenshot(path=tmp_path / f"recovery-{case}-{width}.png", full_page=True)
        await expect(page.locator("#console-recovery")).to_be_visible()
        await expect(page.locator("#console-recovery-action")).to_have_attribute(
            "href", "/activity"
        )
        await expect(page.locator("#reconciliation-choice")).to_have_count(0)
        await expect(page.locator(".activity-entry")).to_have_count(0)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert await snapshot(uses.world.db) == before


@pytest.mark.parametrize("width", [375, 1440])
async def test_session_expiring_during_settlement_read_redirects_and_clears_cookie(
    uses, browser, service, tmp_path, width
):
    origin, _, original, current = service
    target = origin + "/reconciliations/" + original.original.reconcile_ref
    db = uses.world.db
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await signed_in_page(uses, context, origin, current)
        before = await snapshot(db)
        navigation = None
        try:
            async with page.expect_response(lambda response: response.url == target) as observed:
                async with db.transaction() as gate:
                    pid = await gate.fetch_value("SELECT pg_backend_pid()")
                    await gate.fetch_value(
                        "SELECT installation_id FROM {{tables.installation_fences}} FOR UPDATE"
                    )
                    navigation = asyncio.create_task(page.goto(target))
                    # Observe the actual F6 wait, after S4 has admitted this
                    # request. Expire its persisted row before releasing F6;
                    # no wall-clock deadline, sleep or fabricated refusal.
                    async with asyncio.timeout(4):
                        while not await db.fetch_value(
                            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity"
                            " WHERE $1=ANY(pg_blocking_pids(pid)))",
                            pid,
                        ):
                            if navigation.done():
                                await navigation
                                pytest.fail("settlement read did not reach its F6 wait")
                            await asyncio.sleep(0.01)
                    await db.execute(
                        "UPDATE {{tables.console_sessions}}"
                        " SET expires_at=clock_timestamp()-interval '1 second' WHERE scope=$1",
                        current.scope,
                    )
                await navigation
            response = await observed.value
            await page.screenshot(path=tmp_path / f"recovery-session-{width}.png", full_page=True)
            assert response.status == 303
            assert await response.header_value("location") == "/login"
            assert "Max-Age=0" in (await response.header_value("set-cookie") or "")
            for name, value in CONSOLE_HEADERS.items():
                assert await response.header_value(name) == value
            await expect(page).to_have_url(origin + "/login")
            await expect(page.locator("#reconciliation-choice")).to_have_count(0)
            assert not any(cookie["name"] == COOKIE_NAME for cookie in await context.cookies())
            assert await snapshot(db) == before
        finally:
            if navigation is not None:
                if not navigation.done():
                    navigation.cancel()
                await asyncio.gather(navigation, return_exceptions=True)
