"""The owner sees stalled audit delivery and audit events that were never delivered.

Every fault on the page comes from real outbox state: real signed hook events,
materialized and attempted by the shared kit's drain. Only the remote receivers'
answers are scripted, as the kit's own outbox tests script them. Unmaterialized
cancellation tombstones (hook-terminal-delivery, aweb-acgh.16.30) are not in the
kit yet, so no fault here is built from one.
"""

import asyncio

import pytest
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, hook_targets
from aweb_naapp.outbox import (
    Acked,
    Cancelled,
    Permanent,
    Retryable,
    RetryPolicy,
    acknowledge_dead_letters,
    drain,
)
from playwright.async_api import expect

from tests.test_console_access import DB_WRITE
from tests.test_console_access_browser import browser as _browser
from tests.test_console_access_browser import serving
from tests.test_console_access_browser import world as _world
from tests.test_console_access_states_browser import text_contrast
from tests.test_console_audit_delivery import (
    BOUND,
    GOVERNANCE,
    LOGS,
    PRIMARY,
    SECONDARY,
    USE,
    Receivers,
    Registrations,
    age,
    audit_pages,
    producer,
    refusal,
)
from tests.test_console_forms import enrolled_page

world = _world
browser = _browser


async def revoke_db_write(page, origin):
    await page.goto(origin + "/access")
    page.once("dialog", lambda dialog: asyncio.ensure_future(dialog.accept()))
    await page.locator(f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"] .access-revoke').click()
    await expect(page.locator(f'.access-grant[data-grant-id="{DB_WRITE.grant_id}"]')).to_have_count(
        0
    )


@pytest.mark.parametrize("width", [375, 1440])
async def test_the_owner_sees_which_audit_target_stalls_and_which_events_were_never_delivered(
    world, browser, tmp_path, width
):
    registrations = Registrations({USE: (LOGS,), GOVERNANCE: (PRIMARY, SECONDARY)})
    async with serving(world, pages=audit_pages(registrations)) as (_, origin):
        db = world.db
        async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
            page, _, _ = await enrolled_page(world, context, origin)
            # A real narrowing writes the governance event both governance targets are owed.
            before = await db.fetch_value(
                "SELECT coalesce(max(position), 0) FROM {{tables.outbox_events}}"
            )
            await revoke_db_write(page, origin)
            narrowed = await db.fetch_value(
                "SELECT event_id FROM {{tables.outbox_events}} WHERE kind=$1 AND position>$2",
                GOVERNANCE,
                before,
            )
            use_producer = producer()
            cancelled = await refusal(db, use_producer, "grant_revoked")
            rejected = await refusal(db, use_producer, "operation_not_allowed")
            waiting = await refusal(db, use_producer, "policy_rate_limited")
            receivers = Receivers()
            receivers.answers.update(
                {
                    (narrowed, PRIMARY): Acked("delivered"),
                    (narrowed, SECONDARY): Retryable("unavailable"),
                    (cancelled, LOGS): Cancelled("binding_revoked"),
                    (rejected, LOGS): Permanent("schema_rejected"),
                    (waiting, LOGS): Retryable("unavailable"),
                }
            )
            await drain(
                db,
                channel=HOOKS_CHANNEL,
                resolver=hook_targets(registrations),
                transport=receivers,
                policy=RetryPolicy(stalled_after=BOUND, rejected_after_attempts=1),
            )
            assert await acknowledge_dead_letters(db, LOGS, [rejected]) == [rejected]
            # Both still-owed events have waited past the backlog bound.
            for event_id in (narrowed, waiting):
                await age(db, event_id, 2 * BOUND)

            await page.goto(origin + "/audit-delivery")
            use = page.locator(f'.audit-hook[data-hook="{USE}"]')
            governance = page.locator(f'.audit-hook[data-hook="{GOVERNANCE}"]')
            # Its only target is stalled, so secret uses are being refused.
            await expect(use).to_have_attribute("data-admission", "refused")
            await expect(use.locator(f'.audit-target[data-binding-id="{LOGS}"]')).to_have_attribute(
                "data-stalled", "true"
            )
            # A stalled secondary does not block widening while the primary is current.
            await expect(governance).to_have_attribute("data-admission", "open")
            await expect(
                governance.locator(f'.audit-target[data-binding-id="{SECONDARY}"]')
            ).to_have_attribute("data-stalled", "true")
            await expect(
                governance.locator(f'.audit-target[data-binding-id="{PRIMARY}"]')
            ).to_have_attribute("data-stalled", "false")

            undelivered = page.locator(".audit-undelivered")
            await expect(undelivered).to_have_count(2)
            await expect(
                page.locator(
                    f'.audit-undelivered[data-event-id="{cancelled}"]'
                    f' .audit-delivery[data-binding-id="{LOGS}"]'
                )
            ).to_have_attribute("data-state", "cancelled")
            rejected_delivery = page.locator(
                f'.audit-undelivered[data-event-id="{rejected}"]'
                f' .audit-delivery[data-binding-id="{LOGS}"]'
            )
            await expect(rejected_delivery).to_have_attribute("data-state", "rejected")
            await expect(rejected_delivery).to_have_attribute("data-acknowledged", "true")
            # Still being retried, and the narrowing reached its primary: neither is lost.
            for owed in (waiting, narrowed):
                await expect(page.locator(f'[data-event-id="{owed}"]')).to_have_count(0)

            for scheme in ("light", "dark"):
                await page.emulate_media(color_scheme=scheme)
                for badge in (
                    use.locator(".audit-admission .pill"),
                    use.locator(".audit-target .pill"),
                    page.locator(".audit-undelivered .pill"),
                ):
                    assert await text_contrast(badge) >= 4.5, scheme
                assert await text_contrast(page.locator(".audit-delivery")) >= 4.5, scheme
            await page.emulate_media(color_scheme="light")
            await page.screenshot(path=tmp_path / f"audit-delivery-{width}.png", full_page=True)
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")


async def test_a_hook_without_a_registration_view_is_shown_as_unknown_not_healthy(
    world, browser, tmp_path
):
    registrations = Registrations({USE: (LOGS,), GOVERNANCE: None})
    async with serving(world, pages=audit_pages(registrations)) as (_, origin):
        async with await browser.new_context(viewport={"width": 375, "height": 1000}) as context:
            page, _, _ = await enrolled_page(world, context, origin)
            await page.goto(origin + "/audit-delivery")
            await expect(page.locator(f'.audit-hook[data-hook="{USE}"]')).to_have_attribute(
                "data-admission", "open"
            )
            await expect(
                page.locator(f'.audit-target[data-binding-id="{LOGS}"]')
            ).to_have_attribute("data-stalled", "false")
            # Core gave no view: widening acts are refused with audit_target_unavailable.
            await expect(page.locator(f'.audit-hook[data-hook="{GOVERNANCE}"]')).to_have_attribute(
                "data-admission", "unavailable"
            )
            await expect(page.locator(".audit-undelivered")).to_have_count(0)
            await page.screenshot(path=tmp_path / "audit-delivery-clear.png", full_page=True)
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
