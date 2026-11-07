"""The owner sees stalled audit delivery and audit events that were never delivered.

Every fault on the page comes from real outbox state: real signed hook events,
materialized and attempted by the shared kit's drain. Only the remote receivers'
answers are scripted, as the kit's own outbox tests script them. Unmaterialized
cancellation tombstones (hook-terminal-delivery, aweb-acgh.16.30) are not in the
kit yet, so no fault here is built from one.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    HookProducer,
    Registration,
    RegistrationView,
    ServerProducer,
    hook_targets,
)
from aweb_naapp.outbox import (
    Acked,
    Cancelled,
    Permanent,
    Retryable,
    RetryPolicy,
    acknowledge_dead_letters,
    drain,
)
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import expect

from aweb_secrets.broker_audit import _actor
from aweb_secrets.console_audit_delivery import ConsoleAuditDelivery, console_audit_delivery_router
from tests.test_change_sets import TEAM
from tests.test_console_access import DB_AGENT, DB_WRITE
from tests.test_console_access_browser import browser as _browser
from tests.test_console_access_browser import serving
from tests.test_console_access_browser import world as _world
from tests.test_console_access_states_browser import text_contrast
from tests.test_console_forms import enrolled_page

world = _world
browser = _browser

USE = "post-secret-use-hook"
GOVERNANCE = "post-governance-hook"
LOGS = "0b6f1e2a-4c3d-4e5f-8a9b-0c1d2e3f4a5b"
PRIMARY = "1c7a2f3b-5d4e-4f60-9b0c-1d2e3f4a5b6c"
SECONDARY = "2d8b3a4c-6e5f-4071-8c1d-2e3f4a5b6c7d"
BOUND = timedelta(hours=1)


class Registrations:
    """Core's registration answer for each hook: these bindings, or no view at all."""

    def __init__(self, bindings: dict[str, tuple[str, ...] | None]) -> None:
        self.bindings = bindings

    async def view(self, team_id: str, hook: str) -> RegistrationView | None:
        bindings = self.bindings.get(hook)
        if bindings is None:
            return None
        now = datetime.now(UTC)
        return RegistrationView(
            team_id=team_id,
            hook=hook,
            as_of=now,
            max_age=timedelta(seconds=60),
            registrations=tuple(
                Registration(
                    binding_id=binding,
                    origin="https://logs.example.com",
                    method="POST",
                    path="/hooks/ingest",
                    active_from=now - timedelta(days=1),
                )
                for binding in bindings
            ),
        )


class Receivers:
    """Each target's answer to each event it is sent; any other event is acknowledged."""

    def __init__(self) -> None:
        self.answers: dict[tuple[object, str], object] = {}

    async def deliver(self, event, target):
        return self.answers.get((event.event_id, target.id), Acked("delivered"))


def audit_pages(registrations):
    return lambda console: (
        console_audit_delivery_router(
            services=ConsoleAuditDelivery(
                console=console, registrations=registrations, max_backlog_age=BOUND
            )
        ),
    )


def producer() -> HookProducer:
    return HookProducer(
        ServerProducer.app(
            origin="https://secrets.example.com",
            app_id="secrets",
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="audit-delivery-test",
            seed=os.urandom(32),
        )
    )


async def refusal(db, use_producer, code: str):
    async with db.transaction() as tx:
        return await use_producer.enqueue_refusal(
            tx,
            team_id=TEAM,
            payload={"action": "refused", "op_kind": "broker", "refusal_code": code},
            actor=_actor(DB_AGENT),
            occurred_at=datetime.now(UTC),
        )


async def age(db, event_id, by: timedelta) -> None:
    await db.execute(
        "UPDATE {{tables.outbox_events}} SET created_at=created_at-$2 WHERE event_id=$1",
        event_id,
        by,
    )


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

            assert await text_contrast(use.locator(".audit-admission")) >= 4.5
            assert await text_contrast(page.locator(".audit-undelivered .audit-delivery")) >= 4.5
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
