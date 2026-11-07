"""Only the installation's current owner reads audit delivery faults.

Also the shared fixtures of the audit delivery tests: core's registration
answers, the remote receivers' answers, and real signed hook refusals.
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
from aweb_naapp.outbox import Acked, Cancelled, RetryPolicy, drain
from aweb_naapp.roles import unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.broker_audit import _actor
from aweb_secrets.console_audit_delivery import ConsoleAuditDelivery, console_audit_delivery_router
from aweb_secrets.owners import OWNER_ROLE, approver_scope, owner_scope
from tests.test_change_sets import ALICE, TEAM
from tests.test_console_access import DB_AGENT, access, clients  # noqa: F401
from tests.test_console_access import uses as _uses
from tests.test_console_access import world as _world
from tests.test_console_changes import sign_in
from tests.test_use_approvals import designate

world = _world
uses = _uses

USE = "post-secret-use-hook"
GOVERNANCE = "post-governance-hook"
LOGS = "0b6f1e2a-4c3d-4e5f-8a9b-0c1d2e3f4a5b"
PRIMARY = "1c7a2f3b-5d4e-4f60-9b0c-1d2e3f4a5b6c"
SECONDARY = "2d8b3a4c-6e5f-4071-8c1d-2e3f4a5b6c7d"
BOUND = timedelta(hours=1)
ORIGINS = {
    LOGS: "https://logs.example.com",
    PRIMARY: "https://logs.example.com",
    SECONDARY: "https://archive.example.net",
}


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
                    origin=ORIGINS[binding],
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
        "UPDATE {{tables.outbox_events}} SET created_at=created_at-$2::interval WHERE event_id=$1",
        event_id,
        by,
    )


async def cancelled_refusal(db) -> object:
    """A real critical refusal whose only delivery was cancelled: a fault."""
    registrations = Registrations({USE: (LOGS,)})
    event_id = await refusal(db, producer(), "grant_revoked")
    receivers = Receivers()
    receivers.answers[(event_id, LOGS)] = Cancelled("binding_revoked")
    await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(registrations),
        transport=receivers,
        policy=RetryPolicy(stalled_after=BOUND),
    )
    return event_id


async def test_only_a_current_owner_reads_audit_delivery_on_the_human_origin(access):  # noqa: F811
    db = access.world.db
    fault = await cancelled_refusal(db)
    pages = audit_pages(Registrations({USE: (LOGS,), GOVERNANCE: (PRIMARY,)}))
    await designate(access, "finance", "finance@acme.com")
    async with clients(access, pages=pages) as (human, agent):
        assert (await human.get("/audit-delivery")).status_code == 303
        assert (await agent.get("/audit-delivery")).status_code == 404
        # An approver's console session is not the owner's.
        await sign_in(
            access.world,
            human,
            approver_scope(INSTALLATION_ID, TEAM, "finance"),
            "finance@acme.com",
        )
        refused = await human.get("/audit-delivery")
        assert refused.status_code == 403
        assert str(fault) not in refused.text and LOGS not in refused.text
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        shown = await human.get("/audit-delivery")
        assert shown.status_code == 200 and str(fault) in shown.text
        async with db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        withdrawn = await human.get("/audit-delivery")
        assert withdrawn.status_code in (303, 401, 403)
        assert str(fault) not in withdrawn.text and LOGS not in withdrawn.text


async def test_an_owner_withdrawal_under_the_read_hides_every_fault(access):  # noqa: F811
    db = access.world.db
    fault = await cancelled_refusal(db)
    pages = audit_pages(Registrations({USE: (LOGS,), GOVERNANCE: (PRIMARY,)}))
    async with clients(access, pages=pages) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        holding, release = asyncio.Event(), asyncio.Event()

        async def withdraw():
            async with db.transaction() as tx:
                await unassign(tx, ALICE, OWNER_ROLE)
                holding.set()
                await release.wait()

        withdrawal = asyncio.create_task(withdraw())
        await holding.wait()
        read = asyncio.create_task(human.get("/audit-delivery"))
        for _ in range(500):
            if await db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()"
                " AND wait_event_type='Lock' AND query LIKE '%role_assignments%FOR SHARE%')"
            ):
                break
            await asyncio.sleep(0.01)
        else:
            release.set()
            await asyncio.gather(withdrawal, read, return_exceptions=True)
            pytest.fail("the read did not reach the owner role hold")
        release.set()
        await withdrawal
        refused = await asyncio.wait_for(read, 5)
    assert refused.status_code == 409 and refused.headers["retry-after"] == "0"
    assert str(fault) not in refused.text and LOGS not in refused.text
