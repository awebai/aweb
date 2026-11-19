"""The shared recorder's enrolment fence, as the console passes it to B3: it
holds the installation's authority before B3's first statement, checks it
after the audit, and a refusal or an app failure leaves nothing behind."""

from __future__ import annotations

import asyncio
import dataclasses

import pytest
from aweb_naapp_testing.owner_acts import APP_ID, TEAM_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.runtime.passkeys import EnrolmentRefused
from tests.runtime.credential_audit.support import (
    CONTACT,
    ORIGIN,
    World,
    bind,
    designate,
    events,
)
from tests.runtime.credential_audit.test_credential_router import console


async def designated(world: World) -> tuple[str, str]:
    """A bound scope's reader, designated and holding an unused enrolment link."""
    scope = await bind(world)
    await designate(world, scope)
    return scope, world.inbox.enrolments[CONTACT][-1]


async def effect_state(world: World) -> list:
    """Everything a completed enrolment writes: the credential, the spent link,
    the approver and the signed event."""
    return [
        await world.db.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        for table in ("passkey_credentials", "passkey_enrolments", "passkey_approvers")
    ] + [await events(world)]


async def enrol(client, token: str, device: SoftAuthenticator):
    options = await client.post("/enrolment/options", json={"link_token": token})
    assert options.status_code == 200
    return await client.post(
        "/enrolment", json={"link_token": token, "credential": device.create(options.json())}
    )


async def test_the_fence_holds_installation_authority_before_b3_takes_any_lock(world: World):
    scope, token = await designated(world)
    subject = (await world.passkeys.designated_approver(scope)).subject
    registration = SoftAuthenticator(ORIGIN).create(await world.passkeys.enrolment_options(token))
    # As the console does: prepare (which refreshes the installation) first.
    prepared = await world.recorder.prepare_enrolment(token)
    async with world.db.transaction() as holder:
        # A concurrent refresh of the installation holds its fence row.
        await holder.fetch_one(
            "SELECT * FROM {{tables.installation_fences}} "
            "WHERE app_id=$1 AND team_id=$2 FOR UPDATE",
            APP_ID,
            TEAM_ID,
        )
        blocker = await holder.fetch_value("SELECT pg_backend_pid()")
        with world.recorder.prepared(prepared):
            completion = asyncio.create_task(
                world.passkeys.complete_enrolment(token, registration, fence=prepared)
            )
        async with asyncio.timeout(5):
            while not await world.db.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                "WHERE $1 = ANY(pg_blocking_pids(pid)))",
                blocker,
            ):
                if completion.done():
                    await completion
                    pytest.fail("the completion did not wait for the installation")
                await asyncio.sleep(0.01)
        # Waiting on the installation, the completion holds no B3 row.
        async with world.db.transaction() as observer:
            assert (
                await observer.fetch_value(
                    "SELECT subject FROM {{tables.passkey_approvers}} "
                    "WHERE subject=$1 FOR UPDATE NOWAIT",
                    subject,
                )
                == subject
            )
            assert await observer.fetch_value(
                "SELECT count(*) FROM (SELECT 1 FROM {{tables.passkey_enrolments}} "
                "WHERE subject=$1 FOR UPDATE NOWAIT) held",
                subject,
            )
    approver = await asyncio.wait_for(completion, 5)
    assert approver.scope == scope
    assert [fields["payload"]["act"] for _, fields in await events(world)] == [
        "role.designated",
        "credential.enrolled",
    ]


async def test_a_reinstall_before_the_completion_refuses_it_at_prepare(world: World):
    _, token = await designated(world)
    async with console(world) as client:
        options = await client.post("/enrolment/options", json={"link_token": token})
        registration = SoftAuthenticator(ORIGIN).create(options.json())
        before = await effect_state(world)
        prepared = await world.recorder.prepare_enrolment(token)
        # The team reinstalls the app between preparation and completion.
        async with world.db.transaction() as tx:
            await world.fence.admit(tx, dataclasses.replace(world.fence.grants.grant, generation=2))
        with world.recorder.prepared(prepared):
            with pytest.raises(EnrolmentRefused):
                await world.passkeys.complete_enrolment(token, registration, fence=prepared)
        assert await effect_state(world) == before
        refused = await client.post(
            "/enrolment", json={"link_token": token, "credential": registration}
        )
        assert (refused.status_code, refused.json()) == (403, {"detail": "enrolment_refused"})
    assert await effect_state(world) == before


async def test_authority_lost_while_the_effect_runs_refuses_at_check_and_rolls_back(
    world: World,
):
    _, token = await designated(world)
    # The installation's freshness lapses while the enrolment's event is
    # being written: after prepare, before check.
    await world.db.execute(
        "CREATE FUNCTION expire_enrolment_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await world.db.execute(
        "CREATE TRIGGER expire_enrolment_fence AFTER INSERT ON {{tables.outbox_events}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_enrolment_fence()"
    )
    device = SoftAuthenticator(ORIGIN)
    async with console(world) as client:
        before = await effect_state(world)
        refused = await enrol(client, token, device)
        assert (refused.status_code, refused.json()) == (403, {"detail": "enrolment_refused"})
        assert await effect_state(world) == before
        await world.db.execute("DROP TRIGGER expire_enrolment_fence ON {{tables.outbox_events}}")
        # The link was not spent: a fresh ceremony through it completes.
        enrolled = await enrol(client, token, device)
        assert enrolled.status_code == 200
    assert len(await events(world)) == len(before[-1]) + 1


async def test_an_app_failure_inside_the_effect_propagates_and_rolls_back(world: World):
    _, token = await designated(world)
    device = SoftAuthenticator(ORIGIN)
    async with console(world) as client:
        before = await effect_state(world)
        world.fail_after_enqueue[0] = True
        with pytest.raises(RuntimeError, match="could not append the event"):
            await enrol(client, token, device)
        assert await effect_state(world) == before
        world.fail_after_enqueue[0] = False
        enrolled = await enrol(client, token, device)
        assert enrolled.status_code == 200
    assert len(await events(world)) == len(before[-1]) + 1
