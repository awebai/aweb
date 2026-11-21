"""The shared recorder's enrolment fence, as the console passes it to B3: it
holds the installation's authority before B3's first statement, checks it
after the audit, and a refusal or an app failure leaves nothing behind."""

from __future__ import annotations

import asyncio
import dataclasses
import time

import pytest
from aweb_naapp_testing.owner_acts import APP_ID, TEAM_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.runtime.clock import seconds_to_ns
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
        await world.db.fetch_all("SELECT * FROM {{tables.passkey_credentials}} ORDER BY 1"),
        await world.db.fetch_all("SELECT * FROM {{tables.passkey_enrolments}} ORDER BY 1"),
        await world.db.fetch_all("SELECT * FROM {{tables.passkey_approvers}} ORDER BY 1"),
        await events(world),
    ]


async def enrol(client, token: str, device: SoftAuthenticator):
    options = await client.post("/enrolment/options", json={"link_token": token})
    assert options.status_code == 200
    return await client.post(
        "/enrolment", json={"link_token": token, "credential": device.create(options.json())}
    )


async def test_the_fence_holds_installation_authority_before_b3_takes_any_lock(world: World):
    scope, token = await designated(world)
    # Designated but not yet enrolled: read the scope's live approver row.
    subject = await world.db.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=$1 AND superseded_at IS NULL",
        scope,
    )
    assert subject is not None
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
        try:
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
        except BaseException:
            completion.cancel()
            await asyncio.gather(completion, return_exceptions=True)
            raise
    # The holder is released; only now may the completion go on.
    try:
        approver = await asyncio.wait_for(completion, 5)
    finally:
        if not completion.done():
            completion.cancel()
            await asyncio.gather(completion, return_exceptions=True)
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
        # A fresh ceremony, so that only the installation can refuse it.
        refused = await enrol(client, token, SoftAuthenticator(ORIGIN))
        assert (refused.status_code, refused.json()) == (403, {"detail": "enrolment_refused"})
    assert await effect_state(world) == before


async def test_authority_lapsing_while_the_effect_runs_refuses_at_check_and_rolls_back(
    world: World,
):
    _, token = await designated(world)
    grants = world.fence.grants
    standing = grants.grant
    # The server answers with authority fresh for two seconds only.
    grants.grant = dataclasses.replace(standing, fresh_until=time.monotonic_ns() + seconds_to_ns(2))

    async def slow_work() -> None:
        # The effect's work outlasts that authority, after prepare.
        while time.monotonic_ns() <= grants.grant.fresh_until + 500_000_000:
            await asyncio.sleep(0.1)

    device = SoftAuthenticator(ORIGIN)
    async with console(world) as client:
        before, handed = await effect_state(world), len(world.handed)
        world.pause_after_enqueue[0] = slow_work
        refused = await enrol(client, token, device)
        world.pause_after_enqueue[0] = None
        assert (refused.status_code, refused.json()) == (403, {"detail": "enrolment_refused"})
        # The effect reached its event before the refusal: it was check that refused.
        assert len(world.handed) == handed + 1
        assert await effect_state(world) == before
        # Fresh authority again; the link was not spent and a fresh ceremony completes.
        grants.grant = dataclasses.replace(
            standing, fresh_until=time.monotonic_ns() + seconds_to_ns(55)
        )
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
