"""The shared credential cap of a role (human-credential.cap-set): an owner
act sets how many active credentials each holding of an app role may hold,
recorded as policy.changed under the act in the same transaction, or not at
all. Each holding still counts its own credentials. Real owner acts, real
recorder, real PostgreSQL."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime

import pytest
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.owner_act import CREDENTIAL_CAP_ACT
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.credential_caps import CapKey, CredentialCapRefused, CredentialCaps
from aweb_naapp.runtime.passkeys import CredentialPolicy
from tests.runtime.credential_audit.support import ROLE, World, events

ROLE_KEY = CapKey(APP_ID, INSTALLATION_ID, ROLE)


def cap_subject(cap: int, role: str = ROLE) -> dict:
    return {"app_id": APP_ID, "installation_id": INSTALLATION_ID, "role": role, "cap": cap}


async def caps_of(world: World, ceiling: int = 8) -> CredentialCaps:
    caps = CredentialCaps(
        world.db, recorder=world.recorder, ceiling=CredentialPolicy(max_active=ceiling)
    )
    await caps.migrate()
    return caps


async def set_cap(world: World, caps: CredentialCaps, cap: int) -> int:
    """The owner's cap-set act, consumed and applied in one fenced effect
    transaction under the recorder's prepared act."""
    owner = world.owner.for_acts((CREDENTIAL_CAP_ACT,))
    subject = cap_subject(cap)
    signing, signature = owner.sign(CREDENTIAL_CAP_ACT, subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    with world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            act = await owner.consume(tx, prepared, subject)
            result = await caps.set_cap(tx, evidence=act)
            await world.fence.check(tx, world.admitted)
    return result


async def stored(world: World) -> dict | None:
    return await world.db.fetch_one(
        "SELECT * FROM {{tables.credential_caps}} WHERE policy_key = $1", ROLE_KEY.policy_key
    )


async def resolved(world: World, caps: CredentialCaps) -> int | None:
    async with world.db.transaction() as tx:
        return await caps.resolve(tx, ROLE_KEY)


async def test_an_owner_act_sets_the_roles_cap_and_records_policy_changed(world: World):
    caps = await caps_of(world)
    assert await resolved(world, caps) is None
    before = len(await events(world))
    await set_cap(world, caps, 3)
    assert await resolved(world, caps) == 3
    [(_, fields)] = (await events(world))[before:]
    row = await stored(world)
    assert fields["payload"] == {
        **fields["payload"],
        "act": "policy.changed",
        "direction": "widening",
        "authority": "owner_act",
        "owner_act_sha256": row["act_ref"],
        "role": ROLE,
    }
    for absent in ("subject_ref", "cap", "approval_id", "approval_evidence_sha256", "resource_ref"):
        assert absent not in fields["payload"]
    assert fields["actor"]["authority_mode"] == "system"


async def test_lowering_is_a_widening_event_too_and_bumps_the_policy_version(world: World):
    caps = await caps_of(world)
    await set_cap(world, caps, 4)
    first = await stored(world)
    await set_cap(world, caps, 1)
    second = await stored(world)
    assert (second["cap"], second["policy_version"]) == (1, first["policy_version"] + 1)
    assert [fields["payload"]["direction"] for _, fields in (await events(world))[-2:]] == [
        "widening",
        "widening",
    ]


async def test_a_cap_above_the_ceiling_is_refused_and_nothing_is_written(world: World):
    caps = await caps_of(world, ceiling=5)
    before = len(await events(world))
    with pytest.raises(CredentialCapRefused) as refused:
        await set_cap(world, caps, 6)
    assert refused.value.reason == "cap_out_of_range"
    assert await stored(world) is None
    assert len(await events(world)) == before


async def test_protected_evidence_is_refused_until_its_effect_exists(world: World):
    caps = await caps_of(world)
    async with world.db.transaction() as tx:
        with pytest.raises(CredentialCapRefused) as refused:
            await caps.set_cap(tx, evidence=object())
    assert refused.value.reason == "protected_evidence_unavailable"


async def test_an_act_for_another_operation_is_refused(world: World):
    caps = await caps_of(world)
    owner = world.owner.for_acts(("human-role.revoke",))
    subject = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": ROLE,
        "principal": "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6",
    }
    signing, signature = owner.sign("human-role.revoke", subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    async with world.db.transaction() as tx:
        act = await owner.consume(tx, prepared, subject)
        with pytest.raises(CredentialCapRefused) as refused:
            await caps.set_cap(tx, evidence=act)
    assert refused.value.reason == "not_a_cap_act"


# The recorder binds the event to exactly the cap this transaction wrote


async def refused(world: World, write) -> None:
    """A consumed cap-set act whose cap row `write` writes wrongly in its
    transaction: the recorder refuses, and nothing is recorded."""
    await caps_of(world)
    owner = world.owner.for_acts((CREDENTIAL_CAP_ACT,))
    subject = cap_subject(3)
    signing, signature = owner.sign(CREDENTIAL_CAP_ACT, subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    before = len(await events(world))
    with pytest.raises(GovernanceUnavailable), world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            act = await owner.consume(tx, prepared, subject)
            await write(tx, hashlib.sha256(signing).hexdigest())
            await world.recorder.record_credential_cap(
                tx, act, ROLE_KEY, occurred_at=datetime.now(UTC)
            )
    assert await stored(world) is None
    assert len(await events(world)) == before


async def insert(tx: TransactionManager, *, cap: int, act_ref: str, set_in: str) -> None:
    await tx.execute(
        "INSERT INTO {{tables.credential_caps}} "
        f"(policy_key, cap, policy_version, act_ref, set_in, set_at) "
        f"VALUES ($1, $2, 1, $3, {set_in}, now())",
        ROLE_KEY.policy_key,
        cap,
        act_ref,
    )


async def test_the_recorder_records_the_cap_row_its_act_wrote(world: World):
    """The baseline the refusals below vary one fact of."""
    await caps_of(world)
    owner = world.owner.for_acts((CREDENTIAL_CAP_ACT,))
    subject = cap_subject(3)
    signing, signature = owner.sign(CREDENTIAL_CAP_ACT, subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    with world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            act = await owner.consume(tx, prepared, subject)
            await insert(
                tx, cap=3, act_ref=hashlib.sha256(signing).hexdigest(), set_in="txid_current()"
            )
            await world.recorder.record_credential_cap(
                tx, act, ROLE_KEY, occurred_at=datetime.now(UTC)
            )
    assert (await stored(world))["cap"] == 3


async def test_a_cap_row_not_written_in_this_transaction_is_refused(world: World):
    async def write(tx, act_ref):
        await insert(tx, cap=3, act_ref=act_ref, set_in="txid_current() - 1")

    await refused(world, write)


async def test_a_cap_row_under_another_act_is_refused(world: World):
    async def write(tx, act_ref):
        other = hashlib.sha256(b"another act").hexdigest()
        await insert(tx, cap=3, act_ref=other, set_in="txid_current()")

    await refused(world, write)


async def test_a_cap_row_with_another_value_is_refused(world: World):
    async def write(tx, act_ref):
        await insert(tx, cap=4, act_ref=act_ref, set_in="txid_current()")

    await refused(world, write)


async def test_a_cap_set_outside_the_recorders_act_is_refused(world: World):
    caps = await caps_of(world)
    owner = world.owner.for_acts((CREDENTIAL_CAP_ACT,))
    subject = cap_subject(3)
    signing, signature = owner.sign(CREDENTIAL_CAP_ACT, subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    with pytest.raises(GovernanceUnavailable):
        async with world.db.transaction() as tx:
            act = await owner.consume(tx, prepared, subject)
            await caps.set_cap(tx, evidence=act)
    assert await stored(world) is None


# Serialization with credential changes


async def test_a_resolver_read_waits_for_a_cap_change_in_flight(world: World):
    caps = await caps_of(world)
    await set_cap(world, caps, 4)
    reading = None
    try:
        async with world.db.transaction() as writer:
            await writer.fetch_value(
                "SELECT cap FROM {{tables.credential_caps}} WHERE policy_key = $1 FOR UPDATE",
                ROLE_KEY.policy_key,
            )
            await writer.execute(
                "UPDATE {{tables.credential_caps}} SET cap = 2 WHERE policy_key = $1",
                ROLE_KEY.policy_key,
            )
            reading = asyncio.create_task(resolved(world, caps))

            async def waiting() -> None:
                while not await world.db.fetch_value(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
                ):
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(waiting(), 10)
            assert not reading.done()
        assert await asyncio.wait_for(reading, 10) == 2
    finally:
        if reading is not None and not reading.done():
            reading.cancel()
