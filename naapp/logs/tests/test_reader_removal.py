"""A team member removes a reader by team authority alone (audit-substrate.md
§B5), on real PostgreSQL with a real AWID registry, real owner acts and a
software passkey.

The removal is containment (human-role-holders.md): it retires the reader's
credential, so the reader can no longer sign in, and appends logs' own signed
``role.revoked`` event, naming the member's team certificate as its authority,
in one transaction. The holding continues until the owner replaces the
credential or revokes it. Team authority alone never removes the last current
reader of an installation: that takes the owner's act. Concurrent removals,
by members or by the owner, are counted against the same reader set, so
together they cannot leave the installation without a reader.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from aweb_naapp.runtime.team_auth import Principal
from aweb_naapp_testing.owner_acts import INSTALLATION_ID, TEAM_ID
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_logs.readers import READER_ROLE, RemovalRefused

from .reader_world import (
    OTHER_READER,
    World,
    chained,
    held_reader,
    holder,
    reader_scope,
    replaced_reader,
    revoked_reader,
    world_fixture,  # noqa: F401
)


def member(team_id: str = TEAM_ID) -> Principal:
    key = bytes(SigningKey.generate().verify_key)
    return Principal(
        team_id=team_id,
        did_key=did_from_public_key(key),
        did_aw=stable_id_from_public_key(key),
        address=None,
        alias="member",
        certificate_id="cert-member",
        team_did_key="did:key:z6MkteamKey",
    )


async def current(world: World) -> list[str]:
    return [
        reader.scope
        for reader in await world.directory.current_readers(
            installation_id=INSTALLATION_ID, team_id=TEAM_ID
        )
    ]


async def test_a_member_removes_a_reader_on_logs_own_chain(world: World):
    kept, _ = await held_reader(world)
    removed, reader = await held_reader(world, OTHER_READER)
    remover = member()
    await world.removals.remove(principal=remover, grant=world.grant, scope=removed)
    assert await holder(world, removed) is None
    assert await world.directory.reader(removed) is None
    assert await current(world) == [kept]
    entry = (await chained(world))[-1]
    assert entry["payload"] == {
        "act": "role.revoked",
        "direction": "narrowing",
        "role": READER_ROLE,
        "subject_ref": reader,
        "authority": "team_cert",
    }
    assert entry["actor"]["authority_mode"] == "team_cert"
    assert entry["actor"]["did_key"] == remover.did_key


async def test_a_removed_readers_holding_continues_until_the_owner_acts(world: World):
    await held_reader(world)
    removed, _ = await held_reader(world, OTHER_READER)
    await world.removals.remove(principal=member(), grant=world.grant, scope=removed)
    assert not await world.directory.is_current_reader(removed)
    assert await world.directory.record(removed) is not None
    # Still held: the owner replaces its credential, or revokes it.
    await replaced_reader(world, OTHER_READER)
    await revoked_reader(world, OTHER_READER)


async def test_a_member_cannot_remove_the_last_reader(world: World):
    scope, reader = await held_reader(world)
    before = await chained(world)
    with pytest.raises(RemovalRefused) as refused:
        await world.removals.remove(principal=member(), grant=world.grant, scope=scope)
    assert refused.value.code == "last_reader_protected"
    assert await holder(world, scope) == reader
    assert await chained(world) == before


async def test_a_reader_who_cannot_sign_in_does_not_protect_the_last_one_who_can(
    world: World,
):
    """A reader whose credential is being replaced holds the role but cannot
    sign in until the cooling-off ends, so it does not keep the installation
    readable."""
    replacing, _ = await held_reader(world, OTHER_READER)
    await replaced_reader(world, OTHER_READER)
    scope, reader = await held_reader(world)
    with pytest.raises(RemovalRefused) as refused:
        await world.removals.remove(principal=member(), grant=world.grant, scope=scope)
    assert refused.value.code == "last_reader_protected"
    assert await holder(world, scope) == reader
    # The holding that cannot read yet is removable while one who can remains.
    await world.removals.remove(principal=member(), grant=world.grant, scope=replacing)
    assert await world.directory.reader(replacing) is None
    assert await current(world) == [scope]


async def test_a_reader_the_owner_revoked_no_longer_counts(world: World):
    await held_reader(world)
    remaining, reader = await held_reader(world, OTHER_READER)
    await revoked_reader(world)
    with pytest.raises(RemovalRefused) as refused:
        await world.removals.remove(principal=member(), grant=world.grant, scope=remaining)
    assert refused.value.code == "last_reader_protected"
    assert await holder(world, remaining) == reader


@pytest.mark.parametrize("named", ["revoked holding", "never held", "no reader scope"])
async def test_a_scope_that_is_no_current_reader_is_removed_by_nobody(world: World, named):
    await held_reader(world)
    revoked, _ = await held_reader(world, OTHER_READER)
    await held_reader(world, "did:aw:4Ys9oZp6nR2tV3xA7bC1dE5fG8")
    if named == "revoked holding":
        await revoked_reader(world, OTHER_READER)
        scope = revoked
    elif named == "never held":
        scope = reader_scope("did:aw:5Zt1pAq7oS3uW4yB8cD2eF6gH9")
    else:
        scope = "logs.reader." + "0" * 32
    before = await chained(world)
    with pytest.raises(RemovalRefused) as refused:
        await world.removals.remove(principal=member(), grant=world.grant, scope=scope)
    assert refused.value.code == "reader_unknown"
    assert await chained(world) == before


async def test_a_member_of_another_team_removes_nobody(world: World):
    await held_reader(world)
    scope, reader = await held_reader(world, OTHER_READER)
    with pytest.raises(RemovalRefused):
        await world.removals.remove(
            principal=member("another-team"), grant=world.grant, scope=scope
        )
    assert await holder(world, scope) == reader


async def held_open(world: World) -> tuple[asyncio.Event, asyncio.Event]:
    """Hold the next governance transaction open just before logs appends its
    event: returns (entered, release)."""
    entered, release = asyncio.Event(), asyncio.Event()
    first = [True]

    async def gate() -> None:
        if first[0]:
            first[0] = False
            entered.set()
            await release.wait()

    world.before_append = gate
    return entered, release


async def race(world: World, first, second) -> list[Any]:
    entered, release = await held_open(world)
    started = asyncio.create_task(first())
    await asyncio.wait_for(entered.wait(), 10)
    racing = asyncio.create_task(second())
    # Let the second change run as far as it can while the first is open.
    await asyncio.sleep(0.5)
    release.set()
    return list(await asyncio.gather(started, racing, return_exceptions=True))


async def test_concurrent_member_removals_leave_a_reader(world: World):
    first, _ = await held_reader(world)
    second, _ = await held_reader(world, OTHER_READER)
    results = await race(
        world,
        lambda: world.removals.remove(principal=member(), grant=world.grant, scope=first),
        lambda: world.removals.remove(principal=member(), grant=world.grant, scope=second),
    )
    assert results[0] is None
    assert isinstance(results[1], RemovalRefused)
    assert results[1].code == "last_reader_protected"
    assert await current(world) == [second]


async def test_a_member_removal_racing_the_owners_revocation_leaves_a_reader(world: World):
    await held_reader(world)
    remaining, _ = await held_reader(world, OTHER_READER)
    results = await race(
        world,
        lambda: revoked_reader(world),
        lambda: world.removals.remove(principal=member(), grant=world.grant, scope=remaining),
    )
    assert results[0] is None
    assert isinstance(results[1], RemovalRefused)
    assert await current(world) == [remaining]
    entries = await chained(world)
    revoked = [e for e in entries if e["payload"].get("authority") != "team_cert"][-1]
    assert "owner_act_sha256" in revoked["payload"]
    assert [e["payload"].get("authority") for e in entries].count("team_cert") == 0
