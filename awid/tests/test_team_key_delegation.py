"""Team acts use the ID tree's real DNS, delegation and bounded status read."""

from __future__ import annotations
import pytest
from nacl.signing import SigningKey
from awid.team_key_acts import TeamKeyActError, verify_team_key_change
import team_key_delegation_support as support

world = support.world
controller_keypair = support.controller_keypair


async def verify(world, record=None):
    return await verify_team_key_change(
        record or await world.sdk.get_team_key_act(world.domain, "base"),
        domain=world.domain,
        name="base",
        team_did_key=world.team[1],
        pinned_at=None,
        resolver=world.resolver,
        fetch_namespace_evidence=world.sdk.namespace_evidence,
    )


@pytest.mark.asyncio
async def test_inherited_child_controller_act_uses_the_id_tree_evidence_path(world):
    act = await verify(world)
    assert act.signer_did_key == world.child[1]
    evidence = await world.sdk.namespace_evidence(world.domain)
    assert evidence.namespace_authority["controller_key"] == world.parent[1]
    assert (
        evidence.status["namespace"]["delegation"]["controller_key"] == world.child[1]
    )
    assert 0 <= evidence.age_seconds <= 60


@pytest.mark.asyncio
async def test_exact_dns_overrides_a_previously_valid_inherited_witness(world):
    await verify(world)
    world.dns.records["_awid." + world.domain] = controller_keypair()[1]
    with pytest.raises(TeamKeyActError):
        await verify(world)


@pytest.mark.asyncio
async def test_missing_delegation_never_authorises_the_child_act(world):
    await world.db.execute(
        "UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL, parent_controller_key=NULL WHERE domain=$1",
        world.domain,
    )
    with pytest.raises(TeamKeyActError):
        await verify(world)


@pytest.mark.asyncio
@pytest.mark.parametrize("apply", [False, True])
async def test_owner_inventory_backfill_is_explicit_idempotent_and_preserves_team_state(
    world, apply
):
    from awid.controller_signing import ControllerDescriptor
    from awid.team_key_backfill import TeamKeyBackfillTarget, reaffirm_team_keys

    await world.db.execute("DELETE FROM {{tables.team_key_acts}}")
    original = dict(await world.db.fetch_one("SELECT * FROM {{tables.teams}}"))
    controller = ControllerDescriptor(
        "namespace", world.domain, world.child[1], "local", 0
    )

    def signer(context):
        return world.child[1], SigningKey(world.child[0]).sign(
            context.signing_bytes()
        ).signature

    report = await reaffirm_team_keys(
        world.sdk,
        [TeamKeyBackfillTarget(world.domain, "base", world.team[1])],
        controllers={world.domain: controller},
        signer=signer,
        apply=apply,
        resolver=world.resolver,
    )
    assert report["before"] == {"total": 1, "ready": 0, "unready": 1, "conflicted": 0}
    assert report["after"]["ready"] == int(apply)
    assert dict(await world.db.fetch_one("SELECT * FROM {{tables.teams}}")) == original
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.team_certificates}}")
        == 0
    )
    if apply:
        again = await reaffirm_team_keys(
            world.sdk,
            [TeamKeyBackfillTarget(world.domain, "base", world.team[1])],
            controllers={world.domain: controller},
            signer=signer,
            apply=True,
            resolver=world.resolver,
        )
        assert again["before"]["ready"] == 1
        assert (
            await world.db.fetch_value("SELECT count(*) FROM {{tables.team_key_acts}}")
            == 1
        )


@pytest.mark.asyncio
async def test_rotated_controller_explicitly_reattests_kept_team_keys(world):
    from awid.controller_signing import ControllerDescriptor
    from awid.registry import RegistryError
    from awid.team_key_backfill import TeamKeyBackfillTarget, reaffirm_team_keys

    await verify(world)
    previous = await world.sdk.get_team_key_act(world.domain, "base")
    new = controller_keypair()

    def old_signer(payload):
        return world.child[1], SigningKey(world.child[0]).sign(payload).signature

    def new_signer(payload):
        return new[1], SigningKey(new[0]).sign(payload).signature

    await world.sdk.rotate_namespace_with_previous_key(
        world.domain,
        from_seq=1,
        previous_did_key=world.child[1],
        new_did_key=new[1],
        previous_signer=old_signer,
        new_signer=new_signer,
    )
    with pytest.raises(TeamKeyActError) as refused:
        await verify(world, previous)
    assert refused.value.reason == "signer_not_controller"
    with pytest.raises(RegistryError) as refused_write:
        await world.sdk.rotate_team_key(
            world.domain,
            "base",
            new_team_did_key=world.team[1],
            namespace_controller_signing_key=world.child[0],
        )
    assert refused_write.value.status_code == 403
    descriptor = ControllerDescriptor("namespace", world.domain, new[1], "local", 0)
    report = await reaffirm_team_keys(
        world.sdk,
        [TeamKeyBackfillTarget(world.domain, "base", world.team[1])],
        controllers={world.domain: descriptor},
        signer=lambda context: new_signer(context.signing_bytes()),
        apply=True,
        resolver=world.resolver,
    )
    assert report["after"]["ready"] == 1
    assert (await verify(world)).signer_did_key == new[1]


@pytest.mark.asyncio
async def test_pin_memo_does_not_extend_an_aged_id_tree_witness(world):
    from dataclasses import replace
    from awid.team_key_acts import MemoryTeamKeyPins, TeamKeyMemo, pinned_team_key

    elapsed = [0.0]
    memo = TeamKeyMemo(clock=lambda: elapsed[0])
    pins = MemoryTeamKeyPins()
    team_id = "base:" + world.domain
    await pins.first_sight(team_id, world.parent[1])
    evidence = await world.sdk.namespace_evidence(world.domain)

    async def aged(domain):
        assert domain == world.domain
        return replace(evidence, age_seconds=59)

    async def act():
        return await world.sdk.get_team_key_act(world.domain, "base")

    assert (
        await pinned_team_key(
            team_id,
            world.team[1],
            pins=pins,
            fetch_act=act,
            resolver=world.resolver,
            enforce=True,
            fetch_namespace_evidence=aged,
            memo=memo,
        )
        == world.team[1]
    )
    assert memo.get(team_id, world.team[1]) == world.team[1]
    elapsed[0] = 2
    assert memo.get(team_id, world.team[1]) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "rotate"])
async def test_controller_change_waits_for_the_authorised_team_transaction(
    world, operation
):
    import asyncio
    from lock_waits import wait_until_blocked_on_lock

    new_controller = controller_keypair()
    next_team = controller_keypair()[1]

    async def team_write():
        if operation == "create":
            return await world.sdk.register_team(
                domain=world.domain,
                name="concurrent",
                display_name="Concurrent",
                team_did_key=next_team,
                visibility="public",
                namespace_controller_signing_key=world.child[0],
            )
        return await world.sdk.rotate_team_key(
            world.domain,
            "base",
            new_team_did_key=next_team,
            namespace_controller_signing_key=world.child[0],
        )

    def old_signer(payload):
        return world.child[1], SigningKey(world.child[0]).sign(payload).signature

    def new_signer(payload):
        return new_controller[1], SigningKey(new_controller[0]).sign(payload).signature

    team_task = controller_task = None
    try:
        async with world.db.transaction() as blocker:
            await blocker.execute("LOCK TABLE {{tables.teams}} IN SHARE MODE")
            team_task = asyncio.create_task(team_write())
            await wait_until_blocked_on_lock(world.db, team_task)
            controller_task = asyncio.create_task(
                world.sdk.rotate_namespace_with_previous_key(
                    world.domain,
                    from_seq=1,
                    previous_did_key=world.child[1],
                    new_did_key=new_controller[1],
                    previous_signer=old_signer,
                    new_signer=new_signer,
                )
            )
            await wait_until_blocked_on_lock(world.db, controller_task, waiters=2)
        await asyncio.wait_for(team_task, 10)
        await asyncio.wait_for(controller_task, 10)
        assert (
            await world.db.fetch_value(
                "SELECT controller_did FROM {{tables.dns_namespaces}} WHERE domain=$1",
                world.domain,
            )
            == new_controller[1]
        )
        name = "concurrent" if operation == "create" else "base"
        record = await world.sdk.get_team_key_act(world.domain, name)
        assert record["team_did_key"] == next_team
        assert record["signer_did_key"] == world.child[1]
    finally:
        for task in (team_task, controller_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (team_task, controller_task) if task is not None),
            return_exceptions=True,
        )


@pytest.mark.asyncio
async def test_backfill_concurrent_rotation_reports_conflict_without_restoring_inventory_key(
    world,
):
    from awid.controller_signing import ControllerDescriptor
    from awid.team_key_backfill import TeamKeyBackfillTarget, reaffirm_team_keys

    await world.db.execute("DELETE FROM {{tables.team_key_acts}}")
    other_key = controller_keypair()[1]
    raced = False

    async def signer(context):
        nonlocal raced
        assert not raced
        raced = True
        await world.sdk.rotate_team_key(
            world.domain,
            "base",
            new_team_did_key=other_key,
            namespace_controller_signing_key=world.child[0],
        )
        return world.child[1], SigningKey(world.child[0]).sign(
            context.signing_bytes()
        ).signature

    descriptor = ControllerDescriptor(
        "namespace", world.domain, world.child[1], "local", 0
    )
    report = await reaffirm_team_keys(
        world.sdk,
        [TeamKeyBackfillTarget(world.domain, "base", world.team[1])],
        controllers={world.domain: descriptor},
        signer=signer,
        apply=True,
        resolver=world.resolver,
    )
    assert report["after"] == {"total": 1, "ready": 0, "unready": 0, "conflicted": 1}
    assert (await world.sdk.get_team_key_act(world.domain, "base"))[
        "team_did_key"
    ] == other_key
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.team_key_acts}}") == 1
    )
