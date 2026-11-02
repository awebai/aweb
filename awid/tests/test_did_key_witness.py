"""did:aw key epochs are witnessed after the rotation's lock wait.

A registered child's issuer key is the parent key version current at its
registration (docs/id-certificates.md §3), so a parent rotation and a child
registration must serialize on the parent's mapping row, and the rotation's
log time must follow every conflicting event already serialized.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

from identity_support import register_identity, request_rotation, rotate_identity
from lock_waits import wait_until_blocked_on_lock

MICROSECOND = timedelta(microseconds=1)


def _keypair():
    signing_key, public_key = generate_keypair()
    return signing_key, did_from_public_key(public_key)


async def _log_times(awid_db_infra, did_aw):
    db = awid_db_infra.get_manager("aweb")
    rows = await db.fetch_all(
        "SELECT seq, created_at FROM {{tables.did_aw_log}} WHERE did_aw = $1 ORDER BY seq",
        did_aw,
    )
    return [(row["seq"], row["created_at"]) for row in rows]


@pytest.mark.asyncio
async def test_registration_and_rotation_times_come_from_the_tree_clock(
    clocked_client, awid_db_infra, manual_clock,
):
    key, did_key = _keypair()
    did_aw = stable_id_from_did_key(did_key)
    await register_identity(clocked_client, key, did_key)
    registered = manual_clock.now

    manual_clock.now += timedelta(minutes=10)
    _, new_did_key = _keypair()
    await rotate_identity(clocked_client, key, did_aw, did_key, new_did_key)

    assert await _log_times(awid_db_infra, did_aw) == [(1, registered), (2, manual_clock.now)]


@pytest.mark.asyncio
async def test_rotation_time_follows_the_previous_key_epoch(clocked_client, awid_db_infra, manual_clock):
    key, did_key = _keypair()
    did_aw = stable_id_from_did_key(did_key)
    await register_identity(clocked_client, key, did_key)
    registered = manual_clock.now

    manual_clock.now -= timedelta(minutes=10)
    _, new_did_key = _keypair()
    await rotate_identity(clocked_client, key, did_aw, did_key, new_did_key)

    assert await _log_times(awid_db_infra, did_aw) == [(1, registered), (2, registered + MICROSECOND)]


@pytest.mark.asyncio
async def test_rotation_waits_for_the_mapping_lock_and_witnesses_after_it(
    clocked_client, awid_db_infra, manual_clock,
):
    key, did_key = _keypair()
    did_aw = stable_id_from_did_key(did_key)
    await register_identity(clocked_client, key, did_key)
    manual_clock.now += timedelta(minutes=1)

    db = awid_db_infra.get_manager("aweb")
    _, new_did_key = _keypair()
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT did_aw FROM {{tables.did_aw_mappings}} WHERE did_aw = $1 FOR SHARE",
            did_aw,
        )
        rotation = asyncio.create_task(
            rotate_identity(clocked_client, key, did_aw, did_key, new_did_key)
        )
        await wait_until_blocked_on_lock(db, rotation)
        manual_clock.now += timedelta(minutes=5)
    await rotation

    assert (await _log_times(awid_db_infra, did_aw))[-1] == (2, manual_clock.now)


@pytest.mark.asyncio
async def test_concurrent_rotations_from_one_head_serialize_on_the_mapping(
    clocked_client, awid_db_infra,
):
    key, did_key = _keypair()
    did_aw = stable_id_from_did_key(did_key)
    await register_identity(clocked_client, key, did_key)

    db = awid_db_infra.get_manager("aweb")
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT did_aw FROM {{tables.did_aw_mappings}} WHERE did_aw = $1 FOR SHARE",
            did_aw,
        )
        rotations = [
            asyncio.create_task(request_rotation(clocked_client, key, did_aw, did_key, _keypair()[1]))
            for _ in range(2)
        ]
        gathered = asyncio.gather(*rotations)
        await wait_until_blocked_on_lock(db, gathered, waiters=2)
    responses = await gathered

    # The loser reads the rotated mapping after the lock: its signer is no
    # longer the current key.
    assert sorted(resp.status_code for resp in responses) == [200, 401]
    assert [seq for seq, _ in await _log_times(awid_db_infra, did_aw)] == [1, 2]
