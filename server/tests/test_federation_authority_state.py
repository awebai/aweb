from __future__ import annotations

import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest

from aweb.federation.authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    CheckpointCandidate,
)
from aweb.federation.authority_work import AuthorityWorkRepository
from awid.federation_errors import FederationAuthorityError


DID = "did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2"
KEY1 = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
KEY2 = "did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG"
HASH1 = "85aef12d9351bb914c9dafcce9628500efa6ef8fc7c53b557dae53e7b0c65e45"
STATE1 = "a2454771bd0be7cc02175b27a8ae74ebbd9defe13864f9e0c82a90b74c1778ac"
HASH2 = "2461cc5185dfb0d3836241574aca5927db2925069bd4a10216613a87b54351c0"
STATE2 = "f757dacbf0e5c5a90f1f555067aad6d7bf9760c2daefcffd90452bf28c289f8b"
ADDRESS = "alpha.example.com/Alice"


def checkpoint1() -> CheckpointCandidate:
    return CheckpointCandidate(
        did_aw=DID,
        seq=1,
        entry_hash=HASH1,
        state_hash=STATE1,
        current_did_key=KEY1,
        contains_snapshot=True,
        expected_revision=None,
        expected_entry_hash=None,
    )


def checkpoint2() -> CheckpointCandidate:
    return CheckpointCandidate(
        did_aw=DID,
        seq=2,
        entry_hash=HASH2,
        state_hash=STATE2,
        current_did_key=KEY2,
        contains_snapshot=True,
        expected_revision=1,
        expected_entry_hash=HASH1,
    )


def cohort(*, address: str = ADDRESS, key: str = KEY1, checkpoint_seq: int = 1, checkpoint_hash: str = HASH1, checkpoint_revision: int = 1, fence: int = 1) -> AddressAuthorityCandidate:
    return AddressAuthorityCandidate(
        canonical_address=address,
        authority_selection="dns",
        authority_name="_awid.alpha.example.com",
        controller_did=KEY1,
        authority_statement_version="aweb.federation-authority.dns.v1",
        authority_statement_digest="sha256:" + "a" * 64,
        inherited=False,
        registry_explicit=True,
        registry_origin="https://registry-a.example",
        address_id="addr-alpha-alice",
        bound_did_aw=DID,
        bound_current_did_key=key,
        checkpoint_seq=checkpoint_seq,
        checkpoint_entry_hash=checkpoint_hash,
        checkpoint_revision=checkpoint_revision,
        authoritative_delivery_origin="https://aweb-alpha.example",
        publishing_fence=fence,
        reuse_seconds=60,
    )


@pytest.mark.asyncio
async def test_phase_a_first_insert_idempotence_and_fast_path(aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    first = await repository.commit_phase_a(checkpoint1(), cohort())
    assert first.checkpoint_revision == 1
    assert first.cohort_generation == 1

    same = await repository.commit_phase_a(checkpoint1(), cohort())
    assert same.checkpoint_revision == 1
    assert same.cohort_generation == 1

    fast = await repository.authorize_from_cohort(
        canonical_address=ADDRESS,
        did_aw=DID,
        current_did_key=KEY1,
        delivery_origin="https://aweb-alpha.example",
    )
    assert fast == same


@pytest.mark.asyncio
async def test_checkpoint_advance_invalidates_peer_address_and_replaces_whole_tuple(aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    await repository.commit_phase_a(checkpoint1(), cohort())
    await repository.commit_phase_a(
        checkpoint1(),
        cohort(address="beta.example.com/Alice"),
    )

    token = await repository.commit_phase_a(
        checkpoint2(),
        replace(
            cohort(),
            bound_current_did_key=KEY2,
            checkpoint_seq=2,
            checkpoint_entry_hash=HASH2,
            checkpoint_revision=2,
            registry_origin="https://registry-b.example",
            authority_statement_digest="sha256:" + "b" * 64,
            publishing_fence=2,
        ),
    )
    assert token.checkpoint_revision == 2
    assert token.cohort_generation == 2
    peer = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT expires_at <= clock_timestamp() AS expired, generation FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address = $1",
        "beta.example.com/Alice",
    )
    assert peer["expired"] is True
    assert peer["generation"] == 2


@pytest.mark.asyncio
async def test_checkpoint_rejects_rollback_split_view_and_missing_containment(aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    await repository.commit_phase_a(checkpoint1(), cohort())

    fork = replace(checkpoint1(), entry_hash="a" * 64, state_hash="b" * 64)
    with pytest.raises(FederationAuthorityError) as split:
        await repository.commit_phase_a(
            fork,
            replace(
                cohort(),
                checkpoint_entry_hash=fork.entry_hash,
            ),
        )
    assert split.value.reason == "sender_did_log_split_view"

    await repository.commit_phase_a(
        checkpoint2(),
        replace(
            cohort(),
            bound_current_did_key=KEY2,
            checkpoint_seq=2,
            checkpoint_entry_hash=HASH2,
            checkpoint_revision=2,
            publishing_fence=2,
        ),
    )
    with pytest.raises(FederationAuthorityError) as rollback:
        await repository.commit_phase_a(checkpoint1(), cohort())
    assert rollback.value.reason == "sender_did_log_rollback"

    missing = replace(
        checkpoint2(),
        seq=3,
        entry_hash="c" * 64,
        state_hash="d" * 64,
        expected_revision=2,
        expected_entry_hash=HASH2,
        contains_snapshot=False,
    )
    with pytest.raises(FederationAuthorityError) as omitted:
        await repository.commit_phase_a(
            missing,
            replace(
                cohort(),
                bound_current_did_key=KEY2,
                checkpoint_seq=3,
                checkpoint_entry_hash="c" * 64,
                checkpoint_revision=3,
                publishing_fence=3,
            ),
        )
    assert omitted.value.reason == "sender_did_log_split_view"


@pytest.mark.asyncio
async def test_two_n_plus_one_forks_have_one_winner(aweb_cloud_db) -> None:
    repository_a = AuthorityRepository(aweb_cloud_db.aweb_db)
    repository_b = AuthorityRepository(aweb_cloud_db.aweb_db)
    await repository_a.commit_phase_a(checkpoint1(), cohort())
    fork_a = checkpoint2()
    fork_b = replace(checkpoint2(), entry_hash="b" * 64, state_hash="c" * 64)

    async def commit(repository, candidate, candidate_cohort):
        try:
            return await repository.commit_phase_a(candidate, candidate_cohort)
        except FederationAuthorityError as exc:
            return exc.reason

    results = await asyncio.gather(
        commit(
            repository_a,
            fork_a,
            replace(cohort(), bound_current_did_key=KEY2, checkpoint_seq=2, checkpoint_entry_hash=fork_a.entry_hash, checkpoint_revision=2, publishing_fence=2),
        ),
        commit(
            repository_b,
            fork_b,
            replace(cohort(), bound_current_did_key=KEY2, checkpoint_seq=2, checkpoint_entry_hash=fork_b.entry_hash, checkpoint_revision=2, publishing_fence=3),
        ),
    )
    assert sum(not isinstance(result, str) for result in results) == 1
    assert "sender_did_log_split_view" in results


@pytest.mark.asyncio
async def test_phase_a_rejects_expired_or_taken_over_fence(aweb_cloud_db) -> None:
    work = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    scope = "discovery:alpha.example.com"
    old = await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=1)
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
        scope,
    )
    await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
    with pytest.raises(FederationAuthorityError) as stale:
        await repository.commit_phase_a(checkpoint1(), cohort(fence=old.fence), fences=(old,))
    assert stale.value.reason == "federation_authority_cas_conflict"


@pytest.mark.asyncio
async def test_idempotent_phase_a_still_requires_live_fence(aweb_cloud_db) -> None:
    work = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    scope = "discovery:alpha.example.com"
    old = await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
    await repository.commit_phase_a(
        checkpoint1(), cohort(fence=old.fence), fences=(old,)
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
        scope,
    )
    await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
    with pytest.raises(FederationAuthorityError) as stale:
        await repository.commit_phase_a(
            checkpoint1(), cohort(fence=old.fence), fences=(old,)
        )
    assert stale.value.reason == "federation_authority_cas_conflict"
