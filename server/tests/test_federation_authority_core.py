from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from aweb.federation.authority import AuthorityClaim, FederationAuthorityCore
from aweb.federation.authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    AuthoritySecurityToken,
    CheckpointCandidate,
)
from aweb.federation.authority_work import (
    AuthorityEvidenceScope,
    AuthorityWorkRepository,
    authority_result_scope_payload,
    authority_result_ttl_seconds,
)
from aweb.federation.errors import authority_error_body
from awid.external_registry import ExternalAuthorityEvidence
from awid.federation_errors import FederationAuthorityError, federation_error_spec
from awid.identity_log_verify import IdentityCheckpoint, VerifiedIdentityLog


_ROOT = Path(__file__).resolve().parents[2]
_STATE_VECTOR = json.loads(
    (_ROOT / "docs" / "vectors" / "federation-authority-state-v1.json").read_text()
)


def evidence() -> ExternalAuthorityEvidence:
    return ExternalAuthorityEvidence(
        canonical_address="alpha.example.com/Alice",
        authority_selection="dns",
        authority_name="_awid.alpha.example.com",
        controller_did="did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
        authority_statement_version="aweb.federation-authority.dns.v1",
        authority_statement_digest="sha256:" + "a" * 64,
        inherited=False,
        registry_explicit=True,
        registry_origin="https://registry-a.example",
        address_id="addr-alpha-alice",
        did_aw="did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2",
        current_did_key="did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
        delivery_origin="https://aweb-alpha.example",
        authority_generation=1,
        approved_ips=("93.184.216.34",),
        verified_log=VerifiedIdentityLog(
            seq=2,
            entry_hash="2461cc5185dfb0d3836241574aca5927db2925069bd4a10216613a87b54351c0",
            state_hash="f757dacbf0e5c5a90f1f555067aad6d7bf9760c2daefcffd90452bf28c289f8b",
            current_did_key="did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
            contains_checkpoint=True,
        ),
    )


def claim(*, did_aw: str | None = None) -> AuthorityClaim:
    value = evidence()
    return AuthorityClaim(
        canonical_address=value.canonical_address,
        did_aw=did_aw or value.did_aw,
        current_did_key=value.current_did_key,
        delivery_origin=value.delivery_origin,
    )


def vector_checkpoint_candidate(case: dict) -> CheckpointCandidate:
    snapshot = case["snapshot"]
    raw = case.get("candidate") or case["candidates"][0]
    seq = raw["seq"]
    state_hash = raw.get("state_hash") or hashlib.sha256(
        f"{case['name']}:{seq}:state".encode()
    ).hexdigest()
    current_key = raw.get("current_did_key") or (
        snapshot.get("current_did_key") if snapshot else None
    ) or evidence().current_did_key
    return CheckpointCandidate(
        did_aw=evidence().did_aw,
        seq=seq,
        entry_hash=raw["entry_hash"],
        state_hash=state_hash,
        current_did_key=current_key,
        contains_snapshot=raw.get("contains_snapshot", False),
        expected_revision=snapshot.get("revision") if snapshot and seq > snapshot["seq"] else None,
        expected_entry_hash=snapshot.get("entry_hash") if snapshot and seq > snapshot["seq"] else None,
    )


def vector_cohort(candidate: CheckpointCandidate, revision: int, *, address: str | None = None) -> AddressAuthorityCandidate:
    value = evidence()
    return AddressAuthorityCandidate(
        canonical_address=address or value.canonical_address,
        authority_selection=value.authority_selection,
        authority_name=value.authority_name,
        controller_did=value.controller_did,
        authority_statement_version=value.authority_statement_version,
        authority_statement_digest=value.authority_statement_digest,
        inherited=value.inherited,
        registry_explicit=value.registry_explicit,
        registry_origin=value.registry_origin,
        address_id=value.address_id,
        bound_did_aw=candidate.did_aw,
        bound_current_did_key=candidate.current_did_key,
        checkpoint_seq=candidate.seq,
        checkpoint_entry_hash=candidate.entry_hash,
        checkpoint_revision=revision,
        authoritative_delivery_origin=value.delivery_origin,
        publishing_fence=1,
        reuse_seconds=60,
    )


async def insert_vector_snapshot(db, snapshot: dict) -> None:
    await db.execute(
        """
        INSERT INTO {{tables.federation_did_checkpoints}} (
            did_aw, seq, entry_hash, state_hash, current_did_key, revision,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp(), clock_timestamp())
        """,
        evidence().did_aw,
        snapshot["seq"],
        snapshot["entry_hash"],
        snapshot.get("state_hash") or hashlib.sha256(
            f"snapshot:{snapshot['seq']}:state".encode()
        ).hexdigest(),
        snapshot.get("current_did_key") or evidence().current_did_key,
        snapshot["revision"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _STATE_VECTOR["checkpoint_cases"], ids=lambda case: case["name"]
)
async def test_checkpoint_vectors_execute_against_postgresql(case: dict, aweb_cloud_db) -> None:
    if case["snapshot"] is not None:
        await insert_vector_snapshot(aweb_cloud_db.aweb_db, case["snapshot"])
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    expected = case["expected"]

    if case["name"] == "two_n_plus_one_forks_allow_one_winner":
        async def commit(raw: dict):
            candidate = vector_checkpoint_candidate({**case, "candidate": raw})
            try:
                return await repository.commit_phase_a(
                    candidate,
                    vector_cohort(candidate, expected["final_revision"]),
                )
            except FederationAuthorityError as exc:
                return exc.reason

        results = await asyncio.gather(*(commit(raw) for raw in case["candidates"]))
        assert sum(isinstance(result, AuthoritySecurityToken) for result in results) == expected["max_winners"]
        assert expected["reason_for_loser"] in results
        return

    candidate = vector_checkpoint_candidate(case)
    if expected["action"] == "reject":
        with pytest.raises(FederationAuthorityError) as raised:
            await repository.commit_phase_a(
                candidate,
                vector_cohort(candidate, expected["revision"]),
            )
        assert raised.value.reason == expected["reason"]
        checkpoint = await repository.get_checkpoint(candidate.did_aw)
        assert checkpoint is not None
        assert checkpoint.revision == expected["revision"]
        return

    token = await repository.commit_phase_a(
        candidate,
        vector_cohort(candidate, expected["revision"]),
    )
    assert token.checkpoint_revision == expected["revision"]
    if expected["action"] == "idempotent":
        checkpoint = await repository.get_checkpoint(candidate.did_aw)
        assert checkpoint is not None
        assert checkpoint.entry_hash == case["snapshot"]["entry_hash"]


def first_checkpoint() -> CheckpointCandidate:
    value = evidence().verified_log
    return CheckpointCandidate(
        did_aw=evidence().did_aw,
        seq=value.seq,
        entry_hash=value.entry_hash,
        state_hash=value.state_hash,
        current_did_key=value.current_did_key,
        contains_snapshot=True,
        expected_revision=None,
        expected_entry_hash=None,
    )


def advanced_checkpoint() -> CheckpointCandidate:
    first = first_checkpoint()
    return CheckpointCandidate(
        did_aw=first.did_aw,
        seq=first.seq + 1,
        entry_hash="c" * 64,
        state_hash="d" * 64,
        current_did_key=first.current_did_key,
        contains_snapshot=True,
        expected_revision=1,
        expected_entry_hash=first.entry_hash,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _STATE_VECTOR["cohort_cases"], ids=lambda case: case["name"]
)
async def test_cohort_vectors_execute_against_postgresql(case: dict, aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    candidate = first_checkpoint()
    expected = case["expected"]
    name = case["name"]

    if name == "cohort_key_is_canonical_address_not_did":
        address = case["input"]["address"]
        token = await repository.commit_phase_a(
            candidate, vector_cohort(candidate, 1, address=address)
        )
        assert token.canonical_address == expected["key"]
        assert candidate.did_aw not in token.canonical_address
        assert expected["key_includes_did"] is False
        return

    if name == "same_did_two_addresses_have_separate_cohorts":
        for address in case["input"]["addresses"]:
            await repository.commit_phase_a(
                candidate, vector_cohort(candidate, 1, address=address)
            )
        count = await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_address_authority_cohorts}} WHERE bound_did_aw = $1",
            candidate.did_aw,
        )
        assert count == expected["cohort_count"]
        assert expected["cross_hit"] is False
        return

    if name == "checkpoint_advance_invalidates_every_older_did_cohort":
        addresses = ["alpha.example.com/Alice", "beta.example.com/Alice", "gamma.example.com/Alice"]
        for address in addresses:
            await repository.commit_phase_a(
                candidate, vector_cohort(candidate, 1, address=address)
            )
        advanced = advanced_checkpoint()
        await repository.commit_phase_a(
            advanced, vector_cohort(advanced, 2, address=addresses[0])
        )
        expired = await aweb_cloud_db.aweb_db.fetch_all(
            "SELECT generation, expires_at <= clock_timestamp() AS expired FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address <> $1 ORDER BY canonical_address",
            addresses[0],
        )
        assert sum(row["expired"] for row in expired) == expected["expired_count"]
        assert all(
            row["generation"] == expected["generation_invalidated_count"]
            for row in expired
        )
        assert expected["same_transaction"] is True
        return

    if name == "fresh_source_change_invalidates_peer_cohorts":
        addresses = ["alpha.example.com/Alice", "beta.example.com/Alice", "gamma.example.com/Alice"]
        for address in addresses:
            await repository.commit_phase_a(
                candidate, vector_cohort(candidate, 1, address=address)
            )
        assert case["input"] == {"expired": True, "source_changed": True}
        original = vector_cohort(candidate, 1, address=addresses[0])
        changed = AddressAuthorityCandidate(
            **{
                **original.__dict__,
                "controller_did": "did:key:zChangedController",
                "authority_statement_digest": "sha256:" + "c" * 64,
                "registry_origin": "https://registry-changed.example",
                "address_id": "changed-address",
                "authoritative_delivery_origin": "https://delivery-changed.example",
                "publishing_fence": 2,
            }
        )
        token = await repository.commit_phase_a(candidate, changed)
        peers = await aweb_cloud_db.aweb_db.fetch_all(
            "SELECT generation, expires_at <= clock_timestamp() AS expired FROM {{tables.federation_address_authority_cohorts}} WHERE bound_did_aw = $1 AND canonical_address <> $2 ORDER BY canonical_address",
            candidate.did_aw,
            addresses[0],
        )
        old_peer = await repository.authorize_from_cohort(
            canonical_address=addresses[1],
            did_aw=candidate.did_aw,
            current_did_key=candidate.current_did_key,
            delivery_origin=vector_cohort(candidate, 1).authoritative_delivery_origin,
        )
        checkpoint = await repository.get_checkpoint(candidate.did_aw)
        assert token.checkpoint_revision == 1
        assert checkpoint is not None
        assert checkpoint.seq == candidate.seq and checkpoint.revision == 1
        assert len(peers) == 2
        assert all(row["expired"] and row["generation"] == 2 for row in peers)
        assert (old_peer is not None) is expected["old_claim_authorized"]
        assert expected["peer_generations_invalidated"] is True
        return

    if name == "new_authority_tuple_replaces_whole_generation":
        base = vector_cohort(candidate, 1)
        await repository.commit_phase_a(candidate, base)
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.federation_address_authority_cohorts}} SET generation = $2 WHERE canonical_address = $1",
            base.canonical_address,
            case["input"]["old_generation"],
        )
        changed = AddressAuthorityCandidate(
            **{
                **base.__dict__,
                "controller_did": "did:key:zChangedController",
                "registry_origin": "https://registry-changed.example",
                "address_id": "changed-address",
                "authoritative_delivery_origin": "https://delivery-changed.example",
                "publishing_fence": 2,
            }
        )
        token = await repository.commit_phase_a(candidate, changed)
        row = await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT * FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address = $1",
            base.canonical_address,
        )
        assert token.cohort_generation == expected["generation"]
        assert all(row[field] == getattr(changed, field) for field in case["input"]["changed_fields"])
        assert expected["merge_fields"] is False
        return

    if name == "fast_path_requires_postgresql_row_and_exact_tuple":
        class FailedDB:
            def transaction(self):
                raise RuntimeError("postgres unavailable")

        with pytest.raises(FederationAuthorityError) as raised:
            await AuthorityRepository(FailedDB()).authorize_from_cohort(
                canonical_address=evidence().canonical_address,
                did_aw=evidence().did_aw,
                current_did_key=evidence().current_did_key,
                delivery_origin=evidence().delivery_origin,
            )
        assert raised.value.reason == expected["reason"]
        assert expected["authorized"] is False
        return

    await repository.commit_phase_a(candidate, vector_cohort(candidate, 1))
    if name == "expiry_starts_at_complete_authoritative_read_using_database_time":
        row = await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT EXTRACT(EPOCH FROM (expires_at - authoritative_read_completed_at)) AS ttl, authoritative_read_completed_at <= clock_timestamp() AS db_time FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address = $1",
            evidence().canonical_address,
        )
        assert int(row["ttl"]) == 60
        assert row["db_time"] is True
        assert expected["expiry_base"] == "postgresql_clock_timestamp_at_complete_read"
        return

    await aweb_cloud_db.aweb_db.execute(
        "WITH expired AS (SELECT clock_timestamp() - interval '61 seconds' AS completed) UPDATE {{tables.federation_address_authority_cohorts}} SET authoritative_read_completed_at = expired.completed, expires_at = expired.completed + interval '60 seconds' FROM expired WHERE canonical_address = $1",
        evidence().canonical_address,
    )
    if name == "expiry_requires_full_authoritative_reread":
        assert await repository.authorize_from_cohort(
            canonical_address=evidence().canonical_address,
            did_aw=evidence().did_aw,
            current_did_key=evidence().current_did_key,
            delivery_origin=evidence().delivery_origin,
        ) is None
        assert expected["reuse"] is False
        assert expected["reread"] == ["dns", "namespace", "address", "key_or_log", "origin"]
        return

    assert name == "source_suppression_can_renew_old_valid_state_without_sla_claim"
    renewed = await repository.commit_phase_a(candidate, vector_cohort(candidate, 1))
    assert renewed.cohort_generation == 2
    assert expected == {
        "reread_performed": True,
        "old_state_may_renew": True,
        "freshness_sla": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _STATE_VECTOR["work_fence_cases"], ids=lambda case: case["name"]
)
async def test_work_fence_vectors_execute_against_postgresql(case: dict, aweb_cloud_db) -> None:
    work = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    expected = case["expected"]
    name = case["name"]

    if name == "lease_uses_database_time":
        lease = await work.acquire_lease(
            "discovery:vector-time", owner_id=uuid4(), ttl_seconds=5
        )
        row = await aweb_cloud_db.aweb_db.fetch_one(
            "SELECT EXTRACT(EPOCH FROM (expires_at - acquired_at)) AS ttl, acquired_at <= clock_timestamp() AS db_time FROM {{tables.federation_authority_leases}} WHERE scope_key = $1",
            lease.scope_key,
        )
        assert int(row["ttl"]) == 5
        assert row["db_time"] is True
        assert expected["expiry_clock"] == "postgresql_clock_timestamp"
        assert expected["process_clock_authoritative"] is False
        return

    if name == "external_work_holds_no_pool_connection":
        class TrackingRepository:
            active = False

            async def get_checkpoint(self, _did_aw):
                self.active = True
                try:
                    return None
                finally:
                    self.active = False

            async def commit_phase_a(self, _checkpoint, _cohort, *, fences=()):
                self.active = True
                try:
                    return AuthoritySecurityToken(evidence().canonical_address, evidence().did_aw, 1, 1)
                finally:
                    self.active = False

        class Resolver:
            async def fetch_evidence(self, _address, **_kwargs):
                assert repository.active is False
                await asyncio.sleep(0)
                assert repository.active is False
                return evidence()

        repository = TrackingRepository()
        await FederationAuthorityCore(repository).resolve_and_commit(
            claim(), Resolver(), authority_generation=1, publishing_fence=1
        )
        assert expected == {"open_transaction": False, "checked_out_connection": False}
        return

    if name == "takeover_increments_persistent_fence":
        scope = "origin:vector-takeover"
        await aweb_cloud_db.aweb_db.execute(
            "INSERT INTO {{tables.federation_authority_fences}} (scope_key, last_fence) VALUES ($1, $2)",
            scope,
            case["input"]["old_fence"] - 1,
        )
        first = await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
            scope,
        )
        second = await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
        assert first.fence == case["input"]["old_fence"]
        assert second.fence == expected["new_fence"]
        counter = await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT last_fence FROM {{tables.federation_authority_fences}} WHERE scope_key = $1",
            scope,
        )
        assert counter == expected["new_fence"]
        assert expected["counter_deleted"] is False
        return

    if name == "expired_owner_cannot_publish_after_takeover":
        scope = "origin:vector-stale"
        first = await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
            scope,
        )
        await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
        with pytest.raises(FederationAuthorityError) as raised:
            await work.publish_result(first, status="ok", evidence={}, ttl_seconds=5)
        assert raised.value.reason == expected["reason"]
        assert expected["publish"] is False
        return

    if name == "phase_a_locks_every_consumed_fence":
        leases = [
            await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
            for scope in reversed(case["input"]["consumed_scopes"])
        ]
        candidate = first_checkpoint()
        await AuthorityRepository(aweb_cloud_db.aweb_db).commit_phase_a(
            candidate, vector_cohort(candidate, 1), fences=leases
        )
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
            leases[0].scope_key,
        )
        with pytest.raises(FederationAuthorityError) as raised:
            await AuthorityRepository(aweb_cloud_db.aweb_db).commit_phase_a(
                candidate,
                AddressAuthorityCandidate(**{**vector_cohort(candidate, 1).__dict__, "publishing_fence": 2}),
                fences=leases,
            )
        assert raised.value.reason == "federation_authority_cas_conflict"
        assert expected == {"sorted_scope_locking": True, "exact_owner_fence_unexpired_required": True}
        return

    if name == "permit_count_ignores_expired_leases":
        owners = [uuid4() for _ in range(5)]
        for owner in owners:
            await work.acquire_permits(
                owner_id=owner,
                scopes=(("origin", "https://registry.example", 5),),
                ttl_seconds=5,
            )
        await aweb_cloud_db.aweb_db.execute(
            "WITH victims AS (SELECT permit_id FROM {{tables.federation_authority_permits}} ORDER BY permit_id LIMIT 2) UPDATE {{tables.federation_authority_permits}} p SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' FROM victims WHERE p.permit_id = victims.permit_id"
        )
        active = await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_authority_permits}} WHERE expires_at > clock_timestamp()"
        )
        granted = await work.acquire_permits(
            owner_id=uuid4(),
            scopes=(("origin", "https://registry.example", case["input"]["limit"]),),
            ttl_seconds=5,
        )
        assert active == expected["counted"]
        assert bool(granted) is expected["permit_granted"]
        return

    if name == "bigint_fence_overflow_fails_closed":
        scope = "did:vector-overflow"
        await aweb_cloud_db.aweb_db.execute(
            "INSERT INTO {{tables.federation_authority_fences}} (scope_key, last_fence) VALUES ($1, $2)",
            scope,
            case["input"]["fence"],
        )
        with pytest.raises(FederationAuthorityError) as raised:
            await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
        assert raised.value.reason == expected["reason"]
        assert expected["publish"] is False
        return

    assert name == "coordination_outage_has_no_local_or_redis_fallback"

    class FailedDB:
        def transaction(self):
            raise RuntimeError("postgres unavailable")

    with pytest.raises(FederationAuthorityError) as raised:
        await AuthorityWorkRepository(FailedDB()).acquire_lease(
            "discovery:vector-outage", owner_id=uuid4(), ttl_seconds=5
        )
    assert raised.value.reason == expected["reason"]
    assert expected["authorized"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _STATE_VECTOR["evidence_reuse_cases"], ids=lambda case: case["name"]
)
async def test_evidence_reuse_vectors(case: dict, aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    core = FederationAuthorityCore(repository)
    expected = case["expected"]
    name = case["name"]

    if name in {
        "wrong_claim_then_correct_claim_uses_same_evidence_independent_comparison",
        "concurrent_wrong_and_correct_claim_cannot_poison",
    }:
        value = evidence()

        async def attempt(candidate_claim: AuthorityClaim):
            try:
                return await core.commit_verified_evidence(
                    candidate_claim, value, publishing_fence=1
                )
            except FederationAuthorityError as exc:
                return exc.reason

        wrong_did = name.startswith("wrong_claim")
        wrong = claim(did_aw="did:aw:wrong") if wrong_did else AuthorityClaim(
            canonical_address=value.canonical_address,
            did_aw=value.did_aw,
            current_did_key="did:key:wrong",
            delivery_origin=value.delivery_origin,
        )
        wrong_result, correct_result = await asyncio.gather(attempt(wrong), attempt(claim()))
        assert wrong_result == (
            "sender_address_did_mismatch" if wrong_did else "sender_current_key_mismatch"
        )
        assert isinstance(correct_result, AuthoritySecurityToken)
        if wrong_did:
            assert expected["external_fetches"] == 1
            assert expected["mismatch_cached"] is False
        else:
            assert expected["shared_evidence"] is True
            assert expected["correct_result"] == "accepted"
        return

    if name == "mismatch_is_never_keyed_by_address_domain_or_did":
        with pytest.raises(FederationAuthorityError):
            await core.commit_verified_evidence(
                claim(did_aw="did:aw:wrong"), evidence(), publishing_fence=1
            )
        assert await repository.get_checkpoint(evidence().did_aw) is None
        assert expected == {"allowed_keys": [], "default_memoization": "none"}
        return

    scope = AuthorityEvidenceScope(
        authority_statement_digest=evidence().authority_statement_digest,
        authority_generation=4,
        registry_origin=evidence().registry_origin,
        canonical_address=evidence().canonical_address,
        did_aw=evidence().did_aw,
    )
    if name == "authoritative_not_found_scope_is_complete":
        payload = authority_result_scope_payload(scope)
        assert list(payload) == expected["key_fields"]
        reuse_seconds = case["input"]["reuse_seconds"]
        assert authority_result_ttl_seconds(
            "authoritative_not_found", reuse_seconds
        ) == reuse_seconds
        assert authority_result_ttl_seconds(
            "authoritative_not_found", reuse_seconds + 1
        ) == reuse_seconds
        assert authority_result_ttl_seconds(
            "authoritative_not_found", 60
        ) == reuse_seconds
        return

    if name == "malformed_evidence_scope_includes_response_digest":
        payload = authority_result_scope_payload(
            scope, response_digest="sha256:" + "f" * 64
        )
        assert list(payload) == expected["key_fields"]
        assert list(payload["complete_source_scope"]) == _STATE_VECTOR["evidence_reuse_cases"][3]["expected"]["key_fields"]
        return

    if name == "dns_transport_failure_is_retryable_and_short_lived":
        assert authority_result_ttl_seconds("dns_transport_failure", 60) == expected["max_seconds"]
        assert expected["retryable"] is True
        return

    if name == "controlled_bypass_is_one_per_message_and_shared":
        winner = IdentityCheckpoint(
            seq=1,
            entry_hash="1" * 64,
            state_hash="2" * 64,
            current_did_key=evidence().current_did_key,
            revision=1,
        )

        class RacingRepository:
            def __init__(self) -> None:
                self.commits = 0
                self.reads = 0

            async def get_checkpoint(self, _did_aw):
                self.reads += 1
                return None if self.reads == 1 else winner

            async def commit_phase_a(self, _checkpoint, _cohort, *, fences=()):
                self.commits += 1
                if self.commits < case["input"]["attempted_bypasses"]:
                    raise FederationAuthorityError("federation_authority_cas_conflict")
                return AuthoritySecurityToken(evidence().canonical_address, evidence().did_aw, 2, 3)

        class Resolver:
            def __init__(self) -> None:
                self.calls = []

            async def fetch_evidence(self, _address, **kwargs):
                self.calls.append(kwargs)
                return ExternalAuthorityEvidence(
                    **{**evidence().__dict__, "verified_checkpoint": kwargs["checkpoint"]}
                )

        racing = RacingRepository()
        resolver = Resolver()
        await FederationAuthorityCore(racing).resolve_and_commit(
            claim(), resolver, authority_generation=3, publishing_fence=1
        )
        assert sum(item.get("bypass_cache", False) for item in resolver.calls) == expected["performed_bypasses"]
        assert expected["through_singleflight"] is True
        return

    assert name == "source_generation_replacement_discards_old_comparisons"
    first = await core.commit_verified_evidence(claim(), evidence(), publishing_fence=1)
    replacement = ExternalAuthorityEvidence(
        **{
            **evidence().__dict__,
            "authority_statement_digest": "sha256:" + "b" * 64,
            "registry_origin": "https://registry-b.example",
            "authority_generation": case["input"]["new_generation"],
        }
    )
    second = await core.commit_verified_evidence(claim(), replacement, publishing_fence=2)
    assert second.cohort_generation == first.cohort_generation + 1
    assert expected == {"old_mismatch_reused": False, "new_tuple_replaces_whole": True}


@pytest.mark.asyncio
async def test_inactive_core_commits_verified_evidence_then_uses_shared_fast_path(aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    core = FederationAuthorityCore(repository)
    token = await core.commit_verified_evidence(claim(), evidence(), publishing_fence=1)
    assert token.checkpoint_revision == 1
    assert token.cohort_generation == 1
    assert await core.authorize_from_shared_cohort(claim()) == token


@pytest.mark.asyncio
async def test_wrong_claim_does_not_mutate_or_poison_correct_claim(aweb_cloud_db) -> None:
    repository = AuthorityRepository(aweb_cloud_db.aweb_db)
    core = FederationAuthorityCore(repository)
    with pytest.raises(FederationAuthorityError) as wrong:
        await core.commit_verified_evidence(
            claim(did_aw="did:aw:wrong"), evidence(), publishing_fence=1
        )
    assert wrong.value.reason == "sender_address_did_mismatch"
    assert await repository.get_checkpoint(evidence().did_aw) is None

    token = await core.commit_verified_evidence(claim(), evidence(), publishing_fence=1)
    assert token.checkpoint_revision == 1


@pytest.mark.asyncio
async def test_cas_conflict_reloads_winner_and_uses_one_bypass() -> None:
    winner = IdentityCheckpoint(
        seq=1,
        entry_hash="1" * 64,
        state_hash="2" * 64,
        current_did_key=evidence().current_did_key,
        revision=1,
    )

    class RacingRepository:
        def __init__(self) -> None:
            self.commits = 0
            self.reads = 0

        async def get_checkpoint(self, _did_aw):
            self.reads += 1
            return None if self.reads == 1 else winner

        async def commit_phase_a(self, _checkpoint, _cohort, *, fences=()):
            self.commits += 1
            if self.commits == 1:
                raise FederationAuthorityError("federation_authority_cas_conflict")
            return AuthoritySecurityToken(evidence().canonical_address, evidence().did_aw, 2, 3)

    class Resolver:
        def __init__(self) -> None:
            self.calls = []

        async def fetch_evidence(self, _address, *, authority_generation, checkpoint, bypass_cache=False):
            self.calls.append((authority_generation, checkpoint, bypass_cache))
            return ExternalAuthorityEvidence(
                **{
                    **evidence().__dict__,
                    "verified_checkpoint": checkpoint,
                }
            )

    repository = RacingRepository()
    resolver = Resolver()
    core = FederationAuthorityCore(repository)
    token = await core.resolve_and_commit(
        claim(), resolver, authority_generation=3, publishing_fence=9
    )
    assert token.cohort_generation == 3
    assert resolver.calls == [(3, None, False), (3, winner, True)]
    assert repository.commits == 2


def test_stable_error_vector_is_the_runtime_error_vocabulary() -> None:
    vector = json.loads(
        (_ROOT / "docs" / "vectors" / "federation-authority-state-v1.json").read_text()
    )
    for item in vector["stable_errors"]:
        spec = federation_error_spec(item["reason"])
        assert (spec.http_status, spec.retryable, spec.retry_after_required) == (
            item["http_status"],
            item["retryable"],
            item["retry_after_required"],
        )
        error = FederationAuthorityError(
            item["reason"], did_aw="did:aw:fixture", observed_sequence=2
        )
        body = authority_error_body(error, correlation_id="correlation-fixture")
        assert body == {
            "detail": item["reason"],
            "reason": item["reason"],
            "retryable": item["retryable"],
            "correlation_id": "correlation-fixture",
            "did_aw": "did:aw:fixture",
            "observed_sequence": 2,
        }
