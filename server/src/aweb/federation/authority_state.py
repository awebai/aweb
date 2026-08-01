"""Durable DID checkpoint and complete address-authority cohort CAS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from awid.federation_errors import FederationAuthorityError
from awid.identity_log_verify import IdentityCheckpoint

from .authority_work import AuthorityLease


@dataclass(frozen=True)
class CheckpointCandidate:
    did_aw: str
    seq: int
    entry_hash: str
    state_hash: str
    current_did_key: str
    contains_snapshot: bool
    expected_revision: int | None
    expected_entry_hash: str | None


@dataclass(frozen=True)
class AddressAuthorityCandidate:
    canonical_address: str
    authority_selection: str
    authority_name: str
    controller_did: str
    authority_statement_version: str
    authority_statement_digest: str
    inherited: bool
    registry_explicit: bool
    registry_origin: str
    address_id: str | None
    bound_did_aw: str
    bound_current_did_key: str
    checkpoint_seq: int
    checkpoint_entry_hash: str
    checkpoint_revision: int
    authoritative_delivery_origin: str
    publishing_fence: int
    reuse_seconds: int


@dataclass(frozen=True)
class AuthoritySecurityToken:
    canonical_address: str
    did_aw: str
    checkpoint_revision: int
    cohort_generation: int


_COHORT_COMPARE_FIELDS = (
    "authority_selection",
    "authority_name",
    "controller_did",
    "authority_statement_version",
    "authority_statement_digest",
    "inherited",
    "registry_explicit",
    "registry_origin",
    "address_id",
    "bound_did_aw",
    "bound_current_did_key",
    "checkpoint_seq",
    "checkpoint_entry_hash",
    "checkpoint_revision",
    "authoritative_delivery_origin",
    "publishing_fence",
)


class AuthorityRepository:
    def __init__(self, db, *, before_commit=None) -> None:
        self.db = db
        self.before_commit = before_commit

    async def _lock(self, tx, key: str) -> None:
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            "federation-authority-state:" + key,
            timeout=1.0,
        )

    async def _require_fences(self, tx, fences: Sequence[AuthorityLease]) -> None:
        for lease in sorted(fences, key=lambda item: item.scope_key):
            await self._lock(tx, "fence:" + lease.scope_key)
            row = await tx.fetch_one(
                """
                SELECT 1
                FROM {{tables.federation_authority_leases}}
                WHERE scope_key = $1 AND owner_id = $2 AND fence = $3
                  AND expires_at > clock_timestamp()
                FOR UPDATE
                """,
                lease.scope_key,
                lease.owner_id,
                lease.fence,
            )
            if row is None:
                raise FederationAuthorityError("federation_authority_cas_conflict")

    def _validate_candidates(
        self,
        checkpoint: CheckpointCandidate,
        cohort: AddressAuthorityCandidate,
    ) -> None:
        if (
            not checkpoint.did_aw.startswith("did:aw:")
            or checkpoint.seq < 1
            or checkpoint.seq > 2**53 - 1
            or len(checkpoint.entry_hash) != 64
            or len(checkpoint.state_hash) != 64
            or not checkpoint.current_did_key.startswith("did:key:z")
        ):
            raise ValueError("invalid checkpoint candidate")
        if (
            cohort.bound_did_aw != checkpoint.did_aw
            or cohort.checkpoint_seq != checkpoint.seq
            or cohort.checkpoint_entry_hash != checkpoint.entry_hash
            or cohort.bound_current_did_key != checkpoint.current_did_key
            or cohort.publishing_fence < 1
            or not 1 <= cohort.reuse_seconds <= 60
        ):
            raise ValueError("cohort does not match checkpoint candidate")

    async def commit_phase_a(
        self,
        checkpoint: CheckpointCandidate,
        cohort: AddressAuthorityCandidate,
        *,
        fences: Sequence[AuthorityLease] = (),
    ) -> AuthoritySecurityToken:
        self._validate_candidates(checkpoint, cohort)
        try:
            async with self.db.transaction() as tx:
                for key in sorted(
                    ("address:" + cohort.canonical_address, "did:" + checkpoint.did_aw)
                ):
                    await self._lock(tx, key)
                current = await tx.fetch_one(
                    """
                    SELECT did_aw, seq, entry_hash, state_hash, current_did_key, revision
                    FROM {{tables.federation_did_checkpoints}}
                    WHERE did_aw = $1
                    FOR UPDATE
                    """,
                    checkpoint.did_aw,
                )
                existing_cohort = await tx.fetch_one(
                    """
                    SELECT *, expires_at > clock_timestamp() AS live
                    FROM {{tables.federation_address_authority_cohorts}}
                    WHERE canonical_address = $1
                    FOR UPDATE
                    """,
                    cohort.canonical_address,
                )

                advanced = False
                if current is None:
                    if checkpoint.expected_revision is not None:
                        raise FederationAuthorityError("federation_authority_cas_conflict")
                    revision = 1
                    await tx.execute(
                        """
                        INSERT INTO {{tables.federation_did_checkpoints}} (
                            did_aw, seq, entry_hash, state_hash, current_did_key,
                            revision, created_at, updated_at
                        ) VALUES ($1, $2, $3, $4, $5, 1, clock_timestamp(), clock_timestamp())
                        """,
                        checkpoint.did_aw,
                        checkpoint.seq,
                        checkpoint.entry_hash,
                        checkpoint.state_hash,
                        checkpoint.current_did_key,
                    )
                elif checkpoint.seq < current["seq"]:
                    raise FederationAuthorityError(
                        "sender_did_log_rollback",
                        did_aw=checkpoint.did_aw,
                        observed_sequence=checkpoint.seq,
                    )
                elif checkpoint.seq == current["seq"]:
                    if (
                        checkpoint.entry_hash != current["entry_hash"]
                        or checkpoint.state_hash != current["state_hash"]
                        or checkpoint.current_did_key != current["current_did_key"]
                    ):
                        raise FederationAuthorityError(
                            "sender_did_log_split_view",
                            did_aw=checkpoint.did_aw,
                            observed_sequence=checkpoint.seq,
                        )
                    revision = current["revision"]
                else:
                    if not checkpoint.contains_snapshot:
                        raise FederationAuthorityError(
                            "sender_did_log_split_view",
                            did_aw=checkpoint.did_aw,
                            observed_sequence=checkpoint.seq,
                        )
                    if (
                        checkpoint.expected_revision != current["revision"]
                        or checkpoint.expected_entry_hash != current["entry_hash"]
                    ):
                        raise FederationAuthorityError("federation_authority_cas_conflict")
                    row = await tx.fetch_one(
                        """
                        UPDATE {{tables.federation_did_checkpoints}}
                        SET seq = $2, entry_hash = $3, state_hash = $4,
                            current_did_key = $5, revision = revision + 1,
                            updated_at = clock_timestamp()
                        WHERE did_aw = $1 AND revision = $6 AND entry_hash = $7
                        RETURNING revision
                        """,
                        checkpoint.did_aw,
                        checkpoint.seq,
                        checkpoint.entry_hash,
                        checkpoint.state_hash,
                        checkpoint.current_did_key,
                        checkpoint.expected_revision,
                        checkpoint.expected_entry_hash,
                    )
                    if row is None:
                        raise FederationAuthorityError("federation_authority_cas_conflict")
                    revision = row["revision"]
                    advanced = True

                if cohort.checkpoint_revision != revision:
                    raise FederationAuthorityError("federation_authority_cas_conflict")

                source_changed = bool(
                    existing_cohort is not None
                    and not self._cohort_matches(existing_cohort, cohort)
                )
                idempotent_cohort = bool(
                    existing_cohort is not None
                    and existing_cohort["live"]
                    and self._cohort_matches(existing_cohort, cohort)
                )
                if self.before_commit is not None:
                    await self.before_commit()
                # Check every fence immediately before any result can commit,
                # including an idempotent Phase-A result.
                await self._require_fences(tx, fences)
                if idempotent_cohort:
                    return AuthoritySecurityToken(
                        cohort.canonical_address,
                        checkpoint.did_aw,
                        revision,
                        existing_cohort["generation"],
                    )

                if advanced or source_changed:
                    await tx.execute(
                        """
                        UPDATE {{tables.federation_address_authority_cohorts}}
                        SET expires_at = LEAST(expires_at, clock_timestamp()),
                            generation = generation + 1,
                            revision = revision + 1,
                            updated_at = clock_timestamp()
                        WHERE bound_did_aw = $1
                          AND canonical_address <> $2
                        """,
                        checkpoint.did_aw,
                        cohort.canonical_address,
                    )

                generation = 1 if existing_cohort is None else existing_cohort["generation"] + 1
                cohort_revision = 1 if existing_cohort is None else existing_cohort["revision"] + 1
                row = await tx.fetch_one(
                    """
                    WITH authority_clock AS MATERIALIZED (
                        SELECT clock_timestamp() AS completed_at
                    )
                    INSERT INTO {{tables.federation_address_authority_cohorts}} (
                        canonical_address, authority_selection, authority_name,
                        controller_did, authority_statement_version,
                        authority_statement_digest, inherited, registry_explicit,
                        registry_origin, address_id, bound_did_aw,
                        bound_current_did_key, checkpoint_seq,
                        checkpoint_entry_hash, checkpoint_revision,
                        authoritative_delivery_origin,
                        authoritative_read_completed_at, expires_at,
                        generation, revision, publishing_fence,
                        created_at, updated_at
                    ) SELECT
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                        $12, $13, $14, $15, $16,
                        completed_at,
                        completed_at + $17::integer * INTERVAL '1 second',
                        $18, $19, $20, completed_at, completed_at
                    FROM authority_clock
                    ON CONFLICT (canonical_address) DO UPDATE SET
                        authority_selection = EXCLUDED.authority_selection,
                        authority_name = EXCLUDED.authority_name,
                        controller_did = EXCLUDED.controller_did,
                        authority_statement_version = EXCLUDED.authority_statement_version,
                        authority_statement_digest = EXCLUDED.authority_statement_digest,
                        inherited = EXCLUDED.inherited,
                        registry_explicit = EXCLUDED.registry_explicit,
                        registry_origin = EXCLUDED.registry_origin,
                        address_id = EXCLUDED.address_id,
                        bound_did_aw = EXCLUDED.bound_did_aw,
                        bound_current_did_key = EXCLUDED.bound_current_did_key,
                        checkpoint_seq = EXCLUDED.checkpoint_seq,
                        checkpoint_entry_hash = EXCLUDED.checkpoint_entry_hash,
                        checkpoint_revision = EXCLUDED.checkpoint_revision,
                        authoritative_delivery_origin = EXCLUDED.authoritative_delivery_origin,
                        authoritative_read_completed_at = EXCLUDED.authoritative_read_completed_at,
                        expires_at = EXCLUDED.expires_at,
                        generation = EXCLUDED.generation,
                        revision = EXCLUDED.revision,
                        publishing_fence = EXCLUDED.publishing_fence,
                        updated_at = EXCLUDED.updated_at
                    RETURNING generation
                    """,
                    cohort.canonical_address,
                    cohort.authority_selection,
                    cohort.authority_name,
                    cohort.controller_did,
                    cohort.authority_statement_version,
                    cohort.authority_statement_digest,
                    cohort.inherited,
                    cohort.registry_explicit,
                    cohort.registry_origin,
                    cohort.address_id,
                    cohort.bound_did_aw,
                    cohort.bound_current_did_key,
                    cohort.checkpoint_seq,
                    cohort.checkpoint_entry_hash,
                    cohort.checkpoint_revision,
                    cohort.authoritative_delivery_origin,
                    cohort.reuse_seconds,
                    generation,
                    cohort_revision,
                    cohort.publishing_fence,
                )
                return AuthoritySecurityToken(
                    cohort.canonical_address,
                    checkpoint.did_aw,
                    revision,
                    row["generation"],
                )
        except FederationAuthorityError:
            raise
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc

    def _cohort_matches(self, row, candidate: AddressAuthorityCandidate) -> bool:
        return all(row[field] == getattr(candidate, field) for field in _COHORT_COMPARE_FIELDS)

    async def get_checkpoint(self, did_aw: str) -> IdentityCheckpoint | None:
        try:
            row = await self.db.fetch_one(
                """
                SELECT seq, entry_hash, state_hash, current_did_key, revision
                FROM {{tables.federation_did_checkpoints}}
                WHERE did_aw = $1
                """,
                did_aw,
            )
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc
        if row is None:
            return None
        return IdentityCheckpoint(
            seq=row["seq"],
            entry_hash=row["entry_hash"],
            state_hash=row["state_hash"],
            current_did_key=row["current_did_key"],
            revision=row["revision"],
        )

    async def authorize_from_cohort(
        self,
        *,
        canonical_address: str,
        did_aw: str,
        current_did_key: str,
        delivery_origin: str,
    ) -> AuthoritySecurityToken | None:
        try:
            async with self.db.transaction() as tx:
                row = await tx.fetch_one(
                    """
                    SELECT c.canonical_address, c.bound_did_aw,
                           c.checkpoint_revision, c.generation
                    FROM {{tables.federation_address_authority_cohorts}} c
                    JOIN {{tables.federation_did_checkpoints}} d
                      ON d.did_aw = c.bound_did_aw
                     AND d.revision = c.checkpoint_revision
                     AND d.seq = c.checkpoint_seq
                     AND d.entry_hash = c.checkpoint_entry_hash
                     AND d.current_did_key = c.bound_current_did_key
                    WHERE c.canonical_address = $1
                      AND c.bound_did_aw = $2
                      AND c.bound_current_did_key = $3
                      AND c.authoritative_delivery_origin = $4
                      AND c.expires_at > clock_timestamp()
                    """,
                    canonical_address,
                    did_aw,
                    current_did_key,
                    delivery_origin,
                )
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc
        if row is None:
            return None
        return AuthoritySecurityToken(
            row["canonical_address"],
            row["bound_did_aw"],
            row["checkpoint_revision"],
            row["generation"],
        )
