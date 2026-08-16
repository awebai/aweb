"""Strict federation authority orchestration shared by production ingress."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from awid.external_authority import canonical_protocol_address, compare_claim_to_evidence
from awid.external_registry import ExternalAuthorityEvidence, StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError

from .authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    AuthoritySecurityToken,
    CheckpointCandidate,
)
from .authority_work import AuthorityLease


@dataclass(frozen=True)
class AuthorityClaim:
    canonical_address: str
    did_aw: str
    current_did_key: str
    delivery_origin: str


class FederationAuthorityCore:
    def __init__(self, repository: AuthorityRepository, *, reuse_seconds: int = 60) -> None:
        if not 1 <= reuse_seconds <= 60:
            raise ValueError("authority reuse must be between 1 and 60 seconds")
        self.repository = repository
        self.reuse_seconds = reuse_seconds

    async def authorize_from_shared_cohort(
        self, claim: AuthorityClaim
    ) -> AuthoritySecurityToken | None:
        canonical = canonical_protocol_address(claim.canonical_address)
        return await self.repository.authorize_from_cohort(
            canonical_address=canonical,
            did_aw=claim.did_aw,
            current_did_key=claim.current_did_key,
            delivery_origin=claim.delivery_origin,
        )

    async def commit_verified_evidence(
        self,
        claim: AuthorityClaim,
        evidence: ExternalAuthorityEvidence,
        *,
        publishing_fence: int,
        fences: Sequence[AuthorityLease] = (),
    ) -> AuthoritySecurityToken:
        canonical = canonical_protocol_address(claim.canonical_address)
        if canonical != evidence.canonical_address:
            raise FederationAuthorityError(
                "sender_address_did_mismatch", did_aw=claim.did_aw
            )
        compare_claim_to_evidence(
            evidence.claim_evidence(),
            did_aw=claim.did_aw,
            current_did_key=claim.current_did_key,
            delivery_origin=claim.delivery_origin,
        )
        snapshot = evidence.verified_checkpoint
        verified = evidence.verified_log
        checkpoint = CheckpointCandidate(
            did_aw=evidence.did_aw,
            seq=verified.seq,
            entry_hash=verified.entry_hash,
            state_hash=verified.state_hash,
            current_did_key=verified.current_did_key,
            contains_snapshot=verified.contains_checkpoint,
            expected_revision=snapshot.revision if snapshot is not None else None,
            expected_entry_hash=snapshot.entry_hash if snapshot is not None else None,
        )
        if snapshot is None:
            checkpoint_revision = 1
        elif verified.seq == snapshot.seq and verified.entry_hash == snapshot.entry_hash:
            checkpoint_revision = snapshot.revision
        else:
            checkpoint_revision = snapshot.revision + 1
        cohort = AddressAuthorityCandidate(
            canonical_address=evidence.canonical_address,
            authority_selection=evidence.authority_selection,
            authority_name=evidence.authority_name,
            controller_did=evidence.controller_did,
            authority_statement_version=evidence.authority_statement_version,
            authority_statement_digest=evidence.authority_statement_digest,
            inherited=evidence.inherited,
            registry_explicit=evidence.registry_explicit,
            registry_origin=evidence.registry_origin,
            address_id=evidence.address_id,
            bound_did_aw=evidence.did_aw,
            bound_current_did_key=evidence.current_did_key,
            checkpoint_seq=verified.seq,
            checkpoint_entry_hash=verified.entry_hash,
            checkpoint_revision=checkpoint_revision,
            authoritative_delivery_origin=evidence.delivery_origin,
            publishing_fence=publishing_fence,
            reuse_seconds=self.reuse_seconds,
        )
        return await self.repository.commit_phase_a(
            checkpoint,
            cohort,
            fences=fences,
        )

    async def resolve_and_commit(
        self,
        claim: AuthorityClaim,
        resolver: StrictExternalRegistry,
        *,
        authority_generation: int,
        publishing_fence: int,
        fences: Sequence[AuthorityLease] = (),
    ) -> AuthoritySecurityToken:
        snapshot = await self.repository.get_checkpoint(claim.did_aw)
        evidence = await resolver.fetch_evidence(
            claim.canonical_address,
            authority_generation=authority_generation,
            checkpoint=snapshot,
        )
        try:
            return await self.commit_verified_evidence(
                claim,
                evidence,
                publishing_fence=publishing_fence,
                fences=fences,
            )
        except FederationAuthorityError as exc:
            if exc.reason != "federation_authority_cas_conflict":
                raise
        # One controlled bypass re-fetches and re-verifies against the winner.
        winner = await self.repository.get_checkpoint(claim.did_aw)
        evidence = await resolver.fetch_evidence(
            claim.canonical_address,
            authority_generation=authority_generation,
            checkpoint=winner,
            bypass_cache=True,
        )
        return await self.commit_verified_evidence(
            claim,
            evidence,
            publishing_fence=publishing_fence,
            fences=fences,
        )
