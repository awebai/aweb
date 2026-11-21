"""Strict federation authority orchestration shared by production ingress."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from awid.external_authority import (
    RegistryAuthority,
    canonical_protocol_address,
    compare_claim_to_evidence,
)
from awid.external_registry import ExternalAuthorityEvidence, StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError, FederationErrorSpec

from .authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    AuthoritySecurityToken,
    CheckpointCandidate,
)
from .authority_work import AuthorityLease
from .lookup_policy import (
    AUTHORITY_CAS_CONFLICT,
    SENDER_IDENTITY_NOT_FOUND,
    EvidenceCacheUse,
)


@dataclass(frozen=True)
class AuthorityClaim:
    canonical_address: str
    did_aw: str
    current_did_key: str
    delivery_origin: str


@dataclass(frozen=True)
class CommittedAuthorityEvidence:
    token: AuthoritySecurityToken
    evidence: ExternalAuthorityEvidence


class FederationAuthorityCore:
    def __init__(
        self, repository: AuthorityRepository, *, reuse_seconds: int = 60
    ) -> None:
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
        elif (
            verified.seq == snapshot.seq and verified.entry_hash == snapshot.entry_hash
        ):
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

    async def resolve_evidence_and_commit(
        self,
        claim: AuthorityClaim | None,
        resolver: StrictExternalRegistry,
        *,
        authority_generation: int,
        publishing_fence: int,
        fences: Sequence[AuthorityLease] = (),
        address: str | None = None,
        discovered_authority: RegistryAuthority | None = None,
        not_found: FederationErrorSpec = SENDER_IDENTITY_NOT_FOUND,
    ) -> CommittedAuthorityEvidence:
        """Fetch current authority, commit it, and retry one checkpoint race.

        Implements Direct Address Send Protocol (docs/identity-messaging-contract.md:177-196)
        and Strict Cross-Registry Sender Authority
        (docs/identity-messaging-contract.md:199-222).

        A sender claim is independently checked when supplied. Address discovery
        derives its claim only from the resolver's verified evidence.
        """
        canonical = canonical_protocol_address(
            claim.canonical_address if claim is not None else address or ""
        )

        async def fetch_authority_evidence(
            snapshot, *, cache_use: EvidenceCacheUse = EvidenceCacheUse.NORMAL
        ):
            kwargs = {
                "authority_generation": authority_generation,
                "checkpoint": snapshot,
            }
            if cache_use is EvidenceCacheUse.BYPASS:
                kwargs["bypass_cache"] = True
            if discovered_authority is not None:
                kwargs["discovered_authority"] = discovered_authority
            if not_found != SENDER_IDENTITY_NOT_FOUND:
                kwargs["not_found_reason"] = not_found.reason
            return await resolver.fetch_evidence(canonical, **kwargs)

        def claim_for_evidence(value: ExternalAuthorityEvidence) -> AuthorityClaim:
            return claim or AuthorityClaim(
                canonical_address=canonical,
                did_aw=value.did_aw,
                current_did_key=value.current_did_key,
                delivery_origin=value.delivery_origin,
            )

        snapshot = (
            await self.repository.get_checkpoint(claim.did_aw)
            if claim is not None
            else None
        )
        evidence = await fetch_authority_evidence(snapshot)
        if claim is None:
            snapshot = await self.repository.get_checkpoint(evidence.did_aw)
            if snapshot is not None:
                evidence = await fetch_authority_evidence(
                    snapshot, cache_use=EvidenceCacheUse.BYPASS
                )
        try:
            token = await self.commit_verified_evidence(
                claim_for_evidence(evidence),
                evidence,
                publishing_fence=publishing_fence,
                fences=fences,
            )
        except FederationAuthorityError as exc:
            if exc.reason != AUTHORITY_CAS_CONFLICT.reason:
                raise
            winner = await self.repository.get_checkpoint(evidence.did_aw)
            evidence = await fetch_authority_evidence(
                winner, cache_use=EvidenceCacheUse.BYPASS
            )
            token = await self.commit_verified_evidence(
                claim_for_evidence(evidence),
                evidence,
                publishing_fence=publishing_fence,
                fences=fences,
            )
        return CommittedAuthorityEvidence(token, evidence)
