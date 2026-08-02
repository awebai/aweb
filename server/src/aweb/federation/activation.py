"""Production composition for the reviewed strict federation authority core."""

from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import uuid4

from awid.external_authority import (
    OriginContext,
    SystemTXTOutcomeResolver,
    TXTOutcomeResolver,
    canonical_protocol_address,
    discover_registry_authority,
)
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError

from .authority import AuthorityClaim, FederationAuthorityCore
from .authority_state import AuthorityRepository, AuthoritySecurityToken
from .authority_work import AuthorityLease, AuthorityWorkRepository, AuthorityWorkResult


@dataclass(frozen=True)
class AuthorizedFederationSender:
    token: AuthoritySecurityToken
    canonical_address: str
    delivery_origin: str


@dataclass(frozen=True)
class ResolvedContactIdentity:
    token: AuthoritySecurityToken
    canonical_address: str
    did_aw: str
    current_did_key: str
    controller_did: str
    delivery_origin: str


@dataclass
class FederationAuthorityActivation:
    core: FederationAuthorityCore
    work: AuthorityWorkRepository
    resolver: StrictExternalRegistry
    txt_resolver: TXTOutcomeResolver

    @staticmethod
    def _raise_published_failure(result: AuthorityWorkResult | None) -> None:
        if result is None or result.status != "failed":
            return
        reason = str(result.evidence.get("reason") or "").strip()
        if not reason:
            raise FederationAuthorityError("federation_authority_cas_conflict")
        raise FederationAuthorityError(
            reason,
            did_aw=str(result.evidence.get("did_aw") or "").strip() or None,
            observed_sequence=result.evidence.get("observed_sequence"),
        )

    async def _publish_failure(
        self,
        error: FederationAuthorityError,
        *leases: AuthorityLease | None,
    ) -> None:
        evidence = {
            "reason": error.reason,
            "did_aw": error.did_aw,
            "observed_sequence": error.observed_sequence,
        }
        for lease in leases:
            if lease is None or not lease.acquired:
                continue
            try:
                await self.work.publish_result(
                    lease,
                    status="failed",
                    evidence=evidence,
                    ttl_seconds=5,
                )
                await self.work.release_lease(lease)
            except Exception:
                pass

    async def _authorize_from_result(
        self,
        claim: AuthorityClaim,
        result: AuthorityWorkResult | None,
    ) -> AuthorizedFederationSender | None:
        self._raise_published_failure(result)
        if result is None or result.status != "verified":
            return None
        evidence = result.evidence
        canonical = canonical_protocol_address(claim.canonical_address)
        if evidence.get("canonical_address") != canonical:
            raise FederationAuthorityError(
                "sender_address_did_mismatch", did_aw=claim.did_aw
            )
        if evidence.get("did_aw") != claim.did_aw:
            raise FederationAuthorityError(
                "sender_address_did_mismatch", did_aw=claim.did_aw
            )
        if evidence.get("current_did_key") != claim.current_did_key:
            raise FederationAuthorityError(
                "sender_current_key_mismatch", did_aw=claim.did_aw
            )
        delivery_origin = str(evidence.get("delivery_origin") or "").strip()
        if claim.delivery_origin and claim.delivery_origin != delivery_origin:
            raise FederationAuthorityError("sender_route_mismatch", did_aw=claim.did_aw)
        effective_claim = AuthorityClaim(
            canonical_address=claim.canonical_address,
            did_aw=claim.did_aw,
            current_did_key=claim.current_did_key,
            delivery_origin=delivery_origin,
        )
        token = await self.core.authorize_from_shared_cohort(effective_claim)
        if token is None:
            return None
        return AuthorizedFederationSender(
            token=token,
            canonical_address=token.canonical_address,
            delivery_origin=delivery_origin,
        )

    async def _contact_from_result(
        self,
        canonical_address: str,
        result: AuthorityWorkResult | None,
    ) -> ResolvedContactIdentity | None:
        self._raise_published_failure(result)
        if result is None or result.status != "verified":
            return None
        evidence = result.evidence
        if evidence.get("canonical_address") != canonical_address:
            return None
        did_aw = str(evidence.get("did_aw") or "").strip()
        current_did_key = str(evidence.get("current_did_key") or "").strip()
        controller_did = str(evidence.get("controller_did") or "").strip()
        delivery_origin = str(evidence.get("delivery_origin") or "").strip()
        if not all((did_aw, current_did_key, controller_did, delivery_origin)):
            return None
        claim = AuthorityClaim(
            canonical_address=canonical_address,
            did_aw=did_aw,
            current_did_key=current_did_key,
            delivery_origin=delivery_origin,
        )
        token = await self.core.authorize_from_shared_cohort(claim)
        if token is None:
            return None
        return ResolvedContactIdentity(
            token=token,
            canonical_address=canonical_address,
            did_aw=did_aw,
            current_did_key=current_did_key,
            controller_did=controller_did,
            delivery_origin=delivery_origin,
        )

    async def authorize(
        self,
        claim: AuthorityClaim,
        *,
        source_ip: str,
    ) -> AuthorizedFederationSender:
        cached = (
            await self.core.authorize_from_shared_cohort(claim)
            if claim.delivery_origin
            else None
        )
        if cached is not None:
            return AuthorizedFederationSender(
                token=cached,
                canonical_address=cached.canonical_address,
                delivery_origin=claim.delivery_origin,
            )

        canonical = canonical_protocol_address(claim.canonical_address)
        domain = canonical.split("/", 1)[0]
        owner_id = uuid4()
        authority_generation: int | None = None
        discovery_lease: AuthorityLease | None = None
        evidence_lease: AuthorityLease | None = None
        result_published = False
        await self.work.consume_token(
            bucket_kind="source_ip",
            bucket_key=source_ip or "unknown",
            burst=5,
            refill_per_minute=30,
        )
        await self.work.consume_token(
            bucket_kind="domain",
            bucket_key=domain,
            burst=5,
            refill_per_minute=30,
        )
        await self.work.acquire_permits(
            owner_id=owner_id,
            scopes=(("global", "external-reads", 32), ("domain", domain, 2)),
            ttl_seconds=10,
        )
        try:
            discovery_key = "discovery:" + canonical
            discovery_lease = await self.work.acquire_lease(
                discovery_key,
                owner_id=owner_id,
                ttl_seconds=10,
            )
            if not discovery_lease.acquired:
                result = await self.work.wait_for_result(
                    discovery_key,
                    deadline_seconds=5,
                )
                authorized = await self._authorize_from_result(claim, result)
                if authorized is None:
                    raise FederationAuthorityError("federation_authority_cas_conflict")
                return authorized

            authority = await discover_registry_authority(
                domain,
                self.txt_resolver,
                origin_context=self.resolver.origin_context,
            )
            await self.work.consume_token(
                bucket_kind="origin",
                bucket_key=authority.registry_origin,
                burst=5,
                refill_per_minute=30,
            )
            await self.work.acquire_permits(
                owner_id=owner_id,
                scopes=(("origin", authority.registry_origin, 4),),
                ttl_seconds=10,
            )
            evidence_key = f"origin:{authority.registry_origin}:address:{canonical}"
            evidence_lease = await self.work.acquire_lease(
                evidence_key,
                owner_id=owner_id,
                ttl_seconds=10,
            )
            if not evidence_lease.acquired:
                result = await self.work.wait_for_result(
                    evidence_key,
                    deadline_seconds=5,
                )
                authorized = await self._authorize_from_result(claim, result)
                if authorized is None:
                    raise FederationAuthorityError("federation_authority_cas_conflict")
                return authorized

            authority_generation = evidence_lease.fence
            evidence = await self.resolver.fetch_evidence(
                canonical,
                authority_generation=authority_generation,
                discovered_authority=authority,
            )
            checkpoint = await self.core.repository.get_checkpoint(evidence.did_aw)
            if checkpoint is not None:
                evidence = await self.resolver.fetch_evidence(
                    canonical,
                    authority_generation=authority_generation,
                    checkpoint=checkpoint,
                    bypass_cache=True,
                    discovered_authority=authority,
                )
            evidence_claim = AuthorityClaim(
                canonical_address=canonical,
                did_aw=evidence.did_aw,
                current_did_key=evidence.current_did_key,
                delivery_origin=evidence.delivery_origin,
            )
            try:
                token = await self.core.commit_verified_evidence(
                    evidence_claim,
                    evidence,
                    publishing_fence=evidence_lease.fence,
                    fences=(discovery_lease, evidence_lease),
                )
            except FederationAuthorityError as exc:
                if exc.reason != "federation_authority_cas_conflict":
                    raise
                winner = await self.core.repository.get_checkpoint(evidence.did_aw)
                evidence = await self.resolver.fetch_evidence(
                    canonical,
                    authority_generation=authority_generation,
                    checkpoint=winner,
                    bypass_cache=True,
                    discovered_authority=authority,
                )
                evidence_claim = AuthorityClaim(
                    canonical_address=canonical,
                    did_aw=evidence.did_aw,
                    current_did_key=evidence.current_did_key,
                    delivery_origin=evidence.delivery_origin,
                )
                token = await self.core.commit_verified_evidence(
                    evidence_claim,
                    evidence,
                    publishing_fence=evidence_lease.fence,
                    fences=(discovery_lease, evidence_lease),
                )
            result = {
                "canonical_address": token.canonical_address,
                "did_aw": token.did_aw,
                "checkpoint_revision": token.checkpoint_revision,
                "cohort_generation": token.cohort_generation,
                "current_did_key": evidence.current_did_key,
                "controller_did": evidence.controller_did,
                "delivery_origin": evidence.delivery_origin,
            }
            published = await self.work.publish_result(
                evidence_lease,
                status="verified",
                evidence=result,
                ttl_seconds=60,
            )
            await self.work.publish_result(
                discovery_lease,
                status="verified",
                evidence=result,
                ttl_seconds=60,
            )
            result_published = True
            authorized = await self._authorize_from_result(claim, published)
            if authorized is None:
                raise FederationAuthorityError("federation_authority_cas_conflict")
            return authorized
        except FederationAuthorityError as exc:
            if not result_published:
                await self._publish_failure(exc, evidence_lease, discovery_lease)
            raise
        finally:
            await self.work.release_permits(owner_id=owner_id)
            if authority_generation is not None:
                await self.resolver.expire_generation(authority_generation)

    async def resolve_contact(
        self,
        address: str,
        *,
        source_ip: str,
    ) -> ResolvedContactIdentity:
        canonical = canonical_protocol_address(address)
        domain = canonical.split("/", 1)[0]
        owner_id = uuid4()
        authority_generation: int | None = None
        discovery: AuthorityLease | None = None
        evidence_lease: AuthorityLease | None = None
        result_published = False
        for bucket_kind, bucket_key in (
            ("source_ip", source_ip or "unknown"),
            ("domain", domain),
        ):
            await self.work.consume_token(
                bucket_kind=bucket_kind,
                bucket_key=bucket_key,
                burst=5,
                refill_per_minute=30,
            )
        await self.work.acquire_permits(
            owner_id=owner_id,
            scopes=(("global", "external-reads", 32), ("domain", domain, 2)),
            ttl_seconds=10,
        )
        try:
            discovery_key = "discovery:" + canonical
            discovery = await self.work.acquire_lease(
                discovery_key,
                owner_id=owner_id,
                ttl_seconds=10,
            )
            if not discovery.acquired:
                result = await self.work.wait_for_result(
                    discovery_key,
                    deadline_seconds=5,
                )
                resolved = await self._contact_from_result(canonical, result)
                if resolved is None:
                    raise FederationAuthorityError("federation_resolver_busy")
                return resolved
            authority = await discover_registry_authority(
                domain,
                self.txt_resolver,
                origin_context=self.resolver.origin_context,
            )
            await self.work.consume_token(
                bucket_kind="origin",
                bucket_key=authority.registry_origin,
                burst=5,
                refill_per_minute=30,
            )
            await self.work.acquire_permits(
                owner_id=owner_id,
                scopes=(("origin", authority.registry_origin, 4),),
                ttl_seconds=10,
            )
            evidence_key = (
                "origin:" + authority.registry_origin + ":address:" + canonical
            )
            evidence_lease = await self.work.acquire_lease(
                evidence_key,
                owner_id=owner_id,
                ttl_seconds=10,
            )
            if not evidence_lease.acquired:
                result = await self.work.wait_for_result(
                    evidence_key,
                    deadline_seconds=5,
                )
                resolved = await self._contact_from_result(canonical, result)
                if resolved is None:
                    raise FederationAuthorityError("federation_resolver_busy")
                return resolved
            authority_generation = evidence_lease.fence
            evidence = await self.resolver.fetch_evidence(
                canonical,
                authority_generation=evidence_lease.fence,
                discovered_authority=authority,
            )
            checkpoint = await self.core.repository.get_checkpoint(evidence.did_aw)
            if checkpoint is not None:
                evidence = await self.resolver.fetch_evidence(
                    canonical,
                    authority_generation=evidence_lease.fence,
                    checkpoint=checkpoint,
                    bypass_cache=True,
                    discovered_authority=authority,
                )
            claim = AuthorityClaim(
                canonical_address=canonical,
                did_aw=evidence.did_aw,
                current_did_key=evidence.current_did_key,
                delivery_origin=evidence.delivery_origin,
            )
            try:
                token = await self.core.commit_verified_evidence(
                    claim,
                    evidence,
                    publishing_fence=evidence_lease.fence,
                    fences=(discovery, evidence_lease),
                )
            except FederationAuthorityError as exc:
                if exc.reason != "federation_authority_cas_conflict":
                    raise
                checkpoint = await self.core.repository.get_checkpoint(evidence.did_aw)
                evidence = await self.resolver.fetch_evidence(
                    canonical,
                    authority_generation=evidence_lease.fence,
                    checkpoint=checkpoint,
                    bypass_cache=True,
                    discovered_authority=authority,
                )
                claim = AuthorityClaim(
                    canonical_address=canonical,
                    did_aw=evidence.did_aw,
                    current_did_key=evidence.current_did_key,
                    delivery_origin=evidence.delivery_origin,
                )
                token = await self.core.commit_verified_evidence(
                    claim,
                    evidence,
                    publishing_fence=evidence_lease.fence,
                    fences=(discovery, evidence_lease),
                )
            result = {
                "canonical_address": canonical,
                "did_aw": evidence.did_aw,
                "current_did_key": evidence.current_did_key,
                "controller_did": evidence.controller_did,
                "delivery_origin": evidence.delivery_origin,
                "checkpoint_revision": token.checkpoint_revision,
                "cohort_generation": token.cohort_generation,
            }
            await self.work.publish_result(
                evidence_lease,
                status="verified",
                evidence=result,
                ttl_seconds=60,
            )
            await self.work.publish_result(
                discovery,
                status="verified",
                evidence=result,
                ttl_seconds=60,
            )
            result_published = True
            return ResolvedContactIdentity(
                token=token,
                canonical_address=canonical,
                did_aw=evidence.did_aw,
                current_did_key=evidence.current_did_key,
                controller_did=evidence.controller_did,
                delivery_origin=evidence.delivery_origin,
            )
        except FederationAuthorityError as exc:
            if not result_published:
                await self._publish_failure(exc, evidence_lease, discovery)
            raise
        finally:
            await self.work.release_permits(owner_id=owner_id)
            if authority_generation is not None:
                await self.resolver.expire_generation(authority_generation)

    async def aclose(self) -> None:
        await self.resolver.aclose()


def build_federation_authority_activation(db, *, public_origin: str) -> FederationAuthorityActivation:
    manager = db.get_manager("aweb")
    repository = AuthorityRepository(manager)
    work = AuthorityWorkRepository(manager)
    txt_resolver = SystemTXTOutcomeResolver()
    app_env = os.getenv("APP_ENV", "production")
    test_enabled = os.getenv("AWEB_FEDERATION_TEST", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    resolver = StrictExternalRegistry(
        txt_resolver=txt_resolver,
        origin_context=OriginContext(
            app_env=app_env,
            federation_test_enabled=test_enabled,
            listener_origin=public_origin,
        ),
    )
    reuse_seconds = int(os.getenv("AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS", "60"))
    return FederationAuthorityActivation(
        core=FederationAuthorityCore(repository, reuse_seconds=reuse_seconds),
        work=work,
        resolver=resolver,
        txt_resolver=txt_resolver,
    )
