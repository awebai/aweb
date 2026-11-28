"""Production composition for the reviewed strict federation authority core."""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from functools import cached_property
from uuid import uuid4

from awid.external_authority import (
    OriginContext,
    RegistryAuthority,
    SystemTXTOutcomeResolver,
    TXTOutcomeResolver,
    canonical_protocol_address,
    canonical_registry_origin,
    discover_registry_authority,
)
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError

from .authority import AuthorityClaim, FederationAuthorityCore
from .lookup_policy import (
    AUTHORITY_CAS_CONFLICT,
    SENDER_IDENTITY_NOT_FOUND,
    RECIPIENT_IDENTITY_NOT_FOUND,
    SENDER_LOOKUP,
    CONTACT_LOOKUP,
    AuthorityLookupPolicy,
    AuthorityResultState,
)
from .authority_state import AuthorityRepository, AuthoritySecurityToken
from .authority_work import AuthorityLease, AuthorityWorkRepository, AuthorityWorkResult
from .transport import (
    PRIVATE_DELIVERY_ORIGINS_SETTING,
    AddressCheckedTransport,
    private_delivery_origins,
)


logger = logging.getLogger(__name__)


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
    test_default_registry_authority: RegistryAuthority | None = None
    private_delivery_origins: frozenset[str] = frozenset()

    @cached_property
    def delivery_transport(self) -> AddressCheckedTransport:
        """The transport federated delivery sends through: the resolver, origin
        policy and trust anchors are the ones registry reads use. Only this
        transport receives the operator's private delivery origins."""
        return AddressCheckedTransport(
            host_resolver=self.resolver.host_resolver,
            origin_context=self.resolver.origin_context,
            ssl_context=self.resolver.ssl_context,
            private_delivery_origins=self.private_delivery_origins,
        )

    async def _discover_registry_authority(self, domain: str) -> RegistryAuthority:
        if self.test_default_registry_authority is not None:
            return self.test_default_registry_authority
        return await discover_registry_authority(
            domain,
            self.txt_resolver,
            origin_context=self.resolver.origin_context,
        )

    @staticmethod
    def _raise_published_failure(
        result: AuthorityWorkResult | None,
        *,
        lookup: AuthorityLookupPolicy = SENDER_LOOKUP,
    ) -> None:
        if result is None or result.status != AuthorityResultState.FAILED:
            return
        reason = str(result.evidence.get("reason") or "").strip()
        if not reason:
            raise FederationAuthorityError(AUTHORITY_CAS_CONFLICT.reason)
        # Discovery/evidence results are shared by sender and contact lookups.
        if reason in {
            SENDER_IDENTITY_NOT_FOUND.reason,
            RECIPIENT_IDENTITY_NOT_FOUND.reason,
        }:
            reason = lookup.missing_identity.reason
        raise FederationAuthorityError(
            reason,
            did_aw=str(result.evidence.get("did_aw") or "").strip() or None,
            observed_sequence=result.evidence.get("observed_sequence"),
        )

    async def _publish_failure(
        self,
        error: FederationAuthorityError,
        *,
        leases: tuple[AuthorityLease | None, ...],
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
                    status=AuthorityResultState.FAILED,
                    evidence=evidence,
                    ttl_seconds=5,
                )
                await self.work.release_lease(lease)
            except Exception as exc:
                # Cleanup preserves the original authority refusal; publication
                # failure is reported without copying dependency contents.
                logger.warning(
                    "federation_authority_failure_publication_failed failure_type=%s",
                    type(exc).__name__,
                )

    async def _contact_from_result(
        self,
        canonical_address: str,
        result: AuthorityWorkResult | None,
        *,
        lookup: AuthorityLookupPolicy = CONTACT_LOOKUP,
    ) -> ResolvedContactIdentity | None:
        self._raise_published_failure(result, lookup=lookup)
        if result is None or result.status != AuthorityResultState.VERIFIED:
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
        if (
            evidence.get("checkpoint_revision") != token.checkpoint_revision
            or evidence.get("cohort_generation") != token.cohort_generation
        ):
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
        resolved = await self._resolve_address(
            claim.canonical_address,
            source_ip=source_ip,
            lookup=SENDER_LOOKUP,
        )
        if resolved.did_aw != claim.did_aw:
            raise FederationAuthorityError(
                "sender_address_did_mismatch", did_aw=claim.did_aw
            )
        if resolved.current_did_key != claim.current_did_key:
            raise FederationAuthorityError(
                "sender_current_key_mismatch", did_aw=claim.did_aw
            )
        if claim.delivery_origin and resolved.delivery_origin != claim.delivery_origin:
            raise FederationAuthorityError("sender_route_mismatch", did_aw=claim.did_aw)
        return AuthorizedFederationSender(
            resolved.token, resolved.canonical_address, resolved.delivery_origin
        )

    async def resolve_contact(
        self, address: str, *, source_ip: str
    ) -> ResolvedContactIdentity:
        return await self._resolve_address(
            address,
            source_ip=source_ip,
            lookup=CONTACT_LOOKUP,
        )

    async def _resolve_address(
        self,
        address: str,
        *,
        source_ip: str,
        lookup: AuthorityLookupPolicy,
    ) -> ResolvedContactIdentity:
        canonical = canonical_protocol_address(address)
        # Strict Cross-Registry Sender Authority
        # (docs/identity-messaging-contract.md:215-235): reuse only a live,
        # checkpoint-matching PostgreSQL cohort, before charging external work.
        published = await self.work.get_result("discovery:" + canonical)
        if published is not None and published.status == AuthorityResultState.VERIFIED:
            cached = await self._contact_from_result(
                canonical, published, lookup=lookup
            )
            if cached is not None:
                return cached
        domain = canonical.split("/", 1)[0]
        owner_id = uuid4()
        authority_generation = None
        discovery = evidence_lease = None
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
                discovery_key, owner_id=owner_id, ttl_seconds=10
            )
            if not discovery.acquired:
                result = await self.work.wait_for_result(
                    discovery_key, deadline_seconds=5
                )
                resolved = await self._contact_from_result(
                    canonical, result, lookup=lookup
                )
                if resolved is None:
                    raise FederationAuthorityError(lookup.busy.reason)
                return resolved
            authority = await self._discover_registry_authority(domain)
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
                evidence_key, owner_id=owner_id, ttl_seconds=10
            )
            if not evidence_lease.acquired:
                result = await self.work.wait_for_result(
                    evidence_key, deadline_seconds=5
                )
                resolved = await self._contact_from_result(
                    canonical, result, lookup=lookup
                )
                if resolved is None:
                    raise FederationAuthorityError(lookup.busy.reason)
                return resolved
            authority_generation = evidence_lease.fence
            committed = await self.core.resolve_evidence_and_commit(
                None,
                self.resolver,
                address=canonical,
                authority_generation=authority_generation,
                publishing_fence=evidence_lease.fence,
                fences=(discovery, evidence_lease),
                discovered_authority=authority,
                not_found=lookup.missing_identity,
            )
            token, evidence = committed.token, committed.evidence
            published_evidence = {
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
                status=AuthorityResultState.VERIFIED,
                evidence=published_evidence,
                ttl_seconds=60,
            )
            await self.work.publish_result(
                discovery,
                status=AuthorityResultState.VERIFIED,
                evidence=published_evidence,
                ttl_seconds=60,
            )
            result_published = True
            resolved = await self._contact_from_result(
                canonical, published, lookup=lookup
            )
            if resolved is None:
                raise FederationAuthorityError(lookup.busy.reason)
            return resolved
        except FederationAuthorityError as exc:
            if not result_published:
                await self._publish_failure(exc, leases=(evidence_lease, discovery))
            raise
        finally:
            if result_published:
                # The published result carries evidence, not an active worker.
                # A cohort that expires may immediately elect its next reader.
                for lease in (evidence_lease, discovery):
                    if lease is not None and lease.acquired:
                        try:
                            await self.work.release_lease(lease)
                        except FederationAuthorityError as exc:
                            # A published answer survives cleanup; this lease
                            # remains bounded by its original database TTL.
                            logger.warning(
                                "federation_authority_cleanup_failed stage=lease failure_type=%s",
                                type(exc).__name__,
                            )
            try:
                await self.work.release_permits(owner_id=owner_id)
            except FederationAuthorityError as exc:
                logger.warning(
                    "federation_authority_cleanup_failed stage=permit failure_type=%s",
                    type(exc).__name__,
                )
            if authority_generation is not None:
                await self.resolver.expire_generation(authority_generation)

    def received_registry_client(self, token, did_key, redis):
        from .id_tree_registry import received_registry_client

        return received_registry_client(self, token, did_key, redis)

    async def aclose(self) -> None:
        await self.resolver.aclose()


def build_federation_authority_activation(
    db, *, public_origin: str
) -> FederationAuthorityActivation:
    """Build the shared resolver, coordination owner and checked outbound transport."""
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
    origin_context = OriginContext(
        app_env=app_env,
        federation_test_enabled=test_enabled,
        listener_origin=public_origin,
    )
    resolver = StrictExternalRegistry(
        txt_resolver=txt_resolver,
        origin_context=origin_context,
    )
    test_default_enabled = os.getenv(
        "AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "false"
    ).strip().lower() in {"1", "true", "yes", "on"}
    test_default_registry_authority = None
    if test_default_enabled:
        if app_env.strip().lower() != "development" or not test_enabled:
            raise ValueError(
                "test default registry requires APP_ENV=development and "
                "AWEB_FEDERATION_TEST=1"
            )
        registry_origin = (os.getenv("AWID_REGISTRY_URL") or "").strip()
        if not registry_origin:
            raise ValueError("test default registry requires AWID_REGISTRY_URL")
        test_default_registry_authority = RegistryAuthority(
            selection="public_default",
            authority_name="",
            controller_did=None,
            inherited=False,
            registry_explicit=False,
            registry_origin=canonical_registry_origin(
                registry_origin, context=origin_context
            ),
        )
    private_origins = private_delivery_origins(
        os.getenv(PRIVATE_DELIVERY_ORIGINS_SETTING, ""),
        origin_context=origin_context,
    )
    reuse_seconds = int(os.getenv("AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS", "60"))
    return FederationAuthorityActivation(
        core=FederationAuthorityCore(repository, reuse_seconds=reuse_seconds),
        work=work,
        resolver=resolver,
        txt_resolver=txt_resolver,
        test_default_registry_authority=test_default_registry_authority,
        private_delivery_origins=private_origins,
    )
