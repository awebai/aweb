"""Customer-registry evidence with explicit operator-pinned namespace roots."""

from __future__ import annotations

from time import monotonic
from types import MappingProxyType

from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.did import public_key_from_did
from awid.id_certificates import IDChainEvidence, status_request
from awid.log import require_canonical_server_origin
from awid.registry import RegistryClient


class CustomerRegistry(RegistryClient):
    """One configured registry, no Cloud credential or discovery fallback.

    Namespace keys are protected-host provisioning references, not values
    taken from the status response or worker input. Updating a pin is a
    separately authorized operator/controller transition, never auto-recovery.
    Ordinary member keys, when configured, authenticate only the SDK's closed
    private-team read paths; no controller is substituted for a member.
    """

    def __init__(
        self,
        *,
        registry_origin,
        namespace_keys,
        member_signing_keys=None,
        transport=None,
    ):
        require_canonical_server_origin(registry_origin)
        if not namespace_keys:
            raise ValueError("namespace authority references are required")
        for key in namespace_keys.values():
            public_key_from_did(key)
        self.namespace_keys = MappingProxyType(dict(namespace_keys))
        super().__init__(
            registry_url=registry_origin,
            transport=transport,
            member_signing_keys=dict(member_signing_keys or {}),
        )

    async def _registry_url_for_domain(self, domain):
        if domain not in self.namespace_keys:
            raise SignerRefused("scope_refused")
        return self.registry_url

    async def id_chain_evidence(self, bundle, subject, *, domain):
        started = monotonic()
        plan = status_request(bundle, subject, domain=domain)
        if plan is None:
            raise SignerRefused("subject_ineligible")
        status = await self.fetch_id_certificate_status(domain, plan)
        return IDChainEvidence(
            status=status,
            namespace_authority={
                "domain": domain,
                "dns_name": "_awid." + domain,
                "inherited": False,
                "controller_key": self.namespace_keys[domain],
            },
            age_seconds=monotonic() - started,
        )


class PinnedRegistryView:
    """Profile-bound reads over runtime.registry_client(); the host owns close.

    Preserve its actual ordinary member credentials and transport. Do not
    create another HTTP client, swap in controller authority, or discover a
    fallback registry. Namespace trust stays with the explicit profile pins.
    """

    def __init__(self, client, *, profile):
        if (
            client.registry_url != profile.registry_origin
            or getattr(client, "service_token", None)
            or (
                getattr(client, "base_url", None) is not None
                and client.base_url.rstrip("/") != profile.registry_origin
            )
        ):
            raise SignerRefused("scope_refused")
        self.client, self.registry_url = client, profile.registry_origin
        self.namespace_keys = MappingProxyType(profile.namespace_keys())

    def _domain(self, domain):
        if domain not in self.namespace_keys:
            raise SignerRefused("scope_refused")

    async def resolve_key_fresh(self, principal):
        return await self.client.resolve_key_fresh(principal)

    async def get_team_public_key_fresh(self, domain, name):
        self._domain(domain)
        return await self.client.get_team_public_key_fresh(
            domain,
            name,
            registry_origin=self.registry_url,
        )

    async def fetch_id_certificate_status(self, domain, request):
        self._domain(domain)
        return await self.client.fetch_id_certificate_status(
            domain,
            request,
            registry_origin=self.registry_url,
        )

    async def id_chain_evidence(self, bundle, subject, *, domain):
        return await CustomerRegistry.id_chain_evidence(
            self, bundle, subject, domain=domain
        )
