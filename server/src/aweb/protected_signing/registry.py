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
