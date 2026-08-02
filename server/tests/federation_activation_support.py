from __future__ import annotations

from awid.federation_errors import FederationAuthorityError
from aweb.federation.activation import AuthorizedFederationSender, ResolvedContactIdentity
from aweb.federation.authority_state import AuthoritySecurityToken


class TestFederationAuthority:
    """Legacy production-seam fixture that establishes real Phase-A rows."""

    __test__ = False

    def __init__(self, manager, registry) -> None:
        self.manager = manager
        self.registry = registry

    async def authorize(self, claim, *, source_ip: str):
        del source_ip
        resolution = await self.registry.resolve_key(claim.did_aw)
        if resolution is None:
            raise FederationAuthorityError("sender_identity_not_found")
        if resolution.current_did_key != claim.current_did_key:
            raise FederationAuthorityError("sender_current_key_mismatch")
        await self.manager.execute(
            """
            INSERT INTO {{tables.federation_did_checkpoints}} (
                did_aw, seq, entry_hash, state_hash, current_did_key, revision
            ) VALUES ($1, 1, $2, $3, $4, 1)
            ON CONFLICT (did_aw) DO UPDATE SET
                current_did_key = EXCLUDED.current_did_key,
                updated_at = clock_timestamp()
            """,
            claim.did_aw,
            "a" * 64,
            "b" * 64,
            claim.current_did_key,
        )
        await self.manager.execute(
            """
            INSERT INTO {{tables.federation_address_authority_cohorts}} (
                canonical_address, authority_selection, authority_name,
                controller_did, authority_statement_version,
                authority_statement_digest, inherited, registry_explicit,
                registry_origin, bound_did_aw, bound_current_did_key,
                checkpoint_seq, checkpoint_entry_hash, checkpoint_revision,
                authoritative_delivery_origin,
                authoritative_read_completed_at, expires_at,
                generation, revision, publishing_fence
            ) VALUES (
                $1, 'dns', '_awid.test', 'did:key:z6Mktestcontroller',
                'aweb.federation-authority.dns.v1', $2, FALSE, TRUE,
                'https://registry.test', $3, $4, 1, $5, 1, $6,
                clock_timestamp(), clock_timestamp() + INTERVAL '59 seconds',
                1, 1, 1
            )
            ON CONFLICT (canonical_address) DO UPDATE SET
                bound_did_aw = EXCLUDED.bound_did_aw,
                bound_current_did_key = EXCLUDED.bound_current_did_key,
                authoritative_delivery_origin = EXCLUDED.authoritative_delivery_origin,
                expires_at = EXCLUDED.expires_at,
                updated_at = clock_timestamp()
            """,
            claim.canonical_address,
            "sha256:" + "c" * 64,
            claim.did_aw,
            claim.current_did_key,
            "a" * 64,
            claim.delivery_origin,
        )
        token = AuthoritySecurityToken(claim.canonical_address, claim.did_aw, 1, 1)
        return AuthorizedFederationSender(
            token=token,
            canonical_address=claim.canonical_address,
            delivery_origin=claim.delivery_origin,
        )

    async def resolve_contact(self, address: str, *, source_ip: str):
        del source_ip
        domain, name = address.split("/", 1)
        if self.registry is None:
            raise FederationAuthorityError("sender_identity_not_found")
        resolution = await self.registry.resolve_address(domain, name)
        if resolution is None:
            raise FederationAuthorityError("sender_identity_not_found")
        delivery = getattr(resolution, "delivery", None)
        return ResolvedContactIdentity(
            token=AuthoritySecurityToken(address, resolution.did_aw, 1, 1),
            canonical_address=address,
            did_aw=resolution.did_aw,
            current_did_key=resolution.current_did_key,
            controller_did="did:key:z6Mktestcontroller",
            delivery_origin=str(getattr(delivery, "origin", "") or ""),
        )
