"""Identity preconditions for tests whose subject is routing or presentation."""

from collections import OrderedDict
from time import monotonic

from aweb.identity_binding import IdentityBinding
from awid.registry import IDTreeEnrollment


def seed_verified_bindings(app, *bindings):
    """Supply positive binding and unenrolled evidence for legacy routing fixtures."""
    cache = getattr(app.state, "identity_binding_cache", None)
    if cache is None:
        cache = app.state.identity_binding_cache = OrderedDict()
    for did_aw, did_key, address in bindings:
        for claim_address in {"", address or ""}:
            cache[(did_aw, did_key, claim_address)] = (
                monotonic() + 60,
                IdentityBinding(
                    did_aw=did_aw,
                    address=claim_address,
                    did_key=did_key,
                    id_tree=IDTreeEnrollment(False, None),
                ),
            )


async def register_global_identity(env, actor, address=""):
    """Write DID and address evidence through the real signed registry routes.

    The only supplied authority is external DNS for the disposable namespace.
    Namespace/address authorization, writes and binding reads stay production.
    """
    from awid.dns_verify import DomainAuthority
    from awid_service.deps import get_domain_verifier

    registry = env.app.state.awid_registry_client
    identity = await registry.register_did(actor.did, actor.sk)
    if not address:
        return identity.did_aw
    domain, name = address.split("/", 1)
    assert domain == "example.test", "The privacy fixture owns only example.test"

    async def namespace_authority(requested_domain: str) -> DomainAuthority:
        assert requested_domain == domain
        return DomainAuthority(env.team_did, registry.registry_url, "_awid." + domain)

    overrides = env.registry_app.dependency_overrides
    previous = overrides.get(get_domain_verifier)
    overrides[get_domain_verifier] = lambda: namespace_authority
    try:
        namespace = await env.registry_db.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain=$1", domain
        )
        if namespace is None:
            await registry.register_namespace(domain, env.team_did, env.team_sk)
        registered = await registry.register_address(
            domain, name, identity.did_aw, env.team_sk, current_did_key=actor.did
        )
        assert registered.did_aw == identity.did_aw
        assert f"{registered.domain}/{registered.name}" == address
    finally:
        if previous is None:
            del overrides[get_domain_verifier]
        else:
            overrides[get_domain_verifier] = previous
    return identity.did_aw
