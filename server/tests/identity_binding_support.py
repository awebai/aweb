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
    """Write DID/address evidence using the shared namespace owner's custody.

    Registry.ensure_namespace owns the independent controller and external DNS
    answer. A team key never supplies namespace authority by implication.
    """
    registry = env.app.state.awid_registry_client
    identity = await registry.register_did(actor.did, actor.sk)
    if not address:
        return identity.did_aw
    domain, name = address.split("/", 1)
    controller = await env.registry.ensure_namespace(domain=domain)
    registered = await registry.register_address(
        domain, name, identity.did_aw, controller, current_did_key=actor.did
    )
    assert registered.did_aw == identity.did_aw
    assert f"{registered.domain}/{registered.name}" == address
    return identity.did_aw
