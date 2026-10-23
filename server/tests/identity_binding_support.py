"""Identity preconditions for tests whose subject is routing or presentation."""
from collections import OrderedDict
from time import monotonic

from aweb.identity_binding import IdentityBinding


def seed_verified_bindings(app, *bindings):
    """Supply an explicit positive cache fact without replacing authentication."""
    cache = getattr(app.state, "identity_binding_cache", None)
    if cache is None:
        cache = app.state.identity_binding_cache = OrderedDict()
    for did_aw, did_key, address in bindings:
        for claim_address in {"", address or ""}:
            cache[(did_aw, did_key, claim_address)] = (
                monotonic() + 60, IdentityBinding(did_aw=did_aw, address=claim_address),
            )


async def register_global_identity(env, actor, address=""):
    """Provision real DID/address evidence in the disposable AWID service."""
    registry = env.app.state.awid_registry_client
    identity = await registry.register_did(actor.did, actor.sk)
    if address:
        domain, name = address.split("/", 1)
        # DNS and address rows are fixture provisioning, as in the binding
        # admission tests; signature and binding reads use the real service.
        namespace = await env.registry_db.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain=$1", domain,
        )
        if namespace is None:
            namespace = await env.registry_db.fetch_one(
                "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
                "VALUES ($1, $2, 'verified') RETURNING namespace_id", domain, env.team_did,
            )
        await env.registry_db.execute(
            "INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw) VALUES ($1,$2,$3)",
            namespace["namespace_id"], name, identity.did_aw,
        )
    return identity.did_aw
