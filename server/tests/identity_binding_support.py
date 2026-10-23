"""Identity preconditions for tests whose subject is routing or presentation."""
from collections import OrderedDict
from time import monotonic

from awid.registry import RegistryError
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
        try:
            await registry.get_namespace(domain)
        except RegistryError as exc:
            if exc.status_code != 404:
                raise
            await registry.register_namespace(domain, env.team_did, env.team_sk)
        await registry.register_address(domain, name, identity.did_aw, env.team_sk)
    return identity.did_aw
