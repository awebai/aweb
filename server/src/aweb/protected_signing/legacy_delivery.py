"""Legacy registry delivery through the definition's closed request plan."""

import base64
from datetime import UTC, datetime

from awid.registry import CachedRegistryClient

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.types import owner_act_operation


def delivery_plan(custody, operation, artifact, signing, signature, timestamp):
    typed = owner_act_operation(operation)
    context = typed.context
    if (context.service_id != custody.service_id or context.authority_kind != custody.authority_kind
        or context.authority_id != custody.team_id or context.authority_domain != custody.domain):
        raise SignerRefused("scope_refused")
    builder = typed.spec.effect.delivery_plan
    if builder is None:
        raise SignerRefused("operation_not_served")
    plan = builder(typed, artifact, signing, signature, timestamp)
    if plan.controller_did != custody.team_key_did:
        raise SignerRefused("operation_mismatch")
    return plan


def authenticate_plan(custody, plan, *, signing, signature):
    # A revoke artifact already is its exact controller-auth envelope. Reuse
    # its original signature instead of performing another key operation.
    if plan.controller_envelope is None:
        authentication = None
    elif plan.controller_envelope == signing:
        authentication = signature
    else:
        authentication = custody._key.sign(plan.controller_envelope).signature
    return plan.authenticate(authentication)


async def _invalidate(client, operation, domain, name):
    # Preserve the SDK's existing registration tolerance, separately from the
    # strict prepared-revocation invalidation port. No alternate cache exists.
    if operation.spec.effect.cache_tolerates_unavailable and isinstance(client, CachedRegistryClient):
        await client._invalidate_team_certificate_cache_keys(domain, name, tolerate_unavailable=True)
    else:
        await client.invalidate_team_certificate_cache(domain, name)


async def deliver_legacy(custody, registry, operation, artifact, result):
    if set(result) != {"signing", "signature"}:
        raise SignerRefused("operation_mismatch")
    signature = base64.b64decode(result["signature"], validate=True)
    signing = base64.b64decode(result["signing"], validate=True)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    plan = delivery_plan(custody, operation, artifact, signing, signature, timestamp)
    if plan.audience != registry.registry_url:
        raise SignerRefused("scope_refused")
    delivery = authenticate_plan(custody, plan, signing=signing, signature=signature)
    client = getattr(registry, "client", registry)
    typed = owner_act_operation(operation)
    origin = await client._registry_url_for_domain(custody.domain)
    if origin != registry.registry_url:
        raise SignerRefused("scope_refused")
    name = custody.team_id.partition(":")[0]
    await _invalidate(client, typed, custody.domain, name)
    try:
        await client._request_json(delivery.method, delivery.path, headers=dict(delivery.headers),
            content=delivery.body, registry_url=origin)
    finally:
        # A lost answer can follow a committed change. Do not preserve a stale
        # active certificate after returning that ambiguity to reconciliation.
        await _invalidate(client, typed, custody.domain, name)
