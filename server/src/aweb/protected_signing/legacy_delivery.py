"""Legacy registry delivery through the definition's closed request plan."""

import base64
from datetime import UTC, datetime

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


def authenticate_plan(custody, plan):
    authentication = custody._key.sign(plan.controller_envelope).signature if plan.controller_envelope is not None else None
    return plan.authenticate(authentication)


async def deliver_legacy(custody, registry, operation, artifact, result):
    if set(result) != {"signing", "signature"}:
        raise SignerRefused("operation_mismatch")
    signature = base64.b64decode(result["signature"], validate=True)
    signing = base64.b64decode(result["signing"], validate=True)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    plan = delivery_plan(custody, operation, artifact, signing, signature, timestamp)
    if plan.audience != registry.registry_url:
        raise SignerRefused("scope_refused")
    delivery = authenticate_plan(custody, plan)
    client = getattr(registry, "client", registry)
    await client._request_json(delivery.method, delivery.path, headers=dict(delivery.headers),
        content=delivery.body, registry_url=registry.registry_url)
