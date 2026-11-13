"""Independent protected admission policy and controller-authorized effects.

Only the local operator entry point can perform first provisioning. Public
read/prepare never creates a policy or widens its authority on a miss.
"""

import hashlib
import json

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy, PolicyInvalid


async def provision_policy(composition, fields):
    """Install exactly one initial policy under real current controller custody.

    The selected host owns one controller. A list including another controller
    refuses; sharing a service or namespace pin supplies no custody for it.
    Exact repeat is recovery. Replacing even one bound needs the separate live
    policy-change operation, not another invocation of this operator command.
    """
    c = composition
    try:
        policy = AdmissionPolicy.from_unsigned(fields, service_id=c.context.service_id)
    except PolicyInvalid:
        raise SignerRefused("request_invalid") from None
    if c.context.authority_kind != "team_controller" or policy.fields()["teams"] != [c.context.authority_id]:
        raise SignerRefused("scope_refused")
    fence = await c.authority.observe(c.context, purpose="prepare")
    lock = int.from_bytes(hashlib.sha256(
        b"aweb.admission-policy-provision/1\n" + c.context.service_id.encode()
    ).digest()[:8], "big", signed=True)
    async with c.db.transaction() as tx:
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", lock)
        binding = await c.authority.binding(tx, hold=True)
        if binding["generation"] != c.context.generation:
            raise SignerRefused("authority_changed")
        row = await tx.fetch_one(
            "SELECT policy FROM {{tables.protected_admission_policies}} WHERE service_id=$1 FOR UPDATE",
            c.context.service_id,
        )
        if row is not None:
            try:
                value = json.loads(row["policy"]) if isinstance(row["policy"], str) else row["policy"]
                existing = AdmissionPolicy.from_fields(value, service_id=c.context.service_id)
            except (ValueError, TypeError):
                raise SignerRefused("evidence_unavailable") from None
            if existing != policy:
                raise SignerRefused("policy_changed")
        else:
            await tx.execute(
                "INSERT INTO {{tables.protected_admission_policies}} (service_id,version,digest,policy) "
                "VALUES($1,$2,$3,$4::jsonb)",
                c.context.service_id, policy.version, policy.digest, json.dumps(policy.fields()),
            )
        # Recheck the held binding after the last storage await, then the original
        # registry observation synchronously. No remote reads while locks are held.
        binding = await c.authority.binding(tx, hold=True)
        if binding["generation"] != c.context.generation:
            raise SignerRefused("authority_changed")
        fence.require_fresh()
    return policy.fields()
