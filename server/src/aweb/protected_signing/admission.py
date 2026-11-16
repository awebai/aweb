"""Independent protected admission policy and controller-authorized effects.

Only the local operator entry point can perform first provisioning. Public
read/prepare never creates a policy or widens its authority on a miss.
"""

import hashlib
import json
import logging
from datetime import timedelta

from awid.registry_types import RegistryError, RegistryThrottled

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy, PolicyInvalid


logger = logging.getLogger(__name__)


async def _registry(awaitable, *, missing=None):
    try:
        return await awaitable
    except RegistryError as error:
        if error.status_code == 404 and missing is not None:
            raise SignerRefused(missing) from None
        logger.warning("Protected admission registry evidence unavailable", exc_info=True)
        raise SignerRefused("evidence_unavailable", retry_after_seconds=(
            error.retry_after_seconds if isinstance(error, RegistryThrottled) else None
        )) from None


async def admission_counts(tx, *, service_id, team_id, root_id, window_seconds, now):
    """One root's admissions to one team, as the bounds count them: active
    (reserved or active), admitted inside the rate window, and when the
    oldest of those leaves the window (None when the window is empty)."""
    active = await tx.fetch_value(
        "SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE service_id=$1 AND team_id=$2 AND root_id=$3 AND state IN ('reserved','active')",
        service_id, team_id, root_id,
    )
    window = await tx.fetch_one(
        "SELECT count(*) AS in_window, min(admitted_at) AS oldest FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 AND root_id=$3 "
        "AND EXTRACT(EPOCH FROM ($4::timestamptz-admitted_at)) < $5::numeric",
        service_id, team_id, root_id, now, window_seconds,
    )
    oldest = window["oldest"]
    return {"active": active, "in_window": window["in_window"],
        "next_at": None if oldest is None else oldest + timedelta(seconds=window_seconds)}


async def _lock_quota(tx, service_id, team_id, root_id):
    key = int.from_bytes(hashlib.sha256(
        b"aweb.admission-quota/1\n" + json.dumps([service_id, team_id, root_id], separators=(",", ":")).encode()
    ).digest()[:8], "big", signed=True)
    await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", key)


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
    components = getattr(c, "components", (c,))
    selected = []
    for team in policy.fields()["teams"]:
        matches = [part for part in components if part.context.authority_kind == "team_controller" and part.context.authority_id == team]
        if len(matches) != 1:
            raise SignerRefused("scope_refused")
        selected.append(matches[0])
    fences = [(part, await part.authority.observe(part.context, purpose="prepare")) for part in selected]
    lock = int.from_bytes(hashlib.sha256(
        b"aweb.admission-policy-provision/1\n" + c.context.service_id.encode()
    ).digest()[:8], "big", signed=True)
    async with c.db.transaction() as tx:
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", lock)
        for part, _ in fences:
            binding = await part.authority.binding(tx, hold=True)
            if binding["generation"] != part.context.generation:
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
        for part, fence in fences:
            binding = await part.authority.binding(tx, hold=True)
            if binding["generation"] != part.context.generation:
                raise SignerRefused("authority_changed")
        for _, fence in fences:
            fence.require_fresh()
    return policy.fields()


async def read_policy(c, tx=None):
    row = await (c.db if tx is None else tx).fetch_one(
        "SELECT policy FROM {{tables.protected_admission_policies}} WHERE service_id=$1" + (" FOR SHARE" if tx is not None else ""),
        c.context.service_id,
    )
    if row is None:
        raise SignerRefused("admission_policy_missing")
    try:
        value = json.loads(row["policy"]) if isinstance(row["policy"], str) else row["policy"]
        return AdmissionPolicy.from_fields(value, service_id=c.context.service_id)
    except (ValueError, TypeError):
        raise SignerRefused("evidence_unavailable") from None


async def root_head(c, root_id, root_key, *, require_enrolled):
    """The current registered agent/H chain shared by bounded root acts."""
    from awid.id_certificates import verify_id_chain

    root = await _registry(c.registry.resolve_key_fresh(root_id), missing="subject_ineligible")
    if root.did_aw != root_id or root.current_did_key != root_key:
        raise SignerRefused("subject_ineligible")
    tree = root.id_tree
    if tree is None:
        raise SignerRefused("evidence_unavailable")
    if not tree.enrolled:
        if require_enrolled:
            raise SignerRefused("subject_ineligible")
        return None
    if tree.domain != c.context.human_domain:
        raise SignerRefused("subject_ineligible")
    subject = {"id": root_id, "did_key": root_key}
    evidence = await _registry(c.registry.id_chain_evidence(None, subject, domain=tree.domain))
    kind = verify_id_chain(None, subject=subject, evidence=evidence, domain=tree.domain)
    if kind["outcome"] == "unavailable":
        raise SignerRefused("evidence_unavailable")
    if not kind["identity_valid"] or kind["kind"] != "agent" or kind["human_id"] != c.context.human_id:
        raise SignerRefused("subject_ineligible")
    heads = [row["current_certificate_id"] for row in evidence.status["identities"] if row["id"] == root_id]
    if len(heads) != 1:
        raise SignerRefused("evidence_unavailable")
    return heads[0]


async def hold_endorsed_root(composition, tx, root_id, head):
    c = composition.context
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
        c.service_id, root_id,
    )
    if (row is None or row["human_id"] != c.human_id or row["human_domain"] != c.human_domain
        or row["certificate_id"] != head):
        raise SignerRefused("subject_ineligible")
    return row



async def checked_policy(c, tx, observed):
    current = await read_policy(c, tx)
    if current != observed:
        raise SignerRefused("policy_changed")
    return current.fields()
