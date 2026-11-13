"""Member removal ports for the same shared bounded-operation executor.

Current root/self admission precedes signing. Fresh registry confirmation
precedes the atomic quota/receipt/audit transition; uncertain removal keeps
capacity occupied and never repeats its mutation.
"""

from dataclasses import asdict

from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.removal import validate_removal_subject
from aweb_naapp.runtime.protected_signer.types import _checked_self_removal
from awid.contract import normalize_identity_scope
from awid.identity_observation import IdentityObservationRefused, observe_identity_binding, observe_identity_kind
from awid.registry_types import RegistryThrottled

from .admission import _lock_quota, _registry


def membership_fields(record):
    value = asdict(record) if not isinstance(record, dict) else record
    return {"member_did_key": value["member_did_key"], "member_did_aw": value.get("member_did_aw") or None,
        "member_address": value.get("member_address") or None, "alias": value["alias"], "identity_scope": normalize_identity_scope(value.get("identity_scope") or value.get("lifetime"))}


async def current_member(c, operation):
    subject = validate_removal_subject(operation.intent()["subject"])
    name, domain = subject["team_id"].split(":", 1)
    client = getattr(c.registry, "client", c.registry)
    records = await _registry(client.list_team_certificates_fresh(domain, name, active_only=False))
    matches = [record for record in records if record.certificate_id == subject["certificate_id"]]
    if not matches:
        return None
    if len(matches) != 1:
        raise SignerRefused("evidence_unavailable")
    if membership_fields(matches[0]) != subject["expected_membership"]:
        raise SignerRefused("operation_conflict")
    return matches[0]


async def agent_target(c, record, *, self_key=None):
    """Use current identity kind; a certificate grants no human-removal right."""
    human = await _registry(c.registry.resolve_key_fresh(c.context.human_id), missing="authority_changed")
    protected = set(getattr(c, "protected_authority_keys", (c.authority.custody.team_key_did,)))
    protected.update(c.registry.namespace_keys.values())
    protected.add(human.current_did_key)
    if record.member_did_key in protected:
        raise SignerRefused("subject_ineligible")
    if record.identity_scope == "local":
        if record.member_did_aw is not None:
            raise SignerRefused("subject_ineligible")
        return
    if not record.member_did_aw:
        raise SignerRefused("subject_ineligible")
    resolved = await _registry(c.registry.resolve_key_fresh(record.member_did_aw), missing="subject_ineligible")
    if self_key is not None and resolved.current_did_key != self_key:
        raise SignerRefused("subject_ineligible")
    try:
        binding = await observe_identity_binding(c.registry, did_aw=record.member_did_aw, did_key=resolved.current_did_key)
        if binding.self_derived or binding.id_tree is None:
            raise SignerRefused("subject_ineligible")
        if binding.id_tree.enrolled:
            kind = (await observe_identity_kind(c.registry, binding)).result
            if kind["outcome"] == "unavailable":
                raise SignerRefused("evidence_unavailable")
            if kind["identity_valid"] is not True or kind["kind"] != "agent":
                raise SignerRefused("subject_ineligible")
    except IdentityObservationRefused as error:
        if error.code == "identity_binding_mismatch":
            raise SignerRefused("subject_ineligible") from None
        cause = error.__cause__
        raise SignerRefused("evidence_unavailable", retry_after_seconds=(
            cause.retry_after_seconds if isinstance(cause, RegistryThrottled) else None
        )) from None


async def observe_removal(adapter, operation, actor, *, purpose):
    c, subject = adapter.c, operation.intent()["subject"]
    if operation.audience != c.registry.registry_url or subject["team_id"] != c.context.authority_id:
        raise SignerRefused("scope_refused")
    started = adapter.timer()
    cap = _checked_self_removal(actor, operation=operation)
    policy, head = None, None
    if subject["root_id_or_self"] == "self":
        if cap is None:
            raise SignerRefused("scope_refused")
    else:
        if cap is not None or actor.principal != subject["root_id_or_self"] or not actor.key_did:
            raise SignerRefused("scope_refused")
        policy = await adapter.policy()
        if subject["team_id"] not in policy.fields()["teams"]:
            raise SignerRefused("scope_refused")
        head = await adapter.root_head(actor.principal, actor.key_did, require_enrolled=True)
    record = await current_member(c, operation)
    if record is None:
        raise SignerRefused("subject_ineligible")
    if cap is not None and record.member_did_key != actor.key_did:
        raise SignerRefused("scope_refused")
    await agent_target(c, record, self_key=actor.key_did if cap is not None else None)
    return RemovalObservation(adapter, operation, actor, record, policy, head, started + 60)


class RemovalObservation:
    def __init__(self, adapter, operation, actor, record, policy, head, deadline):
        self.adapter, self.operation, self.actor = adapter, operation, actor
        self.record, self.policy, self.head, self.deadline = record, policy, head, deadline

    def require_fresh(self):
        if self.adapter.timer() >= self.deadline:
            raise SignerRefused("evidence_unavailable")

    async def local_row(self, tx, *, hold=False):
        subject, c = self.operation.intent()["subject"], self.operation.context
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.protected_root_admissions}} WHERE service_id=$1 AND team_id=$2 AND certificate_id=$3"
            + (" FOR UPDATE" if hold else ""), c.service_id, c.authority_id, subject["certificate_id"],
        )
        if row is not None and (row["child_key"] != self.record.member_did_key or row["child_id"] != self.record.member_did_aw):
            raise SignerRefused("operation_mismatch")
        if subject["root_id_or_self"] != "self" and (row is None or row["root_id"] != self.actor.principal):
            raise SignerRefused("scope_refused")
        return row

    async def freeze(self, tx):
        await self.check(tx, {"requester_key": self.actor.key_did})
        return {"requester_key": self.actor.key_did}

    async def check(self, tx, request):
        if not self.actor.key_did or request["requester_key"] != self.actor.key_did:
            raise SignerRefused("operation_mismatch")
        if self.policy is not None:
            current = await self.adapter.policy(tx)
            if current.fields() != self.policy.fields():
                raise SignerRefused("policy_changed")
            await self.adapter.hold_endorsed_root(tx, self.actor.principal, self.head)
        await self.local_row(tx)
        self.require_fresh()

    async def reserve(self, tx, request):
        row = await self.local_row(tx)
        if row is not None:
            await _lock_quota(tx, row["service_id"], row["team_id"], row["root_id"])
            await self.local_row(tx, hold=True)
        await self.check(tx, request)


async def removal_confirmed(c, operation):
    record = await current_member(c, operation)
    return record is not None and record.revoked_at is not None


async def confirm_removal(c, tx, operation):
    subject, context = operation.intent()["subject"], operation.context
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.protected_root_admissions}} WHERE service_id=$1 AND team_id=$2 AND certificate_id=$3",
        context.service_id, context.authority_id, subject["certificate_id"],
    )
    if row is not None:
        if subject["root_id_or_self"] != "self" and row["root_id"] != subject["root_id_or_self"]:
            raise SignerRefused("scope_refused")
        expected = subject["expected_membership"]
        if row["child_id"] != expected["member_did_aw"] or row["child_key"] != expected["member_did_key"]:
            raise SignerRefused("operation_mismatch")
        await _lock_quota(tx, context.service_id, context.authority_id, row["root_id"])
        await tx.execute("UPDATE {{tables.protected_root_admissions}} SET state='removed' WHERE operation_id=$1", row["operation_id"])
    elif subject["root_id_or_self"] != "self":
        raise SignerRefused("scope_refused")
    await c.audit.emit(AuditEvent(kind=AuditKind.PROTECTED_MEMBER_REMOVED,
        actor=subject["member_id"] if subject["root_id_or_self"] == "self" else subject["root_id_or_self"],
        subject=operation.operation_id, occurred_at=c.signer.clock(),
        details={"operation_id": operation.operation_id, "team_id": context.authority_id,
            "certificate_id": subject["certificate_id"], "member_id": subject["member_id"]}), tx)
