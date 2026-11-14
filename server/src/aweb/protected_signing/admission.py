"""Independent protected admission policy and controller-authorized effects.

Only the local operator entry point can perform first provisioning. Public
read/prepare never creates a policy or widens its authority on a miss.
"""

import hashlib
import json
import logging
from datetime import timedelta
from time import monotonic

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


class AdmissionEffects:
    """The embedding's current registry/SQL ports for the one shared executor."""

    def __init__(self, composition, *, timer=monotonic):
        self.c, self.timer = composition, timer

    async def policy(self, tx=None):
        c = self.c
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

    async def observe(self, operation, actor, *, purpose):
        """Remote evidence precedes all operation/policy/quota locks."""
        if operation.operation == "team.agent.remove":
            from .removal import observe_removal

            return await observe_removal(self, operation, actor, purpose=purpose)
        c, subject = self.c, operation.intent()["subject"]
        if operation.audience != c.registry.registry_url:
            raise SignerRefused("scope_refused")
        if operation.operation == "team.agent.admit" and actor.principal != subject["root_id"]:
            raise SignerRefused("scope_refused")
        if operation.operation == "identity.root.endorse" and purpose == "prepare" and actor.principal != subject["root_id"]:
            raise SignerRefused("scope_refused")
        started = self.timer()
        policy = await self.policy()
        fields = policy.fields()
        teams = subject["teams"] if operation.operation == "identity.root.endorse" else [subject["team_id"]]
        if not set(teams) <= set(fields["teams"]):
            raise SignerRefused("admission_policy_missing")
        head = await self.root_head(subject["root_id"], subject["root_key"],
            require_enrolled=operation.operation == "team.agent.admit")
        if operation.operation == "team.agent.admit":
            kind_name = "local_agent" if subject["child_id"] is None else "registered_agent"
            if kind_name not in fields["subject_kinds"]:
                raise SignerRefused("subject_ineligible")
            human_key = await _registry(c.registry.resolve_key_fresh(c.context.human_id), missing="authority_changed")
            protected = set(getattr(c, "protected_authority_keys", (c.authority.custody.team_key_did,)))
            protected.add(human_key.current_did_key)
            protected.update(c.registry.namespace_keys.values())
            if subject["child_key"] in protected or (subject["child_key"] == subject["root_key"] and subject["child_id"] != subject["root_id"]):
                raise SignerRefused("subject_ineligible")
            if subject["child_id"] is not None:
                from awid.identity_observation import IdentityObservationRefused, observe_identity_binding, observe_identity_kind

                try:
                    binding = await observe_identity_binding(c.registry, did_aw=subject["child_id"], did_key=subject["child_key"])
                except IdentityObservationRefused as error:
                    if error.code == "identity_binding_mismatch":
                        raise SignerRefused("subject_ineligible") from None
                    cause = error.__cause__
                    raise SignerRefused("evidence_unavailable", retry_after_seconds=(
                        cause.retry_after_seconds if isinstance(cause, RegistryThrottled) else None
                    )) from None
                if binding.self_derived:
                    raise SignerRefused("subject_ineligible")
                # A legacy global mapping may belong to an unenrolled human;
                # only verified agent kind admits a registered child unattended.
                observed = await observe_identity_kind(c.registry, binding)
                if observed.result["outcome"] == "unavailable":
                    raise SignerRefused("evidence_unavailable")
                if observed.result["identity_valid"] is not True or observed.result["kind"] != "agent":
                    raise SignerRefused("subject_ineligible")
        return _AdmissionObservation(self, operation, policy, head, started + 60)

    async def root_head(self, root_id, root_key, *, require_enrolled):
        """The current registered agent/H chain shared by bounded root acts."""
        from awid.id_certificates import verify_id_chain

        c = self.c
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

    async def hold_endorsed_root(self, tx, root_id, head):
        c = self.c.context
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
            c.service_id, root_id,
        )
        if (row is None or row["human_id"] != c.human_id or row["human_domain"] != c.human_domain
            or row["certificate_id"] != head):
            raise SignerRefused("subject_ineligible")
        return row

    async def record_endorsement(self, tx, operation, request, result, evidence, *, artifact):
        from awid.id_certificates import id_certificate_id
        from aweb_naapp.runtime.protected_signer import VerifiedProtectedEffect

        if type(evidence) is not VerifiedProtectedEffect:
            raise SignerRefused("proof_invalid")
        await evidence.require_in(tx, operation, clock=self.c.signer.clock)
        c = operation.context
        await tx.execute(
            "INSERT INTO {{tables.protected_root_endorsements}} "
            "(service_id,root_id,human_id,human_domain,operation_id,certificate_id,policy_digest) "
            "VALUES($1,$2,$3,$4,$5,$6,$7)",
            c.service_id, operation.intent()["subject"]["root_id"], c.human_id, c.human_domain,
            operation.operation_id, id_certificate_id(artifact), request["admission_policy"]["digest"],
        )
        await evidence.require_in(tx, operation, clock=self.c.signer.clock)

    async def registered(self, operation, artifact, signed):
        """Confirm all registration fields on a fresh ordinary member read.

        The immutable certificate UUID is minted once in the frozen artifact;
        AWID registers it once after verifying that signed certificate. No nonce
        alone or mere signature is reported as a completed admission.
        """
        if operation.operation == "team.agent.remove":
            from .removal import removal_confirmed

            return await removal_confirmed(self.c, operation)
        c = self.c
        namespace, name = operation.context.authority_id.split(":", 1)[::-1]
        client = getattr(c.registry, "client", c.registry)
        rows = await _registry(client.list_team_certificates_fresh(namespace, name, active_only=False))
        matches = [row for row in rows if row.certificate_id == artifact["certificate_id"]]
        if not matches:
            return False
        if len(matches) != 1:
            raise SignerRefused("evidence_unavailable")
        row = matches[0]
        if (row.member_did_key != artifact["member_did_key"] or row.member_did_aw != artifact.get("member_did_aw")
            or row.member_address is not None or row.alias != artifact["alias"] or row.identity_scope != artifact["identity_scope"]):
            raise SignerRefused("operation_conflict")
        return True

    async def register(self, operation, artifact, signed):
        if operation.operation == "team.agent.remove":
            return await _registry(self.c.authority.custody.remove_member(self.c.registry, operation, artifact, signed))
        await _registry(self.c.authority.custody.register_admission(self.c.registry, operation, artifact, signed))

    async def confirm(self, tx, operation):
        if operation.operation == "team.agent.remove":
            from .removal import confirm_removal

            return await confirm_removal(self.c, tx, operation)
        await tx.execute("UPDATE {{tables.protected_root_admissions}} SET state='active' WHERE operation_id=$1", operation.operation_id)


class _AdmissionObservation:
    def __init__(self, adapter, operation, policy, head, deadline):
        self.adapter, self.operation, self.policy, self.head, self.deadline = adapter, operation, policy, head, deadline

    def require_fresh(self):
        if self.adapter.timer() >= self.deadline:
            raise SignerRefused("evidence_unavailable")

    async def _current(self, tx):
        policy = await self.adapter.policy(tx)
        if policy != self.policy:
            raise SignerRefused("policy_changed")
        return policy.fields()

    async def _root(self, tx):
        return await self.adapter.hold_endorsed_root(tx, self.operation.intent()["subject"]["root_id"], self.head)

    async def _hold_endorsement(self, tx, *, conflict="operation_conflict"):
        op = self.operation
        key = int.from_bytes(hashlib.sha256(
            b"aweb.root-endorsement/1\n" + op.context.service_id.encode() + b"\n" + op.intent()["subject"]["root_id"].encode()
        ).digest()[:8], "big", signed=True)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", key)
        row = await tx.fetch_one(
            "SELECT operation_id FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
            op.context.service_id, op.intent()["subject"]["root_id"],
        )
        if row is not None and row["operation_id"] != op.operation_id:
            raise SignerRefused(conflict)

    async def freeze(self, tx):
        op, subject = self.operation, self.operation.intent()["subject"]
        fields = await self._current(tx)
        if op.operation == "identity.root.endorse":
            await self._hold_endorsement(tx)
            if self.head is not None:
                # A new certificate over existing ancestry needs its own
                # re-endorsement/reparent path. Exact operation replay bypasses
                # minting and returns the original stored preparation.
                raise SignerRefused("subject_ineligible")
            existing = await tx.fetch_one(
                "SELECT operation_id FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
                op.context.service_id, subject["root_id"],
            )
            if existing is not None:
                raise SignerRefused("operation_conflict")
            return {"registry": self.adapter.c.registry.registry_url, "expected_head": None,
                "responsibility_statement": op.spec.display.responsibility_statement,
                "admission_policy": fields}
        await self._root(tx)
        if fields["digest"] != subject["admission_policy_digest"] or fields["version"] != subject["expected_policy_version"]:
            raise SignerRefused("policy_changed")
        return {"request_id": op.operation_id, "admission_policy_version": fields["version"]}

    async def check(self, tx, request):
        fields = await self._current(tx)
        op, subject = self.operation, self.operation.intent()["subject"]
        if op.operation == "identity.root.endorse":
            await self._hold_endorsement(tx, conflict="operation_mismatch")
            if request["admission_policy"] != fields:
                raise SignerRefused("policy_changed")
            if request["expected_head"] != self.head:
                raise SignerRefused("operation_mismatch")
        else:
            await self._root(tx)
            if (fields["digest"] != subject["admission_policy_digest"] or fields["version"] != subject["expected_policy_version"]
                or request["admission_policy_version"] != fields["version"] or request["request_id"] != op.operation_id):
                raise SignerRefused("policy_changed")
        self.require_fresh()

    async def reserve(self, tx, request):
        op, c, subject = self.operation, self.operation.context, self.operation.intent()["subject"]
        await _lock_quota(tx, c.service_id, subject["team_id"], subject["root_id"])
        fields = await self._current(tx)
        bounds = fields["bounds"]
        counts = await admission_counts(tx, service_id=c.service_id, team_id=subject["team_id"], root_id=subject["root_id"],
            window_seconds=bounds["rate_window_seconds"], now=self.adapter.c.signer.clock())
        if counts["active"] >= bounds["max_active"] or counts["in_window"] >= bounds["max_per_window"]:
            raise SignerRefused("admission_limit_reached")
        await tx.execute(
            "INSERT INTO {{tables.protected_root_admissions}} "
            "(operation_id,service_id,team_id,root_id,policy_digest,certificate_id,child_id,child_key,admitted_at,state) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'reserved')",
            op.operation_id, c.service_id, subject["team_id"], subject["root_id"], fields["digest"],
            request["artifact"]["certificate_id"], subject["child_id"], subject["child_key"], self.adapter.c.signer.clock(),
        )
