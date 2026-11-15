"""Bounded member admission, selected only by its catalog effect port."""
from time import monotonic

from awid.registry_types import RegistryThrottled
from aweb_naapp.runtime.protected_signer import SignerRefused
from .admission import _lock_quota, _registry, admission_counts, checked_policy, hold_endorsed_root, read_policy, root_head


class AdmitEffects:
    def __init__(self, composition, *, timer=monotonic):
        self.c, self.timer = composition, timer

    async def observe(self, operation, actor, *, purpose):
        c, subject = self.c, operation.intent()["subject"]
        if operation.audience != c.registry.registry_url:
            raise SignerRefused("scope_refused")
        started = self.timer()
        policy = await read_policy(c)
        fields = policy.fields()
        if subject["team_id"] not in fields["teams"]:
            raise SignerRefused("admission_policy_missing")
        head = await root_head(c, subject["root_id"], subject["root_key"], require_enrolled=True)
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
        return AdmissionObservation(self, operation, policy, head, started + 60)

    async def registered(self, operation, artifact, signed):
        """Confirm all registration fields on a fresh ordinary member read.

        The immutable certificate UUID is minted once in the frozen artifact;
        AWID registers it once after verifying that signed certificate. No nonce
        alone or mere signature is reported as a completed admission.
        """
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
        await _registry(self.c.authority.custody.register_admission(self.c.registry, operation, artifact, signed))

    async def confirm(self, tx, operation):
        await tx.execute("UPDATE {{tables.protected_root_admissions}} SET state='active' WHERE operation_id=$1", operation.operation_id)


class AdmissionObservation:
    def __init__(self, adapter, operation, policy, head, deadline):
        self.adapter, self.operation, self.policy, self.head, self.deadline = adapter, operation, policy, head, deadline

    def require_fresh(self):
        if self.adapter.timer() >= self.deadline:
            raise SignerRefused("evidence_unavailable")

    async def _current(self, tx):
        return await checked_policy(self.adapter.c, tx, self.policy)

    async def _root(self, tx):
        return await hold_endorsed_root(self.adapter.c, tx, self.operation.intent()["subject"]["root_id"], self.head)

    async def freeze(self, tx):
        op, subject = self.operation, self.operation.intent()["subject"]
        fields = await self._current(tx)
        await self._root(tx)
        if fields["digest"] != subject["admission_policy_digest"] or fields["version"] != subject["expected_policy_version"]:
            raise SignerRefused("policy_changed")
        return {"request_id": op.operation_id, "admission_policy_version": fields["version"]}

    async def check(self, tx, request):
        fields = await self._current(tx)
        op, subject = self.operation, self.operation.intent()["subject"]
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
