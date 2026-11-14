"""Current owner UV removes an exact membership independently of root buckets.

The definition selects this port; requester provenance never supplies the
human's authority. B2/B3 and IndependentAuthority remain the shared executor's
current-owner and exact live-gesture boundary.
"""

from aweb_naapp.runtime.protected_signer import AdmittedHuman, RestrictedRequester, SignerRefused

from .admission import AdmissionEffects
from .removal import confirm_removal, current_member, removable_kind, removal_confirmed


class OwnerRemovalEffects(AdmissionEffects):
    async def observe(self, operation, actor, *, purpose):
        c = self.c
        if (operation.audience != c.registry.registry_url
            or operation.intent()["subject"]["team_id"] != c.context.authority_id
            or actor.context != operation.context):
            raise SignerRefused("scope_refused")
        if purpose == "prepare":
            if type(actor) is not RestrictedRequester or not actor.key_did:
                raise SignerRefused("requester_invalid")
        elif type(actor) is not AdmittedHuman or actor.principal != c.context.human_id:
            raise SignerRefused("scope_refused")
        started = self.timer()
        record = await current_member(c, operation)
        if record is None or record.revoked_at is not None:
            raise SignerRefused("subject_ineligible")
        kind = await removable_kind(c, record, allow_unknown=True)
        return OwnerRemovalObservation(self, actor, kind, started + 60)

    async def registered(self, operation, artifact, signed):
        return await removal_confirmed(self.c, operation)

    async def register(self, operation, artifact, signed):
        from .admission import _registry

        return await _registry(self.c.authority.custody.remove_member(self.c.registry, operation, artifact, signed))

    async def confirm(self, tx, operation):
        await confirm_removal(self.c, tx, operation, require_bucket=False)


class OwnerRemovalObservation:
    def __init__(self, adapter, actor, kind, deadline):
        self.adapter, self.actor, self.kind, self.deadline = adapter, actor, kind, deadline

    def require_fresh(self):
        if self.adapter.timer() >= self.deadline:
            raise SignerRefused("evidence_unavailable")

    async def freeze(self, tx):
        self.require_fresh()
        return {"requester_key": self.actor.key_did, "target_kind": self.kind}

    async def check(self, tx, request):
        if request["target_kind"] != self.kind:
            # A different current classification cannot reuse the frozen
            # display/UV even when both classifications would be eligible.
            raise SignerRefused("operation_mismatch")
        if type(self.actor) is RestrictedRequester and request["requester_key"] != self.actor.key_did:
            raise SignerRefused("operation_mismatch")
        self.require_fresh()
