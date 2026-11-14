"""Current owner UV removes an exact membership independently of root buckets.

The definition selects this port; requester provenance never supplies the
human's authority. B2/B3 and IndependentAuthority remain the shared executor's
current-owner and exact live-gesture boundary.
"""

from aweb_naapp.runtime.protected_signer import AdmittedHuman, CatalogOperation, RestrictedRequester, SignerRefused
from aweb_naapp.runtime.protected_signer.owner_initiation import _checked_owner_initiation

from .admission import AdmissionEffects
from .removal import confirm_removal, current_member, membership_fields, removable_kind, removal_confirmed


class OwnerRemovalEffects(AdmissionEffects):
    async def observe(self, operation, actor, *, purpose):
        c = self.c
        if (operation.audience != c.registry.registry_url
            or operation.intent()["subject"]["team_id"] != c.context.authority_id
            or actor.context != operation.context):
            raise SignerRefused("scope_refused")
        if purpose == "prepare":
            initiation = _checked_owner_initiation(actor, operation=operation)
            if (type(actor) is not RestrictedRequester and initiation is None) or not actor.key_did:
                raise SignerRefused("requester_invalid")
        elif type(actor) is not AdmittedHuman or actor.principal != c.context.human_id:
            raise SignerRefused("scope_refused")
        started = self.timer()
        record = await current_member(c, operation)
        if record is None or record.revoked_at is not None:
            raise SignerRefused("subject_ineligible")
        kind = await removable_kind(c, record, allow_unknown=True)
        return OwnerRemovalObservation(self, actor, kind, started + 60)

    async def prepare_selection(self, selection, actor):
        from .admission import _registry

        if _checked_owner_initiation(actor) is None or selection != actor.selection:
            raise SignerRefused("scope_refused")
        name, domain = actor.context.authority_id.split(":", 1)
        client = getattr(self.c.registry, "client", self.c.registry)
        rows = await _registry(client.list_team_certificates_fresh(domain, name, active_only=False))
        matches = [row for row in rows if row.certificate_id == selection["certificate_id"]]
        if len(matches) > 1:
            raise SignerRefused("evidence_unavailable")
        if not matches or matches[0].revoked_at is not None:
            raise SignerRefused("subject_ineligible")
        record = matches[0]
        operation = CatalogOperation(selection["operation_id"], actor.context, self.c.registry.registry_url,
            selection["operation"], selection["variant"], {"team_id": actor.context.authority_id,
                "member_id": record.member_did_aw or record.member_did_key, "certificate_id": record.certificate_id,
                "expected_membership": membership_fields(record)})
        return await self.c.signer.prepare(operation, requester=actor)

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
        if (type(self.actor) is RestrictedRequester or _checked_owner_initiation(self.actor) is not None) and request["requester_key"] != self.actor.key_did:
            raise SignerRefused("operation_mismatch")
        self.require_fresh()


async def prepare_owner_selection(c, selection, session):
    """Host-only initiation from a validated current B3 console session."""
    from aweb_naapp.runtime.protected_signer.catalog import operation_spec
    from aweb_naapp.runtime.protected_signer.owner_initiation import _admitted_owner_initiation, owner_selection

    selection = owner_selection(selection)
    spec = operation_spec(selection["operation"], selection["variant"])
    if c.context.authority_kind != "team_controller" or selection["team_id"] != c.context.authority_id:
        raise SignerRefused("scope_refused")
    async with c.db.transaction() as tx:
        context = await c.authority.context_for_scope(session.scope, tx=tx)
    human = AdmittedHuman(context.human_id, session.subject, session.scope, context)
    key = getattr(c.authority.custody, "service_did_key", None)
    actor = _admitted_owner_initiation(selection, human=human, session=session, host_key_did=key)
    saved = await c.signer.owner_prepared(actor)
    if saved is not None:
        return saved
    provider = getattr(c.signer, spec.effect.provider or "", None)
    prepare = getattr(provider, spec.effect.initiation_prepare or "", None)
    if not callable(prepare):
        raise SignerRefused("operation_not_served")
    return await prepare(selection, actor)
