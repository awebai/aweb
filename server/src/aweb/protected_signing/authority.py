"""Current independent authorizer bindings, rechecked in the original effect tx."""

from __future__ import annotations

import logging
from time import monotonic

from aweb_naapp.runtime.protected_signer import (
    AdmittedHuman,
    ProtectedKeyContext,
    ReceiptReader,
    RestrictedRequester,
    SignerRefused,
)
from aweb_naapp.runtime.protected_signer.types import _checked_self_removal
from awid.identity_observation import (
    IdentityObservationRefused,
    observe_identity_binding,
    observe_identity_kind,
)
from awid.registry_types import RegistryThrottled

logger = logging.getLogger(__name__)


class IndependentAuthority:
    def __init__(self, db, *, context, registry, custody, timer=monotonic):
        self.db, self.context, self.registry, self.custody, self.timer = (
            db,
            context,
            registry,
            custody,
            timer,
        )

    async def binding(self, tx, *, hold=False):
        c = self.context
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.protected_authorizer_bindings}} "
            "WHERE service_id=$1 AND team_id=$2 AND human_id=$3 AND human_domain=$4 "
            "AND authority_kind=$5 AND COALESCE(authority_domain,split_part(team_id,':',2))=$6"
            + (" FOR SHARE" if hold else ""),
            c.service_id,
            c.authority_id,
            c.human_id,
            c.human_domain,
            c.authority_kind,
            c.authority_domain,
        )
        if row is None or not row["active"]:
            raise SignerRefused("authority_changed")
        return row

    async def context_for_scope(self, scope, *, tx):
        row = await self.binding(tx)
        if scope != row["b3_scope"]:
            raise SignerRefused("scope_refused")
        c = self.context
        return ProtectedKeyContext(
            c.service_id,
            c.authority_kind,
            c.authority_id,
            c.authority_domain,
            c.human_id,
            c.human_domain,
            row["generation"],
        )

    async def observe(self, context, *, purpose):
        c = self.context
        if (
            context.authority_kind
            != getattr(self.custody, "authority_kind", "team_controller")
            or {k: v for k, v in context.fields().items() if k != "generation"}
            != {k: v for k, v in c.fields().items() if k != "generation"}
            or c.service_id != self.custody.service_id
            or c.authority_id != self.custody.team_id
        ):
            raise SignerRefused("scope_refused")
        started = self.timer()
        protection = None
        try:
            human_key = await self._own_human(c.human_id, c.human_domain)
            if c.authority_kind == "team_controller":
                name, domain = c.authority_id.split(":", 1)
                if domain != c.authority_domain:
                    raise SignerRefused("scope_refused")
                from awid.protected_membership import observe_team_protection

                protection = await observe_team_protection(self.registry, c.authority_id)
                team_key = protection.controller_did_key
            elif c.authority_kind == "namespace_controller":
                if c.authority_id != c.authority_domain:
                    raise SignerRefused("scope_refused")
                namespace = await self.registry.get_namespace_fresh(c.authority_domain)
                team_key = namespace.controller_did if namespace is not None else None
            elif c.authority_kind == "human_identity":
                team_key = (
                    human_key
                    if c.authority_id == c.human_id
                    and c.authority_domain == c.human_domain
                    else await self._own_human(c.authority_id, c.authority_domain)
                )
            else:
                raise SignerRefused("scope_refused")
        except SignerRefused:
            raise
        except Exception as exc:
            # The public binding helper preserves the SDK failure as its
            # explicit cause. Keep only that known wrapper's typed metadata.
            cause = (
                exc.__cause__ if isinstance(exc, IdentityObservationRefused) else exc
            )
            logger.warning(
                "Protected signer registry evidence unavailable", exc_info=True
            )
            raise SignerRefused(
                "evidence_unavailable",
                retry_after_seconds=(
                    cause.retry_after_seconds
                    if isinstance(cause, RegistryThrottled)
                    else None
                ),
            ) from None
        if team_key != self.custody.team_key_did:
            raise SignerRefused("authority_changed")
        return _Current(self, context, purpose, started + 60, protection)

    async def _own_human(self, principal, domain):
        resolved = await self.registry.resolve_key_fresh(principal)
        binding = await observe_identity_binding(
            self.registry,
            did_aw=principal,
            did_key=resolved.current_did_key,
        )
        if (
            binding.self_derived
            or binding.id_tree is None
            or not binding.id_tree.enrolled
            or binding.id_tree.domain != domain
        ):
            raise SignerRefused("subject_ineligible")
        kind = await observe_identity_kind(self.registry, binding)
        if kind.result["outcome"] == "unavailable":
            raise SignerRefused("evidence_unavailable")
        if not kind.is_human or kind.result["human_id"] != principal:
            raise SignerRefused("issuer_kind_forbidden")
        return resolved.current_did_key


class _Current:
    def __init__(self, authority, context, purpose, deadline, protection=None):
        self.authority, self.context, self.purpose, self.deadline = (
            authority,
            context,
            purpose,
            deadline,
        )
        self.team_key_did = authority.custody.team_key_did
        self.self_deadline = None
        self.protection = protection

    async def _check(self, tx, actor, *, hold):
        if type(actor) not in {AdmittedHuman, RestrictedRequester, ReceiptReader}:
            raise SignerRefused("scope_refused")
        if actor.context != self.context:
            raise SignerRefused("scope_refused")
        row = await self.authority.binding(tx, hold=hold)
        if self.purpose != "receipt" and row["generation"] != self.context.generation:
            raise SignerRefused("authority_changed")
        if type(actor) is AdmittedHuman:
            if (
                actor.principal != self.context.human_id
                or actor.subject != row["subject"]
                or actor.b3_scope != row["b3_scope"]
            ):
                raise SignerRefused("scope_refused")
        else:
            cap = _checked_self_removal(actor)
            if cap is not None:
                self.self_deadline = cap.deadline
                return
            requester = await tx.fetch_one(
                "SELECT active FROM {{tables.protected_requester_bindings}} "
                "WHERE b3_scope=$1 AND principal=$2" + (" FOR SHARE" if hold else ""),
                row["b3_scope"],
                actor.principal,
            )
            if requester is None or not requester["active"]:
                raise SignerRefused("scope_refused")

    async def prepare(self, tx, actor):
        # ProtectedSigner already holds the operation lock. Keep this binding
        # and (for a requester) its grant held before any B3/B2 locks.
        await self._check(tx, actor, hold=True)

    async def check(self, tx, actor):
        await self._check(tx, actor, hold=False)

    def require_fresh(self):
        if self.protection is not None:
            from awid.protected_effect import EffectRefused

            try:
                self.protection.require_fresh()
            except EffectRefused:
                raise SignerRefused("evidence_unavailable") from None
        now = self.authority.timer()
        if now > self.deadline or (self.self_deadline is not None and now >= self.self_deadline):
            raise SignerRefused("evidence_unavailable")
