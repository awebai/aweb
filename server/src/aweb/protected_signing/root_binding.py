"""Local operator requester provisioning after completed first enrollment.

This installs no key, identity certificate, policy or human approval. A new
registered root must still obtain its own live endorsement under the existing
policy before the shared executor admits a child. No HTTP writer is exposed.
"""

from awid.did import validate_stable_id
from awid.team_ids import build_team_id, parse_team_id

from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.protected_signer import SignerRefused

from .admission import _registry
from .bootstrap import bootstrap_record


def binding_inputs(human, root, teams, replacement=None):
    try:
        if validate_stable_id(human) != human or validate_stable_id(root) != root:
            raise ValueError()
        if replacement is not None and (validate_stable_id(replacement) != replacement or replacement == root):
            raise ValueError()
        if type(teams) is not list or not 1 <= len(teams) <= 4096 or len(set(teams)) != len(teams):
            raise ValueError()
        for team in teams:
            domain, name = parse_team_id(team)
            if build_team_id(domain, name) != team:
                raise ValueError()
        return human, root, sorted(teams), replacement
    except (ValueError, TypeError):
        raise SignerRefused("request_invalid") from None


def selected_bindings(composition, human, teams):
    components = getattr(composition, "components", (composition,))
    humans = [c for c in components if c.context.authority_kind == "human_identity"
        and c.context.authority_id == human and c.context.human_id == human]
    if len(humans) != 1:
        raise SignerRefused("scope_refused")
    owner = humans[0]
    selected = [owner]
    for team in teams:
        matches = [c for c in components if c.context.authority_kind == "team_controller"
            and c.context.authority_id == team and c.context.human_id == human
            and c.context.human_domain == owner.context.human_domain]
        if len(matches) != 1:
            raise SignerRefused("scope_refused")
        selected.append(matches[0])
    if any(c.db is not composition.db or c.context.service_id != owner.context.service_id
        or c.request_origin != owner.request_origin for c in selected):
        raise SignerRefused("scope_refused")
    return owner, sorted(selected, key=lambda c: (c.context.authority_kind, c.context.authority_id))


async def _current_binding(c, tx, *, hold):
    row = await c.authority.binding(tx, hold=hold)
    policy = await c.signer.policies.current("aweb.human-assurance/1", tx=tx)
    if row["generation"] != c.context.generation or policy is None or policy.version != row["policy_version"]:
        raise SignerRefused("authority_changed")
    return row


async def bind_root(composition, *, human_id, root_id, teams, replace_root=None):
    """Called only with the local operator's actual opened host composition.

    Select both H's identity and each controller explicitly. One SQL requester
    row never covers two B3 scopes. Current custody/registry/association and
    usable completed authorizers remain independent of the requester grant.
    """
    human_id, root_id, teams, replace_root = binding_inputs(human_id, root_id, teams, replace_root)
    owner, parts = selected_bindings(composition, human_id, teams)
    started = owner.authority.timer()
    root = await _registry(owner.registry.resolve_key_fresh(root_id), missing="subject_ineligible")
    await owner.signer.admission.root_head(root_id, root.current_did_key, require_enrolled=False)
    observations = [(c, await c.authority.observe(c.context, purpose="prepare")) for c in parts]
    policies = [(c, await c.signer.admission.policy()) for c in parts]
    if any(not set(teams) <= set(policy.fields()["teams"]) for _, policy in policies):
        raise SignerRefused("admission_policy_missing")
    changed, scopes = [], []
    async with composition.db.transaction() as tx:
        # Serialize requester provisioning for this H, including absent rows.
        await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "protected-root-binding:" + owner.context.service_id + ":" + human_id)
        # Bootstrap takes its record before the authority row. Preserve that
        # order, and hold the complete union before B3's credential union.
        completed = [(c, await bootstrap_record(c, tx, hold=True)) for c in parts]
        bindings = [(c, await _current_binding(c, tx, hold=True)) for c in parts]
        for (_, bootstrap), (_, binding) in zip(completed, bindings, strict=True):
            if (bootstrap is None or bootstrap["consumed_at"] is None
                or bootstrap["subject"] != binding["subject"] or bootstrap["b3_scope"] != binding["b3_scope"]):
                raise SignerRefused("bootstrap_incomplete")
        pairs = [(row["b3_scope"], row["subject"]) for _, row in bindings]
        b3 = await owner.passkeys.prepare_current_approvers(tx, pairs)
        for c, expected in policies:
            if await c.signer.admission.policy(tx) != expected:
                raise SignerRefused("policy_changed")
        for c, binding in bindings:
            scope = binding["b3_scope"]
            existing = await tx.fetch_one("SELECT active FROM {{tables.protected_requester_bindings}} "
                "WHERE b3_scope=$1 AND principal=$2 FOR UPDATE", scope, root_id)
            if existing is not None and not existing["active"]:
                raise SignerRefused("requester_binding_retired")
            if existing is None:
                await tx.execute("INSERT INTO {{tables.protected_requester_bindings}} (b3_scope,principal) VALUES($1,$2)", scope, root_id)
                changed.append(scope)
            if replace_root is not None:
                previous = await tx.fetch_one("SELECT active FROM {{tables.protected_requester_bindings}} "
                    "WHERE b3_scope=$1 AND principal=$2 FOR UPDATE", scope, replace_root)
                if previous is None:
                    raise SignerRefused("scope_refused")
                if previous["active"]:
                    await tx.execute("UPDATE {{tables.protected_requester_bindings}} SET active=FALSE WHERE b3_scope=$1 AND principal=$2", scope, replace_root)
                    changed.append(scope)
            scopes.append(c.context.fields())
        if changed:
            await owner.audit.emit(AuditEvent(kind=AuditKind.PROTECTED_ROOT_REQUESTER_BOUND,
                actor="operator", subject=root_id, occurred_at=owner.signer.clock(), details={
                    "human_id": human_id, "root_id": root_id, "root_key": root.current_did_key,
                    "teams": teams, "scopes": scopes, "replaced_root": replace_root,
                }), tx)
        for c, original in bindings:
            current = await _current_binding(c, tx, hold=False)
            if (current["b3_scope"], current["subject"], current["policy_version"]) != (original["b3_scope"], original["subject"], original["policy_version"]):
                raise SignerRefused("authority_changed")
        for scope, subject in pairs:
            if not await owner.passkeys.check_current_approver(tx, b3, scope=scope, subject=subject):
                raise SignerRefused("authority_changed")
        for _, observation in observations:
            observation.require_fresh()
        if owner.authority.timer() >= started + 60:
            raise SignerRefused("evidence_unavailable")
    return {"service_id": owner.context.service_id, "human_id": human_id,
        "root_id": root_id, "root_key": root.current_did_key, "teams": teams,
        "scopes": scopes, "replaced_root": replace_root}
