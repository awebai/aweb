"""Frozen approval plans retain exact terms without carrying send authority."""

from dataclasses import replace
from uuid import uuid4

import pytest
from aweb_naapp.runtime.installation import AdmittedInstallation

from aweb_secrets.derived_lineage import LineageNode
from aweb_secrets.grant import GrantRecord
from aweb_secrets.jobs import JobDefinition
from aweb_secrets.records import StoredSecret
from aweb_secrets.run_plan import FrozenRunPlan, PlannedSlot, RunPlanRefused
from tests.test_admission import ALICE, GENERATION, INSTALLATION, TEAM
from tests.test_jobs import after as job_after
from tests.test_records_store import DID_KEY, POLICY, SECRET
from tests.test_records_store import db as db


def _inputs():
    body = job_after()
    body["credentials"][0]["secret_ref"] = SECRET.ref
    body["env"] = {"DB_ADMIN": {"$credential": SECRET.ref}}
    job = JobDefinition.from_after(body)
    grant = GrantRecord.from_after(
        {
            "v": 1,
            "grant_id": "grt_run001",
            "secret_id": SECRET.secret_id,
            "subject": {"principal": ALICE.did_aw},
            "capability": "run",
            "operations": [],
            "open_request": False,
            "jobs": [{"job_id": job.job_id, "digest": job.digest}],
            "policy_digest": POLICY.digest,
        }
    )
    return dict(
        run_id="run_original001",
        intent_id="int_original001",
        dispatch_id=uuid4(),
        installation=AdmittedInstallation(
            app_id="secrets", team_id=TEAM, installation_id=INSTALLATION, generation=GENERATION
        ),
        requester=ALICE,
        requester_roles=(),
        runner_id=body["runner_ids"][0],
        job=job,
        params={"database": "orders"},
        slots=(
            PlannedSlot(
                ordinal=0,
                label=SECRET.ref,
                source=StoredSecret(SECRET, "active", 4),
                ancestry=(
                    LineageNode(
                        INSTALLATION,
                        TEAM,
                        StoredSecret(SECRET, "active", 4),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                ),
                parent_grant=grant,
                parent_policy=POLICY,
                delivery="durable",
            ),
        ),
    )


def test_freeze_detaches_nested_inputs_and_all_parameter_views():
    inputs = _inputs()
    plan = FrozenRunPlan.freeze(**inputs)
    original = plan.canonical
    inputs["params"]["database"] = "different"
    view = plan.body
    view["params"]["database"] = "another"
    view["slots"][0]["parent_policy"]["rate"].append({"capacity": 100})
    assert plan.canonical == original
    assert plan.body["params"] == {"database": "orders"}
    assert plan.body["slots"][0]["parent_policy"] == dict(POLICY.body)
    assert FrozenRunPlan.from_bytes(original).digest == plan.digest


@pytest.mark.parametrize(
    "field",
    ["run_id", "intent_id", "dispatch_id", "runner_id", "version", "grant", "policy", "params"],
)
def test_every_approval_binding_changes_the_frozen_plan(field):
    inputs = _inputs()
    before = FrozenRunPlan.freeze(**inputs)
    # The storage parser is deliberately inert: loading a plan cannot admit it.
    changed = before.body
    if field in ("run_id", "intent_id", "dispatch_id", "runner_id"):
        changed[field] += "-changed"
    elif field == "version":
        changed["slots"][0]["source"]["version"] += 1
    elif field == "grant":
        changed["slots"][0]["parent_grant"]["grant_id"] = "grt_run002"
    elif field == "policy":
        changed["slots"][0]["parent_policy"]["approval_ttl_s"] += 1
    else:
        changed["params"]["database"] = "other"
    from aweb_secrets.runner_protocol import canonical

    assert FrozenRunPlan.from_bytes(canonical(changed)).digest != before.digest


def test_arbitrary_plan_bytes_do_not_gain_prepared_or_mint_authority():
    inputs = _inputs()
    plan = FrozenRunPlan.freeze(**inputs)
    assert not hasattr(plan, "recheck")
    assert not hasattr(plan, "may_send")
    assert not hasattr(plan, "mint")
    assert "orders" not in repr(plan)
    assert "orders" not in repr(inputs["slots"][0])


@pytest.mark.parametrize(
    "bad", [b'{"v":1,"v":1}', b'{"v":1,"x":1.5}', b'{"v":1,"x":9007199254740992}']
)
def test_invalid_or_noncanonical_persisted_json_has_a_value_free_refusal(bad):
    with pytest.raises(RunPlanRefused) as refused:
        FrozenRunPlan.from_bytes(bad)
    assert str(refused.value) == "run_plan_invalid"


@pytest.mark.parametrize(
    "mutation",
    ["wrong_team", "wrong_grant", "wrong_slot", "missing_slot", "missing_mint", "params"],
)
def test_freeze_refuses_mismatched_slot_and_request_bindings(mutation):
    inputs = _inputs()
    slot = inputs["slots"][0]
    if mutation == "wrong_team":
        inputs["installation"] = replace(inputs["installation"], team_id="other:example.com")
    elif mutation == "wrong_grant":
        inputs["slots"] = (
            replace(slot, parent_grant=replace(slot.parent_grant, secret_id="sec_other001")),
        )
    elif mutation == "wrong_slot":
        inputs["slots"] = (replace(slot, ordinal=1),)
    elif mutation == "missing_slot":
        inputs["slots"] = ()
    elif mutation == "missing_mint":
        inputs["slots"] = (replace(slot, delivery="short_lived"),)
    else:
        inputs["params"] = {"database": "-bad"}
    with pytest.raises(RunPlanRefused):
        FrozenRunPlan.freeze(**inputs)


def _short_lived_inputs():
    import copy

    from awid.signing import canonical_json_bytes

    from aweb_secrets.derived_grants import GrantSnapshot
    from aweb_secrets.grant import GrantTemplate
    from aweb_secrets.operation import OperationTemplate, operation_digest
    from aweb_secrets.run_plan import PlannedMint
    from tests.test_change_records import OPERATION
    from tests.test_operation_record import OAUTH_TOKEN_STORE

    inputs = _inputs()
    template = GrantTemplate.from_after(
        {
            "v": 1,
            "grant_template_id": "gtp_sts-derived",
            "subject": {"principal": ALICE.did_aw},
            "capability": "use",
            "operations": [],
            "open_request": True,
            "jobs": [],
            "policy_digest": POLICY.digest,
        }
    )
    record = copy.deepcopy(OPERATION)
    record.update(
        token_issuing=True,
        result_handling="store_as_secret",
        store_as_secret={**OAUTH_TOKEN_STORE, "grant_template_digest": template.digest},
    )
    # Inert future stored metadata. The public operation loader is still
    # unavailable, asserted below; this fixture never bypasses a broker guard.
    issuer = OperationTemplate(
        record["operation_id"], record["secret_id"], operation_digest(record), record
    )
    body = inputs["job"].after
    body["credentials"][0].update(
        delivery="short_lived",
        mint={
            "operation_id": issuer.operation_id,
            "digest": issuer.digest,
            "params": {"charge": {"$param": "database"}},
        },
    )
    job = JobDefinition.from_after(body)
    slot = inputs["slots"][0]
    grant = replace(slot.parent_grant, jobs=((job.job_id, job.digest),))
    inputs.update(
        job=job,
        slots=(
            replace(
                slot,
                delivery="short_lived",
                parent_grant=grant,
                mint=PlannedMint(
                    issuer,
                    {"charge": "orders"},
                    GrantSnapshot(canonical_json_bytes(template.after)),
                    POLICY,
                ),
            ),
        ),
    )
    return inputs


def test_short_lived_snapshot_includes_exact_expanded_values_and_complete_template():
    from aweb_secrets.operation import OperationInvalid, OperationTemplate

    inputs = _short_lived_inputs()
    mint = inputs["slots"][0].mint
    with pytest.raises(OperationInvalid) as refused:
        OperationTemplate.from_after(mint.operation.after)
    assert refused.value.code == "store_as_secret_unavailable"
    plan = FrozenRunPlan.freeze(**inputs)
    saved = plan.body["slots"][0]["mint"]
    assert saved["params"] == {"charge": "orders"}
    assert saved["grant_template"] == mint.template.template.after
    assert saved["grant_template_digest"] == mint.template.template.digest
    assert saved["template_policy"] == dict(POLICY.body)
    assert plan.slots[0].template_policy.digest == POLICY.digest
    assert not plan.slots[0].approval_required
    assert "orders" not in repr(mint)
    saved["grant_template"]["subject"]["principal"] = "changed"
    assert plan.body["slots"][0]["mint"]["grant_template_digest"] == mint.template.template.digest


def _pin_mint(inputs, slot, mint, record):
    from aweb_secrets.operation import operation_digest

    operation = replace(mint.operation, after=record, digest=operation_digest(record))
    job_record = inputs["job"].after
    job_record["credentials"][0]["mint"]["digest"] = operation.digest
    job = JobDefinition.from_after(job_record)
    inputs["job"] = job
    return (
        replace(slot, parent_grant=replace(slot.parent_grant, jobs=((job.job_id, job.digest),))),
        replace(mint, operation=operation),
    )


@pytest.mark.parametrize(
    "mutation", ["actual_constraint", "expanded", "template_pin", "wrong_subject", "not_issuing"]
)
def test_invalid_mint_bindings_refuse_before_a_plan_is_frozen(mutation):
    from awid.signing import canonical_json_bytes

    from aweb_secrets.derived_grants import GrantSnapshot
    from aweb_secrets.grant import GrantTemplate

    inputs = _short_lived_inputs()
    slot = inputs["slots"][0]
    mint = slot.mint
    if mutation == "actual_constraint":
        inputs["params"] = {"database": "+invalid"}
        mint = replace(mint, params={"charge": "+invalid"})
    elif mutation == "expanded":
        mint = replace(mint, params={"charge": "different"})
    elif mutation in ("template_pin", "wrong_subject"):
        body = mint.template.template.after
        body["subject"] = {"principal": DID_KEY}
        if mutation == "template_pin":
            body["grant_template_id"] = "gtp_different"
        else:
            # Keep the complete hash in sync: the same-requester rule must
            # still refuse a correctly pinned template naming another member.

            body["subject"] = {"principal": DID_KEY}
        template = GrantTemplate.from_after(body)
        mint = replace(mint, template=GrantSnapshot(canonical_json_bytes(template.after)))
        if mutation == "wrong_subject":
            inputs["requester_roles"] = ("secrets.role.deployers",)
            operation = mint.operation
            record = {
                **operation.after,
                "store_as_secret": {
                    **operation.after["store_as_secret"],
                    "grant_template_digest": template.digest,
                },
            }
            slot, mint = _pin_mint(inputs, slot, mint, record)
    else:
        slot, mint = _pin_mint(inputs, slot, mint, {**mint.operation.after, "token_issuing": False})
    inputs["slots"] = (replace(slot, mint=mint),)
    with pytest.raises(RunPlanRefused):
        FrozenRunPlan.freeze(**inputs)


@pytest.mark.parametrize("expired", [True, False])
async def test_prepared_live_recheck_works_inside_joint_savepoint_and_after_wait(db, expired):
    import asyncio
    from datetime import timedelta

    from aweb_secrets import derived_lineage, records
    from aweb_secrets.run_plan import PreparedRun
    from tests.test_derived_lineage import NOW, Clock, _child, _setup, _wait_for_database_lock

    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
    inputs = _inputs()
    clock = Clock()
    pid = asyncio.Future()

    async def submit():
        async with db.transaction() as tx:
            nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
            slot = inputs["slots"][0]
            child_grant = replace(slot.parent_grant, secret_id=child.secret_id)
            await records.create_grant(tx, INSTALLATION, TEAM, child_grant)
            inputs["slots"] = (
                replace(slot, source=nodes[-1].secret, ancestry=nodes, parent_grant=child_grant),
            )
            plan = FrozenRunPlan.freeze(**inputs)
            await derived_lineage.check_ancestry(
                tx, nodes, clock=clock, candidate_grant_ids=[child_grant.grant_id]
            )

            async def recheck(checked, *, clock, max_ttl_s):
                # Real SQL can block after the initial authority locks. The
                # callback must use the callable only after this awaited phase.
                await checked.fetch_value("SELECT count(*) FROM {{tables.config_revisions}}")
                try:
                    await derived_lineage.check_ancestry(
                        checked,
                        nodes,
                        clock=clock,
                        max_ttl_s=max_ttl_s,
                        candidate_grant_ids=[child_grant.grant_id],
                    )
                except derived_lineage.LineageRefused as refusal:
                    raise RunPlanRefused(refusal.code) from None

            prepared = await PreparedRun.bind(
                tx, plan=plan, clock=clock, max_ttl_s=60, recheck=recheck
            )
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            async with tx.transaction() as joint:
                await prepared.recheck(joint)
            return prepared

    async with db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.config_revisions}} IN ACCESS EXCLUSIVE MODE")
        task = asyncio.create_task(submit())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            if expired:
                clock.at = NOW + timedelta(seconds=61)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if expired:
        with pytest.raises(RunPlanRefused) as refusal:
            await task
        assert refusal.value.code == "secret_disabled"
    else:
        prepared = await task
        async with db.transaction() as later:
            with pytest.raises(RunPlanRefused) as refusal:
                await prepared.recheck(later)
        assert refusal.value.code == "run_plan_transaction_changed"


def _derived_inputs(*, exact_child_label=False, ambiguous=False, narrow_ancestor=False):
    from datetime import timedelta

    from aweb_secrets.secret import SecretRecord
    from tests.test_admission import NOW

    inputs = _inputs()
    original = inputs["slots"][0]
    root = original.ancestry[0]
    if narrow_ancestor:
        root = replace(
            root,
            secret=replace(
                root.secret,
                record=SecretRecord.from_after(
                    {
                        **root.secret.record.after,
                        "sensitivity": "sensitive",
                        "approve_only": True,
                    }
                ),
            ),
        )
    child = replace(
        original.source,
        record=SecretRecord.from_after(
            {
                **SECRET.after,
                "secret_id": "sec_child001",
                "ref": "child-session",
            }
        ),
    )
    node = LineageNode(
        INSTALLATION,
        TEAM,
        child,
        SECRET.secret_id,
        4,
        "grt_source001",
        ALICE.did_aw,
        POLICY.digest,
        NOW,
        NOW + timedelta(hours=2),
        NOW + timedelta(hours=1),
    )
    body = inputs["job"].after
    if exact_child_label:
        body["credentials"][0]["secret_ref"] = child.record.ref
        body["env"] = {"DB_ADMIN": {"$credential": child.record.ref}}
    if ambiguous:
        body["credentials"].append(
            {"secret_ref": child.record.ref, "delivery": "durable", "mint": None}
        )
        body["env"]["CHILD_ADMIN"] = {"$credential": child.record.ref}
    job = JobDefinition.from_after(body)
    grant = replace(
        original.parent_grant, secret_id=child.record.secret_id, jobs=((job.job_id, job.digest),)
    )
    child_slot = replace(
        original,
        label=body["credentials"][-1]["secret_ref"],
        source=child,
        ancestry=(root, node),
        parent_grant=grant,
    )
    slots = (child_slot,)
    if ambiguous:
        root_slot = replace(
            original, parent_grant=replace(original.parent_grant, jobs=((job.job_id, job.digest),))
        )
        slots = (root_slot, replace(child_slot, ordinal=1))
    inputs.update(job=job, slots=slots)
    return inputs


@pytest.mark.parametrize("exact", [True, False])
def test_one_durable_child_or_ancestor_label_preserves_original_ordinal(exact):
    plan = FrozenRunPlan.freeze(**_derived_inputs(exact_child_label=exact))
    assert plan.slots[0].ordinal == 0
    assert plan.slots[0].source_id == "sec_child001"
    assert len(plan.slots[0].ancestry_ids) == 2


def test_exact_child_label_does_not_hide_an_ambiguous_ancestor_slot():
    with pytest.raises(RunPlanRefused):
        FrozenRunPlan.freeze(**_derived_inputs(ambiguous=True))


def test_frozen_views_show_strictest_locked_ancestor_flags_and_both_policy_scopes():
    plan = FrozenRunPlan.freeze(**_derived_inputs(narrow_ancestor=True))
    slot = plan.slots[0]
    assert slot.body["sensitivity"] == "sensitive"
    assert slot.approval_required
    assert slot.parent_grant.secret_id == slot.source_id
    assert slot.source_version == 4
    assert slot.parent_policy.digest == POLICY.digest
    assert slot.template_policy is None
    assert plan.body["slots"][0]["ancestry"][0]["approve_only"]


@pytest.mark.parametrize("held", [(), ("secrets.role.other",), ("secrets.role.deployers",)])
@pytest.mark.parametrize("subject_kind", ["parent", "template"])
def test_role_subjects_require_the_planners_locked_requester_role_context(held, subject_kind):
    from awid.signing import canonical_json_bytes

    from aweb_secrets.derived_grants import GrantSnapshot
    from aweb_secrets.grant import GrantTemplate

    inputs = _short_lived_inputs()
    inputs["requester_roles"] = held
    slot = inputs["slots"][0]
    if subject_kind == "parent":
        slot = replace(
            slot,
            parent_grant=replace(
                slot.parent_grant, subject_principal=None, subject_role="secrets.role.deployers"
            ),
        )
    else:
        mint = slot.mint
        template = GrantTemplate.from_after(
            {**mint.template.template.after, "subject": {"role": "secrets.role.deployers"}}
        )
        mint = replace(mint, template=GrantSnapshot(canonical_json_bytes(template.after)))
        slot, mint = _pin_mint(
            inputs,
            slot,
            mint,
            {
                **mint.operation.after,
                "store_as_secret": {
                    **mint.operation.after["store_as_secret"],
                    "grant_template_digest": template.digest,
                },
            },
        )
        slot = replace(slot, mint=mint)
    inputs["slots"] = (slot,)
    if "secrets.role.deployers" in held:
        plan = FrozenRunPlan.freeze(**inputs)
        assert plan.body["requester"]["roles"] == list(held)
    else:
        with pytest.raises(RunPlanRefused):
            FrozenRunPlan.freeze(**inputs)


@pytest.mark.parametrize("which", ["parent", "template"])
@pytest.mark.parametrize("mutated", [False, True])
def test_policy_bodies_must_hash_to_the_exact_parent_and_template_pins(which, mutated):
    from awid.signing import canonical_json_bytes

    from aweb_secrets.derived_grants import GrantSnapshot
    from aweb_secrets.grant import GrantTemplate
    from aweb_secrets.policy import Policy

    inputs = _short_lived_inputs()
    policy = Policy.from_body(
        {**POLICY.body, "approval": "per_use", "approvers": ["finance-approver"]}
    )
    slot = inputs["slots"][0]
    if which == "parent":
        slot = replace(
            slot,
            parent_policy=policy,
            parent_grant=replace(slot.parent_grant, policy_digest=policy.digest),
        )
    else:
        mint = slot.mint
        template = GrantTemplate.from_after(
            {**mint.template.template.after, "policy_digest": policy.digest}
        )
        mint = replace(
            mint,
            template=GrantSnapshot(canonical_json_bytes(template.after)),
            template_policy=policy,
        )
        slot, mint = _pin_mint(
            inputs,
            slot,
            mint,
            {
                **mint.operation.after,
                "store_as_secret": {
                    **mint.operation.after["store_as_secret"],
                    "grant_template_digest": template.digest,
                },
            },
        )
        slot = replace(slot, mint=mint)
    inputs["slots"] = (slot,)
    if mutated:
        policy.body["approval"] = "none"
        with pytest.raises(RunPlanRefused):
            FrozenRunPlan.freeze(**inputs)
    else:
        plan = FrozenRunPlan.freeze(**inputs)
        assert plan.slots[0].approval_required
        saved = plan.slots[0].parent_policy if which == "parent" else plan.slots[0].template_policy
        assert saved.digest == policy.digest
