"""Durable-run acceptance against real PG, custody, B2/B3 and runner crypto."""

import asyncio
import json
from datetime import timedelta
from functools import cached_property

import pytest
from aweb_naapp.crypto import open_sealed
from aweb_naapp.hooks.strictjson import decode_base64url, encode_base64url
from aweb_naapp.runtime.approvals import Assurance, Decision
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import runners
from aweb_secrets.custody import decode_value
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.runner_protocol import RunnerRefused, canonical
from tests.run_world import RunWorld
from tests.run_world import setup as setup_world
from tests.test_broker_audit import envelopes
from tests.test_use_approvals import TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_audit import targets


class Context(RunWorld):
    @cached_property
    def service(self):
        return RunDispatch(self.uses.world.db, **self.arguments)

    async def assigned(self):
        admitted = await self.service.submit(job=self.job.job_id, submission=self.submission)
        assert admitted.status == 202 and admitted.body["state"] == "admitted"
        claim = await self.service.claim(self.signed("/runner/v1/claim"))
        assert claim.status == 200 and isinstance(claim.body, bytes)
        return admitted, claim, json.loads(claim.body)


async def setup(uses, *, approval_required=False):
    original = await setup_world(uses, approval_required=approval_required)
    return Context(**vars(original))


async def test_idle_claim_consumes_nonce_once_without_creating_work(uses):
    context = await setup(uses)
    signed = context.signed("/runner/v1/claim")
    idle = await context.service.claim(signed)
    assert idle.status == 204 and idle.body is None
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(signed)
    assert refused.value.code == "runner_request_replayed"
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 0
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 1


async def test_one_admitted_run_replays_the_same_signed_sealed_assignment(uses):
    context = await setup(uses)
    _, first, wire = await context.assigned()
    payload = wire["assignment"]
    context.arguments["service_key"].verify_key.verify(
        b"aweb.secrets.runner-assignment/1\n" + canonical(payload),
        decode_base64url(wire["signature"], "signature"),
    )
    credential = wire["credentials"][0]
    plaintext = open_sealed(
        context.encryption_key.private_bytes_raw(),
        decode_base64url(credential["sealed"], "sealed"),
        info=payload["dispatch_id"].encode(),
    )
    if decode_value("bearer", plaintext) != {"value": context.credential}:
        raise AssertionError("assignment did not carry the original structured credential")
    replay = await context.service.claim(context.signed("/runner/v1/claim"))
    assert replay == first
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 1
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
    assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
        "admitted",
        "dispatching",
    ]


def report(stdout="safe"):
    return canonical(
        {
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
            "truncated": False,
            "result_withheld": False,
            "redaction_count": 0,
        }
    )


@pytest.mark.parametrize("conflict", ["changed", "reencoded"])
async def test_report_exact_replay_is_idempotent_and_conflicting_bytes_rollback(uses, conflict):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    target = f"/runner/v1/dispatches/{dispatch_ref}"
    started = await context.service.started(dispatch_ref, context.signed(target + "/started"))
    assert started.status == 204
    raw = report(context.credential)
    for _ in range(2):
        result = await context.service.result(dispatch_ref, context.signed(target + "/result", raw))
        assert result.status == 204
    before = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}")
    conflicting_raw = report("changed") if conflict == "changed" else b" " + raw
    with pytest.raises(RunnerRefused) as refused:
        await context.service.result(
            dispatch_ref, context.signed(target + "/result", conflicting_raw)
        )
    assert refused.value.code == "runner_result_conflict"
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == before
    )
    receipt = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert receipt.status == 200 and receipt.body["state"] == "completed"
    assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
        "admitted",
        "dispatching",
        "completed",
    ]
    if context.credential in repr(receipt) + repr(await envelopes(uses.world.db)):
        raise AssertionError("original credential escaped result redaction")


async def test_result_preflight_releases_locks_and_final_check_rejects_key_rotation(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    signed = context.signed(f"/runner/v1/dispatches/{dispatch_ref}/result", report())
    before = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}")
    limit = await context.service.result_body_limit(
        dispatch_ref=dispatch_ref,
        header=signed.header,
        method=signed.method,
        raw_target=signed.raw_target,
    )
    assert limit == 6 * context.job.after["output"]["max_bytes"] + 1024
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == before
    )

    async def rotate():
        async with uses.world.db.transaction() as tx:
            code = await runners.replace_runner(
                tx, uses.world.admitted.installation_id, TEAM, context.runner, now=uses.clock()
            )
            await runners.register_runner(
                tx,
                code=code,
                signing_key=did_from_public_key(bytes(SigningKey.generate().verify_key)),
                encryption_key=encode_base64url(
                    X25519PrivateKey.generate().public_key().public_bytes_raw()
                ),
                clock=uses.clock,
            )

    await asyncio.wait_for(rotate(), 3)
    with pytest.raises(RunnerRefused) as refused:
        await context.service.result(dispatch_ref, signed)
    assert refused.value.code == "runner_unknown"
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == before
    )
    assert (
        await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "dispatching"
    )


async def test_new_worker_without_original_redaction_context_withholds_report_output(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    from aweb_secrets.run_service import RunDispatch

    replacement = RunDispatch(uses.world.db, **context.arguments)
    accepted = await replacement.result(
        dispatch_ref, context.signed(f"/runner/v1/dispatches/{dispatch_ref}/result", report())
    )
    assert accepted.status == 204
    receipt = await replacement.submit(job=context.job.job_id, submission=context.submission)
    assert receipt.status == 200 and receipt.body["state"] == "result_withheld"
    assert receipt.body["code"] == "release_context_unavailable"
    assert receipt.body["result"]["exit_code"] == 0
    assert receipt.body["result"]["body"] is None


async def test_concurrent_claims_publish_one_assignment_and_two_authenticated_receipts(uses):
    context = await setup(uses)
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.body["state"] == "admitted"
    pending = []
    try:
        async with uses.world.db.transaction() as barrier:
            await barrier.execute("LOCK TABLE {{tables.custody_secrets}} IN ACCESS EXCLUSIVE MODE")
            blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
            pending = [
                asyncio.create_task(context.service.claim(context.signed("/runner/v1/claim")))
                for _ in range(2)
            ]
            async with asyncio.timeout(5):
                while (
                    await uses.world.db.fetch_value(
                        "SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
                        blocker,
                    )
                    < 2
                ):
                    if any(task.done() for task in pending):
                        raise AssertionError("claim finished before real custody preparation")
                    await asyncio.sleep(0.01)
        first, second = await asyncio.wait_for(asyncio.gather(*pending), 5)
        assert first.status == 200 and first == second
        assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 2
        assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
            "admitted",
            "dispatching",
        ]
    finally:
        for task in pending:
            if not task.done():
                task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def test_assignment_expiry_does_not_reissue_or_prematurely_sweep_a_running_job(uses):
    context = await setup(uses)
    await context.assigned()
    assert context.job.after["timeout_s"] > context.arguments["assignment_ttl"].total_seconds()
    uses.clock.now += context.arguments["assignment_ttl"] + timedelta(seconds=1)
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(context.signed("/runner/v1/claim"))
    assert refused.value.code == "runner_dispatch_state_conflict"
    assert await context.service.sweep() == 0
    assert (
        await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "dispatching"
    )
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1


async def decide(context, reply, decision):
    uses, approvals = context.uses, context.arguments["approvals"]
    approval_id = await uses.world.db.fetch_value(
        "SELECT approval_id FROM {{tables.run_slot_approvals}} WHERE approval_ref=$1",
        reply.body["approval_ref"],
    )
    [token] = [
        token
        for candidate, token in uses.world.inbox.links["finance@acme.com"]
        if candidate == approval_id
    ]
    options = await approvals.challenge(approval_id, decision, Assurance.PASSKEY, link_token=token)
    with context.arguments["use_audit"].prepared_view(targets(uses.clock())):
        await approvals.decide(
            approval_id,
            decision,
            Assurance.PASSKEY,
            uses.world.devices["finance@acme.com"].get(dict(options)),
            link_token=token,
        )
    return approval_id


async def test_real_run_approval_requires_explicit_resubmission_before_runner_release(uses):
    context = await setup(uses, approval_required=True)
    pending = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert pending.status == 202 and pending.body["state"] == "awaiting_approval"
    approval_id = await decide(context, pending, Decision.APPROVE)
    # A decision and a claim do not consume the approval or admit the run.
    idle = await context.service.claim(context.signed("/runner/v1/claim"))
    assert idle.status == 204
    approval = await context.arguments["approvals"].get(approval_id)
    assert approval.consumed_operation_id is None
    _, _, wire = await context.assigned()
    approval = await context.arguments["approvals"].get(approval_id)
    dispatch_id = await uses.world.db.fetch_value("SELECT dispatch_id FROM {{tables.dispatches}}")
    assert approval.consumed_operation_id == str(dispatch_id)
    assert wire["assignment"]["dispatch_id"] != str(dispatch_id)
    assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
        "approval_requested",
        "approval_decided",
        "admitted",
        "dispatching",
    ]


async def test_rejected_run_closes_without_a_target_or_any_assignment(uses):
    context = await setup(uses, approval_required=True)
    pending = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert pending.body["state"] == "awaiting_approval"
    await decide(context, pending, Decision.REJECT)
    context.available[0] = False
    refused = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert refused.status == 403 and refused.body["code"] == "approval_denied"
    assert (
        await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}")
        == "approval_denied"
    )
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
    idle = await context.service.claim(context.signed("/runner/v1/claim"))
    assert idle.status == 204
    assert (
        await uses.world.db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}") is None
    )


async def test_changed_logical_run_body_cannot_reuse_original_request(uses):
    context = await setup(uses)
    first = await context.service.submit(job=context.job.job_id, submission=context.submission)
    from dataclasses import replace

    body = json.loads(context.submission.inbound.body)
    body["params"]["database"] = "another-database"
    changed = replace(
        context.submission, inbound=replace(context.submission.inbound, body=canonical(body))
    )
    refused = await context.service.submit(job=context.job.job_id, submission=changed)
    assert refused.status == 409 and refused.body["code"] == "idempotency_conflict"
    again = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert again.body == first.body
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 1
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.run_approval_admissions}}")
        == 1
    )


async def test_unavailable_dispatch_target_refuses_before_assignment_and_consumes_claim_once(uses):
    context = await setup(uses)
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.body["state"] == "admitted"
    context.available[0] = False
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(context.signed("/runner/v1/claim"))
    assert refused.value.code == "runner_unavailable"
    assert await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "refused"
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
    assert (
        await uses.world.db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}") is None
    )
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 1
    receipt = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert receipt.body["code"] == "audit_target_unavailable"
    assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
        "admitted",
        "refused",
    ]


async def test_missing_original_native_value_refuses_durable_admission_before_release(uses):
    context = await setup(uses)
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.body["state"] == "admitted"
    from aweb_secrets.custody import SealContext
    from tests.test_use_approvals import SECRET

    async with uses.world.db.transaction() as tx:
        await uses.world.custody.destroy(
            tx,
            context=SealContext(uses.world.admitted.installation_id, TEAM, SECRET["secret_id"], 1),
        )
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(context.signed("/runner/v1/claim"))
    assert refused.value.code == "runner_unavailable"
    assert await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "refused"
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
    assert (
        await uses.world.db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}") is None
    )


async def test_late_result_records_once_without_overwriting_unknown_winner(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    # Move the real S3 deadline, then use the production recovery transaction.
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
        )
    assert await context.service.sweep() == 1
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(context.signed("/runner/v1/claim"))
    assert refused.value.code == "runner_reconciliation_required"
    raw = report()
    for _ in range(2):
        assert (
            await context.service.result(
                dispatch_ref, context.signed(f"/runner/v1/dispatches/{dispatch_ref}/result", raw)
            )
        ).status == 204
    row = await uses.world.db.fetch_one(
        "SELECT state,jsonb_array_length(late_results) AS count FROM {{tables.dispatches}}"
    )
    assert row["state"] == "outcome_unknown" and row["count"] == 1
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
    assert [event["payload"]["action"] for event in await envelopes(uses.world.db)] == [
        "admitted",
        "dispatching",
        "outcome_unknown",
    ]


async def test_two_distinct_slots_wait_for_all_approvals_and_release_in_original_order(uses):
    import secrets

    from aweb_naapp.roles import principal_key
    from aweb_naapp_testing.webauthn import SoftAuthenticator

    from aweb_secrets import jobs, records
    from aweb_secrets.custody import encode_value
    from aweb_secrets.grant import GrantRecord
    from aweb_secrets.policy import Policy
    from aweb_secrets.revisions import config_revision
    from aweb_secrets.secret import SecretRecord
    from tests.governance import view
    from tests.test_change_sets import ALICE, ORIGIN, by_member, change_set, draft
    from tests.test_change_sets import decide as owner_decide
    from tests.test_use_approvals import POLICY_BODY, REQUESTER, SECRET, designate_approver

    context = await setup(uses, approval_required=False)
    scope = uses.world.admitted
    other = SecretRecord.from_after(
        {**SECRET, "secret_id": "sec_run_other01", "ref": "other-credential"}
    )
    body = context.job.after
    body["credentials"].append({"secret_ref": other.ref, "delivery": "durable", "mint": None})
    body["env"]["OTHER_API_KEY"] = {"$credential": other.ref, "field": "value"}
    job = jobs.JobDefinition.from_after(body)
    async with uses.world.db.transaction() as tx:
        policy = Policy.from_body({**POLICY_BODY, "approval": "per_use", "approvers": ["finance"]})
        await records.create_policy(tx, scope.installation_id, policy)
        await records.create_secret(tx, scope.installation_id, TEAM, other)
        version = await uses.world.custody.sealer.ingest(
            tx,
            installation_id=scope.installation_id,
            team_id=TEAM,
            secret_id=other.secret_id,
            value=encode_value("bearer", {"value": secrets.token_urlsafe(32)}),
        )
        await records.set_active_version(tx, scope.installation_id, TEAM, other.secret_id, version)
        await jobs.create_job(tx, scope.installation_id, TEAM, job)
        await records.revoke_grant(tx, scope.installation_id, "grt_durable001")
        for index, secret_id in enumerate((SECRET["secret_id"], other.secret_id)):
            await records.create_grant(
                tx,
                scope.installation_id,
                TEAM,
                GrantRecord.from_after(
                    {
                        "v": 1,
                        "grant_id": f"grt_multi_run{index}",
                        "secret_id": secret_id,
                        "subject": {"principal": principal_key(REQUESTER).principal_did},
                        "capability": "run",
                        "operations": [],
                        "open_request": False,
                        "jobs": [{"job_id": job.job_id, "digest": job.digest}],
                        "policy_digest": policy.digest,
                    }
                ),
            )
    w = uses.world
    change = change_set(
        drafter=by_member(ALICE),
        changes=[
            designate_approver(
                "finance", "finance@acme.com", [SECRET["secret_id"], other.secret_id]
            )
        ],
        base_revision=await config_revision(w.db, scope.installation_id),
    )
    await owner_decide(w, await draft(w, change), "alice@acme.com")
    async with w.db.transaction() as tx:
        confirmation = await w.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id=f"apply-{change['change_id']}",
            fence=w.fence,
            admitted=w.admitted,
            governance_view=view(),
        )
    await w.change_sets.deliver(confirmation)
    token = w.inbox.enrolments["finance@acme.com"][-1]
    device = SoftAuthenticator(ORIGIN)
    await w.passkeys.complete_enrolment(
        token, device.create(await w.passkeys.enrolment_options(token))
    )
    w.devices["finance@acme.com"] = device
    context.job = job
    pending = await context.service.submit(job=job.job_id, submission=context.submission)
    assert pending.body["state"] == "awaiting_approval"
    refs = [
        row["approval_ref"]
        for row in await uses.world.db.fetch_all(
            "SELECT approval_ref FROM {{tables.run_slot_approvals}} ORDER BY ordinal"
        )
    ]
    assert pending.body["approval_ref"] == refs[0]
    assert pending.body["approval_refs"] == refs
    first_id = await decide(context, pending, Decision.APPROVE)
    another = await context.service.submit(job=job.job_id, submission=context.submission)
    assert another.body["state"] == "awaiting_approval"
    assert another.body["approval_ref"] != pending.body["approval_ref"]
    assert another.body["approval_refs"] == refs[1:]
    assert (await context.service.claim(context.signed("/runner/v1/claim"))).status == 204
    assert (await context.arguments["approvals"].get(first_id)).consumed_operation_id is None
    second_id = await decide(context, another, Decision.APPROVE)
    _, _, wire = await context.assigned()
    assert [slot["secret_ref"] for slot in wire["credentials"]] == [SECRET["ref"], other.ref]
    dispatch_id = await uses.world.db.fetch_value("SELECT dispatch_id FROM {{tables.dispatches}}")
    for approval_id in (first_id, second_id):
        assert (await context.arguments["approvals"].get(approval_id)).consumed_operation_id == str(
            dispatch_id
        )
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.run_approval_admissions}}")
        == 1
    )


async def test_invalid_member_value_field_records_only_a_commitment_without_admitting(uses):
    from dataclasses import replace

    context = await setup(uses)
    body = json.loads(context.submission.inbound.body)
    body["value"] = context.credential
    invalid = replace(
        context.submission, inbound=replace(context.submission.inbound, body=canonical(body))
    )
    tables = (
        "dispatches",
        "run_contexts",
        "run_approval_plans",
        "run_slot_approvals",
        "idempotency_keys",
        "rate_buckets",
    )
    before = {
        table: [
            dict(row)
            for row in await uses.world.db.fetch_all("SELECT * FROM {{tables." + table + "}}")
        ]
        for table in tables
    }
    refused = await context.service.submit(job=context.job.job_id, submission=invalid)
    assert refused.status == 400 and refused.body["code"] == "params_invalid"
    after = {
        table: [
            dict(row)
            for row in await uses.world.db.fetch_all("SELECT * FROM {{tables." + table + "}}")
        ]
        for table in tables
    }
    assert before == after
    [event] = await envelopes(uses.world.db)
    assert event["payload"]["op_kind"] == "run_job"
    assert event["payload"]["action"] == "refused"
    assert event["payload"]["refusal_code"] == "params_invalid"
    assert len(event["payload"]["request_sha256"]) == 64
    if context.credential in repr(event):
        raise AssertionError("caller-supplied credential escaped the refusal commitment")


async def test_optional_child_selector_signs_the_actual_delivered_ref_for_its_fixed_slot(uses):
    import secrets
    from dataclasses import replace

    from aweb_secrets import derived_lineage, records
    from aweb_secrets.custody import encode_value
    from aweb_secrets.grant import GrantRecord
    from aweb_secrets.secret import SecretRecord
    from tests.test_use_approvals import REQUESTER, SECRET

    context = await setup(uses)
    scope = uses.world.admitted
    child = SecretRecord.from_after({**SECRET, "secret_id": "sec_run_child01", "ref": "run-child"})
    child_value = secrets.token_urlsafe(32)
    async with uses.world.db.transaction() as tx:
        policy = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id='grt_durable001'"
        )
        issuer = GrantRecord.from_after(
            {
                "v": 1,
                "grant_id": "grt_run_issuer",
                "secret_id": SECRET["secret_id"],
                "subject": {"principal": REQUESTER.did_aw},
                "capability": "use",
                "operations": [],
                "open_request": True,
                "jobs": [],
                "policy_digest": policy,
            }
        )
        await records.create_grant(tx, scope.installation_id, TEAM, issuer)
        await records.create_secret(tx, scope.installation_id, TEAM, child)
        version = await uses.world.custody.sealer.ingest(
            tx,
            installation_id=scope.installation_id,
            team_id=TEAM,
            secret_id=child.secret_id,
            value=encode_value("bearer", {"value": child_value}),
        )
        await records.set_active_version(tx, scope.installation_id, TEAM, child.secret_id, version)
        await derived_lineage.record_lineage(
            tx,
            installation_id=scope.installation_id,
            team_id=TEAM,
            secret_id=child.secret_id,
            parent_secret_id=SECRET["secret_id"],
            parent_version=1,
            source_dispatch_id="ordinary-source",
            source_grant_id=issuer.grant_id,
            issuing_principal=REQUESTER.did_aw,
            policy_digest=policy,
            dispatch_started_at=uses.clock(),
            upstream_expires_at=uses.clock() + timedelta(hours=1),
            expires_at=uses.clock() + timedelta(minutes=30),
            clock=uses.clock,
        )
        await records.create_grant(
            tx,
            scope.installation_id,
            TEAM,
            GrantRecord.from_after(
                {
                    **issuer.after,
                    "grant_id": "grt_selected_run",
                    "secret_id": child.secret_id,
                    "capability": "run",
                    "open_request": False,
                    "jobs": [{"job_id": context.job.job_id, "digest": context.job.digest}],
                }
            ),
        )
    body = json.loads(context.submission.inbound.body)
    body["secret"] = child.ref
    selected = replace(
        context.submission, inbound=replace(context.submission.inbound, body=canonical(body))
    )
    admitted = await context.service.submit(job=context.job.job_id, submission=selected)
    assert admitted.status == 202 and admitted.body["state"] == "admitted"
    conflict = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert conflict.status == 409 and conflict.body["code"] == "idempotency_conflict"
    assignment = await context.service.claim(context.signed("/runner/v1/claim"))
    wire = json.loads(assignment.body)
    [slot] = wire["credentials"]
    # The wire identifies the actual child. Only the job's fixed ordinal label
    # controls its environment mapping (secrets §9.5), never the wire ref.
    assert slot["secret_ref"] == child.ref
    plaintext = open_sealed(
        context.encryption_key.private_bytes_raw(),
        decode_base64url(slot["sealed"], "sealed"),
        info=wire["assignment"]["dispatch_id"].encode(),
    )
    if decode_value("bearer", plaintext) != {"value": child_value}:
        raise AssertionError("selected run released another source value")
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 1
