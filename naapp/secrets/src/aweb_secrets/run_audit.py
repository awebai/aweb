"""Original ordered run-slot associations and S3 run transition recording.

B2 lifecycle/proof recording remains in the shared UseApprovalAudit branch.
This module adds no proof serializer, state machine, opener or send authority.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from aweb_naapp.dispatch import State, Transition
from aweb_naapp.hooks.producer import HookProducerFactory, RegistrationView
from aweb_naapp.runtime.approvals import Approval
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, parse_request_json, request_sha256
from pgdbm.core import TransactionManager

from aweb_secrets.broker_audit import _ACTIONS, _COMPLETED, _activity, _same_producer
from aweb_secrets.run_context import original_run
from aweb_secrets.use_audit import UseAuditUnavailable


async def associate_run_approval(
    tx: TransactionManager, approval: Approval, dispatch_id: UUID
) -> None:
    original = await original_run(tx, dispatch_id)
    raw = await tx.fetch_value(
        "SELECT canonical FROM {{tables.approval_requests}} WHERE request_ref=$1",
        approval.request_ref,
    )
    if original is None or raw is None or not bytes(raw).startswith(DOMAIN_PREFIX):
        raise UseAuditUnavailable()
    covered = parse_request_json(bytes(raw)[len(DOMAIN_PREFIX) :])
    if request_sha256(covered) != approval.request_sha256:
        raise UseAuditUnavailable()
    try:
        request = covered["request"]
        body = original.plan.body
        scope, who, job = body["installation"], body["requester"], body["job"]
        if (
            (
                request["v"],
                request["type"],
                request["action"],
                request["installation_id"],
                request["team_id"],
                request["install_generation"],
                request["request_id"],
            )
            != (
                1,
                "aweb.secrets.use-approval",
                "run_job",
                scope["installation_id"],
                scope["team_id"],
                scope["generation"],
                original.run_id,
            )
            or (
                request["requester"]["principal"],
                request["requester"]["member_did_key"],
                request["requester"]["certificate_id"],
            )
            != (who["principal_did"], who["member_did_key"], who["certificate_id"])
            or approval.requested_by != who["principal_did"]
        ):
            raise UseAuditUnavailable()
        slots = []
        for slot in original.plan.slots:
            value = slot.body
            source = value["source"]
            secret = source["record"]
            if (
                request["secret"]
                == {
                    "secret_id": source["secret_id"],
                    "secret_ref": source["ref"],
                    "version": source["version"],
                    "kind": secret["kind"],
                    "backend": secret["backend"],
                }
                and request["grant_id"] == slot.parent_grant.grant_id
                and request["policy_digest"] == slot.parent_policy.digest
                and request["run_job"]
                == {
                    "runner_id": body["runner_id"],
                    "job_id": job["job_id"],
                    "job_digest": job["digest"],
                    "params": body["params"],
                    "credential_delivery": value["delivery"],
                }
                and slot.approval_required
            ):
                slots.append(slot)
        if len(slots) != 1:
            raise UseAuditUnavailable()
    except (KeyError, TypeError, ValueError):
        raise UseAuditUnavailable() from None
    await tx.execute(
        "INSERT INTO {{tables.run_approval_audits}}"
        " (approval_id,dispatch_id,installation_id,team_id,run_id,ordinal,request_ref,request_sha256,policy_ref)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        approval.approval_id,
        dispatch_id,
        scope["installation_id"],
        scope["team_id"],
        original.run_id,
        slots[0].ordinal,
        approval.request_ref,
        approval.request_sha256,
        approval.policy_ref,
    )


async def original_run_approval(tx: TransactionManager, approval: Approval):
    row = await tx.fetch_one(
        "SELECT c.*,a.ordinal,'run'::text AS tool FROM {{tables.run_approval_audits}} a"
        " JOIN {{tables.run_contexts}} c USING (dispatch_id,installation_id,team_id,run_id)"
        " WHERE a.approval_id=$1 AND a.request_ref=$2 AND a.request_sha256=$3 AND a.policy_ref=$4",
        approval.approval_id,
        approval.request_ref,
        approval.request_sha256,
        approval.policy_ref,
    )
    if row is None:
        raise UseAuditUnavailable()
    original = await original_run(tx, row["dispatch_id"])
    if original is None:
        raise UseAuditUnavailable()
    slot = original.plan.slots[row["ordinal"]]
    source = slot.body["source"]
    payload = json.loads(row["payload"])
    payload.update(
        secret_id=source["secret_id"],
        secret_ref=source["ref"],
        secret_version=source["version"],
        secret_kind=source["record"]["kind"],
        secret_backend=source["record"]["backend"],
        secret_sensitivity=slot.body["sensitivity"],
        grant_id=slot.parent_grant.grant_id,
        policy_digest=slot.parent_policy.digest,
    )
    correlation = json.loads(row["correlation"])
    correlation.update(secret_id=source["secret_id"], secret_ref=source["ref"])
    return dict(row, payload=json.dumps(payload), correlation=json.dumps(correlation))


class RunAudit:
    def __init__(
        self,
        *,
        producer: HookProducerFactory,
        view: RegistrationView | None,
        refusal_code: str | None = None,
        completed: Mapping[str, Any] | None = None,
    ) -> None:
        if completed is not None and completed.keys() - _COMPLETED:
            raise ValueError("completed metadata cannot change frozen run authority")
        self._producer, self._view, self._refusal_code = producer, view, refusal_code
        self._completed = None if completed is None else dict(completed)

    async def __call__(self, tx: TransactionManager, event: Transition) -> None:
        original = await original_run(tx, event.dispatch_id)
        if original is None:
            raise UseAuditUnavailable()
        if event.to_state is State.RECEIVED:
            return
        if event.to_state in {
            State.AWAITING_APPROVAL,
            State.APPROVAL_DENIED,
            State.APPROVAL_EXPIRED,
            State.CANCELLED,
        }:
            decision = {
                State.AWAITING_APPROVAL: None,
                State.APPROVAL_DENIED: "denied",
                State.APPROVAL_EXPIRED: "expired",
                State.CANCELLED: "revoked",
            }[event.to_state]
            count = await tx.fetch_value(
                "SELECT count(DISTINCT a.approval_id) FROM {{tables.run_approval_audits}} a"
                " JOIN {{tables.broker_use_events}} e ON e.dispatch_id=a.dispatch_id"
                " AND e.correlation->>'approval_id'=a.approval_id"
                " WHERE a.dispatch_id=$1 AND e.action=$2"
                " AND ($3::text IS NULL OR e.payload->>'approval_decision'=$3)",
                event.dispatch_id,
                "approval_requested" if decision is None else "approval_decided",
                decision,
            )
            required = sum(slot.approval_required for slot in original.plan.slots)
            if not count or decision is None and count != required:
                raise UseAuditUnavailable()
            return
        if event.to_state not in _ACTIONS:
            raise UseAuditUnavailable()
        required = sum(slot.approval_required for slot in original.plan.slots)
        proofs = await tx.fetch_all(
            "SELECT a.approval_id,a.request_ref,p.commitment FROM {{tables.run_approval_audits}} a"
            " JOIN {{tables.run_approval_audit_proofs}} p USING (approval_id)"
            " WHERE a.dispatch_id=$1 AND p.purpose='approve' ORDER BY a.ordinal",
            event.dispatch_id,
        )
        if required and event.to_state not in {State.REFUSED} and len(proofs) != required:
            raise UseAuditUnavailable()
        row = await tx.fetch_one(
            "SELECT actor,payload,correlation,signed_trace_id FROM {{tables.run_contexts}} WHERE dispatch_id=$1",
            event.dispatch_id,
        )
        if row is None:
            raise UseAuditUnavailable()
        payload, correlation = json.loads(row["payload"]), json.loads(row["correlation"])
        payload.update(
            action=_ACTIONS[event.to_state],
            dispatch_id=original.dispatch_ref,
            dispatch_state=event.to_state.value,
        )
        if len(proofs) == 1:
            payload.update(
                approval_id=proofs[0]["approval_id"],
                approval_assurance="passkey",
                approval_evidence_sha256=proofs[0]["commitment"],
            )
        status = "success"
        if event.to_state is State.REFUSED:
            if self._refusal_code is None:
                raise UseAuditUnavailable()
            payload["refusal_code"], status = self._refusal_code, "denied"
        elif event.to_state is State.COMPLETED:
            if self._completed is None:
                raise UseAuditUnavailable()
            payload.update(self._completed)
        elif event.to_state in {State.NOT_SENT, State.RECONCILED_FAILED}:
            status = "failed"
        elif event.to_state in {State.OUTCOME_UNKNOWN, State.RECONCILED_UNKNOWN}:
            status = "outcome_unknown"
        producer, context = (
            self._producer(
                installation_id=original.commitments.context.installation_id,
                generation=original.commitments.context.generation,
            ),
            original.commitments.context,
        )
        _same_producer(producer, context)
        options = dict(
            team_id=context.team_id,
            payload=payload,
            actor=json.loads(row["actor"]),
            occurred_at=event.occurred_at,
            signed_trace_id=row["signed_trace_id"],
        )
        if event.to_state is State.REFUSED:
            event_id = await producer.enqueue_refusal(tx, **options)
        else:
            event_id = await producer.enqueue(
                tx, hook="post-secret-use-hook", result_status=status, view=self._view, **options
            )
        await _activity(
            tx,
            event_id=event_id,
            context=context,
            dispatch_id=event.dispatch_id,
            occurred_at=event.occurred_at,
            payload=payload,
            actor=json.loads(row["actor"]),
            correlation=correlation,
        )
