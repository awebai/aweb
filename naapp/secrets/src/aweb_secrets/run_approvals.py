"""Frozen per-slot B2 approvals and joint original-run admission (§9.5).

Only S13's trusted PreparedRun enters these functions. Its installation, role,
whole-forest, grant, CURRENT job/runner/op/template locks precede covering-record
and B2 locks here. This module records approval associations, never constructs
AdmittedRun, opens credentials or admits an internal mint. Deliver returned new
pending links only after the caller commits. No availability guard is lifted.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRefused,
    Approvals,
    PendingApproval,
    Refusal,
)
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import records
from aweb_secrets.approvers import approvers_for_secrets
from aweb_secrets.owners import is_owner_scope
from aweb_secrets.run_plan import FrozenRunSlot, PreparedRun, RunPlanRefused
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approval import RunJob, use_approval_request
from aweb_secrets.use_approvals import _b2_policy, _granted_policy, _refusal

POLICY_PREFIX = "secrets.run"


@dataclass(frozen=True)
class RunSlotApproval:
    ordinal: int
    secret_id: str
    approval_id: str | None
    approval_ref: str | None


@dataclass(frozen=True)
class RunApprovalRecord:
    installation_id: str
    team_id: str
    run_id: str
    intent_id: str
    dispatch_id: str
    plan_digest: str
    slots: tuple[RunSlotApproval, ...]
    admitted: bool


@dataclass(frozen=True)
class RunApprovalAdmission(RunApprovalRecord):
    may_send: bool
    refusal: str | None


@dataclass(frozen=True, repr=False)
class PendingRunApproval:
    ordinal: int
    approval_id: str
    approval_ref: str
    pending: PendingApproval | None


def _policy_ref(prepared: PreparedRun, slot: FrozenRunSlot) -> str:
    scope = prepared.installation
    mint = slot.body["mint"]
    template = ("-", "-", "-")
    if mint is not None:
        child = slot.template_policy
        assert child is not None
        template = (
            mint["grant_template"]["grant_template_id"],
            mint["grant_template_digest"],
            child.digest,
        )
    return "|".join(
        (
            POLICY_PREFIX,
            scope.installation_id,
            scope.team_id,
            slot.parent_grant.grant_id,
            slot.parent_policy.digest,
            *template,
        )
    )


async def current_run_policy(tx: TransactionManager, policy_ref: str) -> ActionPolicy | None:
    parts = policy_ref.split("|")
    if len(parts) != 8 or parts[0] != POLICY_PREFIX:
        return None
    _, installation, team, grant, digest, template_id, template_digest, child_digest = parts
    parent = await _granted_policy(tx, installation, team, grant, digest)
    if parent is None:
        return None
    combined = _b2_policy(policy_ref, installation, team, parent)
    if combined is None or template_id == "-":
        return combined
    template = await records.grant_template(tx, installation, template_id)
    if (
        template is None
        or template.digest != template_digest
        or template.terms["policy_digest"] != child_digest
    ):
        return None
    child = await records.policy(tx, installation, child_digest)
    other = None if child is None else _b2_policy(policy_ref, installation, team, child)
    if other is None:
        return None
    scopes = tuple(sorted(set(combined.approver_scopes).intersection(other.approver_scopes)))
    if not scopes:
        return None
    return replace(
        combined,
        approver_scopes=scopes,
        ttl=min(combined.ttl, other.ttl),
        allow_requester_approval=combined.allow_requester_approval
        and other.allow_requester_approval,
    )


async def run_approval_record(
    tx: TransactionManager, *, installation_id: str, team_id: str, run_id: str
) -> RunApprovalRecord | None:
    """Same-scope inert association lookup; not send or mint authority."""
    row = await tx.fetch_one(
        "SELECT p.*, EXISTS(SELECT 1 FROM {{tables.run_approval_admissions}} a "
        "WHERE (a.installation_id,a.team_id,a.run_id)=(p.installation_id,p.team_id,p.run_id)) AS admitted "
        "FROM {{tables.run_approval_plans}} p WHERE installation_id=$1 AND team_id=$2 AND run_id=$3",
        installation_id,
        team_id,
        run_id,
    )
    if row is None:
        return None
    slots = await _slots(tx, installation_id, team_id, run_id)
    return RunApprovalRecord(
        installation_id,
        team_id,
        run_id,
        row["intent_id"],
        str(row["dispatch_id"]),
        row["plan_digest"],
        tuple(
            RunSlotApproval(s["ordinal"], s["secret_id"], s["approval_id"], s["approval_ref"])
            for s in slots
        ),
        row["admitted"],
    )


async def _slots(tx, installation, team, run):
    return await tx.fetch_all(
        "SELECT * FROM {{tables.run_slot_approvals}} "
        "WHERE installation_id=$1 AND team_id=$2 AND run_id=$3 ORDER BY ordinal",
        installation,
        team,
        run,
    )


async def _locked_plan(tx: TransactionManager, prepared: PreparedRun, *, create=False):
    body, scope = prepared.plan.body, prepared.installation
    args = (scope.installation_id, scope.team_id, body["run_id"])
    inserted = False
    if create:
        inserted = bool(
            await tx.fetch_value(
                "INSERT INTO {{tables.run_approval_plans}} "
                "(installation_id,team_id,run_id,intent_id,dispatch_id,plan_digest,canonical) "
                "VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING run_id",
                *args,
                body["intent_id"],
                uuid.UUID(body["dispatch_id"]),
                prepared.plan.digest,
                prepared.plan.canonical,
            )
        )
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.run_approval_plans}} "
        "WHERE installation_id=$1 AND team_id=$2 AND run_id=$3 FOR UPDATE",
        *args,
    )
    if row is None:
        raise RunPlanRefused("run_approval_not_requested")
    if (
        row["canonical"] != prepared.plan.canonical
        or row["plan_digest"] != prepared.plan.digest
        or row["intent_id"] != body["intent_id"]
        or str(row["dispatch_id"]) != body["dispatch_id"]
    ):
        raise RunPlanRefused("run_plan_mismatch")
    return inserted


async def _covering(tx: TransactionManager, prepared: PreparedRun):
    scope = prepared.installation
    # Lock once in covering-record order across the WHOLE run, not in slot order.
    records_ = await approvers_for_secrets(
        tx,
        installation_id=scope.installation_id,
        team_id=scope.team_id,
        secret_ids=sorted({s for slot in prepared.slots for s in slot.ancestry_ids}),
    )
    policies, scopes = {}, {}
    for slot in prepared.slots:
        if not slot.approval_required:
            continue
        policy = await current_run_policy(tx, _policy_ref(prepared, slot))
        policies[slot.ordinal] = policy
        listed = set() if policy is None else set(policy.approver_scopes)
        scopes[slot.ordinal] = frozenset(
            {r.scope for r in records_ if set(r.covers).intersection(slot.ancestry_ids)}.union(
                s for s in listed if is_owner_scope(s)
            ).intersection(listed)
        )
    return policies, scopes


async def _authority_refusal(tx: TransactionManager, prepared: PreparedRun) -> str | None:
    try:
        await prepared.recheck(tx)
    except RunPlanRefused as exc:
        if exc.code == "run_plan_transaction_changed":
            raise
        return exc.code
    return None


def _request(
    prepared: PreparedRun,
    slot: FrozenRunSlot,
    principal: Principal,
    reason: str,
    policy: ActionPolicy,
) -> dict[str, Any]:
    body, frozen = prepared.plan.body, slot.body
    now = prepared.clock()
    issued = now.replace(microsecond=0)
    expiry = issued + policy.ttl
    for node in frozen["ancestry"]:
        deadlines = [
            datetime.fromisoformat(node[k])
            for k in ("expires_at", "upstream_expires_at")
            if node[k] is not None
        ]
        if node["dispatch_started_at"] is not None:
            deadlines.append(
                datetime.fromisoformat(node["dispatch_started_at"])
                + timedelta(seconds=prepared.max_ttl_s)
            )
        if deadlines:
            expiry = min(expiry, *deadlines)
    expiry = expiry.replace(microsecond=0)
    if expiry <= now:
        raise RunPlanRefused("approval_expired")
    request = use_approval_request(
        installation_id=prepared.installation.installation_id,
        install_generation=prepared.installation.generation,
        team_id=prepared.installation.team_id,
        requester=principal,
        secret=SecretRecord.from_after(frozen["source"]["record"]),
        secret_version=slot.source_version,
        policy_digest=slot.parent_policy.digest,
        grant_id=slot.parent_grant.grant_id,
        request_id=body["run_id"],
        reason=reason,
        issued_at=issued,
        ttl=expiry - issued,
        action=RunJob(
            body["runner_id"],
            body["job"]["job_id"],
            body["job"]["digest"],
            body["params"],
            frozen["delivery"],
        ),
    )
    request["run_job"].update(
        slot_ordinal=slot.ordinal, plan_digest=prepared.plan.digest, frozen_plan=body
    )
    return request


async def request_run_approvals(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    prepared: PreparedRun,
    principal: Principal,
    reason: str,
) -> tuple[PendingRunApproval, ...]:
    body = prepared.plan.body
    who = body["requester"]
    if (
        principal.team_id != prepared.installation.team_id
        or principal_key(principal).principal_did != who["principal_did"]
        or principal.did_key != who["member_did_key"]
        or principal.certificate_id != who["certificate_id"]
    ):
        raise RunPlanRefused("run_requester_changed")
    refusal = await _authority_refusal(tx, prepared)
    async with tx.transaction() as attempt:
        new = await _locked_plan(attempt, prepared, create=True)
        if not new:
            rows = await _slots(
                attempt,
                prepared.installation.installation_id,
                prepared.installation.team_id,
                body["run_id"],
            )
            return tuple(
                PendingRunApproval(r["ordinal"], r["approval_id"], r["approval_ref"], None)
                for r in rows
                if r["approval_id"] is not None
            )
        if refusal:
            raise RunPlanRefused(refusal)
        policies, scopes = await _covering(attempt, prepared)
        pending = []
        for slot in prepared.slots:
            policy_ref = request = item = None
            if slot.approval_required:
                policy, eligible = policies[slot.ordinal], scopes[slot.ordinal]
                if policy is None or not eligible:
                    raise RunPlanRefused("no_eligible_approver")
                policy_ref = _policy_ref(prepared, slot)
                request = _request(prepared, slot, principal, reason, policy)
                try:
                    item = await approvals.mint(
                        request=request,
                        policy_ref=policy_ref,
                        requested_by=who["principal_did"],
                        expires_at=datetime.fromisoformat(request["expires_at"]),
                        tx=attempt,
                    )
                except ApprovalRefused as exc:
                    codes = {
                        Refusal.NO_ELIGIBLE_APPROVER: "no_eligible_approver",
                        Refusal.POLICY_UNKNOWN: "grant_revoked",
                        Refusal.POLICY_CHANGED: "grant_revoked",
                        Refusal.EXPIRED: "approval_expired",
                    }
                    if exc.reason in codes:
                        raise RunPlanRefused(codes[exc.reason]) from None
                    raise
                if any(c.scope not in eligible for c in item.approval.candidates):
                    raise RunPlanRefused("no_eligible_approver")
                pending.append(
                    PendingRunApproval(
                        slot.ordinal, item.approval.approval_id, item.view.request_id, item
                    )
                )
            await attempt.execute(
                "INSERT INTO {{tables.run_slot_approvals}} "
                "(installation_id,team_id,run_id,ordinal,secret_id,secret_version,grant_id,policy_ref,approval_id,approval_ref,request) "
                "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                prepared.installation.installation_id,
                prepared.installation.team_id,
                body["run_id"],
                slot.ordinal,
                slot.source_id,
                slot.source_version,
                slot.parent_grant.grant_id,
                policy_ref,
                None if item is None else item.approval.approval_id,
                None if item is None else item.view.request_id,
                None if request is None else json.dumps(request),
            )
        await prepared.recheck(attempt)
        return tuple(pending)


def _result(record: RunApprovalRecord, *, may_send=False, refusal=None) -> RunApprovalAdmission:
    return RunApprovalAdmission(**record.__dict__, may_send=may_send, refusal=refusal)


async def admit_run_approvals(
    tx: TransactionManager, approvals: Approvals, *, prepared: PreparedRun
) -> RunApprovalAdmission:
    refusal = await _authority_refusal(tx, prepared)
    await _locked_plan(tx, prepared)
    record = await run_approval_record(
        tx,
        installation_id=prepared.installation.installation_id,
        team_id=prepared.installation.team_id,
        run_id=prepared.plan.body["run_id"],
    )
    assert record is not None
    if record.admitted:
        # This immutable original-run marker is never rearmed by a mint/retry ID.
        return _result(record)
    policies, scopes = await _covering(tx, prepared)
    ids = sorted(s.approval_id for s in record.slots if s.approval_id is not None)
    await approvals.lock_many(tx, ids)
    rows = await _slots(tx, record.installation_id, record.team_id, record.run_id)
    for row in rows:
        if row["approval_id"] is None:
            continue
        policy = policies[row["ordinal"]]
        if policy is None:
            refusal = refusal or "grant_revoked"
        approval = await approvals.get(row["approval_id"])
        assert approval is not None
        eligible = scopes[row["ordinal"]]
        if (approval.decided_by is not None and approval.decided_by.scope not in eligible) or (
            approval.decided_by is None
            and not any(c.scope in eligible for c in approval.candidates)
        ):
            refusal = refusal or "approval_revoked"
    if refusal:
        await approvals.revoke_many(ids, revoked_by="secrets", reason=refusal, tx=tx)
        return _result(record, refusal=refusal)
    failed_id = None
    try:
        async with tx.transaction() as joint:
            for row in rows:
                if row["approval_id"] is not None:
                    failed_id = row["approval_id"]
                    admitted = await approvals.admit(
                        failed_id, json.loads(row["request"]), record.dispatch_id, tx=joint
                    )
                    if not admitted.first or not admitted.may_send:
                        # Without our atomic marker, an earlier standalone B2
                        # consumption is not a fresh joint run admission.
                        raise RunPlanRefused("approval_consumed")
            await joint.execute(
                "INSERT INTO {{tables.run_approval_admissions}} (installation_id,team_id,run_id,admitted_at) VALUES($1,$2,$3,$4)",
                record.installation_id,
                record.team_id,
                record.run_id,
                prepared.clock(),
            )
            await prepared.recheck(joint)
            now = prepared.clock()
            if any(
                r["request"] is not None
                and datetime.fromisoformat(json.loads(r["request"])["expires_at"]) <= now
                for r in rows
            ):
                raise RunPlanRefused("approval_expired")
    except RunPlanRefused as exc:
        await approvals.revoke_many(ids, revoked_by="secrets", reason=exc.code, tx=tx)
        return _result(record, refusal=exc.code)
    except ApprovalRefused as exc:
        assert failed_id is not None
        refusal = await _refusal(tx, approvals, failed_id, exc.reason)
        if refusal in ("grant_revoked", "approval_revoked"):
            await approvals.revoke_many(ids, revoked_by="secrets", reason=refusal, tx=tx)
        return _result(record, refusal=refusal)
    return _result(replace(record, admitted=True), may_send=True)
