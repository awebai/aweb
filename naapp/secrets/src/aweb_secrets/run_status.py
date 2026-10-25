"""Read-only original-run receipts for the shared member status service.

The caller holds S4/owner or B1/current-role and installation authority in its
transaction. This module never admits, consumes, opens or reconstructs a run.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from aweb_naapp.dispatch import Dispatch, State
from aweb_naapp.runtime.approvals import ApprovalRefused, Approvals, ApprovalState
from aweb_naapp.runtime.installation import AdmittedInstallation
from pgdbm.core import TransactionManager

from aweb_secrets import records, tool_results
from aweb_secrets.member_types import ToolReply
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.run_context import OriginalRun, original_run
from aweb_secrets.use_audit import UseApprovalAudit, UseAuditUnavailable


class RunStatus:
    def __init__(self, *, approvals: Approvals, use_audit: UseApprovalAudit) -> None:
        self._approvals, self._use_audit = approvals, use_audit

    async def get_in(
        self,
        tx: TransactionManager,
        *,
        ref: str,
        scope: AdmittedInstallation,
        principal_did: str,
        roles: Sequence[str],
    ) -> ToolReply:
        row = await tx.fetch_one(
            "SELECT c.dispatch_id,d.state,d.result,c.principal_did,c.install_generation"
            " FROM {{tables.run_contexts}} c JOIN {{tables.dispatches}} d USING(dispatch_id)"
            " WHERE c.app_id=$1 AND c.installation_id=$2 AND c.team_id=$3"
            " AND ((c.request_id=$4 AND c.principal_did=$5) OR"
            " ((c.intent_id=$4 OR c.run_id=$4 OR c.dispatch_ref=$4 OR EXISTS"
            " (SELECT 1 FROM {{tables.run_slot_approvals}} a WHERE a.installation_id=c.installation_id"
            " AND a.team_id=c.team_id AND a.run_id=c.run_id AND a.approval_ref=$4))"
            " AND (c.principal_did=$5 OR $6))) ORDER BY (c.intent_id=$4) DESC LIMIT 1",
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            ref,
            principal_did,
            OWNER_ROLE in roles,
        )
        original = None if row is None else await original_run(tx, row["dispatch_id"])
        if original is None or (
            OWNER_ROLE not in roles
            and not await self.read_granted(tx, original, principal_did=principal_did, roles=roles)
        ):
            return ToolReply(404, tool_results.refused("not_found", request_id=None))
        assert row is not None
        if original.installation != scope:
            return ToolReply(409, tool_results.refused("generation_superseded", request_id=None))
        try:
            return await self.reply(
                tx,
                original,
                state=State(row["state"]),
                result=row["result"],
                own=row["principal_did"] == principal_did,
            )
        except (UseAuditUnavailable, ApprovalRefused):
            return ToolReply(
                503,
                {
                    **tool_results.refused(
                        "release_context_unavailable", request_id=original.request_id
                    ),
                    "request_ref": original.intent_id,
                },
            )

    @staticmethod
    async def read_granted(
        tx: TransactionManager, original: OriginalRun, *, principal_did: str, roles: Sequence[str]
    ) -> bool:
        for slot in original.plan.slots:
            grants = await records.active_grants(
                tx,
                original.installation.installation_id,
                slot.source_id,
                principal_did=principal_did,
                roles=roles,
            )
            if not any(
                grant.grant_id == slot.parent_grant.grant_id and grant.capability == "run"
                for grant in grants
            ):
                return False
        return True

    async def reply(
        self, tx: TransactionManager, original: OriginalRun, *, state: State, result: Any, own: bool
    ) -> ToolReply:
        identity = {"request_id": original.request_id, "request_ref": original.intent_id}
        if state is State.AWAITING_APPROVAL:
            rows = await tx.fetch_all(
                "SELECT approval_ref FROM {{tables.run_slot_approvals}} WHERE installation_id=$1"
                " AND team_id=$2 AND run_id=$3 AND approval_id IS NOT NULL ORDER BY ordinal",
                original.installation.installation_id,
                original.installation.team_id,
                original.run_id,
            )
            if not rows:
                raise UseAuditUnavailable()
            requester = original.plan.body["requester"]["principal_did"]
            # The initial mint is still uncommitted. Read the original B2
            # objects through the same non-locking caller-tx association reader,
            # never a second transaction that cannot see the new approvals.
            approvals = {
                approval.request_ref: approval
                for approval in await self._use_audit.dispatch_approvals(tx, original.dispatch_id)
            }
            if any(
                row["approval_ref"] not in approvals
                or approvals[row["approval_ref"]].requested_by != requester
                for row in rows
            ):
                raise UseAuditUnavailable()
            now = self._approvals.now()
            slot_states = [approvals[row["approval_ref"]].state_at(now) for row in rows]
            states = set(slot_states)
            for terminal, code in (
                (ApprovalState.REJECTED, "approval_denied"),
                (ApprovalState.EXPIRED, "approval_expired"),
                (ApprovalState.REVOKED, "approval_revoked"),
            ):
                if terminal in states:
                    return ToolReply(200, {"state": "refused", **identity, "code": code})
            if states <= {ApprovalState.APPROVED, ApprovalState.CONSUMED}:
                return ToolReply(200, {"state": "approved", **identity, "next": "resubmit"})
            pending = next(
                (
                    row
                    for row, slot_state in zip(rows, slot_states, strict=True)
                    if slot_state is ApprovalState.PENDING
                ),
                None,
            )
            if pending is None:
                raise UseAuditUnavailable()
            return ToolReply(
                200,
                tool_results.awaiting_approval(**identity, approval_ref=pending["approval_ref"]),
            )
        if state in {
            State.COMPLETED,
            State.RECONCILED_COMPLETED,
            State.RECONCILED_FAILED,
            State.RECONCILED_UNKNOWN,
        }:
            stored = json.loads(result) if isinstance(result, str) else result
            allowed = (
                {"completed", "result_withheld"} if state is State.COMPLETED else {state.value}
            )
            if (
                not isinstance(stored, Mapping)
                or stored.get("state") not in allowed
                or any(stored.get(key) != value for key, value in identity.items())
            ):
                raise UseAuditUnavailable()
            body = dict(stored)
            if not own:
                body.pop("result", None)
            return ToolReply(200, body)
        closing = {
            State.APPROVAL_DENIED: "approval_denied",
            State.APPROVAL_EXPIRED: "approval_expired",
            State.CANCELLED: "approval_revoked",
        }
        if state in closing:
            return ToolReply(200, {"state": "refused", **identity, "code": closing[state]})
        if state is State.REFUSED:
            payload = await tx.fetch_value(
                "SELECT payload FROM {{tables.broker_use_events}} WHERE dispatch_id=$1 AND action='refused' ORDER BY occurred_at DESC LIMIT 1",
                original.dispatch_id,
            )
            payload = json.loads(payload) if isinstance(payload, str) else payload
            if not isinstance(payload, Mapping) or not isinstance(payload.get("refusal_code"), str):
                raise UseAuditUnavailable()
            return ToolReply(200, {"state": "refused", **identity, "code": payload["refusal_code"]})
        return ToolReply(200, {"state": state.value, **identity})

    async def receipt(
        self, tx: TransactionManager, original: OriginalRun, dispatch: Dispatch
    ) -> ToolReply:
        reply = await self.reply(
            tx, original, state=dispatch.state, result=dispatch.result, own=True
        )
        status = (
            202
            if reply.body["state"] in {"received", "admitted", "dispatching", "awaiting_approval"}
            else reply.status
        )
        if dispatch.state is State.REFUSED:
            status = 503
        return ToolReply(status, reply.body)
