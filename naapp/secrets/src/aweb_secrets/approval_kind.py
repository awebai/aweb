"""Read-only personal-link routing from immutable app approval associations.

This returns a closed kind, no request terms, token, scope or authority.
Custody separately checks change sets and requires exactly one global kind.
"""

from __future__ import annotations

from typing import Literal

from aweb_naapp.runtime.approvals import Approval
from pgdbm.core import TransactionManager

from aweb_secrets.use_approvals import POLICY_VERSION, use_policy_ref
from aweb_secrets.use_audit import UseAuditUnavailable

ApprovalKind = Literal["use", "run", "reconciliation_control"]


async def approval_kind(
    tx: TransactionManager,
    approval: Approval,
    *,
    enable_runs: bool = False,
    enable_reconciliation: bool = False,
) -> ApprovalKind | None:
    if type(enable_runs) is not bool or type(enable_reconciliation) is not bool:
        raise ValueError("approval routing requires explicit migration configuration")
    matches: list[ApprovalKind] = []
    row = await tx.fetch_one(
        "SELECT a.request_ref,a.request_sha256,c.tool,i.installation_id,i.team_id,i.grant_id,i.policy_digest"
        " FROM {{tables.use_approval_audits}} a"
        " LEFT JOIN {{tables.use_contexts}} c USING(dispatch_id)"
        " LEFT JOIN {{tables.intents}} i USING(intent_id,installation_id,team_id,install_generation)"
        " WHERE a.approval_id=$1",
        approval.approval_id,
    )
    if row is not None:
        if row["tool"] != "request" or any(
            row[name] is None
            for name in ("installation_id", "team_id", "grant_id", "policy_digest")
        ):
            raise UseAuditUnavailable()
        ref = use_policy_ref(
            row["installation_id"], row["team_id"], row["grant_id"], row["policy_digest"]
        )
        _same(approval, row, ref, POLICY_VERSION)
        matches.append("use")
    if enable_runs:
        row = await tx.fetch_one(
            "SELECT request_ref,request_sha256,policy_ref FROM {{tables.run_approval_audits}} WHERE approval_id=$1",
            approval.approval_id,
        )
        if row is not None:
            _same(approval, row, row["policy_ref"], POLICY_VERSION)
            matches.append("run")
    if enable_reconciliation:
        row = await tx.fetch_one(
            "SELECT request_ref,request_sha256,policy_ref,policy_version FROM {{tables.reconciliation_controls}} WHERE approval_id=$1",
            approval.approval_id,
        )
        if row is not None:
            _same(approval, row, row["policy_ref"], row["policy_version"])
            matches.append("reconciliation_control")
    if len(matches) > 1:
        raise UseAuditUnavailable()
    return matches[0] if matches else None


def _same(approval, row, policy_ref, policy_version):
    if (
        approval.request_ref,
        approval.request_sha256,
        approval.policy_ref,
        approval.policy_version,
    ) != (
        row["request_ref"],
        row["request_sha256"],
        policy_ref,
        policy_version,
    ):
        raise UseAuditUnavailable()
