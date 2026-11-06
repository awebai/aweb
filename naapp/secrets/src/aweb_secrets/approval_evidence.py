"""One retained-B3 proof binding and commitment recorder for B2 audit branches."""

from typing import Literal

from aweb_naapp.runtime.approvals import Approval, Assurance
from aweb_naapp.runtime.audit import AuditEvent
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    Passkeys,
)
from pgdbm.core import TransactionManager


async def record_approval_proof(
    tx: TransactionManager,
    *,
    passkeys: Passkeys,
    context: PasskeyInstallationContext,
    approval: Approval,
    event: AuditEvent,
    table: Literal[
        "use_approval_audit_proofs", "run_approval_audit_proofs", "reconciliation_control_proofs"
    ],
) -> dict[str, str]:
    from aweb_secrets.use_audit import UseAuditUnavailable

    if table not in {
        "use_approval_audit_proofs",
        "run_approval_audit_proofs",
        "reconciliation_control_proofs",
    }:
        raise UseAuditUnavailable()
    decided = approval.decided_by
    if (
        decided is None
        or decided.assurance is not Assurance.PASSKEY
        or (
            decided.evidence_ref != event.details.get("evidence_ref")
            or decided.subject != event.actor
        )
    ):
        raise UseAuditUnavailable()
    try:
        proof = await passkeys.retained_proof(decided.evidence_ref, tx=tx)
    except PasskeyProofUnavailable:
        raise UseAuditUnavailable() from None
    if any(
        proof.metadata.get(name) != expected
        for name, expected in (
            ("approval_id", approval.approval_id),
            ("request_sha256", approval.request_sha256),
            ("policy_ref", approval.policy_ref),
            ("policy_version", approval.policy_version),
        )
    ):
        raise UseAuditUnavailable()
    purpose = event.details["decision"]
    try:
        commitment = await passkeys.evidence_commitment(
            decided.evidence_ref,
            context=context,
            scope=decided.scope,
            subject=decided.subject,
            purpose=purpose,
            tx=tx,
        )
    except PasskeyProofUnavailable:
        raise UseAuditUnavailable() from None
    await tx.execute(
        f"INSERT INTO {{{{tables.{table}}}}}"
        " (approval_id,evidence_ref,scope,subject,purpose,commitment) VALUES ($1,$2,$3,$4,$5,$6)",
        approval.approval_id,
        decided.evidence_ref,
        decided.scope,
        decided.subject,
        purpose,
        commitment,
    )
    return {"approval_assurance": "passkey", "approval_evidence_sha256": commitment}
