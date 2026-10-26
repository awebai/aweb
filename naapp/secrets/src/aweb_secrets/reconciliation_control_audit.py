"""Durable local B2 control audit; only actual S3 settlement emits a hook.

The root must route this classifier to this required branch. No HookProducer,
registration lookup or availability gate participates in a control ceremony.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import UUID, uuid4

from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import Approval, ApprovalState
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, parse_request_json, request_sha256
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext, Passkeys
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.approval_evidence import record_approval_proof
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.reconciliation_policy import (
    POLICY_PREFIX,
    POLICY_VERSION,
    reconciliation_policy_ref,
    reconciliation_request,
)
from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.reconciliation_types import ReconciliationControl
from aweb_secrets.use_audit import UseAuditUnavailable

_KINDS = frozenset(
    {
        AuditKind.APPROVAL_REQUESTED,
        AuditKind.APPROVAL_DECIDED,
        AuditKind.APPROVAL_REVOKED,
        AuditKind.DISPATCH_ADMITTED,
        AuditKind.DISPATCH_OUTCOME,
    }
)


def is_reconciliation_control(event: AuditEvent) -> bool:
    return (
        event.kind in _KINDS
        and event.details.get("policy_ref", "").split("|", 1)[0] == POLICY_PREFIX
    )


async def apply_reconciliation_migrations(db: AsyncDatabaseManager) -> None:
    """After B2/S3, records and dispatch audit migrations; before composing controls.

    Run-backed reads additionally require run-dispatch migrations before the
    caller enables its shared ReconciliationReads instance.
    """
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "reconciliation_migrations"),
        module_name="aweb_secrets_reconciliation",
    ).apply_pending_migrations()


class ReconciliationAudit:
    def __init__(
        self,
        *,
        reads: ReconciliationReads,
        approval: Callable[[TransactionManager, str], Awaitable[Approval | None]],
        passkeys: Callable[[], Passkeys],
    ) -> None:
        self._reads, self._approval, self._passkeys = reads, approval, passkeys

    async def _request(self, tx: TransactionManager, approval: Approval):
        raw = await tx.fetch_value(
            "SELECT canonical FROM {{tables.approval_requests}} WHERE request_ref=$1",
            approval.request_ref,
        )
        if raw is None or not bytes(raw).startswith(DOMAIN_PREFIX):
            raise UseAuditUnavailable()
        try:
            covered = parse_request_json(bytes(raw)[len(DOMAIN_PREFIX) :])
            if (
                set(covered) != {"policy", "request"}
                or request_sha256(covered) != approval.request_sha256
                or covered["policy"]
                != {"ref": approval.policy_ref, "version": approval.policy_version}
                or approval.policy_version != POLICY_VERSION
                or reconciliation_policy_ref(covered["request"]) != approval.policy_ref
            ):
                raise UseAuditUnavailable()
            return covered["request"]
        except (KeyError, TypeError, ValueError):
            raise UseAuditUnavailable() from None

    async def _associate(self, tx: TransactionManager, approval: Approval) -> None:
        request = await self._request(tx, approval)
        try:
            scope = AdmittedInstallation(**request["original"]["installation"])
            view = await self._reads.get(
                tx, scope=scope, reconcile_ref=request["original"]["reconcile_ref"]
            )
            owner = request["owner"]
            candidates = approval.candidates
            principal = await tx.fetch_value(
                "SELECT principal_did FROM {{tables.owner_principals}}"
                " WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
                owner["scope"],
                scope.installation_id,
                scope.team_id,
            )
            from aweb_naapp.roles import PrincipalKey, has_role

            if (
                view is None
                or view.state is not State.OUTCOME_UNKNOWN
                or principal is None
                or principal != approval.requested_by
                or owner_scope(scope.installation_id, scope.team_id, principal) != owner["scope"]
                or not await has_role(
                    tx, PrincipalKey(team_id=scope.team_id, principal_did=principal), OWNER_ROLE
                )
                or len(candidates) != 1
                or (candidates[0].scope, candidates[0].subject)
                != (owner["scope"], owner["subject"])
                or request
                != reconciliation_request(
                    view.original,
                    control_id=UUID(request["control_id"]),
                    outcome=request["outcome"],
                    owner_scope=owner["scope"],
                    owner_subject=owner["subject"],
                )
            ):
                raise UseAuditUnavailable()
        except (KeyError, TypeError, ValueError):
            raise UseAuditUnavailable() from None
        await tx.execute(
            "INSERT INTO {{tables.reconciliation_controls}}"
            " (control_id,approval_id,app_id,installation_id,team_id,install_generation,reconcile_ref,"
            "dispatch_id,outcome,request_ref,request_sha256,policy_ref,policy_version,owner_scope,"
            "owner_subject,owner_principal,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            UUID(request["control_id"]),
            approval.approval_id,
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            scope.generation,
            view.original.reconcile_ref,
            view.original.dispatch_id,
            request["outcome"],
            approval.request_ref,
            approval.request_sha256,
            approval.policy_ref,
            approval.policy_version,
            owner["scope"],
            owner["subject"],
            principal,
            approval.expires_at,
        )

    async def control(
        self, tx: TransactionManager, *, scope: AdmittedInstallation, approval_id: str
    ) -> ReconciliationControl | None:
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.reconciliation_controls}}"
            " WHERE approval_id=$1 AND app_id=$2 AND installation_id=$3 AND team_id=$4",
            approval_id,
            scope.app_id,
            scope.installation_id,
            scope.team_id,
        )
        if row is None:
            return None
        original = await self._reads.get(tx, scope=scope, reconcile_ref=row["reconcile_ref"])
        approval = await self._approval(tx, approval_id)
        if (
            original is None
            or original.original.dispatch_id != row["dispatch_id"]
            or row["install_generation"] != scope.generation
            or approval is None
            or (
                approval.request_ref,
                approval.request_sha256,
                approval.policy_ref,
                approval.policy_version,
                approval.requested_by,
                approval.expires_at,
            )
            != (
                row["request_ref"],
                row["request_sha256"],
                row["policy_ref"],
                row["policy_version"],
                row["owner_principal"],
                row["expires_at"],
            )
        ):
            raise UseAuditUnavailable()
        return ReconciliationControl(
            original=original.original,
            outcome=row["outcome"],
            control_id=row["control_id"],
            approval_id=approval_id,
            approval_ref=row["request_ref"],
            request_sha256=row["request_sha256"],
            policy_ref=row["policy_ref"],
            policy_version=row["policy_version"],
            owner_scope=row["owner_scope"],
            owner_subject=row["owner_subject"],
            expires_at=row["expires_at"],
        )

    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        tx = transaction
        if not is_reconciliation_control(event) or event.approval_id is None:
            raise UseAuditUnavailable()
        approval = await self._approval(tx, event.approval_id)
        if approval is None or (approval.policy_ref, approval.request_sha256) != (
            event.details.get("policy_ref"),
            event.details.get("request_sha256"),
        ):
            raise UseAuditUnavailable()
        if event.kind is AuditKind.APPROVAL_REQUESTED:
            if approval.state is not ApprovalState.PENDING:
                raise UseAuditUnavailable()
            await self._associate(tx, approval)
        request = await self._request(tx, approval)
        scope = AdmittedInstallation(**request["original"]["installation"])
        control = await self.control(tx, scope=scope, approval_id=approval.approval_id)
        if control is None:
            raise UseAuditUnavailable()
        if event.kind is AuditKind.APPROVAL_DECIDED:
            decision = event.details.get("decision")
            expected = {"approve": ApprovalState.APPROVED, "reject": ApprovalState.REJECTED}.get(
                decision
            )
            decided = approval.decided_by
            if (
                expected is None
                or approval.state is not expected
                or decided is None
                or (decided.scope, decided.subject) != (control.owner_scope, control.owner_subject)
            ):
                raise UseAuditUnavailable()
            await record_approval_proof(
                tx,
                passkeys=self._passkeys(),
                context=PasskeyInstallationContext(**request["original"]["installation"]),
                approval=approval,
                event=event,
                table="reconciliation_control_proofs",
            )
        elif event.kind is AuditKind.APPROVAL_REVOKED:
            if approval.state is not ApprovalState.REVOKED:
                raise UseAuditUnavailable()
        elif event.kind in {AuditKind.DISPATCH_ADMITTED, AuditKind.DISPATCH_OUTCOME}:
            if (
                approval.state is not ApprovalState.CONSUMED
                or approval.consumed_operation_id != str(control.control_id)
            ):
                raise UseAuditUnavailable()
        details = {
            key: event.details[key]
            for key in ("policy_ref", "policy_version", "request_sha256", "decision", "outcome")
            if key in event.details
        }
        await tx.execute(
            "INSERT INTO {{tables.reconciliation_control_events}}"
            " (event_id,approval_id,kind,actor,subject,occurred_at,details) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)",
            uuid4(),
            approval.approval_id,
            event.kind.value,
            event.actor,
            event.subject,
            event.occurred_at,
            json.dumps(details),
        )
