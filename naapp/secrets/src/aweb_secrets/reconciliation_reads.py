"""Value-free original-association reads in the owner's authority transaction.

The caller holds OWNER/S4/F6 and checks their live authority after this read.
No row lock, opener, approval consumer, grant refresh or mutation lives here.
Run reads require the run-dispatch migrations before enable_runs=True.
"""

from __future__ import annotations

from aweb_naapp.dispatch import State
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationRefused
from pgdbm.core import TransactionManager

from aweb_secrets.reconciliation_types import (
    ReconciliationOriginal,
    ReconciliationResource,
    ReconciliationView,
)
from aweb_secrets.run_context import original_run
from aweb_secrets.use_audit import UseAuditUnavailable


def _current_generation(scope: AdmittedInstallation, generation: int) -> None:
    if scope.generation != generation:
        raise InstallationRefused(
            "generation_superseded", 409, "the original reconciliation generation is superseded"
        )


class ReconciliationReads:
    def __init__(self, *, enable_runs: bool = False) -> None:
        if type(enable_runs) is not bool:
            raise ValueError("run projection must be explicitly configured")
        self._enable_runs = enable_runs

    async def get(
        self,
        tx: TransactionManager,
        *,
        scope: AdmittedInstallation,
        reconcile_ref: str,
    ) -> ReconciliationView | None:
        """Only the original opaque locator, under the caller's held owner scope.

        Fields come from immutable original records, never current secret/job
        definitions or a response entity. This method provides no authority to
        create a control or settle what it returns.
        """
        row = await tx.fetch_one(
            "SELECT i.intent_id,i.install_generation,i.request_id,i.principal_did,"
            "i.secret_id,i.secret_version,i.operation_id,i.operation_digest,c.dispatch_id,d.state,"
            "b.correlation->>'secret_ref' AS secret_ref"
            " FROM {{tables.intents}} i"
            " JOIN {{tables.use_contexts}} c USING(intent_id,installation_id,team_id,install_generation)"
            " JOIN {{tables.dispatches}} d USING(dispatch_id)"
            " LEFT JOIN {{tables.broker_audit_contexts}} b USING(dispatch_id)"
            " WHERE c.app_id=$1 AND i.installation_id=$2 AND i.team_id=$3"
            " AND c.tool='request' AND i.intent_id=$4",
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            reconcile_ref,
        )
        if row is not None:
            _current_generation(scope, row["install_generation"])
            return ReconciliationView(
                original=ReconciliationOriginal(
                    installation=scope,
                    reconcile_ref=row["intent_id"],
                    request_id=row["request_id"],
                    dispatch_id=row["dispatch_id"],
                    op_kind="broker",
                    requested_by=row["principal_did"],
                    resources=(
                        ReconciliationResource(
                            row["secret_id"], row["secret_ref"], row["secret_version"]
                        ),
                    ),
                    operation_id=row["operation_id"],
                    operation_digest=row["operation_digest"],
                ),
                state=State(row["state"]),
            )
        if not self._enable_runs:
            return None
        row = await tx.fetch_one(
            "SELECT c.dispatch_id,d.state FROM {{tables.run_contexts}} c"
            " JOIN {{tables.dispatches}} d USING(dispatch_id)"
            " WHERE c.app_id=$1 AND c.installation_id=$2 AND c.team_id=$3 AND c.intent_id=$4",
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            reconcile_ref,
        )
        if row is None:
            return None
        original = await original_run(tx, row["dispatch_id"])
        if original is None:
            raise UseAuditUnavailable()
        _current_generation(scope, original.installation.generation)
        return ReconciliationView(
            original=ReconciliationOriginal(
                installation=original.installation,
                reconcile_ref=original.intent_id,
                request_id=original.request_id,
                dispatch_id=original.dispatch_id,
                op_kind="run_job",
                requested_by=original.plan.body["requester"]["principal_did"],
                resources=tuple(
                    ReconciliationResource(
                        slot.body["source"]["secret_id"],
                        slot.body["source"]["ref"],
                        slot.body["source"]["version"],
                    )
                    for slot in original.plan.slots
                ),
                job_id=original.plan.body["job"]["job_id"],
                job_digest=original.plan.body["job"]["digest"],
                runner_id=original.runner_id,
            ),
            state=State(row["state"]),
        )
