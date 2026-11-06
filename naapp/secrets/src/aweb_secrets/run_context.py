"""Inert original run association on the shared dispatch UUID and S12 plan.

No state machine, queue, grant, nonce consumer, authority checker or opener
lives here. The business service owns every transaction and final fence.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import UUID

from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.attestation import VerifiedAttestation
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.broker_audit import _actor
from aweb_secrets.run_input import RunInput
from aweb_secrets.run_plan import FrozenRunPlan, PreparedRun, RunPlanRefused
from aweb_secrets.use_audit import UseAuditUnavailable
from aweb_secrets.use_context import UseCommitments

_TRACE = re.compile(r"[0-9a-f]{32}")


async def apply_run_dispatch_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "run_dispatch_migrations"),
        module_name="aweb_secrets_run_dispatch",
    ).apply_pending_migrations()


@dataclass(frozen=True, repr=False)
class OriginalRun:
    dispatch_id: UUID
    dispatch_ref: str
    request_id: str
    request_sha256: bytes
    plan: FrozenRunPlan
    commitments: UseCommitments
    principal: Principal
    attestation: VerifiedAttestation | None

    @property
    def installation(self) -> AdmittedInstallation:
        return AdmittedInstallation(**self.plan.body["installation"])

    @property
    def intent_id(self) -> str:
        return self.plan.body["intent_id"]

    @property
    def run_id(self) -> str:
        return self.plan.body["run_id"]

    @property
    def runner_id(self) -> str:
        return self.plan.body["runner_id"]


def _original(row) -> OriginalRun:
    try:
        plan = FrozenRunPlan.from_bytes(bytes(row["canonical"]))
        body = plan.body
        installation, requester, job = body["installation"], body["requester"], body["job"]
        if (
            plan.digest != row["plan_digest"]
            or (body["run_id"], body["intent_id"], body["dispatch_id"], body["runner_id"])
            != (row["run_id"], row["intent_id"], str(row["dispatch_id"]), row["runner_id"])
            or (
                installation["app_id"],
                installation["installation_id"],
                installation["team_id"],
                installation["generation"],
            )
            != (row["app_id"], row["installation_id"], row["team_id"], row["install_generation"])
            or (
                requester["principal_did"],
                requester["member_did_key"],
                requester["certificate_id"],
            )
            != (row["principal_did"], row["member_did_key"], row["certificate_id"])
            or (job["job_id"], job["digest"]) != (row["job_id"], row["job_digest"])
        ):
            raise ValueError()
        actor = json.loads(row["actor"])
        if (actor["did_key"], actor["certificate_id"]) != (
            row["member_did_key"],
            row["certificate_id"],
        ) or actor.get("did_aw", row["principal_did"]) != row["principal_did"]:
            raise ValueError()
        principal = Principal(
            team_id=row["team_id"],
            did_key=row["member_did_key"],
            did_aw=row["principal_did"] if row["principal_did"].startswith("did:aw:") else None,
            address=None,
            alias=None,
            certificate_id=row["certificate_id"],
            team_did_key=row["team_did_key"],
        )
        return OriginalRun(
            row["dispatch_id"],
            row["dispatch_ref"],
            row["request_id"],
            bytes(row["request_sha256"]),
            plan,
            UseCommitments(
                CommitmentContext(
                    row["app_id"],
                    row["team_id"],
                    row["installation_id"],
                    row["install_generation"],
                    "run",
                ),
                row["request_mac"],
                row["params_mac"],
            ),
            principal,
            None
            if row["attestation"] is None
            else VerifiedAttestation(**json.loads(row["attestation"])),
        )
    except (ValueError, KeyError, TypeError, RunPlanRefused):
        raise UseAuditUnavailable() from None


async def original_run(tx: TransactionManager, dispatch_id: UUID) -> OriginalRun | None:
    row = await tx.fetch_one(
        "SELECT c.*,p.canonical FROM {{tables.run_contexts}} c"
        " JOIN {{tables.run_approval_plans}} p USING (installation_id,team_id,run_id,intent_id,dispatch_id,plan_digest)"
        " WHERE c.dispatch_id=$1",
        dispatch_id,
    )
    return None if row is None else _original(row)


async def store_run_context(
    tx: TransactionManager,
    *,
    prepared: PreparedRun,
    inputs: RunInput,
    principal: Principal,
    commitments: UseCommitments,
    signed_trace_id: str | None,
    attestation: VerifiedAttestation | None = None,
) -> str:
    """Freeze original metadata before S12's in-tx mint callbacks and S3.create.

    Deferred foreign keys require the matching S12 plan and S3 row to commit in
    this same transaction. Later callbacks do not trust a caller-supplied plan.
    """
    body, scope, context = prepared.plan.body, prepared.installation, commitments.context
    if (
        (context.app_id, context.team_id, context.installation_id, context.generation, context.tool)
        != (scope.app_id, scope.team_id, scope.installation_id, scope.generation, "run")
        or commitments.request_mac is None
        or (inputs.job_id, inputs.job_digest, inputs.runner_id, inputs.params)
        != (body["job"]["job_id"], body["job"]["digest"], body["runner_id"], body["params"])
        or (
            principal.team_id,
            principal_key(principal).principal_did,
            principal.did_key,
            principal.certificate_id,
        )
        != (
            scope.team_id,
            body["requester"]["principal_did"],
            body["requester"]["member_did_key"],
            body["requester"]["certificate_id"],
        )
    ):
        raise UseAuditUnavailable()
    if inputs.secret_ref is not None:
        candidates = [
            slot
            for slot in prepared.slots
            if slot.body["delivery"] == "durable"
            and slot.body["source"]["ref"] == inputs.secret_ref
        ]
        if len(candidates) != 1 or candidates[0].body["source"]["ref"] != inputs.secret_ref:
            raise UseAuditUnavailable()
    payload = {
        "op_kind": "run_job",
        "use_ref": body["intent_id"],
        "job_id": inputs.job_id,
        "job_digest": inputs.job_digest,
        "runner_id": inputs.runner_id,
        "request_sha256": commitments.request_mac,
    }
    if commitments.params_mac is not None:
        payload["params_sha256"] = commitments.params_mac
    correlation = {
        "principal_did": body["requester"]["principal_did"],
        "request_id": inputs.request_id,
        "request_ref": body["intent_id"],
        "job_id": inputs.job_id,
        "job_digest": inputs.job_digest,
        "runner_id": inputs.runner_id,
    }
    trace = signed_trace_id
    if trace is not None and (_TRACE.fullmatch(trace) is None or trace == "0" * 32):
        trace = None
    dispatch_ref = "dsp_" + secrets.token_urlsafe(16)
    await tx.execute(
        "INSERT INTO {{tables.run_contexts}}"
        " (dispatch_id,dispatch_ref,run_id,intent_id,app_id,installation_id,team_id,install_generation,"
        "principal_did,member_did_key,certificate_id,team_did_key,request_id,request_sha256,request_mac,params_mac,"
        "job_id,job_digest,runner_id,plan_digest,actor,payload,correlation,signed_trace_id,attestation)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::jsonb,$22::jsonb,$23::jsonb,$24,$25::jsonb)",
        UUID(body["dispatch_id"]),
        dispatch_ref,
        body["run_id"],
        body["intent_id"],
        scope.app_id,
        scope.installation_id,
        scope.team_id,
        scope.generation,
        body["requester"]["principal_did"],
        principal.did_key,
        principal.certificate_id,
        principal.team_did_key,
        inputs.request_id,
        inputs.request_sha256,
        commitments.request_mac,
        commitments.params_mac,
        inputs.job_id,
        inputs.job_digest,
        inputs.runner_id,
        prepared.plan.digest,
        json.dumps(_actor(principal)),
        json.dumps(payload),
        json.dumps(correlation),
        trace,
        None if attestation is None else json.dumps(asdict(attestation)),
    )
    await tx.execute(
        "INSERT INTO {{tables.run_deliveries}} (dispatch_id) VALUES ($1)", UUID(body["dispatch_id"])
    )
    return dispatch_ref
