"""The sole member-to-runner S3 composition on original S12 run associations.

The transport sees only immutable submissions/replies. Custody preparation occurs
outside authority transactions; a fresh whole-run/B2 fence publishes assignment,
nonce and outbox together. Stored assignment replay never opens or reseals.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from aweb_naapp import ratelimit
from aweb_naapp.dispatch import Dispatch, Dispatches, DispatchInFlight, ReconciliationPending, State
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.producer import HookProducerFactory, RegistrationView
from aweb_naapp.hooks.strictjson import Refused as HookRefused
from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired, claim
from aweb_naapp.roles import hold_role, principal_key, roles_of
from aweb_naapp.runtime.approvals import (
    Approval,
    ApprovalRefused,
    Approvals,
    ApprovalState,
    DispatchBinding,
    DispatchOutcome,
)
from aweb_naapp.runtime.approvals.dispatch_fence import PreparedDispatch
from aweb_naapp.runtime.approvals.request import RequestNotCanonical, parse_request_json
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import Passkeys
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets import jobs, records, runners, tool_results
from aweb_secrets.admission import IDEMPOTENCY_RETENTION, AdmissionRefused, _charges, mint_intent_id
from aweb_secrets.broker_audit import record_use_refusal
from aweb_secrets.containment_state import ContainmentRefused, require_enabled
from aweb_secrets.custody import (
    CustodyUnavailable,
    Plaintext,
    SealContext,
    ValueInvalid,
    decode_value,
)
from aweb_secrets.custody.opening import BackendObservation, UseSecretOpener
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.member_types import MemberSubmission, ToolReply
from aweb_secrets.policy import IDENTIFIER
from aweb_secrets.redaction import KnownValues
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.responses import BrokeredResult
from aweb_secrets.run_approvals import (
    PendingRunApproval,
    admit_run_approvals,
    request_run_approvals,
    run_approval_record,
)
from aweb_secrets.run_audit import RunAudit
from aweb_secrets.run_context import OriginalRun, original_run, store_run_context
from aweb_secrets.run_dispatch_authority import RunDispatchAuthority
from aweb_secrets.run_input import RunInput
from aweb_secrets.run_plan import PreparedRun, RunPlanRefused
from aweb_secrets.run_planner import RunPlanner
from aweb_secrets.run_status import RunStatus
from aweb_secrets.runner_protocol import (
    SKEW,
    ParsedRequest,
    RunnerRefused,
    canonical,
    parse_request,
    sign_assignment,
    verify_request,
    verify_request_signature,
)
from aweb_secrets.runner_results import RunnerResultInvalid, process_runner_result
from aweb_secrets.runner_types import RunnerReply, RunnerSubmission
from aweb_secrets.use_audit import UseApprovalAudit, UseAuditUnavailable
from aweb_secrets.use_context import UseCommitter

if TYPE_CHECKING:
    from aweb_secrets.reconciliation_types import ReconciliationOriginal

_LOG = logging.getLogger(__name__)
_HOOK = "post-secret-use-hook"
_CLOSING = {
    "approval_denied": State.APPROVAL_DENIED,
    "approval_expired": State.APPROVAL_EXPIRED,
    "approval_revoked": State.CANCELLED,
}


@dataclass(frozen=True, repr=False)
class _Opened:
    values: tuple[Plaintext, ...]
    observations: tuple[BackendObservation | None, ...]
    contexts: tuple[SealContext, ...]
    known: KnownValues


@dataclass(frozen=True, repr=False)
class _ReleaseContext:
    known: KnownValues
    deadline: datetime


def _job(original: OriginalRun) -> jobs.JobDefinition:
    return jobs.JobDefinition.from_after(original.plan.body["job"]["record"])


def _contexts(original: OriginalRun) -> tuple[SealContext, ...]:
    scope = original.installation
    return tuple(
        SealContext(scope.installation_id, scope.team_id, slot.source_id, slot.source_version)
        for slot in original.plan.slots
    )


class _RunFence:
    """Prepared application/B3 union, then B2, then S3; final reads only."""

    def __init__(
        self,
        service: RunDispatch,
        original: OriginalRun,
        grant: Grant,
        view: RegistrationView | None,
        *,
        opened: _Opened | None = None,
    ) -> None:
        self.service, self.original, self.view, self.opened = service, original, view, opened
        self.authority = RunDispatchAuthority(
            original=original, planner=service._planner, grant=grant, passkeys=service._passkeys
        )
        self._tx: TransactionManager | None = None
        self._checks: tuple[PreparedDispatch, ...] = ()

    async def prepare(self, tx: TransactionManager) -> None:
        if self._tx is tx:
            return
        approvals = await self.service._use_audit.dispatch_approvals(tx, self.original.dispatch_id)
        await self.authority.prepare(tx, approvals)
        rows = await tx.fetch_all(
            "SELECT approval_id,request FROM {{tables.run_slot_approvals}}"
            " WHERE installation_id=$1 AND team_id=$2 AND run_id=$3 AND approval_id IS NOT NULL"
            " ORDER BY approval_id",
            self.original.installation.installation_id,
            self.original.installation.team_id,
            self.original.run_id,
        )
        self._checks = (
            await self.service._approvals.prepare_dispatches(
                tx,
                [
                    DispatchBinding(
                        row["approval_id"],
                        json.loads(row["request"]),
                        str(self.original.dispatch_id),
                    )
                    for row in rows
                ],
                authority=self.authority,
            )
            if rows
            else ()
        )
        self._tx = tx

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        if self._tx is not tx or dispatch.dispatch_id != self.original.dispatch_id:
            raise UseAuditUnavailable()
        record = await run_approval_record(
            tx,
            installation_id=self.original.installation.installation_id,
            team_id=self.original.installation.team_id,
            run_id=self.original.run_id,
        )
        if record is None or not record.admitted or record.dispatch_id != str(dispatch.dispatch_id):
            raise UseAuditUnavailable()
        await self.service._available(tx, self.original, self.view)
        for prepared in self._checks:
            await self.service._approvals.check_dispatch(tx, prepared)
        if self.opened is not None:
            for context, observation in zip(
                self.opened.contexts, self.opened.observations, strict=True
            ):
                await self.service._opener.check_observation(tx, context, observation)
        await self.authority.installation_fence.check(tx, dispatch)
        # The planner finishes with F6 and pure live forest/window checks. No
        # awaited authority read may follow those deadline samples.
        await self.authority.prepared.recheck(tx)
        now = self.service._clock()
        if any(item.expires_at <= now for item in self._checks):
            raise AdmissionRefused("approval_expired")


class RunDispatch:
    """One instance shared by UseServices.runs and runner_dispatch_router."""

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        fence: InstallationFence,
        opener: UseSecretOpener,
        committer: UseCommitter,
        response_key: ResponseKey,
        service_key: SigningKey,
        origin: str,
        producer: HookProducerFactory,
        registration_view: Callable[[str], Awaitable[RegistrationView | None]],
        approvals: Approvals,
        use_audit: UseApprovalAudit,
        passkeys: Passkeys,
        max_backlog_age: timedelta,
        assignment_ttl: timedelta,
        sweep_margin: timedelta,
        claim_wait: timedelta,
        derived_max_ttl_s: int,
        internal_destinations: InternalDestinations,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (
            not isinstance(response_key, ResponseKey)
            or not isinstance(service_key, SigningKey)
            or not timedelta(seconds=1) <= assignment_ttl <= timedelta(seconds=300)
            or not timedelta(0) <= claim_wait <= timedelta(seconds=30)
            or sweep_margin <= timedelta(0)
            or max_backlog_age <= timedelta(0)
        ):
            raise ValueError("run composition requires valid keys and bounded lifetimes")
        self._db, self._fence, self._opener = db, fence, opener
        self._committer, self._response_key, self._service_key = (
            committer,
            response_key,
            service_key,
        )
        self._origin, self._producer, self._registration_view = origin, producer, registration_view
        self._approvals, self._use_audit, self._passkeys = approvals, use_audit, passkeys
        self.status = RunStatus(approvals=approvals, use_audit=use_audit)
        self._max_backlog_age, self._assignment_ttl = max_backlog_age, assignment_ttl
        self._sweep_margin, self._claim_wait, self._clock = sweep_margin, claim_wait, clock
        self._planner = RunPlanner(
            fence,
            clock=clock,
            derived_max_ttl_s=derived_max_ttl_s,
            internal_destinations=internal_destinations,
        )
        # Only original known values live here. This is not a work/assignment
        # registry; another worker safely withholds output if context was lost.
        self._release_context: dict[UUID, _ReleaseContext] = {}

    def _machine(
        self,
        original: OriginalRun,
        view: RegistrationView | None = None,
        *,
        max_dispatch: timedelta | None = None,
        **details: Any,
    ) -> Dispatches:
        return Dispatches(
            on_transition=RunAudit(producer=self._producer, view=view, **details),
            max_dispatch=(
                timedelta(seconds=_job(original).after["timeout_s"])
                if max_dispatch is None
                else max_dispatch
            ),
            sweep_margin=self._sweep_margin,
        )

    async def _available(
        self, tx: TransactionManager, original: OriginalRun, view: RegistrationView | None
    ) -> None:
        scope = original.installation
        await self._producer(
            installation_id=scope.installation_id, generation=scope.generation
        ).require_admission(
            tx,
            team_id=scope.team_id,
            hook=_HOOK,
            occurred_at=self._clock(),
            view=view,
            max_backlog_age=self._max_backlog_age,
        )

    async def submit(self, *, job: str, submission: MemberSubmission) -> ToolReply:
        auth, request_id = submission.authorization, None
        if auth.tool.name != "run" or auth.principal.team_id != auth.grant.team_id:
            return ToolReply(403, tool_results.refused("grant_missing", request_id=None))
        try:
            body = parse_request_json(submission.inbound.body)
            candidate = body.get("request_id")
            request_id = candidate if isinstance(candidate, str) and candidate else None
            view = await self._registration_view(auth.grant.team_id)
            with self._use_audit.prepared_view(view):
                return await self._submit(job, body, submission, view)
        except (RequestNotCanonical, UnicodeError, RecursionError):
            return await self._refusal(submission, job, request_id, "params_invalid", 400)
        except (IdempotencyConflict, IdempotencyExpired) as refused:
            return await self._refusal(submission, job, request_id, refused.code, refused.status)
        except (AdmissionRefused, InstallationRefused, ContainmentRefused) as refused:
            headers = (
                {"Retry-After": str(refused.retry_after_s)}
                if isinstance(refused, AdmissionRefused) and refused.retry_after_s
                else {}
            )
            return await self._refusal(
                submission, job, request_id, refused.code, refused.status, headers
            )
        except (DispatchInFlight, ReconciliationPending) as refused:
            return await self._refusal(submission, job, request_id, refused.code, 409)
        except (UseAuditUnavailable, HookRefused) as refused:
            return await self._refusal(submission, job, request_id, refused.code, 503)
        except RunPlanRefused as refused:
            code = (
                "release_context_unavailable"
                if refused.code.startswith("run_plan_")
                else refused.code
            )
            return await self._refusal(
                submission,
                job,
                request_id,
                code,
                503 if code == "release_context_unavailable" else 403,
            )

    async def _refusal(
        self,
        submission: MemberSubmission,
        job: str,
        request_id: str | None,
        code: str,
        status: int,
        headers: Mapping[str, str] | None = None,
    ) -> ToolReply:
        # The failed admission transaction has ended: no claim, plan, approval
        # or rate charge survives it. Record only an attributed catalog refusal.
        if code not in {
            "release_context_unavailable",
            "authority_unavailable",
            "installation_identity_required",
            "idempotency_expired",
            "not_found",
        }:
            try:
                async with self._db.transaction() as tx:
                    auth = submission.authorization
                    scope = await self._fence.admit(tx, auth.grant)
                    context = CommitmentContext(
                        scope.app_id, scope.team_id, scope.installation_id, scope.generation, "run"
                    )
                    try:
                        body = parse_request_json(submission.inbound.body)
                        params = body.get("params", {})
                    except (RequestNotCanonical, UnicodeError, RecursionError):
                        params = None
                    commitments = self._committer.commit(
                        context,
                        submission.inbound,
                        parameters=params if isinstance(params, Mapping) else None,
                    )
                    await record_use_refusal(
                        tx,
                        producer=self._producer(
                            installation_id=scope.installation_id, generation=scope.generation
                        ),
                        principal=auth.principal,
                        commitments=commitments,
                        code="installation_disabled" if code == "installation_inactive" else code,
                        occurred_at=self._clock(),
                        signed_trace_id=submission.signed_trace_id,
                        request_id=request_id,
                        job_id=job if isinstance(job, str) and IDENTIFIER.fullmatch(job) else None,
                    )
                    await self._fence.check(tx, scope)
            except InstallationRefused as refused:
                return ToolReply(
                    refused.status, tool_results.refused(refused.code, request_id=request_id)
                )
        return ToolReply(status, tool_results.refused(code, request_id=request_id), headers or {})

    async def _submit(
        self,
        job: str,
        body: Mapping[str, Any],
        submission: MemberSubmission,
        view: RegistrationView | None,
    ) -> ToolReply:
        auth = submission.authorization
        pending: tuple[PendingRunApproval, ...] = ()
        async with self._db.transaction() as discovery:
            candidate = await jobs.current_job(discovery, auth.grant.installation_id, job)
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, auth.grant)
            who = principal_key(auth.principal)
            previous = await tx.fetch_one(
                "SELECT dispatch_id,job_id,job_digest FROM {{tables.run_contexts}}"
                " WHERE installation_id=$1 AND team_id=$2 AND principal_did=$3 AND request_id=$4",
                scope.installation_id,
                scope.team_id,
                who.principal_did,
                body.get("request_id") if isinstance(body.get("request_id"), str) else None,
            )
            if previous is not None and previous["job_id"] != job:
                raise AdmissionRefused("idempotency_conflict", 409)
            if previous is None and candidate is None:
                raise AdmissionRefused("job_not_allowed")
            inputs = RunInput.from_body(
                job,
                body,
                job_digest=previous["job_digest"]
                if previous is not None
                else self._candidate_digest(candidate),
            )
            # Derived credentials remain outside the first-release surface.
            # Keep the typed selector's validation, but never claim or prepare
            # a child run until its service/runner substitution path is enabled.
            if inputs.secret_ref is not None:
                raise AdmissionRefused("job_not_allowed")
            intent_id = mint_intent_id()
            receipt = await claim(
                tx,
                key=(scope.installation_id, who.principal_did, inputs.request_id),
                request_hash=inputs.request_sha256,
                receipt_ref=intent_id,
                retention=IDEMPOTENCY_RETENTION,
            )
            if not receipt.created:
                row = await tx.fetch_one(
                    "SELECT dispatch_id FROM {{tables.run_contexts}} WHERE intent_id=$1",
                    receipt.receipt_ref,
                )
                if row is None:
                    raise UseAuditUnavailable()
                original = await original_run(tx, row["dispatch_id"])
                if original is None or original.installation != scope:
                    raise AdmissionRefused("generation_superseded", 409)
                current = await self._machine(original).get(tx, original.dispatch_id)
                if current.state is not State.AWAITING_APPROVAL:
                    await self._read_authorized(tx, original, submission)
                    reply = await self._receipt(tx, original, current)
                    await self._fence.check(tx, scope)
                    return reply
                reply = await self._receipt(tx, original, current)
                if reply.body["state"] == "awaiting_approval":
                    await self._read_authorized(tx, original, submission)
                    await self._fence.check(tx, scope)
                    return reply
                if reply.body.get("code") in _CLOSING:
                    await self._read_authorized(tx, original, submission)
                    await self._close_waiting(tx, original, reply.body["code"])
                    await self._fence.check(tx, scope)
                    return ToolReply(403, reply.body)
                # Whole-run current decider and B3 authority precedes B2.
                authority = RunDispatchAuthority(
                    original=original,
                    planner=self._planner,
                    grant=auth.grant,
                    passkeys=self._passkeys,
                )
                original_approvals = await self._use_audit.dispatch_approvals(
                    tx, original.dispatch_id
                )
                await authority.prepare(tx, original_approvals)
                admitted = await admit_run_approvals(
                    tx, self._approvals, prepared=authority.prepared
                )
                if admitted.refusal is not None:
                    if admitted.refusal in _CLOSING:
                        await self._close_waiting(tx, original, admitted.refusal)
                    await self._fence.check(tx, scope)
                    return ToolReply(
                        403,
                        {
                            **tool_results.refused(
                                admitted.refusal, request_id=original.request_id
                            ),
                            "request_ref": original.intent_id,
                        },
                    )
                if not admitted.may_send:
                    raise AdmissionRefused("approval_consumed", 409)
                publication = _RunFence(self, original, auth.grant, view)
                publication.authority = authority
                await publication.prepare(tx)
                machine = self._machine(original, view)
                current = await machine.admit(tx, original.dispatch_id, fence=publication)
                await publication.check(tx, current)
                reply = await self._receipt(tx, original, current)
            else:
                assert candidate is not None
                dispatch_id = uuid4()
                prepared = await self._planner.prepare(
                    tx,
                    grant=auth.grant,
                    principal=auth.principal,
                    run_id="run_" + secrets.token_urlsafe(16),
                    intent_id=intent_id,
                    dispatch_id=dispatch_id,
                    candidate_job=candidate,
                    runner_id=inputs.runner_id,
                    params=inputs.params,
                    attestation=auth.attestation,
                    selected_ref=inputs.secret_ref,
                )
                # Issuance is a separately parked activation; this service only
                # releases existing durable slots allowed by the pinned job.
                if any(
                    slot.body["delivery"] != "durable" or slot.body["mint"] is not None
                    for slot in prepared.slots
                ):
                    raise AdmissionRefused("job_not_allowed")
                await self._charge(tx, prepared)
                commitments = self._committer.commit(
                    CommitmentContext(
                        scope.app_id, scope.team_id, scope.installation_id, scope.generation, "run"
                    ),
                    submission.inbound,
                    parameters=inputs.params,
                )
                await store_run_context(
                    tx,
                    prepared=prepared,
                    inputs=inputs,
                    principal=auth.principal,
                    commitments=commitments,
                    signed_trace_id=submission.signed_trace_id,
                    attestation=auth.attestation,
                )
                with self._use_audit.minting(dispatch_id):
                    pending = await request_run_approvals(
                        tx,
                        self._approvals,
                        prepared=prepared,
                        principal=auth.principal,
                        reason=inputs.reason,
                    )
                original = await original_run(tx, dispatch_id)
                if original is None:
                    raise UseAuditUnavailable()
                await self._available(tx, original, view)
                machine = self._machine(original, view)
                current = await machine.create(
                    tx,
                    dispatch_id=dispatch_id,
                    subject=scope.installation_id + ":runner:" + inputs.runner_id,
                    action="run_job",
                )
                if any(slot.approval_required for slot in prepared.slots):
                    current = await machine.await_approval(tx, dispatch_id)
                    await prepared.recheck(tx)
                else:
                    admitted = await admit_run_approvals(tx, self._approvals, prepared=prepared)
                    if not admitted.may_send:
                        raise AdmissionRefused(admitted.refusal or "approval_consumed", 409)
                    publication = _RunFence(self, original, auth.grant, view)
                    await publication.prepare(tx)
                    current = await machine.admit(tx, dispatch_id, fence=publication)
                    await publication.check(tx, current)
                reply = await self._receipt(tx, original, current)
            await self._fence.check(tx, scope)
        for item in pending:
            if item.pending is not None:
                await self._approvals.deliver(item.pending)
        return reply

    @staticmethod
    def _candidate_digest(candidate: jobs.JobDefinition | None) -> str:
        if candidate is None:
            raise AdmissionRefused("job_not_allowed")
        return candidate.digest

    async def _charge(self, tx: TransactionManager, prepared: PreparedRun) -> None:
        charges = {}
        principal = prepared.plan.body["requester"]["principal_did"]
        for slot in prepared.slots:
            for charge in _charges(
                prepared.installation, slot.source_id, principal, slot.parent_policy
            ):
                charges[(charge.bucket, charge.key)] = charge
            # Charge each ancestor's original issuing policy only once across
            # the complete forest, including overlapping credential slots.
            for node in slot.body["ancestry"]:
                if node["policy_digest"] is None:
                    continue
                policy = await records.policy(
                    tx, prepared.installation.installation_id, node["policy_digest"]
                )
                if policy is None:
                    raise AdmissionRefused("grant_revoked")
                for charge in _charges(
                    prepared.installation,
                    node["parent_secret_id"],
                    node["issuing_principal"],
                    policy,
                ):
                    charges[(charge.bucket, charge.key)] = charge
        if charges:
            decision = await ratelimit.take(tx, list(charges.values()), now=self._clock())
            if not decision.allowed:
                raise AdmissionRefused(
                    "policy_rate_limited", 429, retry_after_s=decision.retry_after_s
                )

    async def _read_authorized(
        self, tx: TransactionManager, original: OriginalRun, submission: MemberSubmission
    ) -> None:
        principal = principal_key(submission.authorization.principal)
        if principal.principal_did != principal_key(original.principal).principal_did:
            raise AdmissionRefused("not_found", 404)
        roles = []
        for role in sorted(await roles_of(tx, principal)):
            if is_secrets_role(role) and await hold_role(tx, principal, role):
                roles.append(role)
        if not await self.status.read_granted(
            tx, original, principal_did=principal.principal_did, roles=roles
        ):
            raise AdmissionRefused("not_found", 404)

    async def _receipt(
        self, tx: TransactionManager, original: OriginalRun, dispatch: Dispatch
    ) -> ToolReply:
        return await self.status.receipt(tx, original, dispatch)

    async def _close_waiting(
        self, tx: TransactionManager, original: OriginalRun, code: str
    ) -> None:
        approvals = await self._use_audit.dispatch_approvals(tx, original.dispatch_id)
        await self._approvals.lock_many(tx, [approval.approval_id for approval in approvals])
        if code == "approval_expired":
            for approval in approvals:
                if approval.state_at(self._clock()) is ApprovalState.EXPIRED:
                    await self._use_audit.expired(tx, approval.approval_id)
        elif code == "approval_revoked":
            await self._approvals.revoke_many(
                [a.approval_id for a in approvals], revoked_by="secrets", reason=code, tx=tx
            )
        await self._machine(original).close(tx, original.dispatch_id, _CLOSING[code])

    async def _runner_grant(self, parsed: ParsedRequest) -> Grant:
        directory = await runners.runner_scope(self._db, parsed.runner_id)
        if directory is None:
            raise RunnerRefused("runner_unknown")
        permit = await self._fence.permit(directory[1])
        if permit.admitted.installation_id != directory[0]:
            raise RunnerRefused("runner_unknown")
        return Grant(
            team_id=permit.admitted.team_id,
            scopes=permit.status.granted_scopes,
            installation_id=permit.admitted.installation_id,
            generation=permit.admitted.generation,
            fresh_until=permit.status.fresh_until,
        )

    async def _verify(
        self, tx: TransactionManager, submission: RunnerSubmission, grant: Grant
    ) -> runners.RegisteredRunner:
        parsed = parse_request(submission.header)
        runner = await runners.active_runner(tx, parsed.runner_id)
        kid = (
            runner.signing_key
            if runner is not None
            and (runner.installation_id, runner.team_id) == (grant.installation_id, grant.team_id)
            else None
        )
        verify_request(
            parsed,
            registered_kid=kid,
            origin=self._origin,
            method=submission.method,
            path=submission.raw_target,
            body=submission.body,
            now=self._clock(),
        )
        if runner is None:
            raise RunnerRefused("runner_unknown")
        return runner

    async def _consume(
        self, tx: TransactionManager, submission: RunnerSubmission, grant: Grant
    ) -> None:
        await runners.authenticate_in(
            tx,
            installation_id=grant.installation_id,
            header=submission.header,
            origin=self._origin,
            method=submission.method,
            path=submission.raw_target,
            body=submission.body,
            clock=self._clock,
        )

    @staticmethod
    def _empty(submission: RunnerSubmission) -> None:
        try:
            if parse_request_json(submission.body) != {}:
                raise ValueError()
        except (RequestNotCanonical, ValueError, RecursionError, UnicodeError):
            raise RunnerRefused("runner_request_invalid") from None

    async def _precheck(self, submission: RunnerSubmission, grant: Grant) -> None:
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            await self._verify(tx, submission, grant)
            await self._fence.check(tx, scope)

    async def claim(self, submission: RunnerSubmission) -> RunnerReply:
        parsed = parse_request(submission.header)
        grant = await self._runner_grant(parsed)
        await self._precheck(submission, grant)
        self._empty(submission)
        # Long polling owns no transaction, runner row or authority lock.
        deadline = asyncio.get_running_loop().time() + self._claim_wait.total_seconds()
        while True:
            row = await self._db.fetch_one(
                "SELECT c.dispatch_id,d.state FROM {{tables.run_contexts}} c"
                " JOIN {{tables.dispatches}} d USING(dispatch_id)"
                " WHERE c.installation_id=$1 AND c.team_id=$2 AND c.install_generation=$3"
                " AND c.runner_id=$4 AND d.state IN ('admitted','dispatching','outcome_unknown')"
                " ORDER BY (d.state='outcome_unknown') DESC,(d.state='dispatching') DESC,c.created_at,c.dispatch_id LIMIT 1",
                grant.installation_id,
                grant.team_id,
                grant.generation,
                parsed.runner_id,
            )
            if row is not None:
                async with self._db.transaction() as discovery:
                    original = await original_run(discovery, row["dispatch_id"])
                if original is None:
                    raise RunnerRefused("runner_unavailable")
                if row["state"] != State.ADMITTED:
                    return await self._replay(submission, grant, original)
                if "secrets:run" not in grant.scopes:
                    raise RunnerRefused("runner_unavailable")
                view = await self._registration_view(grant.team_id)
                try:
                    opened = await self._open(original)
                except (CustodyUnavailable, ValueInvalid, TimeoutError):
                    return await self._preparation_failed(
                        submission, grant, original, "custody_unavailable"
                    )
                try:
                    return await self._publish(submission, grant, original, opened, view)
                except (
                    RunPlanRefused,
                    AdmissionRefused,
                    InstallationRefused,
                    ContainmentRefused,
                    UseAuditUnavailable,
                    HookRefused,
                    ApprovalRefused,
                    CustodyUnavailable,
                ) as refused:
                    # Publication refusal never grants effect authority. It is
                    # recorded only while still admitted; a competing committed
                    # assignment is replayed before any refusal is attempted.
                    cause = getattr(refused, "code", None)
                    if isinstance(refused, ApprovalRefused):
                        cause = "approval_revoked"
                    if cause in {
                        None,
                        "release_context_unavailable",
                        "authority_unavailable",
                        "installation_identity_required",
                    } or cause.startswith("run_plan_"):
                        cause = "runner_unavailable"
                    return await self._preparation_failed(submission, grant, original, cause)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                async with self._db.transaction() as tx:
                    scope = await self._fence.admit(tx, grant)
                    await self._verify(tx, submission, grant)
                    await self._consume(tx, submission, grant)
                    await self._fence.check(tx, scope)
                return RunnerReply(204)
            await asyncio.sleep(min(0.1, remaining))
            grant = await self._runner_grant(parsed)

    async def _open(self, original: OriginalRun) -> _Opened:
        known, values, observations = KnownValues(), [], []
        contexts = _contexts(original)
        # SDK/network and native unsealing have a bounded lifetime and run
        # outside every held authority transaction. No later failure reopens a
        # value to reconstruct this original redaction context.
        async with asyncio.timeout(self._assignment_ttl.total_seconds()):
            for slot, context in zip(original.plan.slots, contexts, strict=True):
                observation = await self._opener.observe(context)
                value = await self._opener.open(context)
                fields = decode_value(slot.body["source"]["record"]["kind"], value.reveal())
                required = {
                    binding["field"]
                    for binding in _job(original).after["env"].values()
                    if isinstance(binding, dict)
                    and binding.get("$credential") == slot.body["label"]
                }
                if not required.issubset(fields) or any("\0" in fields[name] for name in required):
                    raise CustodyUnavailable("job credential fields unavailable")
                for item in fields.values():
                    if item:
                        known.add(slot.body["label"], item)
                if "username" in fields and "password" in fields:
                    known.add_basic(slot.body["label"], fields["username"], fields["password"])
                values.append(value)
                observations.append(observation)
        return _Opened(tuple(values), tuple(observations), contexts, known)

    async def _published(
        self,
        tx: TransactionManager,
        submission: RunnerSubmission,
        grant: Grant,
        original: OriginalRun,
    ) -> RunnerReply | None:
        row = await tx.fetch_one(
            "SELECT d.state,v.assignment,v.expires_at FROM {{tables.dispatches}} d"
            " JOIN {{tables.run_deliveries}} v USING(dispatch_id) WHERE d.dispatch_id=$1",
            original.dispatch_id,
        )
        if row is None:
            raise RunnerRefused("runner_dispatch_unknown")
        if row["state"] == State.OUTCOME_UNKNOWN:
            raise RunnerRefused("runner_reconciliation_required")
        if row["state"] == State.ADMITTED and row["assignment"] is None:
            return None
        if row["state"] != State.DISPATCHING or row["assignment"] is None:
            raise RunnerRefused("runner_dispatch_state_conflict")
        await require_enabled(
            tx, original.installation.installation_id, original.installation.team_id
        )
        for slot, context in zip(original.plan.slots, _contexts(original), strict=True):
            if slot.body["source"]["record"]["backend"] == "native":
                await self._opener.check_observation(tx, context, None)
            else:
                await self._published_backend(tx, context)
        await self._consume(tx, submission, grant)
        await self._fence.check(tx, original.installation)
        if row["expires_at"] <= self._clock():
            raise RunnerRefused("runner_dispatch_state_conflict")
        return RunnerReply(200, bytes(row["assignment"]))

    async def _published_backend(self, tx: TransactionManager, context: SealContext) -> None:
        # Current local 1Password binding/credential epoch is checked without
        # a new remote observation or a read of any value.
        from aweb_secrets.custody.opening import active_binding

        await active_binding(tx, context)

    async def _replay(
        self, submission: RunnerSubmission, grant: Grant, original: OriginalRun
    ) -> RunnerReply:
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            if scope != original.installation:
                raise RunnerRefused("runner_dispatch_unknown")
            await self._verify(tx, submission, grant)
            reply = await self._published(tx, submission, grant, original)
            if reply is None:
                raise RunnerRefused("runner_dispatch_state_conflict")
            return reply

    async def _publish(
        self,
        submission: RunnerSubmission,
        grant: Grant,
        original: OriginalRun,
        opened: _Opened,
        view: RegistrationView | None,
    ) -> RunnerReply:
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            if scope != original.installation:
                raise RunnerRefused("runner_dispatch_unknown")
            # This UPDATE fence serializes claims for the installation before
            # either runner/B2/S3. A loser classifies stored publication first.
            if (
                await tx.fetch_value(
                    "SELECT state FROM {{tables.dispatches}} WHERE dispatch_id=$1",
                    original.dispatch_id,
                )
                != State.ADMITTED
            ):
                await self._verify(tx, submission, grant)
                replay = await self._published(tx, submission, grant, original)
                if replay is not None:
                    return replay
            fence = _RunFence(self, original, grant, view, opened=opened)
            await fence.prepare(tx)
            await self._verify(tx, submission, grant)
            credentials = []
            for slot, value in zip(original.plan.slots, opened.values, strict=True):
                credentials.append(
                    {
                        "secret_ref": slot.body["label"],
                        "sealed": await runners.seal_credential(
                            tx,
                            installation_id=scope.installation_id,
                            runner_id=original.runner_id,
                            dispatch_id=original.dispatch_ref,
                            value=value.reveal(),
                        ),
                    }
                )
            issued = self._clock().replace(microsecond=0)
            expires = issued + timedelta(seconds=int(self._assignment_ttl.total_seconds()))
            wire = canonical(
                sign_assignment(
                    key=self._service_key,
                    origin=self._origin,
                    runner_id=original.runner_id,
                    dispatch_id=original.dispatch_ref,
                    job_id=original.plan.body["job"]["job_id"],
                    job_digest=original.plan.body["job"]["digest"],
                    params=original.plan.body["params"],
                    credentials=credentials,
                    issued_at=issued,
                    expires_at=expires,
                )
            )
            # A valid assignment may start just before its signed expiry and
            # then run for the entire job timeout. Base S3 recovery on that
            # absolute bound, using its own database clock. Publication and
            # replay never move this persisted deadline.
            database_now = await tx.fetch_value("SELECT clock_timestamp()")
            machine = self._machine(
                original,
                view,
                max_dispatch=timedelta(seconds=_job(original).after["timeout_s"])
                + max(expires - database_now, timedelta(0)),
            )
            current = await machine.begin_dispatch(tx, original.dispatch_id, fence=fence)
            recovery_deadline = await tx.fetch_value(
                "SELECT sweep_after FROM {{tables.dispatches}} WHERE dispatch_id=$1",
                original.dispatch_id,
            )
            await tx.execute(
                "UPDATE {{tables.run_deliveries}} SET assignment=$2,issued_at=$3,expires_at=$4 WHERE dispatch_id=$1",
                original.dispatch_id,
                wire,
                issued,
                expires,
            )
            await self._consume(tx, submission, grant)
            # Nonce/outbox/sealing await work too: the sole aggregate final
            # fence follows all of them, before this transaction commits.
            await fence.check(tx, current)
            if expires <= self._clock():
                raise RunnerRefused("runner_dispatch_state_conflict")
        self._prune_contexts()
        self._release_context[original.dispatch_id] = _ReleaseContext(
            opened.known,
            recovery_deadline,
        )
        return RunnerReply(200, wire)

    async def _preparation_failed(
        self, submission: RunnerSubmission, grant: Grant, original: OriginalRun, cause: str
    ) -> RunnerReply:
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            if scope != original.installation:
                raise RunnerRefused("runner_dispatch_unknown")
            await self._verify(tx, submission, grant)
            state = await tx.fetch_value(
                "SELECT state FROM {{tables.dispatches}} WHERE dispatch_id=$1", original.dispatch_id
            )
            if state != State.ADMITTED:
                reply = await self._published(tx, submission, grant, original)
                if reply is not None:
                    return reply
            approvals = await self._lock_outcomes(tx, original)
            await self._approvals.revoke_many(
                [a.approval_id for a in approvals],
                revoked_by="secrets",
                reason=cause,
                tx=tx,
            )
            await self._machine(original, refusal_code=cause).refuse(tx, original.dispatch_id)
            await self._consume(tx, submission, grant)
            await self._fence.check(tx, scope)
        raise RunnerRefused("runner_unavailable")

    def _prune_contexts(self) -> None:
        now = self._clock()
        for dispatch_id, context in tuple(self._release_context.items()):
            if context.deadline <= now:
                self._release_context.pop(dispatch_id, None)

    async def result_body_limit(
        self, *, dispatch_ref: str, header: str, method: str, raw_target: str
    ) -> int:
        parsed = parse_request(header)
        grant = await self._runner_grant(parsed)
        async with self._db.transaction() as tx:
            scope = AdmittedInstallation(
                app_id=self._fence.app_id,
                team_id=grant.team_id,
                installation_id=grant.installation_id,
                generation=grant.generation,
            )
            installation = self._fence.for_installation(scope)
            await installation.prepare(tx)
            runner = await runners.active_runner(tx, parsed.runner_id)
            kid = (
                runner.signing_key
                if runner is not None
                and (runner.installation_id, runner.team_id)
                == (scope.installation_id, scope.team_id)
                else None
            )
            verify_request_signature(parsed, registered_kid=kid)
            if (parsed.payload["origin"], parsed.payload["method"], parsed.payload["path"]) != (
                self._origin,
                method,
                raw_target,
            ):
                raise RunnerRefused("runner_request_binding_mismatch")
            if abs(self._clock() - parsed.timestamp) > SKEW:
                raise RunnerRefused("runner_request_stale")
            original = await self._assigned(tx, dispatch_ref, parsed.runner_id, grant)
            limit = 6 * _job(original).after["output"]["max_bytes"] + 1024
            await installation.check(tx, None)
            if abs(self._clock() - parsed.timestamp) > SKEW:
                raise RunnerRefused("runner_request_stale")
        # All read transactions/runner-key holds end before the adapter streams.
        return limit

    async def _assigned(
        self, tx: TransactionManager, dispatch_ref: str, runner_id: str, grant: Grant
    ) -> OriginalRun:
        row = await tx.fetch_one(
            "SELECT c.dispatch_id FROM {{tables.run_contexts}} c JOIN {{tables.run_deliveries}} v USING(dispatch_id)"
            " WHERE c.dispatch_ref=$1 AND c.runner_id=$2 AND c.installation_id=$3 AND c.team_id=$4"
            " AND c.install_generation=$5 AND v.assignment IS NOT NULL",
            dispatch_ref,
            runner_id,
            grant.installation_id,
            grant.team_id,
            grant.generation,
        )
        original = None if row is None else await original_run(tx, row["dispatch_id"])
        if original is None:
            raise RunnerRefused("runner_dispatch_unknown")
        return original

    async def started(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply:
        parsed = parse_request(submission.header)
        grant = await self._runner_grant(parsed)
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            await self._verify(tx, submission, grant)
            self._empty(submission)
            original = await self._assigned(tx, dispatch_ref, parsed.runner_id, grant)
            await tx.fetch_one(
                "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
                original.dispatch_id,
            )
            state = await tx.fetch_value(
                "SELECT state FROM {{tables.dispatches}} WHERE dispatch_id=$1", original.dispatch_id
            )
            if state not in {
                State.DISPATCHING,
                State.COMPLETED,
                State.OUTCOME_UNKNOWN,
                State.RECONCILED_COMPLETED,
                State.RECONCILED_FAILED,
                State.RECONCILED_UNKNOWN,
            }:
                raise RunnerRefused("runner_dispatch_state_conflict")
            if state == State.DISPATCHING:
                await tx.execute(
                    "UPDATE {{tables.run_deliveries}} SET started_at=COALESCE(started_at,$2) WHERE dispatch_id=$1",
                    original.dispatch_id,
                    self._clock(),
                )
            await self._consume(tx, submission, grant)
            await self._fence.check(tx, scope)
        return RunnerReply(204)

    async def _lock_outcomes(
        self, tx: TransactionManager, original: OriginalRun
    ) -> tuple[Approval, ...]:
        approvals = await self._use_audit.dispatch_approvals(tx, original.dispatch_id)
        await self._approvals.lock_many(tx, [approval.approval_id for approval in approvals])
        return tuple(approvals)

    async def _record(
        self,
        tx: TransactionManager,
        original: OriginalRun,
        state: State,
        reply: ToolReply,
        audit: Mapping[str, Any] | None,
        approvals: tuple[Approval, ...],
    ) -> bool:
        machine = self._machine(original, completed=audit)
        record = {
            State.COMPLETED: machine.complete,
            State.OUTCOME_UNKNOWN: machine.outcome_unknown,
        }[state]
        # S3 is held after the complete B2 union, so its winner cannot change
        # between reading and settling. B2 writes share this same transaction.
        row = await tx.fetch_one(
            "SELECT state FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
            original.dispatch_id,
        )
        if row is None:
            raise UseAuditUnavailable()
        if row["state"] == State.DISPATCHING:
            for approval in approvals:
                await self._approvals.record_outcome(
                    approval.approval_id,
                    str(original.dispatch_id),
                    DispatchOutcome(state.value),
                    response_status=None if audit is None else str(audit["upstream_status_code"]),
                    tx=tx,
                )
        return await record(tx, original.dispatch_id, dict(reply.body))

    async def result(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply:
        parsed = parse_request(submission.header)
        grant = await self._runner_grant(parsed)
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, grant)
            await self._consume(tx, submission, grant)
            original = await self._assigned(tx, dispatch_ref, parsed.runner_id, grant)
            if len(submission.body) > 6 * _job(original).after["output"]["max_bytes"] + 1024:
                raise RunnerRefused("runner_result_invalid")
            approvals = await self._lock_outcomes(tx, original)
            await tx.fetch_one(
                "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
                original.dispatch_id,
            )
            previous = await tx.fetch_value(
                "SELECT report_sha256 FROM {{tables.run_deliveries}} WHERE dispatch_id=$1",
                original.dispatch_id,
            )
            digest = hashlib.sha256(submission.body).digest()
            if previous is not None and bytes(previous) != digest:
                raise RunnerRefused("runner_result_conflict")
            if previous is None:
                self._prune_contexts()
                context = self._release_context.get(original.dispatch_id)
                known = None if context is None else context.known
                # Disable/rotation observations discard the original in-memory
                # context; they never cause a replacement value to be opened.
                try:
                    await require_enabled(tx, scope.installation_id, scope.team_id)
                    for slot, sealed_context in zip(
                        original.plan.slots, _contexts(original), strict=True
                    ):
                        current = await records.secret_by_ref(
                            tx,
                            scope.installation_id,
                            scope.team_id,
                            slot.body["source"]["ref"],
                            lock=False,
                        )
                        if (
                            current is None
                            or current.active_version != sealed_context.version
                            or current.state != "active"
                        ):
                            known = None
                except ContainmentRefused:
                    known = None
                try:
                    handled = process_runner_result(
                        submission.body, job=_job(original), known=known
                    )
                except RunnerResultInvalid:
                    raise RunnerRefused("runner_result_invalid") from None
                projected = {
                    "exit_code": handled.exit_code,
                    "body": None if handled.body is None else json.loads(handled.body),
                    "truncated": handled.truncated,
                    "upstream_bytes": handled.output_bytes,
                    "redaction_count": handled.redaction_count,
                    "runner_redaction_count": handled.runner_redaction_count,
                    "runner_result_withheld": handled.runner_result_withheld,
                    "runner_truncated": handled.runner_truncated,
                }
                identity = {"request_id": original.request_id, "request_ref": original.intent_id}
                envelope: dict[str, Any] = (
                    tool_results.result_withheld(
                        handled.withheld_reason or "release_context_unavailable", **identity
                    )
                    if handled.result_withheld
                    else {"state": "completed", **identity}
                )
                envelope["result"] = projected
                response = BrokeredResult(
                    status=200,
                    headers=[],
                    body=handled.body,
                    disposition="withheld" if handled.result_withheld else "returned",
                    withheld_reason=None,
                    undeclared_credential=handled.withheld_reason == "credential_shaped",
                    redaction_count=handled.redaction_count,
                    truncated=handled.truncated,
                    upstream_bytes=len(submission.body),
                )
                audit = self._response_key.record(
                    submission.body, upstream_truncated=handled.runner_truncated, result=response
                ).fields()
                await self._record(
                    tx, original, State.COMPLETED, ToolReply(200, envelope), audit, approvals
                )
                await tx.execute(
                    "UPDATE {{tables.run_deliveries}} SET report_sha256=$2 WHERE dispatch_id=$1",
                    original.dispatch_id,
                    digest,
                )
            # Recheck exact bytes/time/current held key after the report work.
            # The nonce inserted above rolls back with any refusal or effect.
            await self._verify(tx, submission, grant)
            await self._fence.check(tx, scope)
        self._release_context.pop(original.dispatch_id, None)
        return RunnerReply(204)

    async def reconcile(
        self,
        tx: TransactionManager,
        *,
        original: ReconciliationOriginal,
        state: State,
        result: Mapping[str, Any],
    ) -> None:
        """Caller-authorized first UNKNOWN settlement, using the same run sink.

        Owner and all B2 holds precede this call. No custody, current grant,
        target lookup or publication gate is needed to record a consequence.
        """
        from aweb_secrets.reconciliation_reads import ReconciliationReads

        view = await ReconciliationReads(enable_runs=True).get(
            tx, scope=original.installation, reconcile_ref=original.reconcile_ref
        )
        frozen = await original_run(tx, original.dispatch_id)
        if (
            original.op_kind != "run_job"
            or view is None
            or view.original != original
            or frozen is None
        ):
            raise UseAuditUnavailable()
        await self._machine(frozen).reconcile(tx, original.dispatch_id, state, dict(result))

    async def sweep(self, *, limit: int = 50) -> int:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("run recovery limit must be between 1 and 100")
        rows = await self._db.fetch_all(
            "SELECT c.dispatch_id FROM {{tables.run_contexts}} c JOIN {{tables.dispatches}} d USING(dispatch_id) WHERE d.state='dispatching' AND d.sweep_after<=clock_timestamp() ORDER BY d.sweep_after,d.dispatch_id LIMIT $1",
            limit,
        )
        swept = 0
        for row in rows:
            try:
                async with self._db.transaction() as tx:
                    original = await original_run(tx, row["dispatch_id"])
                    if original is None:
                        raise UseAuditUnavailable()
                    approvals = await self._lock_outcomes(tx, original)
                    current = await tx.fetch_one(
                        "SELECT state,sweep_after FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
                        original.dispatch_id,
                    )
                    now = await tx.fetch_value("SELECT clock_timestamp()")
                    if (
                        current is None
                        or current["state"] != State.DISPATCHING
                        or current["sweep_after"] is None
                        or current["sweep_after"] > now
                    ):
                        continue
                    reply = ToolReply(
                        200,
                        tool_results.outcome_unknown(
                            request_id=original.request_id, request_ref=original.intent_id
                        ),
                    )
                    swept += int(
                        await self._record(
                            tx, original, State.OUTCOME_UNKNOWN, reply, None, approvals
                        )
                    )
                self._release_context.pop(row["dispatch_id"], None)
            except (UseAuditUnavailable, ApprovalRefused):
                _LOG.error(
                    "run recovery context unavailable",
                    extra={"dispatch_id": str(row["dispatch_id"])},
                )
        self._prune_contexts()
        return swept
