"""Authenticated broker submission, sole S3 publication, then exact custody use.

Only this invocation's detached input can be sent. Receipts and approval
decisions never reconstruct an outbound request. All authority and outbox
writes precede the dispatching commit; custody, OAuth and TLS follow it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from aweb_naapp.dispatch import (
    Dispatch,
    Dispatches,
    DispatchInFlight,
    InvalidTransition,
    ReconciliationPending,
    State,
)
from aweb_naapp.egress import (
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    InternalDestinations,
)
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.producer import RegistrationView
from aweb_naapp.hooks.strictjson import Refused as HookRefused
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals import (
    Approval,
    ApprovalRefused,
    Approvals,
    DispatchOutcome,
    Refusal,
    RequestNotCanonical,
)
from aweb_naapp.runtime.approvals.request import parse_request_json
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, tool_results
from aweb_secrets.admission import Admission, AdmissionRefused, admit_use
from aweb_secrets.broker import broker_operation
from aweb_secrets.broker_audit import BrokerAudit, freeze_broker_audit, record_broker_refusal
from aweb_secrets.broker_fence import BrokerFence, PreparedBrokerCall
from aweb_secrets.broker_input import BrokerInput
from aweb_secrets.custody import CustodyUnavailable, SealContext, ValueInvalid, decode_value
from aweb_secrets.custody.opening import BackendObservation, UseSecretOpener
from aweb_secrets.member_types import MemberSubmission, ToolReply, broker_result_reply
from aweb_secrets.onepassword_reconciliation import BackendReconciler
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.status_service import UseStatus
from aweb_secrets.tokens import TokenCache
from aweb_secrets.use_approval import BrokerOpen, BrokerOperation, UseApprovalRefused
from aweb_secrets.use_approvals import admit_approved_use, request_use_approval
from aweb_secrets.use_audit import HookProducerFactory, UseApprovalAudit, UseAuditUnavailable
from aweb_secrets.use_context import UseCommitter, store_use_context, use_context

if TYPE_CHECKING:
    from aweb_naapp.runtime.approvals.dispatch_fence import DispatchAuthority, PreparedDispatch

    from aweb_secrets.reconciliation_types import ReconciliationOriginal

_LOG = logging.getLogger(__name__)
_HOOK = "post-secret-use-hook"
_PROGRESS = frozenset({State.RECEIVED, State.ADMITTED, State.DISPATCHING})
_TERMINAL = frozenset(State) - _PROGRESS - {State.AWAITING_APPROVAL, State.NOT_SENT}


class _OutcomeMoved(Exception):
    """Rollback a tentative B2 outcome when S3 retains a swept/reconciled winner."""


def _context(call: PreparedBrokerCall) -> SealContext:
    version = call.secret
    return SealContext(version.installation_id, version.team_id, version.secret_id, version.version)


@dataclass(frozen=True, repr=False)
class _PreparedUse:
    admission: Admission
    inputs: BrokerInput
    dispatch_id: UUID
    call: PreparedBrokerCall


class _PublicationFence:
    """One transaction's complete preparation, including the B2 final handle."""

    def __init__(
        self,
        service: BrokerRequests,
        use: _PreparedUse,
        submission: MemberSubmission,
        observation: BackendObservation | None,
        view: RegistrationView | None,
    ) -> None:
        async def backend(tx: TransactionManager, context: SealContext) -> None:
            await service._opener.check_observation(tx, context, observation)

        self.service, self.use = service, use
        self.view = view
        self.broker = service._fence_for(
            use.admission, use.inputs, use.dispatch_id, submission, backend_version_check=backend
        )
        self._tx: TransactionManager | None = None
        self._approval: PreparedDispatch | None = None
        self._retry_deadline: datetime | None = None
        self.may_send = True
        self.refusal: str | None = None
        self.authority = (
            service._approval_authority(submission.authorization.principal, use.admission)
            if use.admission.approval_required and service._approval_authority is not None
            else None
        )

    async def prepare(self, tx: TransactionManager) -> None:
        if self._tx is tx:
            return  # S3 repeats preparation; never take app locks after B2/S3.
        await self.service._fence.for_installation(self.use.admission.installation).prepare(tx)
        if self.use.admission.approval_required:
            if self.authority is None or self.service._use_audit is None:
                raise UseAuditUnavailable()
            original = await self.service._use_audit.dispatch_approvals(tx, self.use.dispatch_id)
            if len(original) != 1:
                raise UseAuditUnavailable()
            await self.authority.prepare(tx, original)
        await self.broker.prepare(tx)
        await self.use.inputs.check_binding(
            tx, admission=self.use.admission, dispatch_id=self.use.dispatch_id
        )
        if not self.use.admission.approval_required:
            stored_context = await use_context(tx, self.use.dispatch_id)
            if stored_context.dispatch_started_at is not None:
                self._retry_deadline = stored_context.dispatch_started_at + timedelta(
                    seconds=min(
                        self.service._max_dispatch.total_seconds(),
                        self.broker.call.rendered.bounds.total_timeout,
                    )
                )
        if self.use.admission.approval_required:
            approvals, _ = self.service._approval_services()
            admitted = await admit_approved_use(
                tx,
                approvals,
                intent_id=self.use.admission.intent_id,
                dispatch_id=self.use.dispatch_id,
                max_ttl_s=self.service._derived_max_ttl_s,
            )
            if admitted.admission is None:
                self.refusal = admitted.refusal or "approval_revoked"
                self.may_send = False
            else:
                self.may_send = admitted.admission.may_send
            if self.may_send:
                link = await tx.fetch_one(
                    "SELECT approval_id,request FROM {{tables.use_approvals}} WHERE intent_id=$1"
                    " AND dispatch_id=$2",
                    self.use.admission.intent_id,
                    self.use.dispatch_id,
                )
                if link is None:
                    raise AdmissionRefused("release_context_unavailable", 503)
                self._approval = await approvals.prepare_dispatch(
                    tx,
                    link["approval_id"],
                    json.loads(link["request"]),
                    str(self.use.dispatch_id),
                    authority=self.authority,
                )
        if self.may_send:
            await self._audit_available(tx)
        self._tx = tx

    async def _audit_available(self, tx: TransactionManager) -> None:
        scope = self.use.admission.installation
        await self.service._producer(
            installation_id=scope.installation_id, generation=scope.generation
        ).require_admission(
            tx,
            team_id=scope.team_id,
            hook=_HOOK,
            occurred_at=self.service._clock(),
            view=self.view,
            max_backlog_age=self.service._max_backlog_age,
        )

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        if self._tx is not tx:
            raise RuntimeError("publication authority belongs to its original transaction")
        if not self.may_send:
            raise AdmissionRefused("approval_consumed", 409)
        await self._audit_available(tx)
        if self._approval is not None:
            approvals, _ = self.service._approval_services()
            await approvals.check_dispatch(tx, self._approval)
        # F6/forest/window are checked after the B2 awaits. The aggregate
        # approval deadline below is sampled after that final awaited read.
        await self.broker.check(tx, dispatch)
        if self._approval is not None and self._approval.expires_at <= self.service._clock():
            raise AdmissionRefused("approval_expired")
        if self._retry_deadline is not None and self._retry_deadline <= self.service._clock():
            raise AdmissionRefused("operation_not_allowed")

    def send_budget(self) -> float:
        remaining = min(
            self.service._max_dispatch.total_seconds(),
            self.broker.call.rendered.bounds.total_timeout,
        )
        deadline = self._retry_deadline
        if self._approval is not None:
            deadline = self._approval.expires_at
        if deadline is not None:
            remaining = min(remaining, (deadline - self.service._clock()).total_seconds())
        return max(0.0, remaining)


class BrokerRequests:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        fence: InstallationFence,
        opener: UseSecretOpener,
        egress: Egress,
        tokens: TokenCache,
        committer: UseCommitter,
        response_key: ResponseKey,
        producer: HookProducerFactory,
        registration_view: Callable[[str], Awaitable[RegistrationView | None]],
        max_backlog_age: timedelta,
        max_dispatch: timedelta,
        sweep_margin: timedelta,
        derived_max_ttl_s: int,
        internal_destinations: InternalDestinations,
        approvals: Approvals | None = None,
        approval_authority: Callable[[Principal, Admission], DispatchAuthority] | None = None,
        use_audit: UseApprovalAudit | None = None,
        reconciler: BackendReconciler | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not isinstance(response_key, ResponseKey):
            raise ValueError("broker requests require the independent response key")
        if (approvals is None) != (approval_authority is None):
            raise ValueError("approvals and their dispatch authority must be composed together")
        if (approvals is None) != (use_audit is None):
            raise ValueError("approvals require their shared use lifecycle audit branch")
        if (
            min(max_backlog_age, max_dispatch, sweep_margin) <= timedelta(0)
            or type(derived_max_ttl_s) is not int
            or derived_max_ttl_s <= 0
        ):
            raise ValueError("broker bounds must be positive")
        self._db, self._fence, self._opener = db, fence, opener
        self._egress, self._tokens, self._committer = egress, tokens, committer
        self._response_key, self._producer, self._registration_view = (
            response_key,
            producer,
            registration_view,
        )
        self._max_backlog_age, self._max_dispatch, self._sweep_margin = (
            max_backlog_age,
            max_dispatch,
            sweep_margin,
        )
        self._derived_max_ttl_s, self._internal_destinations, self._clock = (
            derived_max_ttl_s,
            internal_destinations,
            clock,
        )
        self._approvals, self._approval_authority, self._reconciler = (
            approvals,
            approval_authority,
            reconciler,
        )
        self._status = UseStatus(db, fence=fence, approvals=approvals)
        self._use_audit = use_audit

    def _approval_services(
        self,
    ) -> tuple[Approvals, Callable[[Principal, Admission], DispatchAuthority]]:
        if self._approvals is None or self._approval_authority is None:
            raise AdmissionRefused("release_context_unavailable", 503)
        return self._approvals, self._approval_authority

    def _machine(self, view: RegistrationView | None, **details: Any) -> Dispatches:
        return Dispatches(
            on_transition=BrokerAudit(producer=self._producer, view=view, **details),
            max_dispatch=self._max_dispatch,
            sweep_margin=self._sweep_margin,
        )

    def _fence_for(
        self,
        admission: Admission,
        inputs: BrokerInput,
        dispatch_id: UUID,
        submission: MemberSubmission,
        *,
        backend_version_check: Callable[[TransactionManager, SealContext], Awaitable[None]]
        | None = None,
    ) -> BrokerFence:
        return BrokerFence(
            self._fence,
            admission=admission,
            principal=submission.authorization.principal,
            request=inputs.request,
            dispatch_id=dispatch_id,
            headers=inputs.headers,
            attestation=submission.authorization.attestation,
            clock=self._clock,
            derived_max_ttl_s=self._derived_max_ttl_s,
            internal_destinations=self._internal_destinations,
            open_call=inputs.open_call,
            backend_version_check=backend_version_check,
        )

    async def submit(self, *, secret: str, submission: MemberSubmission) -> ToolReply:
        authorization = submission.authorization
        if (
            authorization.tool.name != "request"
            or authorization.principal.team_id != authorization.grant.team_id
        ):
            return ToolReply(403, tool_results.refused("grant_missing", request_id=None))
        request_id: str | None = None
        try:
            body = parse_request_json(submission.inbound.body)
            candidate = body.get("request_id")
            request_id = candidate if isinstance(candidate, str) and candidate else None
        except (RequestNotCanonical, UnicodeError, RecursionError):
            body = {}
        view = await self._registration_view(authorization.grant.team_id)
        try:
            with (
                self._use_audit.prepared_view(view)
                if self._use_audit is not None
                else nullcontext()
            ):
                prepared = await self._admit(secret, body, submission, view)
                if isinstance(prepared, ToolReply):
                    return prepared
                return await self._dispatch(prepared, submission, view)
        except (AdmissionRefused, InstallationRefused) as refused:
            headers = {}
            if isinstance(refused, AdmissionRefused) and refused.retry_after_s:
                headers["Retry-After"] = str(refused.retry_after_s)
            return ToolReply(
                refused.status, tool_results.refused(refused.code, request_id=request_id), headers
            )

    async def _inputs(
        self,
        tx: TransactionManager,
        scope: AdmittedInstallation,
        secret: str,
        body: Mapping[str, Any],
        principal: Principal,
    ) -> BrokerInput:
        digest = None
        if "operation" in body:
            # An existing logical request retains its original operation pin.
            # Never compare it using a newly edited definition's digest.
            original = await tx.fetch_one(
                "SELECT operation_id,operation_digest FROM {{tables.intents}} WHERE installation_id=$1"
                " AND team_id=$2 AND principal_did=$3 AND request_id=$4",
                scope.installation_id,
                scope.team_id,
                principal_key(principal).principal_did,
                body.get("request_id") if isinstance(body.get("request_id"), str) else None,
            )
            if original is not None:
                if original["operation_id"] != body["operation"]:
                    raise AdmissionRefused("idempotency_conflict", 409)
                digest = original["operation_digest"]
            elif isinstance(body["operation"], str):
                # Pin discovery grants no authority and takes no row lock.
                # S8 and BrokerFence check it again under the full forest.
                secret_id = await tx.fetch_value(
                    "SELECT secret_id FROM {{tables.secrets}}"
                    " WHERE installation_id=$1 AND team_id=$2 AND ref=$3",
                    scope.installation_id,
                    scope.team_id,
                    secret,
                )
                path: tuple[str, ...] = ()
                if secret_id is not None:
                    try:
                        path = await derived_lineage.ancestry_ids(
                            tx, scope.installation_id, scope.team_id, secret_id
                        )
                    except derived_lineage.LineageRefused:
                        # S8 alone classifies current authority and liveness.
                        pass
                if path:
                    digest = await tx.fetch_value(
                        "SELECT digest FROM {{tables.current_operations}}"
                        " WHERE installation_id=$1 AND secret_id=ANY($2::text[])"
                        " AND operation_id=$3"
                        " ORDER BY array_position($2::text[],secret_id) DESC LIMIT 1",
                        scope.installation_id,
                        list(path),
                        body["operation"],
                    )
                # An absent pin remains inert until S8 has classified authority.
                # No unresolved named input may pass the publication binding.
        return BrokerInput.from_body(secret, body, operation_digest=digest)

    async def _admit(
        self,
        secret: str,
        body: Mapping[str, Any],
        submission: MemberSubmission,
        view: RegistrationView | None,
    ) -> _PreparedUse | ToolReply:
        auth = submission.authorization
        pending = None
        async with self._db.transaction() as tx:
            scope = await self._fence.admit(tx, auth.grant)
            context = CommitmentContext(
                scope.app_id, scope.team_id, scope.installation_id, scope.generation, "request"
            )
            inputs = None
            commitments = self._committer.commit(context, submission.inbound, parameters=None)
            refused = None
            try:
                # Destination/input/backlog failures also roll back S8's claim
                # and charge. Their fixed refusal commits in the outer tx.
                async with tx.transaction() as attempt:
                    inputs = await self._inputs(attempt, scope, secret, body, auth.principal)
                    commitments = self._committer.commit(
                        context, submission.inbound, parameters=inputs.request.params
                    )
                    admission = await admit_use(
                        attempt,
                        fence=self._fence,
                        grant=auth.grant,
                        principal=auth.principal,
                        request=inputs.request,
                        attestation=auth.attestation,
                        now=self._clock(),
                        clock=self._clock,
                        derived_max_ttl_s=self._derived_max_ttl_s,
                    )
                    existing = await attempt.fetch_one(
                        "SELECT c.dispatch_id,d.state FROM {{tables.use_contexts}} c"
                        " JOIN {{tables.dispatches}} d USING(dispatch_id) WHERE c.intent_id=$1",
                        admission.intent_id,
                    )
                    if existing is not None:
                        dispatch_id = existing["dispatch_id"]
                        await inputs.check_binding(
                            attempt, admission=admission, dispatch_id=dispatch_id
                        )
                        if State(existing["state"]) in _TERMINAL | {State.DISPATCHING}:
                            reply = await self._receipt(attempt, admission, dispatch_id)
                            await self._fence.check(attempt, scope)
                            return reply
                        if State(existing["state"]) is State.AWAITING_APPROVAL:
                            reply = await self._receipt(attempt, admission, dispatch_id)
                            if reply.body["state"] == "awaiting_approval":
                                await self._fence.check(attempt, scope)
                                return reply
                            if reply.body.get("code") in {
                                "approval_denied",
                                "approval_expired",
                                "approval_revoked",
                            }:
                                reply = ToolReply(403, reply.body)
                                try:
                                    async with attempt.transaction() as narrowing:
                                        await self._close_waiting(
                                            narrowing, dispatch_id, reply.body["code"], view
                                        )
                                except InvalidTransition:
                                    reply = await self._receipt(attempt, admission, dispatch_id)
                                await self._fence.check(attempt, scope)
                                return reply
                    else:
                        dispatch_id = uuid4()
                    fence = self._fence_for(admission, inputs, dispatch_id, submission)
                    await fence.prepare(attempt)
                    if (
                        inputs.request.operation_id is not None and inputs.operation_digest is None
                    ) or (
                        None if fence.call.operation is None else fence.call.operation.digest
                    ) != inputs.operation_digest:
                        raise AdmissionRefused("operation_not_allowed")
                    if existing is None:
                        await self._producer(
                            installation_id=scope.installation_id, generation=scope.generation
                        ).require_admission(
                            attempt,
                            team_id=scope.team_id,
                            hook=_HOOK,
                            occurred_at=self._clock(),
                            view=view,
                            max_backlog_age=self._max_backlog_age,
                        )
                        await store_use_context(
                            attempt,
                            admission=admission,
                            dispatch_id=dispatch_id,
                            commitments=commitments,
                        )
                        await freeze_broker_audit(
                            attempt,
                            admission=admission,
                            principal=auth.principal,
                            dispatch_id=dispatch_id,
                            call=fence.call,
                            signed_trace_id=submission.signed_trace_id,
                        )
                        if admission.approval_required:
                            approvals, _ = self._approval_services()
                            action: BrokerOpen | BrokerOperation
                            opened = inputs.open_call
                            action = (
                                opened
                                if opened is not None
                                else BrokerOperation(
                                    inputs.request.operation_id or "",
                                    inputs.operation_digest or "",
                                    inputs.request.params or {},
                                )
                            )
                            if self._use_audit is None:
                                raise UseAuditUnavailable()
                            with self._use_audit.minting(dispatch_id):
                                pending = await request_use_approval(
                                    attempt,
                                    approvals,
                                    admission=admission,
                                    dispatch_id=dispatch_id,
                                    principal=auth.principal,
                                    action=action,
                                    reason=inputs.reason,
                                    max_ttl_s=self._derived_max_ttl_s,
                                )
                        # Deferred context FK permits B2 mint/audit before any
                        # S3 row lock. S3 always follows the complete B2 phase.
                        await self._machine(view).create(
                            attempt,
                            dispatch_id=dispatch_id,
                            subject=json.dumps(
                                [
                                    scope.installation_id,
                                    scope.team_id,
                                    principal_key(auth.principal).principal_did,
                                    fence.call.secret.secret_id,
                                ],
                                separators=(",", ":"),
                            ),
                            action=inputs.request.operation_id
                            or "open:"
                            + hashlib.sha256(
                                b"aweb.secrets.open-pair/1\n"
                                + json.dumps(
                                    [fence.call.rendered.method, fence.call.rendered.url],
                                    separators=(",", ":"),
                                ).encode("utf-8")
                            ).hexdigest(),
                            retry_exempt=fence.call.operation is not None
                            and fence.call.operation.after["side_effect"] == "none",
                        )
                        if pending is not None:
                            await self._machine(view).await_approval(attempt, dispatch_id)
                    prepared = _PreparedUse(admission, inputs, dispatch_id, fence.call)
                    # Initial preparation records no 1Password observation;
                    # release performs that outside all authority locks.
                    await fence.check_authority(
                        attempt, await self._machine(view).get(attempt, dispatch_id)
                    )
            except (AdmissionRefused, UseApprovalRefused, HookRefused, UseAuditUnavailable) as exc:
                refused = (
                    exc
                    if isinstance(exc, AdmissionRefused)
                    else AdmissionRefused(
                        "release_context_unavailable"
                        if isinstance(exc, UseAuditUnavailable)
                        else exc.code,
                        503 if isinstance(exc, (UseAuditUnavailable, HookRefused)) else 403,
                    )
                )
            if refused is not None:
                # Configuration/context failures have no catalog refusal code.
                if refused.code != "release_context_unavailable":
                    await record_broker_refusal(
                        tx,
                        producer=self._producer(
                            installation_id=scope.installation_id, generation=scope.generation
                        ),
                        principal=auth.principal,
                        commitments=commitments,
                        code=refused.code,
                        occurred_at=self._clock(),
                        signed_trace_id=submission.signed_trace_id,
                        request_id=None if inputs is None else inputs.request.request_id,
                        secret_ref=secret,
                    )
                await self._fence.check(tx, scope)
        if refused is not None:
            raise refused
        if pending is not None:
            approvals, _ = self._approval_services()
            await approvals.deliver(pending.pending)
            return ToolReply(
                202,
                tool_results.awaiting_approval(
                    request_id=prepared.inputs.request.request_id,
                    request_ref=prepared.admission.intent_id,
                    approval_ref=pending.approval_ref,
                ),
            )
        return prepared

    async def _receipt(
        self, tx: TransactionManager, admission: Admission, dispatch_id: UUID
    ) -> ToolReply:
        row = await tx.fetch_one(
            "SELECT i.*,c.dispatch_id,d.state,d.result FROM {{tables.intents}} i"
            " JOIN {{tables.use_contexts}} c USING(intent_id,installation_id,team_id,install_generation)"
            " JOIN {{tables.dispatches}} d USING(dispatch_id) WHERE i.intent_id=$1 AND c.dispatch_id=$2",
            admission.intent_id,
            dispatch_id,
        )
        if row is None:
            raise AdmissionRefused("release_context_unavailable", 503)
        reply = await self._status._reply(tx, row, admission.intent_id, own=True)
        state = reply.body["state"]
        status = (
            202 if state in {"received", "admitted", "dispatching", "awaiting_approval"} else 200
        )
        if state == "not_sent":
            status = 503
        return ToolReply(status if reply.status == 200 else reply.status, reply.body)

    async def _publication_receipt(self, tx: TransactionManager, use: _PreparedUse) -> ToolReply:
        reply = await self._receipt(tx, use.admission, use.dispatch_id)
        await self._fence.check(tx, use.admission.installation)
        return reply

    async def _dispatch(
        self,
        use: _PreparedUse,
        submission: MemberSubmission,
        view: RegistrationView | None,
    ) -> ToolReply:
        try:
            observation = await self._opener.observe(_context(use.call))
            if (
                observation is not None
                and observation.item_version != observation.binding.item_version
            ):
                if self._reconciler is None:
                    raise CustodyUnavailable("backend reconciliation unavailable")
                changed = await self._reconciler.reconcile(
                    observation, admitted=use.admission.installation
                )
                for secret_id in changed.affected_secret_ids:
                    await self._tokens.evict_secret(
                        installation_id=use.admission.installation.installation_id,
                        team_id=use.admission.installation.team_id,
                        secret_id=secret_id,
                    )
                raise AdmissionRefused("secret_version_changed")
            final = _PublicationFence(self, use, submission, observation, view)
            async with self._db.transaction() as tx:
                await final.prepare(tx)
                current = await self._machine(view).get(tx, use.dispatch_id)
                if current.state not in {
                    State.RECEIVED,
                    State.AWAITING_APPROVAL,
                    State.ADMITTED,
                    State.NOT_SENT,
                }:
                    return await self._publication_receipt(tx, use)
                if not final.may_send:
                    if final.refusal is not None:
                        reply = await self._close_refusal(tx, use, current, final.refusal, view)
                        await self._fence.check(tx, use.admission.installation)
                        return reply
                    return await self._publication_receipt(tx, use)
                if current.state in {State.RECEIVED, State.AWAITING_APPROVAL}:
                    current = await self._machine(view).admit(tx, use.dispatch_id, fence=final)
                send_until = asyncio.get_running_loop().time() + final.send_budget()
                current = await self._machine(view).begin_dispatch(tx, use.dispatch_id, fence=final)
                await final.check(tx, current)
            # The only opening/cache/egress path follows the committed winner.
            call = final.broker.call
        except (
            AdmissionRefused,
            CustodyUnavailable,
            ApprovalRefused,
            HookRefused,
            DispatchInFlight,
            ReconciliationPending,
            InvalidTransition,
            UseAuditUnavailable,
        ) as exc:
            if isinstance(exc, (InvalidTransition,)):
                async with self._db.transaction() as tx:
                    scope = await self._fence.admit(tx, submission.authorization.grant)
                    if scope != use.admission.installation:
                        raise AdmissionRefused("generation_superseded", 409) from None
                    return await self._publication_receipt(tx, use)
            if isinstance(exc, UseAuditUnavailable):
                raise AdmissionRefused(exc.code, exc.status) from None
            if isinstance(exc, CustodyUnavailable):
                refused = AdmissionRefused("custody_unavailable", 503)
            elif isinstance(exc, ApprovalRefused):
                code = {
                    Refusal.EXPIRED: "approval_expired",
                    Refusal.REVOKED: "approval_revoked",
                    Refusal.POLICY_UNKNOWN: "grant_revoked",
                    Refusal.POLICY_CHANGED: "grant_revoked",
                    Refusal.APPROVER_RETIRED: "approval_revoked",
                    Refusal.ASSURANCE_INSUFFICIENT: "approval_revoked",
                }.get(exc.reason, "release_context_unavailable")
                refused = AdmissionRefused(
                    code, 503 if code == "release_context_unavailable" else 403
                )
            elif isinstance(exc, AdmissionRefused):
                refused = exc
            else:
                refused = AdmissionRefused(
                    exc.code,
                    409 if isinstance(exc, (DispatchInFlight, ReconciliationPending)) else 503,
                )
            if refused.code == "release_context_unavailable":
                raise refused from None
            async with self._db.transaction() as tx:
                scope = await self._fence.admit(tx, submission.authorization.grant)
                if scope != use.admission.installation:
                    raise AdmissionRefused("generation_superseded", 409) from None
                current = await self._machine(view).get(tx, use.dispatch_id)
                reply = await self._close_refusal(
                    tx, use, current, refused.code, view, status=refused.status
                )
                await self._fence.check(tx, scope)
                return reply
        request_id, request_ref = use.inputs.request.request_id, use.admission.intent_id
        audit = None
        sending = False
        try:
            async with asyncio.timeout_at(send_until):
                plaintext = await self._opener.open(_context(call))
                value = decode_value(call.stored.record.kind, plaintext.reveal())
                sending = True
                outcome = await broker_operation(
                    self._egress,
                    call.rendered,
                    kind=call.stored.record.kind,
                    value=value,
                    kind_params=call.stored.record.kind_params,
                    secret_ref=call.stored.record.ref,
                    response_key=self._response_key,
                    token_destination=call.token_destination,
                    tokens=self._tokens,
                    secret=call.secret,
                )
            reply = broker_result_reply(
                outcome.result, request_id=request_id, request_ref=request_ref
            )
            state, audit = State.COMPLETED, outcome.audit.fields()
        except EgressOutcomeUnknown:
            state = State.OUTCOME_UNKNOWN
        except TimeoutError:
            state = State.OUTCOME_UNKNOWN if sending else State.NOT_SENT
        except (CustodyUnavailable, ValueInvalid, EgressRefused, EgressNotSent):
            state = State.NOT_SENT
        if state is State.OUTCOME_UNKNOWN:
            reply = ToolReply(
                200, tool_results.outcome_unknown(request_id=request_id, request_ref=request_ref)
            )
        elif state is State.NOT_SENT:
            reply = ToolReply(
                503,
                {
                    "state": "not_sent",
                    "request_id": request_id,
                    "request_ref": request_ref,
                    "next": "resubmit",
                },
            )
        async with self._db.transaction() as tx:
            approval = await self._lock_outcome(tx, use.dispatch_id)
            committed = await self._settle_locked(
                tx, use.dispatch_id, state, reply, audit, approval
            )
            if not committed:
                return await self._receipt(tx, use.admission, use.dispatch_id)
        return reply

    async def _lock_outcome(self, tx: TransactionManager, dispatch_id: UUID) -> Approval | None:
        row = await tx.fetch_one(
            "SELECT i.approval_required FROM {{tables.use_contexts}} c"
            " JOIN {{tables.intents}} i USING(intent_id,installation_id,team_id,install_generation)"
            " WHERE c.dispatch_id=$1 AND c.tool='request'",
            dispatch_id,
        )
        if row is None:
            raise UseAuditUnavailable()
        if not row["approval_required"]:
            return None
        approvals, _ = self._approval_services()
        if self._use_audit is None:
            raise UseAuditUnavailable()
        original = await self._use_audit.dispatch_approvals(tx, dispatch_id)
        if len(original) != 1:
            raise UseAuditUnavailable()
        approval = original[0]
        # Consequences retain original scope after containment. B2 precedes
        # S3; neither recovery nor recording grants fresh send authority.
        await approvals.lock_many(tx, [approval.approval_id])
        return approval

    async def _settle_locked(
        self,
        tx: TransactionManager,
        dispatch_id: UUID,
        state: State,
        reply: ToolReply,
        audit: Mapping[str, Any] | None,
        approval: Approval | None,
    ) -> bool:
        machine = self._machine(None, completed=audit)
        record = {
            State.COMPLETED: machine.complete,
            State.NOT_SENT: machine.not_sent,
            State.OUTCOME_UNKNOWN: machine.outcome_unknown,
        }[state]
        current = await machine.get(tx, dispatch_id)
        if approval is not None and current.state is State.DISPATCHING:
            approvals, _ = self._approval_services()
            try:
                async with tx.transaction() as attempt:
                    await approvals.record_outcome(
                        approval.approval_id,
                        str(dispatch_id),
                        DispatchOutcome(state.value),
                        response_status=None
                        if audit is None
                        else str(audit["upstream_status_code"]),
                        tx=attempt,
                    )
                    committed = await record(attempt, dispatch_id, dict(reply.body))
                    if not committed:
                        raise _OutcomeMoved()
                    return True
            except _OutcomeMoved:
                # Roll back tentative B2 state and late evidence; retain the
                # original S3 winner and record this evidence exactly once.
                return await record(tx, dispatch_id, dict(reply.body))
        return await record(tx, dispatch_id, dict(reply.body))

    async def reconcile(
        self,
        tx: TransactionManager,
        *,
        original: ReconciliationOriginal,
        state: State,
        result: Mapping[str, Any],
    ) -> None:
        """Record a caller-authorized consequence through this service's S3 sink.

        The caller prepares owner authority and the complete B2 union first.
        This opens/sends nothing and applies no publication availability gate.
        S3 locks the original and permits only its first UNKNOWN settlement.
        """
        from aweb_secrets.reconciliation_reads import ReconciliationReads

        view = await ReconciliationReads().get(
            tx, scope=original.installation, reconcile_ref=original.reconcile_ref
        )
        if original.op_kind != "broker" or view is None or view.original != original:
            raise UseAuditUnavailable()
        await self._machine(None).reconcile(tx, original.dispatch_id, state, dict(result))

    async def sweep(self, *, limit: int = 50) -> int:
        """Recover bounded stale broker publications through the sole S3.

        Root schedules this method, rather than S3's unscoped sweeper: the
        original broker association selects B2 locks before the S3 row. No
        current authority, opener, token lookup, registration lookup or egress
        is invoked by this post-dispatch recording path.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("broker recovery limit must be between 1 and 100")
        candidates = await self._db.fetch_all(
            "SELECT d.dispatch_id,i.request_id,i.intent_id FROM {{tables.dispatches}} d"
            " JOIN {{tables.use_contexts}} c USING(dispatch_id)"
            " JOIN {{tables.intents}} i USING(intent_id,installation_id,team_id,install_generation)"
            " WHERE c.tool='request' AND d.state='dispatching'"
            " AND d.sweep_after<=clock_timestamp() ORDER BY d.sweep_after,d.dispatch_id LIMIT $1",
            limit,
        )
        swept = 0
        for candidate in candidates:
            dispatch_id = candidate["dispatch_id"]
            try:
                async with self._db.transaction() as tx:
                    approval = await self._lock_outcome(tx, dispatch_id)
                    current = await tx.fetch_one(
                        "SELECT state,sweep_after FROM {{tables.dispatches}}"
                        " WHERE dispatch_id=$1 FOR UPDATE",
                        dispatch_id,
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
                            request_id=candidate["request_id"], request_ref=candidate["intent_id"]
                        ),
                    )
                    committed = await self._settle_locked(
                        tx, dispatch_id, State.OUTCOME_UNKNOWN, reply, None, approval
                    )
                swept += int(committed)
            except (UseAuditUnavailable, ApprovalRefused, AdmissionRefused):
                # Do not expose proof/contact or exception details. A broken
                # original association remains pending for operator repair.
                _LOG.error(
                    "broker recovery context unavailable", extra={"dispatch_id": str(dispatch_id)}
                )
        return swept

    async def _close_refusal(
        self,
        tx: TransactionManager,
        use: _PreparedUse,
        current: Dispatch,
        code: str,
        view: RegistrationView | None,
        *,
        status: int = 403,
    ) -> ToolReply:
        try:
            async with tx.transaction() as attempt:
                return await self._close_refusal_once(
                    attempt, use, current, code, view, status=status
                )
        except InvalidTransition:
            # A concurrent publication/settlement won. Roll back any tentative
            # B2 narrowing and return its receipt; never reopen or dispatch.
            return await self._receipt(tx, use.admission, use.dispatch_id)

    async def _close_refusal_once(
        self,
        tx: TransactionManager,
        use: _PreparedUse,
        current: Dispatch,
        code: str,
        view: RegistrationView | None,
        *,
        status: int,
    ) -> ToolReply:
        if code == "approval_pending":
            return await self._receipt(tx, use.admission, use.dispatch_id)
        if current.state is State.AWAITING_APPROVAL:
            await self._close_waiting(tx, use.dispatch_id, code, view)
        elif current.state in {State.RECEIVED, State.ADMITTED, State.NOT_SENT}:
            await self._machine(view, refusal_code=code).refuse(tx, use.dispatch_id)
        else:
            return await self._receipt(tx, use.admission, use.dispatch_id)
        return ToolReply(
            status,
            {
                **tool_results.refused(code, request_id=use.inputs.request.request_id),
                "request_ref": use.admission.intent_id,
            },
        )

    async def _close_waiting(
        self, tx: TransactionManager, dispatch_id: UUID, code: str, view: RegistrationView | None
    ) -> None:
        approvals, _ = self._approval_services()
        if self._use_audit is None:
            raise UseAuditUnavailable()
        original = await self._use_audit.dispatch_approvals(tx, dispatch_id)
        if len(original) != 1:
            raise UseAuditUnavailable()
        approval = original[0]
        # B2 locks precede the S3 closure; S12 may already hold them.
        await approvals.lock_many(tx, [approval.approval_id])
        if code == "approval_expired":
            await self._use_audit.expired(tx, approval.approval_id)
            state = State.APPROVAL_EXPIRED
        elif code == "approval_denied":
            state = State.APPROVAL_DENIED
        else:
            await approvals.revoke_many(
                [approval.approval_id], revoked_by="secrets", reason=code, tx=tx
            )
            state = State.CANCELLED
        await self._machine(view).close(tx, dispatch_id, state)
