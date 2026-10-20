"""The approval primitive: mint, present, decide, admit one dispatch, reconcile.

The requester proposes and can read only its `RequesterView`. The approver is
the one the owner designated for the policy, the link goes only to that
approver's registered contact, and the decision needs an authenticator's
verified evidence at the policy's minimum assurance. A trusted dispatcher then
admits exactly one dispatch of the exact approved request.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals.model import (
    DISPATCHER_OUTCOMES,
    RECONCILED_OUTCOMES,
    UNRECONCILED_OUTCOMES,
    ActionPolicy,
    Admission,
    Approval,
    ApprovalDelivery,
    ApprovalRefused,
    ApprovalState,
    Approver,
    ApproverDirectory,
    Assurance,
    AuthenticationFailed,
    Authenticator,
    Decision,
    DeliveryStatus,
    DispatchOutcome,
    LinkedApproval,
    PolicySource,
    PresentationKind,
    Refusal,
    RequesterView,
)
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, canonical_request
from aweb_naapp.runtime.approvals.store import ApprovalLink, ApprovalStore, StoredRequest
from aweb_naapp.runtime.audit import AuditEvent, AuditKind, AuditSink
from aweb_naapp.runtime.links import LinkLifetime, link_verifier, new_link_token

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _covered(request: Mapping[str, Any], policy_ref: str, policy_version: int) -> bytes:
    return canonical_request(
        {"policy": {"ref": policy_ref, "version": policy_version}, "request": request}
    )


def _sha256(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


class Approvals:
    def __init__(
        self,
        *,
        store: ApprovalStore,
        policies: PolicySource,
        approvers: ApproverDirectory,
        delivery: ApprovalDelivery,
        authenticators: Sequence[Authenticator],
        audit: AuditSink,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._policies = policies
        self._approvers = approvers
        self._delivery = delivery
        self._authenticators = {a.assurance: a for a in authenticators}
        self._audit = audit
        self._clock = clock

    # Requesting

    async def mint(
        self,
        *,
        request: Mapping[str, Any],
        policy_ref: str,
        requested_by: str,
        presentation: PresentationKind = PresentationKind.LINK,
        presentation_ref: str | None = None,
    ) -> RequesterView:
        """Freeze the request, record a pending approval for the designated
        approver, and deliver its link when presented as a link."""
        policy = await self._policies.current(policy_ref)
        if policy is None:
            raise ApprovalRefused(Refusal.POLICY_UNKNOWN)
        if (presentation is PresentationKind.TASK) != (presentation_ref is not None):
            raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
        approver = await self._approvers.designated_approver(policy)
        if approver is None:
            raise ApprovalRefused(Refusal.NO_APPROVER)

        now = self._clock()
        canonical = _covered(request, policy.policy_ref, policy.version)
        digest = _sha256(canonical)
        approval_id = str(uuid.uuid4())
        expires_at = now + policy.ttl
        token = link = None
        if presentation is PresentationKind.LINK:
            token, verifier = new_link_token()
            link = ApprovalLink(
                link_id=str(uuid.uuid4()),
                approval_id=approval_id,
                request_sha256=digest,
                verifier_sha256=verifier,
                created_at=now,
                lifetime=LinkLifetime(expires_at=expires_at, revoked_at=None, used_at=None),
            )
            presentation_ref = link.link_id
        approval = Approval(
            approval_id=approval_id,
            request_sha256=digest,
            request_ref=str(uuid.uuid4()),
            policy_ref=policy.policy_ref,
            policy_version=policy.version,
            requested_by=requested_by,
            approver_subject=approver.subject,
            approver_subject_type=approver.subject_type,
            authenticator=None,
            auth_evidence_ref=None,
            presentation_kind=presentation,
            presentation_ref=presentation_ref,
            task_answer_ref=None,
            state=ApprovalState.PENDING,
            delivery_status=DeliveryStatus.PENDING if link else DeliveryStatus.NOT_REQUIRED,
            created_at=now,
            expires_at=expires_at,
            decided_at=None,
            revoked_at=None,
            consumed_operation_id=None,
            dispatch_outcome=None,
            response_status=None,
        )
        stored = StoredRequest(approval.request_ref, digest, canonical, now)
        async with self._store.transaction(None) as tx:
            await self._store.create(stored, approval, link, tx)
            await self._emit(AuditKind.APPROVAL_REQUESTED, requested_by, approval, now, tx)

        if token is not None:
            status = await self._deliver(approver, token, approval)
            await self._store.set_delivery_status(approval_id, status)
            approval = replace(approval, delivery_status=status)
        return self._view(approval, now)

    async def _deliver(self, approver: Approver, token: str, approval: Approval) -> DeliveryStatus:
        try:
            return await self._delivery.deliver_approval_link(approver, token, approval)
        except Exception:
            logger.exception("approval link delivery failed for approval %s", approval.approval_id)
            return DeliveryStatus.FAILED

    async def requester_view(self, request_id: str) -> RequesterView:
        approval = await self._store.get_by_request(request_id)
        if approval is None:
            raise ApprovalRefused(Refusal.NOT_FOUND)
        return self._view(approval, self._clock())

    def _view(self, approval: Approval, now: datetime) -> RequesterView:
        return RequesterView(
            request_id=approval.request_ref,
            approval_state=approval.state_at(now),
            delivery_status=approval.delivery_status,
            dispatch_outcome=approval.dispatch_outcome,
        )

    # Trusted reads by the app

    async def get(self, approval_id: str) -> Approval | None:
        return await self._store.get(approval_id)

    async def for_request(self, request_id: str) -> Approval | None:
        return await self._store.get_by_request(request_id)

    # The approver

    async def open_link(self, link_token: str) -> LinkedApproval:
        """What the approver sees behind the link. Reading consumes nothing."""
        link = await self._usable_link(link_token)
        approval = await self._store.get(link.approval_id)
        if approval is None or approval.state_at(self._clock()) is not ApprovalState.PENDING:
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        canonical = await self._store.request_canonical(approval.request_ref)
        covered = json.loads(canonical[len(DOMAIN_PREFIX) :])
        return LinkedApproval(approval=approval, request=covered["request"])

    async def _usable_link(self, link_token: str) -> ApprovalLink:
        link = await self._store.find_link(link_verifier(link_token))
        if link is None or not link.lifetime.usable_at(self._clock()):
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        return link

    async def _presented(
        self, approval: Approval, link_token: str | None, task_answer_ref: str | None
    ) -> str | None:
        """Check the decision arrives through the approval's own presentation;
        return the link it uses, if any."""
        if approval.presentation_kind is PresentationKind.TASK:
            if link_token is not None:
                raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
            return None
        if task_answer_ref is not None or link_token is None:
            raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
        link = await self._usable_link(link_token)
        if (
            link.approval_id != approval.approval_id
            or link.request_sha256 != approval.request_sha256
        ):
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        return link.link_id

    def _check_pending(self, approval: Approval | None) -> Approval:
        if approval is None:
            raise ApprovalRefused(Refusal.NOT_FOUND)
        state = approval.state_at(self._clock())
        if state is ApprovalState.EXPIRED:
            raise ApprovalRefused(Refusal.EXPIRED)
        if state is ApprovalState.REVOKED:
            raise ApprovalRefused(Refusal.REVOKED)
        if state is not ApprovalState.PENDING:
            raise ApprovalRefused(Refusal.NOT_PENDING)
        return approval

    async def _current_policy(self, approval: Approval) -> ActionPolicy:
        policy = await self._policies.current(approval.policy_ref)
        if policy is None:
            raise ApprovalRefused(Refusal.POLICY_UNKNOWN)
        if policy.version != approval.policy_version:
            raise ApprovalRefused(Refusal.POLICY_CHANGED)
        return policy

    async def _authenticator(self, approval: Approval, assurance: Assurance) -> Authenticator:
        policy = await self._current_policy(approval)
        if not assurance.satisfies(policy.min_assurance):
            raise ApprovalRefused(Refusal.ASSURANCE_INSUFFICIENT)
        authenticator = self._authenticators.get(assurance)
        if authenticator is None:
            raise ApprovalRefused(Refusal.AUTHENTICATOR_UNAVAILABLE)
        return authenticator

    async def challenge(
        self,
        approval_id: str,
        decision: Decision,
        assurance: Assurance,
        *,
        link_token: str | None = None,
    ) -> Mapping[str, Any]:
        """Start the authenticator ceremony for one decision. Consumes nothing."""
        approval = self._check_pending(await self._store.get(approval_id))
        await self._presented(approval, link_token, None)
        authenticator = await self._authenticator(approval, assurance)
        try:
            return await authenticator.challenge(approval, decision)
        except AuthenticationFailed as exc:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED) from exc

    async def decide(
        self,
        approval_id: str,
        decision: Decision,
        assurance: Assurance,
        proof: Mapping[str, Any],
        *,
        link_token: str | None = None,
        task_answer_ref: str | None = None,
        tx: TransactionManager | None = None,
    ) -> Approval:
        """Record the designated approver's verified decision, once. A link
        presentation uses its link for this; a task presentation records the
        task answer it came with."""
        approval = self._check_pending(await self._store.get(approval_id))
        link_id = await self._presented(approval, link_token, task_answer_ref)
        if approval.presentation_kind is PresentationKind.TASK and task_answer_ref is None:
            raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
        authenticator = await self._authenticator(approval, assurance)
        try:
            evidence = await authenticator.verify(approval, decision, proof)
        except AuthenticationFailed as exc:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED) from exc
        if evidence.assurance is not authenticator.assurance:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED)
        if (evidence.subject, evidence.subject_type) != (
            approval.approver_subject,
            approval.approver_subject_type,
        ):
            raise ApprovalRefused(Refusal.APPROVER_MISMATCH)

        async with self._store.locked(approval_id, tx) as locked:
            self._check_pending(locked.approval)
            now = self._clock()
            state = (
                ApprovalState.APPROVED if decision is Decision.APPROVE else ApprovalState.REJECTED
            )
            decided = await locked.set_decision(state, evidence, task_answer_ref, link_id, now)
            await self._emit(
                AuditKind.APPROVAL_DECIDED,
                evidence.subject,
                decided,
                now,
                locked.transaction,
                decision=decision.value,
                authenticator=evidence.assurance.value,
                evidence_ref=evidence.evidence_ref,
            )
        return decided

    # The owner

    async def revoke(
        self,
        approval_id: str,
        *,
        revoked_by: str,
        reason: str = "",
        tx: TransactionManager | None = None,
    ) -> Approval:
        """Revoke one pending or approved approval. Revocation before dispatch wins."""
        async with self._store.locked(approval_id, tx) as locked:
            approval = locked.approval
            if approval is None:
                raise ApprovalRefused(Refusal.NOT_FOUND)
            if approval.state is ApprovalState.CONSUMED:
                raise ApprovalRefused(Refusal.CONSUMED)
            if approval.state is ApprovalState.REVOKED:
                raise ApprovalRefused(Refusal.REVOKED)
            if approval.state is ApprovalState.REJECTED:
                raise ApprovalRefused(Refusal.NOT_PENDING)
            now = self._clock()
            revoked = await locked.revoke(now)
            await self._emit(
                AuditKind.APPROVAL_REVOKED,
                revoked_by,
                revoked,
                now,
                locked.transaction,
                reason=reason,
            )
        return revoked

    async def revoke_many(
        self,
        approval_ids: Sequence[str],
        *,
        revoked_by: str,
        reason: str = "",
        tx: TransactionManager | None = None,
    ) -> list[Approval]:
        """Containment: revoke whichever of these approvals, chosen by the app's
        own predicate, are still pending or approved. Consumed ones stay
        consumed. Returns the approvals revoked."""
        async with self._store.transaction(tx) as t:
            now = self._clock()
            revoked = await self._store.revoke_many(approval_ids, now, t)
            for approval in revoked:
                await self._emit(
                    AuditKind.APPROVAL_REVOKED, revoked_by, approval, now, t, reason=reason
                )
        return revoked

    # The trusted dispatcher

    async def admit(
        self,
        approval_id: str,
        request: Mapping[str, Any],
        operation_id: str,
        *,
        tx: TransactionManager | None = None,
    ) -> Admission:
        """Admit exactly one dispatch of the exact approved request.

        Asking again with the same operation ID retrieves that admission and is
        not a new dispatch; after `not_sent` it allows a transport retry. Any
        other operation ID is refused for good: a new business attempt needs a
        new approval.
        """
        async with self._store.locked(approval_id, tx) as locked:
            approval = locked.approval
            if approval is None:
                raise ApprovalRefused(Refusal.NOT_FOUND)
            covered = _covered(request, approval.policy_ref, approval.policy_version)
            if _sha256(covered) != approval.request_sha256:
                raise ApprovalRefused(Refusal.REQUEST_MISMATCH)
            if approval.state is ApprovalState.CONSUMED:
                if approval.consumed_operation_id != operation_id:
                    raise ApprovalRefused(Refusal.CONSUMED)
                if approval.dispatch_outcome is not DispatchOutcome.NOT_SENT:
                    return self._admission(approval, first=False, may_send=False)
                if await locked.unreconciled_dispatch_exists():
                    raise ApprovalRefused(Refusal.UNRECONCILED_DISPATCH)
                now = self._clock()
                retried = await locked.set_outcome(DispatchOutcome.DISPATCHING, None, now)
                await self._emit(
                    AuditKind.DISPATCH_ADMITTED,
                    approval.requested_by,
                    retried,
                    now,
                    locked.transaction,
                    operation_id=operation_id,
                    attempt="transport_retry",
                )
                return self._admission(retried, first=False, may_send=True)
            if approval.state is ApprovalState.REVOKED:
                raise ApprovalRefused(Refusal.REVOKED)
            if approval.state is not ApprovalState.APPROVED:
                raise ApprovalRefused(Refusal.NOT_APPROVED)
            now = self._clock()
            if approval.state_at(now) is ApprovalState.EXPIRED:
                raise ApprovalRefused(Refusal.EXPIRED)
            policy = await self._current_policy(approval)
            if approval.authenticator is None or not approval.authenticator.satisfies(
                policy.min_assurance
            ):
                raise ApprovalRefused(Refusal.ASSURANCE_INSUFFICIENT)
            if await locked.unreconciled_dispatch_exists():
                raise ApprovalRefused(Refusal.UNRECONCILED_DISPATCH)
            consumed = await locked.consume(operation_id, now)
            await self._emit(
                AuditKind.DISPATCH_ADMITTED,
                approval.requested_by,
                consumed,
                now,
                locked.transaction,
                operation_id=operation_id,
                attempt="first",
            )
        return self._admission(consumed, first=True, may_send=True)

    @staticmethod
    def _admission(approval: Approval, *, first: bool, may_send: bool) -> Admission:
        assert approval.consumed_operation_id is not None
        assert approval.dispatch_outcome is not None
        return Admission(
            approval_id=approval.approval_id,
            operation_id=approval.consumed_operation_id,
            first=first,
            may_send=may_send,
            dispatch_outcome=approval.dispatch_outcome,
            response_status=approval.response_status,
        )

    async def record_outcome(
        self,
        approval_id: str,
        operation_id: str,
        outcome: DispatchOutcome,
        *,
        response_status: str | None = None,
        tx: TransactionManager | None = None,
    ) -> Approval:
        """The dispatcher records how its admitted dispatch ended: `completed`
        with the upstream response status, `not_sent`, or `outcome_unknown`."""
        if outcome not in DISPATCHER_OUTCOMES:
            raise ApprovalRefused(Refusal.OUTCOME_INVALID)
        if (outcome is DispatchOutcome.COMPLETED) != (response_status is not None):
            raise ApprovalRefused(Refusal.OUTCOME_INVALID)
        return await self._set_outcome(
            approval_id,
            operation_id,
            outcome,
            response_status,
            from_outcomes=(DispatchOutcome.DISPATCHING,),
            actor=None,
            tx=tx,
        )

    async def reconcile(
        self,
        approval_id: str,
        operation_id: str,
        outcome: DispatchOutcome,
        *,
        reconciled_by: str,
        response_status: str | None = None,
        tx: TransactionManager | None = None,
    ) -> Approval:
        """The owner closes a dispatch whose outcome the dispatcher could not
        establish. It never rearms the approval."""
        if outcome not in RECONCILED_OUTCOMES:
            raise ApprovalRefused(Refusal.OUTCOME_INVALID)
        return await self._set_outcome(
            approval_id,
            operation_id,
            outcome,
            response_status,
            from_outcomes=UNRECONCILED_OUTCOMES,
            actor=reconciled_by,
            tx=tx,
        )

    async def _set_outcome(
        self,
        approval_id: str,
        operation_id: str,
        outcome: DispatchOutcome,
        response_status: str | None,
        *,
        from_outcomes: Sequence[DispatchOutcome],
        actor: str | None,
        tx: TransactionManager | None,
    ) -> Approval:
        async with self._store.locked(approval_id, tx) as locked:
            approval = locked.approval
            if approval is None:
                raise ApprovalRefused(Refusal.NOT_FOUND)
            if (
                approval.state is not ApprovalState.CONSUMED
                or approval.consumed_operation_id != operation_id
            ):
                raise ApprovalRefused(Refusal.OPERATION_MISMATCH)
            if (approval.dispatch_outcome, approval.response_status) == (outcome, response_status):
                return approval
            if approval.dispatch_outcome not in from_outcomes:
                raise ApprovalRefused(Refusal.OUTCOME_FINAL)
            now = self._clock()
            updated = await locked.set_outcome(outcome, response_status, now)
            details = {"operation_id": operation_id, "outcome": outcome.value}
            if response_status is not None:
                details["response_status"] = response_status
            await self._emit(
                AuditKind.DISPATCH_OUTCOME,
                actor or approval.requested_by,
                updated,
                now,
                locked.transaction,
                **details,
            )
        return updated

    async def _emit(
        self,
        kind: AuditKind,
        actor: str,
        approval: Approval,
        at: datetime,
        tx: TransactionManager,
        **details: str,
    ) -> None:
        await self._audit.emit(
            AuditEvent(
                kind=kind,
                actor=actor,
                subject=approval.approver_subject,
                occurred_at=at,
                approval_id=approval.approval_id,
                details={
                    "policy_ref": approval.policy_ref,
                    "policy_version": str(approval.policy_version),
                    "request_sha256": approval.request_sha256,
                    **details,
                },
            ),
            tx,
        )
