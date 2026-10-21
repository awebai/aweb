"""The approval primitive: mint, present, decide, admit one dispatch, reconcile.

The requester proposes and can read only its `RequesterView`. The app's
directory names the eligible approvers, each one designated person; their set
is frozen at mint, without the requester unless the policy allows it. Each
candidate's own link goes only to their registered contact. Any one candidate
decides, with an authenticator's verified evidence at the policy's minimum
assurance, and that first decision, approve or reject, is the only one. A
trusted dispatcher then admits exactly one dispatch of the exact approved
request.

A decision is only as good as its approver's current designation: challenge,
decide and admit refuse with `approver_retired` once the directory no longer
names the candidate, and with `no_eligible_approver` once no candidate is left.
The check reads the directory, so an admission that commits just before a
re-designation still dispatches; that is an ordering, not a gap.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, overload

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
    Candidate,
    DecidedBy,
    Decision,
    DeliveryStatus,
    DispatchOutcome,
    LinkedApproval,
    PendingApproval,
    PendingDelivery,
    PolicySource,
    PresentationKind,
    Purpose,
    Refusal,
    RequesterView,
    TaskAnswerRejected,
    TaskAnswerVerifier,
)
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, canonical_request
from aweb_naapp.runtime.approvals.store import (
    ApprovalLink,
    ApprovalStore,
    LinkAlreadyUsed,
    LockedApproval,
    StoredRequest,
)
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


def _locked_request(locked: LockedApproval, request: Mapping[str, Any]) -> Approval:
    """The locked approval, provided it exists and covers exactly `request`."""
    approval = locked.approval
    if approval is None:
        raise ApprovalRefused(Refusal.NOT_FOUND)
    covered = _covered(request, approval.policy_ref, approval.policy_version)
    if _sha256(covered) != approval.request_sha256:
        raise ApprovalRefused(Refusal.REQUEST_MISMATCH)
    return approval


def _is_requester(approver: Approver | Candidate, requested_by: str) -> bool:
    """Whether this approver is the requester: by subject, or by the principal
    the approver stands for, when one is known."""
    return requested_by in (approver.subject, approver.principal_did)


def _seen_by(approval: Approval, candidate: Candidate) -> Approval:
    """The approval as one candidate sees it: not who else may approve."""
    return replace(approval, candidates=(candidate,))


async def _emit(
    audit: AuditSink,
    kind: AuditKind,
    actor: str,
    approval: Approval,
    at: datetime,
    tx: TransactionManager,
    **details: str,
) -> None:
    await audit.emit(
        AuditEvent(
            kind=kind,
            actor=actor,
            subject=approval.decided_by.subject if approval.decided_by else approval.approval_id,
            occurred_at=at,
            approval_id=approval.approval_id,
            details={
                "policy_ref": approval.policy_ref,
                "policy_version": str(approval.policy_version),
                "request_sha256": approval.request_sha256,
                "candidates": " ".join(c.subject for c in approval.candidates),
                **details,
            },
        ),
        tx,
    )


class ApprovalRevocation:
    """Revokes live approvals, auditing each. `Approvals` uses it for
    `revoke_many`; an approver directory uses it as its `ApproverRetirement`,
    so a retired approver's approvals are revoked as it is retired."""

    def __init__(
        self,
        store: ApprovalStore,
        audit: AuditSink,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._audit = audit
        self._clock = clock

    async def revoke_many(
        self,
        approval_ids: Sequence[str],
        *,
        revoked_by: str,
        reason: str = "",
        tx: TransactionManager | None = None,
    ) -> list[Approval]:
        async with self._store.transaction(tx) as t:
            now = self._clock()
            revoked = await self._store.revoke_many(approval_ids, now, t)
            await self._audit_all(revoked, revoked_by, reason, now, t)
        return revoked

    async def approver_retired(
        self, approver_subject: str, *, retired_by: str, tx: TransactionManager
    ) -> None:
        """The retired approver stops being a candidate of pending approvals and
        loses their links; approvals they decided and that are not yet
        dispatched are revoked.

        It locks those approvals in `tx`. Call it after removing the authority
        it follows from (the role or membership delete), never before: paths
        that check authority take its lock before an approval's."""
        async with self._store.transaction(tx) as t:
            now = self._clock()
            revoked = await self._store.retire_candidate(approver_subject, now, t)
            await self._audit_all(revoked, retired_by, "approver_retired", now, t)

    async def _audit_all(
        self,
        revoked: list[Approval],
        revoked_by: str,
        reason: str,
        at: datetime,
        tx: TransactionManager,
    ) -> None:
        for approval in revoked:
            await _emit(
                self._audit, AuditKind.APPROVAL_REVOKED, revoked_by, approval, at, tx, reason=reason
            )


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
        task_answers: TaskAnswerVerifier | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._policies = policies
        self._approvers = approvers
        self._delivery = delivery
        self._authenticators = {a.assurance: a for a in authenticators}
        self._task_answers = task_answers
        self._revocation = ApprovalRevocation(store, audit, clock)
        self._audit = audit
        self._clock = clock

    # Requesting

    @overload
    async def mint(
        self,
        *,
        request: Mapping[str, Any],
        policy_ref: str,
        requested_by: str,
        presentation: PresentationKind = ...,
        presentation_ref: str | None = ...,
        expires_at: datetime | None = ...,
        tx: None = ...,
    ) -> RequesterView: ...

    @overload
    async def mint(
        self,
        *,
        request: Mapping[str, Any],
        policy_ref: str,
        requested_by: str,
        presentation: PresentationKind = ...,
        presentation_ref: str | None = ...,
        expires_at: datetime | None = ...,
        tx: TransactionManager,
    ) -> PendingApproval: ...

    async def mint(
        self,
        *,
        request: Mapping[str, Any],
        policy_ref: str,
        requested_by: str,
        presentation: PresentationKind = PresentationKind.LINK,
        presentation_ref: str | None = None,
        expires_at: datetime | None = None,
        tx: TransactionManager | None = None,
    ) -> RequesterView | PendingApproval:
        """Freeze the request and its eligible approvers and record a pending
        approval. When presented by link, each candidate gets their own.

        A request that shows its approver an expiry passes it as `expires_at`:
        the approval then ends at the earlier of it and the policy's ttl, so it
        is never admitted after the instant the approver was shown.

        Without `tx` the approval commits at once and its links are sent.
        With `tx` it commits with the caller's transaction, and nothing is
        sent: the caller passes the returned `PendingApproval` to `deliver`
        after the commit, so no link points at an approval that rolled back.

        The directory is read on its own connection, not in `tx`, so it does
        not see designations or roles the caller wrote earlier in the same
        transaction: designate and mint in separate transactions."""
        policy = await self._policies.current(policy_ref)
        if policy is None:
            raise ApprovalRefused(Refusal.POLICY_UNKNOWN)
        if (presentation is PresentationKind.TASK) != (presentation_ref is not None):
            raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
        if presentation is PresentationKind.TASK and self._task_answers is None:
            raise ApprovalRefused(Refusal.PRESENTATION_UNSUPPORTED)
        approvers = await self._eligible(policy, request, requested_by, presentation)
        if not approvers:
            raise ApprovalRefused(Refusal.NO_ELIGIBLE_APPROVER)

        now = self._clock()
        canonical = _covered(request, policy.policy_ref, policy.version)
        digest = _sha256(canonical)
        approval_id = str(uuid.uuid4())
        ends = now + policy.ttl
        expires_at = ends if expires_at is None else min(ends, expires_at)
        sending: list[tuple[Approver, str]] = []
        links: list[ApprovalLink] = []
        if presentation is PresentationKind.LINK:
            for approver in approvers:
                token, verifier = new_link_token()
                sending.append((approver, token))
                links.append(
                    ApprovalLink(
                        link_id=str(uuid.uuid4()),
                        approval_id=approval_id,
                        candidate_subject=approver.subject,
                        request_sha256=digest,
                        verifier_sha256=verifier,
                        created_at=now,
                        lifetime=LinkLifetime(expires_at=expires_at, revoked_at=None, used_at=None),
                    )
                )
        approval = Approval(
            approval_id=approval_id,
            request_sha256=digest,
            request_ref=str(uuid.uuid4()),
            policy_ref=policy.policy_ref,
            policy_version=policy.version,
            requested_by=requested_by,
            candidates=tuple(
                Candidate(
                    scope=a.scope,
                    subject=a.subject,
                    subject_type=a.subject_type,
                    principal_did=a.principal_did,
                )
                for a in approvers
            ),
            decided_by=None,
            presentation_kind=presentation,
            presentation_ref=presentation_ref,
            task_answer_ref=None,
            state=ApprovalState.PENDING,
            delivery_status=DeliveryStatus.PENDING if links else DeliveryStatus.NOT_REQUIRED,
            created_at=now,
            expires_at=expires_at,
            decided_at=None,
            revoked_at=None,
            consumed_operation_id=None,
            dispatch_outcome=None,
            response_status=None,
        )
        stored = StoredRequest(approval.request_ref, digest, canonical, now)
        async with self._store.transaction(tx) as t:
            await self._store.create(stored, approval, links, t)
            await self._emit(AuditKind.APPROVAL_REQUESTED, requested_by, approval, now, t)
        pending = PendingApproval(
            view=self._view(approval, now),
            approval=approval,
            deliveries=tuple(PendingDelivery(a, token) for a, token in sending),
        )
        if tx is not None:
            return pending
        return await self.deliver(pending)

    async def deliver(self, pending: PendingApproval) -> RequesterView:
        """Send each candidate their link, once the approval has committed, and
        record how the delivery went: delivered if any candidate's link was.

        It is not idempotent: a second call sends the same single-use links
        again and records the delivery again."""
        approval = pending.approval
        if not pending.deliveries:
            return pending.view
        statuses = [
            await self._deliver(d.approver, d.link_token, approval) for d in pending.deliveries
        ]
        status = (
            DeliveryStatus.DELIVERED
            if DeliveryStatus.DELIVERED in statuses
            else DeliveryStatus.FAILED
        )
        await self._store.set_delivery_status(approval.approval_id, status)
        return self._view(replace(approval, delivery_status=status), self._clock())

    async def _eligible(
        self,
        policy: ActionPolicy,
        request: Mapping[str, Any],
        requested_by: str,
        presentation: PresentationKind,
    ) -> list[Approver]:
        """The directory's approvers in the policy's scopes, one per subject,
        without the requester unless the policy allows it. A task presentation
        needs each candidate's principal, to match the answer's."""
        eligible: dict[str, Approver] = {}
        for approver in await self._approvers.candidates(policy, request):
            if approver.scope not in policy.approver_scopes:
                continue
            if _is_requester(approver, requested_by) and not policy.allow_requester_approval:
                continue
            if presentation is PresentationKind.TASK and approver.principal_did is None:
                continue
            eligible.setdefault(approver.subject, approver)
        return list(eligible.values())

    async def _deliver(self, approver: Approver, token: str, approval: Approval) -> DeliveryStatus:
        try:
            return await self._delivery.deliver_approval_link(approver, token, approval)
        except Exception:
            logger.exception("approval link delivery failed for approval %s", approval.approval_id)
            return DeliveryStatus.FAILED

    async def requester_view(self, request_id: str, requested_by: str) -> RequesterView:
        """The requester's own view. Another caller gets `not_found`, as for an
        unknown request."""
        approval = await self._store.get_by_request(request_id)
        if approval is None or approval.requested_by != requested_by:
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

    def now(self) -> datetime:
        """The time on the clock these approvals expire by."""
        return self._clock()

    async def get(self, approval_id: str) -> Approval | None:
        return await self._store.get(approval_id)

    async def for_request(self, request_id: str) -> Approval | None:
        return await self._store.get_by_request(request_id)

    # The approver

    async def open_link(self, link_token: str) -> LinkedApproval:
        """What the link locates, for the candidate it was sent to. Reading
        consumes nothing. The request itself is included only when the policy
        lets link possession reveal it; otherwise the approver authenticates
        first with `view`."""
        link = await self._usable_link(link_token)
        approval = await self._store.get(link.approval_id)
        if approval is None or approval.state_at(self._clock()) is not ApprovalState.PENDING:
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        candidate = approval.candidate(link.candidate_subject)
        assert candidate is not None
        policy = await self._policies.current(approval.policy_ref)
        revealed = policy is not None and policy.reveals_request_on_link()
        return LinkedApproval(
            approval=_seen_by(approval, candidate),
            request=await self._request(approval) if revealed else None,
        )

    async def _request(self, approval: Approval) -> Mapping[str, Any]:
        canonical = await self._store.request_canonical(approval.request_ref)
        return json.loads(canonical[len(DOMAIN_PREFIX) :])["request"]

    async def _usable_link(self, link_token: str) -> ApprovalLink:
        link = await self._store.find_link(link_verifier(link_token))
        if link is None or not link.lifetime.usable_at(self._clock()):
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        return link

    async def _presented(
        self,
        approval: Approval | None,
        link_token: str | None,
        task_answer_ref: str | None,
        subject: str | None,
        *,
        deciding: bool,
    ) -> tuple[Approval, Candidate, str | None]:
        """Check the call arrives through the approval's own presentation, and
        find the candidate it is for. A link is personal: it is for the
        candidate it was sent to. A task presentation names its candidate with
        `subject`, and carries its task answer when deciding. Return the
        approval, the candidate and the link used, if any."""
        if approval is None:
            raise ApprovalRefused(Refusal.NOT_FOUND)
        if approval.presentation_kind is PresentationKind.TASK:
            if (
                link_token is not None
                or subject is None
                or deciding != (task_answer_ref is not None)
            ):
                raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
            candidate = approval.candidate(subject)
            if candidate is None:
                raise ApprovalRefused(Refusal.APPROVER_MISMATCH)
            return approval, candidate, None
        if task_answer_ref is not None or subject is not None or link_token is None:
            raise ApprovalRefused(Refusal.PRESENTATION_MISMATCH)
        link = await self._usable_link(link_token)
        if (
            link.approval_id != approval.approval_id
            or link.request_sha256 != approval.request_sha256
        ):
            raise ApprovalRefused(Refusal.LINK_UNAVAILABLE)
        candidate = approval.candidate(link.candidate_subject)
        assert candidate is not None
        return approval, candidate, link.link_id

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

    async def _still_eligible(self, approval: Approval, candidate: Candidate) -> bool:
        return candidate.retired_at is None and await self._approvers.is_current(
            candidate.scope, candidate.subject
        )

    async def _check_candidate(
        self, approval: Approval, candidate: Candidate, policy: ActionPolicy
    ) -> None:
        """The candidate may still decide: still designated, not retired, and
        not the requester unless the policy allows it."""
        if _is_requester(candidate, approval.requested_by) and not policy.allow_requester_approval:
            raise ApprovalRefused(Refusal.NO_ELIGIBLE_APPROVER)
        if await self._still_eligible(approval, candidate):
            return
        for other in approval.candidates:
            if other.subject != candidate.subject and await self._still_eligible(approval, other):
                raise ApprovalRefused(Refusal.APPROVER_RETIRED)
        raise ApprovalRefused(Refusal.NO_ELIGIBLE_APPROVER)

    async def _check_decider(self, approval: Approval) -> None:
        """The approver who decided is still designated and not retired."""
        decider = approval.decided_by
        if decider is None or not await self._approvers.is_current(decider.scope, decider.subject):
            raise ApprovalRefused(Refusal.APPROVER_RETIRED)
        candidate = approval.candidate(decider.subject)
        if candidate is None or candidate.retired_at is not None:
            raise ApprovalRefused(Refusal.APPROVER_RETIRED)

    async def _authenticator(
        self, approval: Approval, candidate: Candidate, assurance: Assurance
    ) -> Authenticator:
        policy = await self._current_policy(approval)
        await self._check_candidate(approval, candidate, policy)
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
        task_answer_ref: str | None = None,
        subject: str | None = None,
    ) -> Mapping[str, Any]:
        """Start one candidate's authenticator ceremony for one decision.
        Consumes nothing. A task presentation names its candidate with `subject`
        and binds the task answer the decision will carry."""
        approval, candidate, _ = await self._presented(
            await self._store.get(approval_id), link_token, task_answer_ref, subject, deciding=True
        )
        self._check_pending(approval)
        return await self._challenge(
            approval, candidate, decision.purpose, assurance, task_answer_ref
        )

    async def _challenge(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        assurance: Assurance,
        task_answer_ref: str | None,
    ) -> Mapping[str, Any]:
        authenticator = await self._authenticator(approval, candidate, assurance)
        try:
            return await authenticator.challenge(approval, candidate, purpose, task_answer_ref)
        except AuthenticationFailed as exc:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED) from exc

    async def _verified(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        assurance: Assurance,
        proof: Mapping[str, Any],
        task_answer_ref: str | None,
    ) -> DecidedBy:
        """The authenticator's evidence that this candidate made this proof."""
        authenticator = await self._authenticator(approval, candidate, assurance)
        try:
            evidence = await authenticator.verify(
                approval, candidate, purpose, proof, task_answer_ref
            )
        except AuthenticationFailed as exc:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED) from exc
        if evidence.assurance is not authenticator.assurance:
            raise ApprovalRefused(Refusal.AUTHENTICATION_FAILED)
        if (evidence.subject, evidence.subject_type) != (candidate.subject, candidate.subject_type):
            raise ApprovalRefused(Refusal.APPROVER_MISMATCH)
        return DecidedBy(
            scope=candidate.scope,
            subject=candidate.subject,
            assurance=evidence.assurance,
            evidence_ref=evidence.evidence_ref,
        )

    async def _verify_task_answer(
        self, approval: Approval, candidate: Candidate, decision: Decision, task_answer_ref: str
    ) -> None:
        """The app verified this answer for this approval and decision, and it
        was given by the principal this candidate stands for."""
        if self._task_answers is None:
            raise ApprovalRefused(Refusal.PRESENTATION_UNSUPPORTED)
        try:
            answer = await self._task_answers.verify(approval, decision, task_answer_ref)
        except TaskAnswerRejected as exc:
            raise ApprovalRefused(Refusal.TASK_ANSWER_UNVERIFIED) from exc
        if (
            answer.task_answer_ref,
            answer.approval_id,
            answer.decision,
            answer.request_sha256,
            answer.answered_by,
        ) != (
            task_answer_ref,
            approval.approval_id,
            decision,
            approval.request_sha256,
            candidate.principal_did,
        ):
            raise ApprovalRefused(Refusal.TASK_ANSWER_UNVERIFIED)

    async def view_challenge(
        self,
        approval_id: str,
        assurance: Assurance,
        *,
        link_token: str | None = None,
        subject: str | None = None,
    ) -> Mapping[str, Any]:
        """Start the ceremony that shows a candidate the request. Consumes nothing."""
        approval, candidate, _ = await self._presented(
            await self._store.get(approval_id), link_token, None, subject, deciding=False
        )
        self._check_pending(approval)
        return await self._challenge(approval, candidate, Purpose.VIEW, assurance, None)

    async def view(
        self,
        approval_id: str,
        assurance: Assurance,
        proof: Mapping[str, Any],
        *,
        link_token: str | None = None,
        subject: str | None = None,
    ) -> LinkedApproval:
        """The request, for a candidate once authenticated. A view proof
        consumes nothing and cannot decide."""
        approval, candidate, _ = await self._presented(
            await self._store.get(approval_id), link_token, None, subject, deciding=False
        )
        self._check_pending(approval)
        await self._verified(approval, candidate, Purpose.VIEW, assurance, proof, None)
        return LinkedApproval(
            approval=_seen_by(approval, candidate), request=await self._request(approval)
        )

    async def decide(
        self,
        approval_id: str,
        decision: Decision,
        assurance: Assurance,
        proof: Mapping[str, Any],
        *,
        link_token: str | None = None,
        task_answer_ref: str | None = None,
        subject: str | None = None,
        tx: TransactionManager | None = None,
    ) -> Approval:
        """Record one candidate's verified decision; the first decision is the
        only one. A link presentation uses its link and revokes every other
        candidate's. A task presentation names its candidate with `subject` and
        needs both the app's verification of its task answer, given by that
        candidate's principal, and the authenticator proof bound to that
        answer; until both verify the approval stays pending."""
        approval, candidate, link_id = await self._presented(
            await self._store.get(approval_id), link_token, task_answer_ref, subject, deciding=True
        )
        self._check_pending(approval)
        if task_answer_ref is not None:
            await self._verify_task_answer(approval, candidate, decision, task_answer_ref)
        decided_by = await self._verified(
            approval, candidate, decision.purpose, assurance, proof, task_answer_ref
        )

        async with self._store.locked(approval_id, tx) as locked:
            current = self._check_pending(locked.approval)
            # Eligibility again under the lock: a retirement serialises with
            # this decision on the approval row, so one committed during the
            # ceremony is seen here.
            locked_candidate = current.candidate(candidate.subject)
            if locked_candidate is None:
                raise ApprovalRefused(Refusal.APPROVER_MISMATCH)
            await self._check_candidate(
                current, locked_candidate, await self._current_policy(current)
            )
            now = self._clock()
            state = (
                ApprovalState.APPROVED if decision is Decision.APPROVE else ApprovalState.REJECTED
            )
            try:
                decided = await locked.set_decision(
                    state, decided_by, task_answer_ref, link_id, now
                )
            except LinkAlreadyUsed as exc:
                raise ApprovalRefused(Refusal.LINK_UNAVAILABLE) from exc
            await self._emit(
                AuditKind.APPROVAL_DECIDED,
                decided_by.subject,
                decided,
                now,
                locked.transaction,
                decision=decision.value,
                authenticator=decided_by.assurance.value,
                evidence_ref=decided_by.evidence_ref,
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
        """Revoke one pending or approved approval, or stop the transport retry
        of one consumed but never sent. Revocation before dispatch wins."""
        async with self._store.locked(approval_id, tx) as locked:
            approval = locked.approval
            if approval is None:
                raise ApprovalRefused(Refusal.NOT_FOUND)
            if approval.revoked_at is not None:
                raise ApprovalRefused(Refusal.REVOKED)
            if (
                approval.state is ApprovalState.CONSUMED
                and approval.dispatch_outcome is not DispatchOutcome.NOT_SENT
            ):
                raise ApprovalRefused(Refusal.CONSUMED)
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
        own predicate, are still pending or approved, and stop the transport
        retry of those consumed but never sent. Other consumed approvals are
        left as they are. Returns the approvals revoked."""
        return await self._revocation.revoke_many(
            approval_ids, revoked_by=revoked_by, reason=reason, tx=tx
        )

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
            approval = _locked_request(locked, request)
            if approval.state is ApprovalState.CONSUMED:
                if approval.consumed_operation_id != operation_id:
                    raise ApprovalRefused(Refusal.CONSUMED)
                if approval.dispatch_outcome is not DispatchOutcome.NOT_SENT:
                    return self._admission(approval, first=False, may_send=False)
                if approval.revoked_at is not None:
                    raise ApprovalRefused(Refusal.REVOKED)
                if self._clock() >= approval.expires_at:
                    raise ApprovalRefused(Refusal.EXPIRED)
                await self._current_policy(approval)
                await self._check_decider(approval)
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
            await self._check_decider(approval)
            assert approval.decided_by is not None
            if not approval.decided_by.assurance.satisfies(policy.min_assurance):
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

    async def retrieve(
        self,
        approval_id: str,
        request: Mapping[str, Any],
        operation_id: str,
        *,
        tx: TransactionManager | None = None,
    ) -> Admission | None:
        """The stable result of the attempt already admitted under this
        operation ID, or None when asking `admit` again would send: the attempt
        was never admitted, or it was not sent. Retrieves without admitting,
        and holds the approval locked in `tx` until it ends."""
        async with self._store.locked(approval_id, tx) as locked:
            approval = _locked_request(locked, request)
            if (
                approval.state is not ApprovalState.CONSUMED
                or approval.consumed_operation_id != operation_id
                or approval.dispatch_outcome is DispatchOutcome.NOT_SENT
            ):
                return None
            return self._admission(approval, first=False, may_send=False)

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
        await _emit(self._audit, kind, actor, approval, at, tx, **details)
