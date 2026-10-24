"""B2 use lifecycle recording through retained B3 proof and the shared outbox.

The root's composite sink routes use/run policy events here. Minting supplies
an internal original-dispatch association; later decisions read that frozen
association. A prepared registration view is request-local and obtained before
authority locks. Neither context confers admission or send authority.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.producer import HookProducer, RegistrationView
from aweb_naapp.runtime.approvals import Approval, ApprovalState, Assurance
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, parse_request_json, request_sha256
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    Passkeys,
)
from pgdbm.core import TransactionManager

from aweb_secrets.broker_audit import _activity, _same_producer

_KINDS = frozenset(
    {
        AuditKind.APPROVAL_REQUESTED,
        AuditKind.APPROVAL_DECIDED,
        AuditKind.APPROVAL_REVOKED,
        AuditKind.DISPATCH_ADMITTED,
        AuditKind.DISPATCH_OUTCOME,
    }
)


def is_use_approval(event: AuditEvent) -> bool:
    return event.kind in _KINDS and event.details.get("policy_ref", "").split("|", 1)[0] in {
        "secrets.use",
        "secrets.run",
    }


class UseAuditUnavailable(RuntimeError):
    code = "release_context_unavailable"
    status = 503

    def __init__(self) -> None:
        super().__init__("use approval audit context unavailable")


class HookProducerFactory(Protocol):
    def __call__(self, *, installation_id: str, generation: int) -> HookProducer: ...


class UseApprovalAudit:
    def __init__(
        self,
        *,
        producer: HookProducerFactory,
        passkeys: Callable[[], Passkeys],
        approval: Callable[[TransactionManager, str], Awaitable[Approval | None]],
        max_backlog_age: timedelta,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._producer, self._passkeys, self._approval = producer, passkeys, approval
        if max_backlog_age <= timedelta(0):
            raise ValueError("the use audit backlog bound must be positive")
        self._max_backlog_age = max_backlog_age
        self._clock = clock
        self._view: ContextVar[RegistrationView | None] = ContextVar("use_audit_view", default=None)
        self._mint: ContextVar[UUID | None] = ContextVar("use_audit_mint", default=None)

    @contextmanager
    def prepared_view(self, view: RegistrationView | None) -> Iterator[None]:
        """The caller obtains this immutable view outside its effect transaction."""
        token = self._view.set(view)
        try:
            yield
        finally:
            self._view.reset(token)

    @contextmanager
    def minting(self, dispatch_id: UUID) -> Iterator[None]:
        """Internal association for S12's synchronous in-tx mint callback only."""
        token = self._mint.set(dispatch_id)
        try:
            yield
        finally:
            self._mint.reset(token)

    async def dispatch_approvals(
        self, tx: TransactionManager, dispatch_id: UUID
    ) -> tuple[Approval, ...]:
        """Read the original B2 associations before preparing publication authority."""
        rows = await tx.fetch_all(
            "SELECT approval_id,request_ref,request_sha256 FROM {{tables.use_approval_audits}}"
            " WHERE dispatch_id=$1 ORDER BY approval_id",
            dispatch_id,
        )
        found = []
        for row in rows:
            approval = await self._approval(tx, row["approval_id"])
            if approval is None or (approval.request_ref, approval.request_sha256) != (
                row["request_ref"],
                row["request_sha256"],
            ):
                raise UseAuditUnavailable()
            found.append(approval)
        return tuple(found)

    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        tx = transaction
        if not is_use_approval(event) or event.approval_id is None:
            raise UseAuditUnavailable()
        approval = await self._approval(tx, event.approval_id)
        if approval is None or (
            approval.policy_ref != event.details.get("policy_ref")
            or approval.request_sha256 != event.details.get("request_sha256")
        ):
            raise UseAuditUnavailable()
        if event.kind is AuditKind.APPROVAL_REQUESTED:
            await self._associate(tx, approval)
        row = await self._original(tx, approval)
        # Admission/outcome have one S3 hook in their same effect transaction.
        # B2 still records its own association/outcome and calls this required
        # branch, which validates that it is the original dispatch.
        if event.kind in {AuditKind.DISPATCH_ADMITTED, AuditKind.DISPATCH_OUTCOME}:
            if approval.consumed_operation_id != str(row["dispatch_id"]):
                raise UseAuditUnavailable()
            return
        context = CommitmentContext(
            row["app_id"],
            row["team_id"],
            row["installation_id"],
            row["install_generation"],
            row["tool"],
        )
        payload = json.loads(row["payload"])
        payload.update(approval_id=approval.approval_id)
        decision = None
        if event.kind is AuditKind.APPROVAL_REQUESTED:
            if approval.state is not ApprovalState.PENDING:
                raise UseAuditUnavailable()
            payload["action"] = "approval_requested"
        elif event.kind is AuditKind.APPROVAL_DECIDED:
            decision = {"approve": "approved", "reject": "denied"}.get(
                event.details.get("decision", "")
            )
            expected = ApprovalState.APPROVED if decision == "approved" else ApprovalState.REJECTED
            if decision is None or approval.state is not expected:
                raise UseAuditUnavailable()
            payload.update(await self._proof(tx, context, approval, event))
        elif event.kind is AuditKind.APPROVAL_REVOKED:
            if approval.state is not ApprovalState.REVOKED:
                raise UseAuditUnavailable()
            decision = "revoked"
        if decision is not None:
            payload.update(action="approval_decided", approval_decision=decision)
        await self._record(tx, approval, row, context, payload, decision, event.occurred_at)

    async def expired(self, tx: TransactionManager, approval_id: str) -> None:
        """Caller holds B2 before closing its still-waiting original S3 row.

        Expiry is a live read of B2's existing state rule. This records the
        consequence, never mutates/rearms/consumes the approval or sends.
        """
        approval = await self._approval(tx, approval_id)
        if approval is None:
            raise UseAuditUnavailable()
        row = await self._original(tx, approval)
        now = self._clock()
        if approval.state_at(now) is not ApprovalState.EXPIRED:
            raise UseAuditUnavailable()
        context = CommitmentContext(
            row["app_id"],
            row["team_id"],
            row["installation_id"],
            row["install_generation"],
            row["tool"],
        )
        payload = json.loads(row["payload"])
        payload.update(
            action="approval_decided", approval_decision="expired", approval_id=approval_id
        )
        await self._record(tx, approval, row, context, payload, "expired", now)

    async def _original(self, tx, approval):
        row = await tx.fetch_one(
            "SELECT c.*,b.actor,b.payload,b.correlation,b.signed_trace_id FROM {{tables.use_approval_audits}} a"
            " JOIN {{tables.broker_audit_contexts}} b USING(dispatch_id)"
            " JOIN {{tables.use_contexts}} c USING(dispatch_id)"
            " WHERE a.approval_id=$1 AND a.request_ref=$2 AND a.request_sha256=$3",
            approval.approval_id,
            approval.request_ref,
            approval.request_sha256,
        )
        if row is None:
            raise UseAuditUnavailable()
        return row

    async def _record(self, tx, approval, row, context, payload, decision, occurred_at):
        producer = self._producer(
            installation_id=context.installation_id, generation=context.generation
        )
        _same_producer(producer, context)
        options = dict(
            team_id=context.team_id,
            payload=payload,
            actor=json.loads(row["actor"]),
            occurred_at=occurred_at,
            signed_trace_id=row["signed_trace_id"],
        )
        if decision in {"denied", "expired", "revoked"}:
            event_id = await producer.enqueue_lifecycle(tx, result_status="denied", **options)
        else:
            await producer.require_admission(
                tx,
                team_id=context.team_id,
                hook="post-secret-use-hook",
                occurred_at=occurred_at,
                view=self._view.get(),
                max_backlog_age=self._max_backlog_age,
            )
            event_id = await producer.enqueue(
                tx,
                hook="post-secret-use-hook",
                result_status="success",
                view=self._view.get(),
                **options,
            )
        correlation = json.loads(row["correlation"])
        correlation.update(approval_id=approval.approval_id, approval_ref=approval.request_ref)
        await _activity(
            tx,
            event_id=event_id,
            context=context,
            dispatch_id=row["dispatch_id"],
            occurred_at=occurred_at,
            payload=payload,
            actor=json.loads(row["actor"]),
            correlation=correlation,
        )

    async def _associate(self, tx: TransactionManager, approval: Approval) -> None:
        dispatch_id = self._mint.get()
        if dispatch_id is None:
            raise UseAuditUnavailable()
        raw = await tx.fetch_value(
            "SELECT canonical FROM {{tables.approval_requests}} WHERE request_ref=$1",
            approval.request_ref,
        )
        if raw is None or not bytes(raw).startswith(DOMAIN_PREFIX):
            raise UseAuditUnavailable()
        covered = parse_request_json(bytes(raw)[len(DOMAIN_PREFIX) :])
        if request_sha256(covered) != approval.request_sha256:
            raise UseAuditUnavailable()
        request = covered["request"]
        row = await tx.fetch_one(
            "SELECT i.*,c.app_id FROM {{tables.use_contexts}} c"
            " JOIN {{tables.intents}} i USING(intent_id,installation_id,team_id,install_generation)"
            " JOIN {{tables.broker_audit_contexts}} b USING(dispatch_id) WHERE c.dispatch_id=$1",
            dispatch_id,
        )
        if (
            row is None
            or (
                request["type"],
                request["action"],
                request["installation_id"],
                request["team_id"],
                request["install_generation"],
                request["request_id"],
                request["requester"]["principal"],
                request["secret"]["secret_id"],
                request["secret"]["version"],
                request["grant_id"],
                request["policy_digest"],
            )
            != (
                "aweb.secrets.use-approval",
                "broker",
                row["installation_id"],
                row["team_id"],
                row["install_generation"],
                row["request_id"],
                row["principal_did"],
                row["secret_id"],
                row["secret_version"],
                row["grant_id"],
                row["policy_digest"],
            )
            or approval.requested_by != row["principal_did"]
        ):
            raise UseAuditUnavailable()
        await tx.execute(
            "INSERT INTO {{tables.use_approval_audits}} (approval_id,dispatch_id,request_ref,request_sha256)"
            " VALUES ($1,$2,$3,$4)",
            approval.approval_id,
            dispatch_id,
            approval.request_ref,
            approval.request_sha256,
        )

    async def _proof(self, tx, context, approval, event) -> dict[str, str]:
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
        passkeys = self._passkeys()
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
                context=PasskeyInstallationContext(
                    app_id=context.app_id,
                    team_id=context.team_id,
                    installation_id=context.installation_id,
                    generation=context.generation,
                ),
                scope=decided.scope,
                subject=decided.subject,
                purpose=purpose,
                tx=tx,
            )
        except PasskeyProofUnavailable:
            raise UseAuditUnavailable() from None
        await tx.execute(
            "INSERT INTO {{tables.use_approval_audit_proofs}}"
            " (approval_id,evidence_ref,scope,subject,purpose,commitment) VALUES ($1,$2,$3,$4,$5,$6)",
            approval.approval_id,
            decided.evidence_ref,
            decided.scope,
            decided.subject,
            purpose,
            commitment,
        )
        return {"approval_assurance": "passkey", "approval_evidence_sha256": commitment}
