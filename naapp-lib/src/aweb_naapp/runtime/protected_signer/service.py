"""Single-consume protected owner-act signing over the existing B2/B3 engines."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from awid.signing import canonical_json_bytes, verify_did_key_signature
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_naapp.console import ConsoleSession, session_is_current
from aweb_naapp.runtime.approvals import (
    ApprovalDelivery,
    ApprovalRefused,
    Approvals,
    ApprovalState,
    Assurance,
    Decision,
    DispatchOutcome,
    PgApprovalStore,
    PolicySource,
    Refusal,
    request_sha256,
)
from aweb_naapp.runtime.audit import AuditEvent, AuditKind, AuditSink
from aweb_naapp.runtime.passkeys import Passkeys, passkey_evidence_commitment

from . import catalog
from .codecs import artifact_for, authority_key, signing_bytes
from .retention import EffectConfirmation, RetainedEffect
from .types import (
    AdmittedHuman,
    AuthorityProvider,
    ControllerCustody,
    OperationReceipt,
    OwnerActOperation,
    PreparedOperation,
    ProtectedKeyContext,
    ReceiptReader,
    RequestExpired,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
    _checked_self_removal,
    owner_act_operation,
)

POLICY_REF = "aweb.human-assurance/1"


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _stamp(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


MAILED_APPROVAL_WAIT_CEILING = timedelta(hours=24)


def decision_named(value) -> Decision:
    """A link's decision word; anything else refuses."""
    if value == "approve":
        return Decision.APPROVE
    if value == "reject":
        return Decision.REJECT
    raise SignerRefused("request_invalid")


def _stable_context(context):
    return {k: v for k, v in context.fields().items() if k != "generation"}


class ProtectedSigner:
    """Shared local executor. Unimplemented catalog operations fail closed.

    Passkeys owns UV/challenges/proofs, Approvals owns decisions/consume, and
    the embedding owns current authority and isolated custody. The catalog
    selects the closed artifact codec; consumers apply signed owner acts through
    their existing nonce-fenced effect transaction.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        passkeys: Passkeys,
        policies: PolicySource,
        delivery: ApprovalDelivery,
        audit: AuditSink,
        authority: AuthorityProvider,
        custody: ControllerCustody,
        admission=None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        mailed_approval_wait: timedelta | None = None,
    ) -> None:
        self.db, self.passkeys, self.policies, self.audit = db, passkeys, policies, audit
        self.authority, self.custody, self.clock = authority, custody, clock
        self.admission = admission
        # When set, the signer mails each approver their personal link after
        # prepare commits, and a live-floor approval may wait this long for
        # them, still capped by every frozen artifact and policy deadline
        # (human-assurance-contract.md, "Mailed approval links").
        if mailed_approval_wait is not None and not (
            timedelta(0) < mailed_approval_wait <= MAILED_APPROVAL_WAIT_CEILING
        ):
            raise ValueError("a mailed approval waits more than nothing and at most 24 hours")
        self.mailed_approval_wait = mailed_approval_wait
        if passkeys.db is not db:
            raise ValueError("signer and B3 need the same original database")
        self.store = PgApprovalStore(db)
        self.approvals = Approvals(
            store=self.store,
            policies=policies,
            approvers=passkeys,
            delivery=delivery,
            authenticators=[passkeys.authenticator()],
            audit=audit,
            clock=clock,
        )

    async def migrate(self) -> None:
        await self.store.migrate()
        await self.passkeys.migrate()
        await AsyncMigrationManager(
            self.db,
            migrations_path=str(Path(__file__).parent / "migrations"),
            module_name="aweb_naapp_protected_signer",
        ).apply_pending_migrations()

    @staticmethod
    def _operation_id(operation_id):
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise SignerRefused("request_invalid") from None
        return operation_id

    async def lookup_context(self, operation_id: str) -> ProtectedKeyContext | None:
        """Internal authentication routing metadata; never a receipt or authority.

        No result, credential or candidate link is returned. Adapters use the
        exact retained context to authenticate their actual caller, then call
        receipt(), which reauthorizes under operation/authority locks. Do not
        expose this actor-free metadata helper as an HTTP endpoint. None is
        absence in this read, never proof that a request did not commit.
        """
        row = await self.db.fetch_one(
            "SELECT request FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
            self._operation_id(operation_id),
        )
        return self._operation(_json(row["request"])).context if row is not None else None

    async def lookup_operation(self, operation_id):
        """Internal authentication input, never an actor-free HTTP disclosure."""
        row = await self.db.fetch_one(
            "SELECT request FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
            self._operation_id(operation_id),
        )
        return self._operation(_json(row["request"])) if row is not None else None

    async def lookup_owned_self_removal(self, operation_id, *, principal, key_did, certificate_id):
        """Routing only: the embedding must still verify the actual fresh proof.

        A retained self request permits its own historical receipt/reconciliation,
        not a new operation or general membership. No result is disclosed here.
        """
        row = await self.db.fetch_one(
            "SELECT request,requester FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
            self._operation_id(operation_id),
        )
        if row is None or row["requester"] != principal:
            return None
        request = _json(row["request"])
        if (not owner_act_operation(self._operation(request)).spec.supports_self_removal or request["subject"]["root_id_or_self"] != "self"
            or request["subject"]["certificate_id"] != certificate_id or request["requester_key"] != key_did):
            return None
        return self._operation(request)

    async def lookup_handoff(self, handoff_id: str) -> dict[str, Any] | None:
        """Public routing facts only; the id grants no inspection or execution."""
        row = await self.db.fetch_one(
            "SELECT operation_id,request,approval_id FROM {{tables.protected_signer_operations}} "
            "WHERE handoff_id=$1",
            self._operation_id(handoff_id),
        )
        if row is None:
            return None
        if row["approval_id"] is None:
            return None
        approval = await self.store.get(row["approval_id"])
        # This closed slice has one selected human holding. Never guess among
        # candidates if an embedding supplied an unsupported approval policy.
        if approval is None or len(approval.candidates) != 1:
            raise SignerRefused("scope_refused")
        return {
            "operation_id": row["operation_id"],
            "context": self._operation(_json(row["request"])).context,
            "login_scope": approval.candidates[0].scope,
        }

    async def inspect(self, operation_id, *, human, human_session=None):
        return self._prepared(
            await self._authorized(operation_id, human, "approval", human_session=human_session)
        )

    async def _hold_session(self, tx, human, session, *, b3_held=False):
        if session is None:
            return
        if type(session) is not ConsoleSession or (session.scope, session.subject) != (
            human.b3_scope,
            human.subject,
        ):
            raise SignerRefused("console_session_required")
        if not b3_held:
            await self.passkeys.prepare_current_approvers(tx, [(human.b3_scope, human.subject)])
        if not await self.passkeys.login_evidence_is_current(
            session.scope, session.subject, session.evidence_ref, tx=tx, hold=False
        ) or not await session_is_current(tx, session, hold=True):
            raise SignerRefused("console_session_required")

    async def _check_session(self, tx, session):
        if session is not None and (
            not await session_is_current(tx, session, hold=False)
            or not await self.passkeys.login_evidence_is_current(
                session.scope, session.subject, session.evidence_ref, tx=tx, hold=False
            )
        ):
            raise SignerRefused("console_session_required")

    def _session_fresh(self, session):
        if session is not None and self.clock() >= session.expires_at:
            raise SignerRefused("console_session_required")

    async def _lock(self, tx, operation_id):
        operation_id = self._operation_id(operation_id)
        key = int.from_bytes(
            hashlib.sha256(b"aweb.protected-operation-lock/1\n" + operation_id.encode()).digest()[
                :8
            ],
            "big",
            signed=True,
        )
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", key)
        return await tx.fetch_one(
            "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1 FOR UPDATE",
            operation_id,
        )

    def _prepared(self, row):
        return PreparedOperation(
            row["operation_id"],
            row["handoff_id"],
            row["digest"],
            _json(row["request"]),
            _stamp(row["expires_at"]),
        )

    async def _emit(self, kind, tx, row, actor, *, evidence=None, refusal=None):
        await self.audit.emit(
            AuditEvent(
                kind=kind,
                actor=actor,
                subject=row["operation_id"],
                occurred_at=self.clock(),
                approval_id=row["approval_id"],
                details={
                    "operation": _json(row["request"])["operation"],
                    "operation_id": row["operation_id"],
                    "request_sha256": row["digest"],
                    **({"refusal_code": refusal} if refusal is not None else {}),
                    **(
                        {
                            "evidence_ref": evidence.metadata["evidence_ref"],
                            "approval_evidence_sha256": passkey_evidence_commitment(evidence),
                        }
                        if evidence is not None
                        else {}
                    ),
                },
            ),
            tx,
        )

    async def prepare(
        self, operation: RevokeHumanRole | OwnerActOperation, *, requester: RestrictedRequester
    ) -> PreparedOperation:
        typed = owner_act_operation(operation)
        provider = self._effect_provider(typed)
        # Existing owner-act-only embeddings retain their released port. A
        # missing adapter for a new family refuses before creating B2 state.
        signing_port = typed.spec.signing_port
        if not callable(getattr(self.custody, signing_port, None)):
            raise SignerRefused("operation_not_served")
        if type(requester) is not RestrictedRequester:
            raise SignerRefused("operation_refused")
        if requester.context != operation.context or not requester.principal:
            raise SignerRefused("scope_refused")
        _checked_self_removal(requester, operation_id=operation.operation_id)
        intent = canonical_json_bytes(operation.intent())
        fence = await self.authority.observe(operation.context, purpose="prepare")
        if provider is not None:
            # Authenticate the current local grant before reading admission
            # configuration. Existing operations reconcile their retained body
            # before new operation-specific registry observations can refuse a
            # changed child/key/policy under an owned UUID for the wrong reason.
            async with self.db.transaction() as tx:
                retained = await self._lock(tx, operation.operation_id)
                await fence.prepare(tx, requester)
                if retained is not None:
                    if retained["requester"] != requester.principal:
                        raise SignerRefused("scope_refused")
                    if bytes(retained["intent"]) != intent:
                        raise SignerRefused("operation_conflict")
                    await fence.check(tx, requester)
                    fence.require_fresh()
                    return self._prepared(retained)
                await fence.check(tx, requester)
                fence.require_fresh()
        cap = _checked_self_removal(requester, operation=typed)
        if cap is not None and cap.read_only:
            raise SignerRefused("scope_refused")
        extra = await provider.observe(typed, requester, purpose="prepare") if provider is not None else None
        pending = None
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation.operation_id)
            await fence.prepare(tx, requester)
            if row is not None:
                if bytes(row["intent"]) != intent or row["requester"] != requester.principal:
                    raise SignerRefused("operation_conflict")
                await fence.check(tx, requester)
                fence.require_fresh()
                return self._prepared(row)
            policy = await self.policies.current(POLICY_REF, tx=tx)
            if policy is None or policy.min_assurance is not Assurance.PASSKEY:
                raise SignerRefused("policy_changed")
            now = self.clock().replace(microsecond=0)
            fields = artifact_for(typed, fence.team_key_did, now)
            signing_bytes(typed, fields)  # Validate the existing consumer's closed wire.
            # Pending approval is bounded even for artifacts whose existing
            # consumer wire has no expiry (for example a team server record).
            # B2 additionally caps this deadline by the current policy TTL.
            wait = timedelta(seconds=600)
            if typed.spec.needs_human and self.mailed_approval_wait is not None:
                wait = self.mailed_approval_wait
            expires_at = typed.spec.effect_deadline(fields, now + wait)
            additions = await extra.freeze(tx) if extra is not None else {}
            if set(additions) != typed.spec.prepared_fields:
                raise SignerRefused("operation_mismatch")
            request = {
                **operation.intent(),
                "requester": requester.principal,
                "policy_ref": POLICY_REF,
                "policy_version": policy.version,
                "artifact": fields,
                **additions,
            }
            typed.spec.bound_values(request)
            if typed.spec.needs_human:
                pending = await self.approvals.mint(
                    request=request,
                    policy_ref=POLICY_REF,
                    requested_by=requester.principal,
                    expires_at=expires_at,
                    tx=tx,
                )
                if pending.approval.policy_version != policy.version:
                    raise SignerRefused("policy_changed")
                # B2's candidate link is private server presentation state. It never
                # reaches a requester and cannot replace B3 PASSKEY assurance.
                links = {d.approver.subject: d.link_token for d in pending.deliveries}
                approval_id = pending.approval.approval_id
                digest, expires_at = pending.approval.request_sha256, pending.approval.expires_at
            else:
                # Bounded admission has an authenticated root/policy admission,
                # never a fabricated B3 human decision or reusable UV unlock.
                approval_id, links = None, {}
                expires_at = min(expires_at, now + policy.ttl)
                digest = request_sha256({"policy": {"ref": POLICY_REF, "version": policy.version}, "request": request})
            await tx.execute(
                "INSERT INTO {{tables.protected_signer_operations}} "
                "(operation_id,handoff_id,requester,intent,request,digest,approval_id,"
                "candidate_links,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)",
                operation.operation_id,
                str(uuid.uuid4()),
                requester.principal,
                intent,
                canonical_json_bytes(request),
                digest,
                approval_id,
                json.dumps(links),
                expires_at,
            )
            row = await self._lock(tx, operation.operation_id)
            await self._emit(AuditKind.PROTECTED_OPERATION_PREPARED, tx, row, requester.principal)
            if extra is not None:
                await extra.check(tx, request)
                extra.require_fresh()
            await fence.check(tx, requester)
            fence.require_fresh()
            if extra is not None:
                extra.require_fresh()
            if self.clock() >= row["expires_at"]:
                raise SignerRefused("operation_expired")
            prepared = self._prepared(row)
        if pending is not None and self.mailed_approval_wait is not None:
            # After commit only: B2's delivery reads the committed handoff row.
            # Each approver's personal link goes to their own recorded contact.
            await self.approvals.deliver(pending)
        return prepared

    async def _authorized(self, operation_id, actor, purpose, *, human_session=None):
        fence = await self.authority.observe(actor.context, purpose=purpose)
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row is None:
                raise SignerRefused("operation_not_found")
            _checked_self_removal(actor, operation=self._operation(_json(row["request"])))
            expected = _json(row["request"])["scope"]
            if purpose == "receipt":
                matches = {
                    k: v for k, v in expected.items() if k != "generation"
                } == _stable_context(actor.context)
            else:
                matches = expected == actor.context.fields()
            if not matches:
                raise SignerRefused("scope_refused")
            await fence.prepare(tx, actor)
            await self._hold_session(tx, actor, human_session)
            if not isinstance(actor, AdmittedHuman) and row["requester"] != actor.principal:
                raise SignerRefused("scope_refused")
            await self._check_session(tx, human_session)
            await fence.check(tx, actor)
            fence.require_fresh()
            self._session_fresh(human_session)
            return row

    def _link(self, row, human):
        if type(human) is not AdmittedHuman or human.principal != human.context.human_id:
            raise SignerRefused("scope_refused")
        link = _json(row["candidate_links"]).get(human.subject)
        if not link:
            raise SignerRefused("scope_refused")
        return link

    async def approval_options(
        self, operation_id: str, *, human: AdmittedHuman, human_session=None,
        decision: Decision = Decision.APPROVE,
    ) -> Mapping[str, Any]:
        row = await self._authorized(operation_id, human, "approval", human_session=human_session)
        if row["refusal_code"] is not None:
            raise SignerRefused(row["refusal_code"])
        link = self._link(row, human)
        if row["result"] is not None or self.clock() >= row["expires_at"]:
            raise SignerRefused("operation_expired")
        return await self.approvals.challenge(
            row["approval_id"],
            decision,
            Assurance.PASSKEY,
            link_token=link,
        )

    # Mailed approval links (human-assurance-contract.md, "Mailed approval
    # links"): the personal token names one candidate of one operation. It
    # reveals only what B2's policy lets a link reveal and decides nothing by
    # itself; approve and reject each need that candidate's fresh exact-act UV
    # under every existing fence. No console session is created or used.

    async def _link_human(self, handoff_id: str, token: str):
        """The operation and current admitted human a personal link was sent to."""
        if not isinstance(token, str) or not token:
            raise SignerRefused("scope_refused")
        row = await self.db.fetch_one(
            "SELECT operation_id,request,approval_id,candidate_links FROM {{tables.protected_signer_operations}} "
            "WHERE handoff_id=$1",
            self._operation_id(handoff_id),
        )
        if row is None or row["approval_id"] is None:
            raise SignerRefused("scope_refused")
        subjects = [
            subject for subject, link in _json(row["candidate_links"]).items()
            if isinstance(link, str) and hmac.compare_digest(link.encode(), token.encode())
        ]
        approval = await self.store.get(row["approval_id"])
        candidate = approval.candidate(subjects[0]) if approval is not None and len(subjects) == 1 else None
        if candidate is None:
            raise SignerRefused("scope_refused")
        context = self._operation(_json(row["request"])).context
        return row["operation_id"], AdmittedHuman(context.human_id, candidate.subject, candidate.scope, context)

    async def link_view(self, handoff_id: str, token: str) -> PreparedOperation:
        """The complete frozen request, for the link's own approver; consumes nothing."""
        operation_id, human = await self._link_human(handoff_id, token)
        await self._authorized(operation_id, human, "approval")
        # Classify decided, signed and expired together while the operation
        # lock is held: a snapshot taken before the lock was released could
        # miss a signing that happened since. A decided or signed effect (which
        # may already be applied) spends the link without saying how it ended.
        # An unsigned, undecided row past its expiry can no longer be signed,
        # since every effect rechecks its deadline before it commits.
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row is None or row["result"] is not None or row["refusal_code"] is not None \
                    or row.get("signed_result") is not None:
                raise SignerRefused("scope_refused")
            if self.clock() >= row["expires_at"]:
                # Only the link's own approver reaches this, and may know when.
                raise RequestExpired(_stamp(row["expires_at"]))
        intent = self._operation(_json(row["request"])).intent()
        spec = catalog.OPERATIONS.get((intent["operation"], intent["variant"]))
        if spec is None or not spec.link_revealable:
            # The operation's own classification, not the deployment policy,
            # decides whether its whole frozen request may be revealed.
            raise SignerRefused("scope_refused")
        try:
            linked = await self.approvals.open_link(token)
        except ApprovalRefused:
            raise SignerRefused("scope_refused") from None
        if linked.request is None:
            # This deployment's policy does not let a link reveal its request.
            raise SignerRefused("scope_refused")
        return self._prepared(row)

    async def link_options(self, handoff_id: str, token: str, decision: str) -> Mapping[str, Any]:
        operation_id, human = await self._link_human(handoff_id, token)
        return await self.approval_options(operation_id, human=human, decision=decision_named(decision))

    async def link_decide(self, handoff_id: str, token: str, decision: str, proof) -> OperationReceipt:
        operation_id, human = await self._link_human(handoff_id, token)
        if decision_named(decision) is Decision.APPROVE:
            return await self.execute(operation_id, proof, human=human)
        return await self._reject_human(operation_id, proof, human=human)

    async def reject(self, operation_id, proof, *, human: AdmittedHuman, human_session=None) -> OperationReceipt:
        """A signed-in approver's Deny: the same exact-act ceremony as a link's."""
        if type(human) is not AdmittedHuman:
            raise SignerRefused("scope_refused")
        return await self._reject_human(operation_id, proof, human=human, human_session=human_session)

    async def _reject_human(self, operation_id, proof, *, human: AdmittedHuman, human_session=None) -> OperationReceipt:
        """The candidate's exact-act UV with the reject purpose: a final
        refused(human_refused) receipt. A B2 rejection that committed before a
        crash is recorded by the next call, never decided twice."""
        row = await self._authorized(operation_id, human, "execute", human_session=human_session)
        if row["result"] is not None or row["refusal_code"] is not None:
            return self._receipt(row)
        link = self._link(row, human)
        approval = await self.store.get(row["approval_id"])
        if approval is None:
            raise SignerRefused("approval_spent")
        if approval.state is ApprovalState.PENDING:
            claim, phase = await self._claim_verification(operation_id, human, human_session=human_session)
            if claim is None:
                return self._receipt(phase)
            try:
                approval = await self.approvals.decide(
                    approval.approval_id, Decision.REJECT, Assurance.PASSKEY, proof, link_token=link
                )
            except ApprovalRefused as exc:
                code = {
                    Refusal.POLICY_CHANGED: "policy_changed",
                    Refusal.EXPIRED: "approval_expired",
                    Refusal.AUTHENTICATION_FAILED: "proof_invalid",
                    Refusal.APPROVER_RETIRED: "approval_spent",
                    Refusal.REVOKED: "approval_spent",
                    Refusal.APPROVER_MISMATCH: "scope_refused",
                    Refusal.REQUEST_MISMATCH: "operation_mismatch",
                }.get(exc.reason, "operation_refused")
                await self._refuse_verification(operation_id, claim, code)
                raise SignerRefused(code) from exc
        decided = approval.decided_by
        if approval.state is not ApprovalState.REJECTED or decided is None or (
            decided.subject, decided.scope, decided.assurance
        ) != (human.subject, human.b3_scope, Assurance.PASSKEY):
            raise SignerRefused("scope_refused")
        fence = await self.authority.observe(human.context, purpose="execute")
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            await fence.prepare(tx, human)
            await self._hold_session(tx, human, human_session)
            if row["result"] is None and row["refusal_code"] is None:
                await tx.execute(
                    "UPDATE {{tables.protected_signer_operations}} SET refusal_code='human_refused',"
                    "evidence_ref=$2,candidate_links='{}'::jsonb WHERE operation_id=$1",
                    operation_id,
                    decided.evidence_ref,
                )
                await self._emit(AuditKind.PROTECTED_OPERATION_REFUSED, tx, row, human.principal, refusal="human_refused")
            await self._check_session(tx, human_session)
            await fence.check(tx, human)
            fence.require_fresh()
            self._session_fresh(human_session)
            row = await self._lock(tx, operation_id)
            return self._receipt(row)

    async def execute(self, operation_id, proof, *, human, human_session=None):
        try:
            return await self._execute_human(operation_id, proof, human=human, human_session=human_session)
        except SignerRefused as error:
            return await self._execution_refusal(operation_id, human, error,
                human_session=human_session)

    async def _execute_human(
        self,
        operation_id: str,
        proof: Mapping[str, Any],
        *,
        human: AdmittedHuman,
        human_session=None,
    ) -> OperationReceipt:
        if type(human) is not AdmittedHuman:
            raise SignerRefused("scope_refused")
        row = await self._authorized(operation_id, human, "execute", human_session=human_session)
        if row["result"] is not None or row["refusal_code"] is not None:
            return self._receipt(row)
        if row.get("retained_effect") is not None:
            return await self._reconcile_retained(operation_id, human, may_send=True, human_session=human_session)
        if row["signed_result"] is not None:
            return await self._reconcile_admission(operation_id, human, may_send=True, human_session=human_session)
        link = self._link(row, human)
        approval = await self.store.get(row["approval_id"])
        if approval is None:
            raise SignerRefused("approval_spent")
        if approval.state is ApprovalState.PENDING:
            claim, phase = await self._claim_verification(
                operation_id, human, human_session=human_session
            )
            if claim is None:
                return self._receipt(phase)
            try:
                approval = await self.approvals.decide(
                    approval.approval_id,
                    Decision.APPROVE,
                    Assurance.PASSKEY,
                    proof,
                    link_token=link,
                )
            except ApprovalRefused as exc:
                # Another execution can finish the very same one-use assertion.
                approval = await self.store.get(row["approval_id"])
                if approval is None or approval.state not in (
                    ApprovalState.APPROVED,
                    ApprovalState.CONSUMED,
                ):
                    code = {
                        Refusal.POLICY_CHANGED: "policy_changed",
                        Refusal.EXPIRED: "approval_expired",
                        Refusal.AUTHENTICATION_FAILED: "proof_invalid",
                        Refusal.APPROVER_RETIRED: "approval_spent",
                        Refusal.REVOKED: "approval_spent",
                        Refusal.APPROVER_MISMATCH: "scope_refused",
                        Refusal.REQUEST_MISMATCH: "operation_mismatch",
                    }.get(exc.reason, "operation_refused")
                    await self._refuse_verification(operation_id, claim, code)
                    raise SignerRefused(code) from exc
        decided = approval.decided_by
        if decided is None or (decided.subject, decided.scope, decided.assurance) != (
            human.subject,
            human.b3_scope,
            Assurance.PASSKEY,
        ):
            raise SignerRefused("scope_refused")
        fence = await self.authority.observe(human.context, purpose="execute")
        typed = owner_act_operation(self._operation(_json(row["request"])))
        provider = self._effect_provider(typed)
        extra = await provider.observe(typed, human, purpose="execute") if provider is not None else None
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row is None:
                raise SignerRefused("operation_not_found")
            await fence.prepare(tx, human)
            if row["result"] is not None:
                await self._hold_session(tx, human, human_session)
                await self._check_session(tx, human_session)
                await fence.check(tx, human)
                fence.require_fresh()
                self._session_fresh(human_session)
                return self._receipt(row)
            request = _json(row["request"])
            if fence.team_key_did != authority_key(self._operation(request), request["artifact"]):
                raise SignerRefused("authority_changed")
            held = await self.passkeys.prepare_current_approvers(
                tx, [(human.b3_scope, human.subject)]
            )
            await self._hold_session(tx, human, human_session, b3_held=True)
            retained = await self.passkeys.retained_proof(decided.evidence_ref, tx=tx)
            metadata, context = retained.metadata, retained.context
            if (
                metadata.get("purpose") != "approve"
                or metadata.get("approval_id") != approval.approval_id
                or metadata.get("request_sha256") != row["digest"]
                or metadata.get("subject") != human.subject
                or context["scope"] != human.b3_scope
                or any(context.get(k) != v for k, v in human.context.fields().items())
            ):
                raise SignerRefused("proof_invalid")
            deadline = min(
                _time(metadata["challenge_issued_at"]) + timedelta(seconds=300),
                _time(metadata["challenge_expires_at"]),
                row["expires_at"],
            )
            if self.clock() >= deadline:
                raise SignerRefused("gesture_expired")
            if not await self._credential_current(tx, human, retained.credential_id):
                raise SignerRefused("approval_spent")
            admission = await self.approvals.admit(
                approval.approval_id,
                request,
                operation_id,
                tx=tx,
            )
            if not admission.may_send:
                raise SignerRefused("external_effect_unresolved")
            operation = self._operation(request)
            if extra is not None:
                await extra.check(tx, request)
                extra.require_fresh()
            signature = self._sign_artifact(operation, request["artifact"])
            signing = signing_bytes(owner_act_operation(operation), request["artifact"])
            if not isinstance(signature, bytes) or len(signature) != 64:
                raise SignerRefused("operation_refused")
            verify_did_key_signature(
                did_key=fence.team_key_did,
                payload=signing,
                signature_b64=base64.b64encode(signature).decode(),
            )
            result = {
                "signing": base64.b64encode(signing).decode(),
                "signature": base64.b64encode(signature).decode(),
            }
            retained_effect = self._retain_authorized_effect(operation, request, signing, signature, fence, deadline)
            awaits_confirmation = retained_effect is not None or typed.spec.effect.confirmation_commit is not None
            await tx.execute(
                "UPDATE {{tables.protected_signer_operations}} SET result=$2::jsonb,"
                "signed_result=$3::jsonb,retained_effect=$4::jsonb,evidence_ref=$5,committed_at=$6,"
                "candidate_links='{}'::jsonb WHERE operation_id=$1",
                operation_id,
                None if awaits_confirmation else json.dumps(result),
                json.dumps(result) if awaits_confirmation else None,
                json.dumps(retained_effect.fields()) if retained_effect is not None else None,
                decided.evidence_ref,
                None if awaits_confirmation else self.clock(),
            )
            if typed.spec.effect.signing_commit is not None:
                from .types import _verified_effect

                effect = _verified_effect(operation, human=human,
                    transaction_id=int(await tx.fetch_value("SELECT txid_current()")),
                    evidence_ref=decided.evidence_ref, expires_at=deadline)
                await getattr(provider, typed.spec.effect.signing_commit)(tx, operation, request, result, effect)
            await self.approvals.record_outcome(
                approval.approval_id,
                operation_id,
                DispatchOutcome.COMPLETED,
                response_status="signed",
                tx=tx,
            )
            await self._emit(
                AuditKind.PROTECTED_OPERATION_SIGNED, tx, row, human.principal, evidence=retained
            )
            policy = await self.policies.current(POLICY_REF, tx=tx)
            if policy is None or policy.version != request["policy_version"]:
                raise SignerRefused("policy_changed")
            if not await self.passkeys.check_current_approver(
                tx, held, scope=human.b3_scope, subject=human.subject
            ) or not await self._credential_current(tx, human, retained.credential_id):
                raise SignerRefused("approval_spent")
            await self._check_session(tx, human_session)
            if extra is not None:
                await extra.check(tx, request)
                extra.require_fresh()
            await fence.check(tx, human)  # Final await: caller's held F6/authority checks.
            fence.require_fresh()
            if extra is not None:
                extra.require_fresh()
            self._session_fresh(human_session)
            if self.clock() >= deadline:
                raise SignerRefused("gesture_expired")
        if retained_effect is not None:
            return await self._reconcile_retained(operation_id, human, may_send=True, human_session=human_session)
        if awaits_confirmation:
            return await self._reconcile_admission(operation_id, human, may_send=True, human_session=human_session)
        return OperationReceipt(operation_id, "committed", result=result)

    async def execute_request(self, operation_id, *, requester):
        try:
            return await self._execute_request(operation_id, requester=requester)
        except SignerRefused as error:
            return await self._execution_refusal(operation_id, requester, error)

    async def _execution_refusal(self, operation_id, actor, error, *, human_session=None):
        # Only definite execution failures in this slice become final receipts.
        # Ingress/auth/unavailability failures stay errors. In particular a
        # live-floor requester execute cannot kill its pending human operation.
        code = {"gesture_expired": "approval_expired"}.get(error.code, error.code)
        if code not in {"policy_changed", "subject_ineligible", "admission_limit_reached",
                        "admission_policy_missing", "operation_expired", "approval_expired", "operation_mismatch"}:
            raise error
        route = await self.db.fetch_one(
            "SELECT request FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
            self._operation_id(operation_id),
        )
        if route is None or not owner_act_operation(self._operation(_json(route["request"]))).spec.finalize_execution_refusal:
            raise error
        await self._authorized(operation_id, actor, "receipt", human_session=human_session)
        fence = await self.authority.observe(actor.context, purpose="receipt")
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            await fence.prepare(tx, actor)
            await self._hold_session(tx, actor, human_session)
            if row["result"] is None and row["signed_result"] is None and row["refusal_code"] is None:
                await tx.execute(
                    "UPDATE {{tables.protected_signer_operations}} SET refusal_code=$2,candidate_links='{}'::jsonb WHERE operation_id=$1",
                    operation_id, code,
                )
                await self._emit(AuditKind.PROTECTED_OPERATION_REFUSED, tx, row, actor.principal, refusal=code)
            await self._check_session(tx, human_session)
            await fence.check(tx, actor)
            fence.require_fresh()
            self._session_fresh(human_session)
            row = await self._lock(tx, operation_id)
            fence.require_fresh()
            self._session_fresh(human_session)
            return self._receipt(row)

    async def _execute_request(self, operation_id, *, requester):
        """The same operation store, under a bounded root admission; no fake UV.

        One durable signature/quota reservation commits before registration.
        A delivery claim admits at most one mutation attempt. Lost answers and
        concurrent invocations reconcile the same certificate by safe reads.
        """
        if type(requester) is not RestrictedRequester:
            raise SignerRefused("requester_invalid")
        row = await self._authorized(operation_id, requester, "execute")
        operation = owner_act_operation(self._operation(_json(row["request"])))
        if operation.spec.needs_human:
            raise SignerRefused("live_approval_required")
        provider = self._effect_provider(operation)
        if provider is None:
            raise SignerRefused("operation_not_served")
        if row["result"] is not None or row["refusal_code"] is not None:
            return self._receipt(row)
        cap = _checked_self_removal(requester, operation=operation)
        if row["signed_result"] is None:
            if cap is not None and cap.read_only:
                raise SignerRefused("scope_refused")
            extra = await self._effect_provider(operation).observe(operation, requester, purpose="execute")
            fence = await self.authority.observe(operation.context, purpose="execute")
            async with self.db.transaction() as tx:
                row = await self._lock(tx, operation_id)
                await fence.prepare(tx, requester)
                if row["result"] is not None or row["refusal_code"] is not None:
                    await fence.check(tx, requester)
                    fence.require_fresh()
                    return self._receipt(row)
                if self.clock() >= row["expires_at"]:
                    raise SignerRefused("operation_expired")
                request = _json(row["request"])
                if row["requester"] != requester.principal or operation.context.fields() != request["scope"]:
                    raise SignerRefused("scope_refused")
                await extra.check(tx, request)
                await self._check_prepared_policy(tx, request)
                if row["signed_result"] is None:
                    await extra.reserve(tx, request)
                    if fence.team_key_did != authority_key(operation, request["artifact"]):
                        raise SignerRefused("authority_changed")
                    signing = signing_bytes(operation, request["artifact"])
                    signature = self._sign_artifact(operation, request["artifact"])
                    if type(signature) is not bytes or len(signature) != 64:
                        raise SignerRefused("operation_refused")
                    verify_did_key_signature(did_key=fence.team_key_did, payload=signing,
                        signature_b64=base64.b64encode(signature).decode())
                    signed = {"signing": base64.b64encode(signing).decode(), "signature": base64.b64encode(signature).decode()}
                    retained_effect = self._retain_authorized_effect(operation, request, signing, signature, fence, row["expires_at"])
                    await tx.execute(
                        "UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb,retained_effect=$3::jsonb WHERE operation_id=$1",
                        operation_id, json.dumps(signed), json.dumps(retained_effect.fields()) if retained_effect is not None else None,
                    )
                    await self._emit(AuditKind.PROTECTED_OPERATION_SIGNED, tx, row, requester.principal)
                await extra.check(tx, request)
                extra.require_fresh()
                await fence.check(tx, requester)
                await self._check_prepared_policy(tx, request)
                fence.require_fresh()
                extra.require_fresh()
                if self.clock() >= row["expires_at"]:
                    raise SignerRefused("operation_expired")
        return await self._reconcile_admission(operation_id, requester, may_send=True)

    async def _signed_deadline(self, row):
        """Original signed-effect window, including the exact retained human UV."""
        until = row["expires_at"]
        if row["evidence_ref"] is not None:
            evidence = await self.passkeys.retained_proof(row["evidence_ref"])
            metadata = evidence.metadata
            if (metadata.get("purpose") != "approve" or metadata.get("approval_id") != row["approval_id"]
                or metadata.get("request_sha256") != row["digest"]):
                raise SignerRefused("evidence_unavailable")
            until = min(until, _time(metadata["challenge_issued_at"]) + timedelta(seconds=300),
                _time(metadata["challenge_expires_at"]))
        return until

    async def _reconcile_admission(self, operation_id, requester, *, may_send, human_session=None):
        """Legacy consumer delivery uses the same signed-result/one-claim store.

        Human rows retain their exact UV deadline and current credential checks
        through release. Receipt-only recovery can confirm historical effects,
        but never authorizes another mutation or restarts the UV window.
        """
        row = await self._authorized(operation_id, requester, "receipt", human_session=human_session)
        if row["result"] is not None or row["signed_result"] is None:
            return self._receipt(row)
        if row.get("retained_effect") is not None:
            return await self._reconcile_retained(operation_id, requester, may_send=may_send, human_session=human_session)
        request, signed = _json(row["request"]), _json(row["signed_result"])
        operation = self._operation(request)
        provider = self._effect_provider(operation)
        until = await self._signed_deadline(row)
        cap = _checked_self_removal(requester, operation=operation)
        if cap is not None and cap.read_only:
            may_send = False

        async def observed():
            started = self.clock()
            confirmed = await provider.registered(operation, request["artifact"], signed)
            return started + timedelta(seconds=60) if confirmed else None

        confirmed_until = await observed()
        if confirmed_until is None and may_send and row["delivery_claim"] is None and self.clock() < until:
            extra = await provider.observe(operation, requester, purpose="execute")
            fence = await self.authority.observe(operation.context, purpose="execute")
            claim = str(uuid.uuid4())
            async with self.db.transaction() as tx:
                row = await self._lock(tx, operation_id)
                await fence.prepare(tx, requester)
                await self._hold_session(tx, requester, human_session)
                await extra.check(tx, request)
                await self._check_prepared_policy(tx, request)
                await self._retained_uv(tx, row, requester)
                if row["delivery_claim"] is not None or row["result"] is not None:
                    claim = None
                else:
                    await tx.execute(
                        "UPDATE {{tables.protected_signer_operations}} SET delivery_claim=$2 WHERE operation_id=$1",
                        operation_id, claim,
                    )
                await extra.check(tx, request)
                extra.require_fresh()
                await self._retained_uv(tx, row, requester)
                await self._check_session(tx, human_session)
                await fence.check(tx, requester)
                await self._check_prepared_policy(tx, request)
                fence.require_fresh()
                extra.require_fresh()
                self._session_fresh(human_session)
                if self.clock() >= until:
                    raise SignerRefused("operation_expired")
            if claim is not None and self.clock() < until:
                async with asyncio.timeout((until - self.clock()).total_seconds()):
                    await provider.register(operation, request["artifact"], signed)
                confirmed_until = await observed()
        if confirmed_until is not None:
            fence = await self.authority.observe(operation.context, purpose="receipt")
            async with self.db.transaction() as tx:
                row = await self._lock(tx, operation_id)
                await fence.prepare(tx, requester)
                await self._hold_session(tx, requester, human_session)
                if row["result"] is None:
                    await provider.confirm(tx, operation)
                    await tx.execute(
                        "UPDATE {{tables.protected_signer_operations}} SET result=signed_result,committed_at=$2 WHERE operation_id=$1",
                        operation_id, self.clock(),
                    )
                    await self._emit(AuditKind.PROTECTED_OPERATION_APPLIED, tx, row, requester.principal)
                await self._check_session(tx, human_session)
                await fence.check(tx, requester)
                fence.require_fresh()
                self._session_fresh(human_session)
                if self.clock() >= confirmed_until:
                    raise SignerRefused("evidence_unavailable")
            return OperationReceipt(operation_id, "committed", result=signed)
        if self.clock() >= until:
            return OperationReceipt(operation_id, "unknown", code="external_effect_unresolved")
        return self._receipt(row)

    async def _check_prepared_policy(self, tx, request):
        # The bounded admission policy and B2 action policy are independent.
        # Holding current authority is not a comparison with the prepared B2
        # version. Recheck it before signing/release and as the final await.
        policy = await self.policies.current(POLICY_REF, tx=tx)
        if policy is None or policy.version != request["policy_version"]:
            raise SignerRefused("policy_changed")

    def _effect_provider(self, operation):
        name = owner_act_operation(operation).spec.effect.provider
        if name is None:
            return None
        provider = getattr(self, name, None)
        if provider is None:
            raise SignerRefused("operation_not_served")
        return provider

    def _retain_authorized_effect(self, operation, request, signing, signature, authority, expires_at):
        """Local only, inside the signature transaction; never exposes a proof."""
        retain = getattr(self.custody, "retain_authorized_effect", None)
        if not callable(retain):
            return None
        typed = owner_act_operation(operation)
        retained = retain(operation=typed, request=request, artifact=request["artifact"], signing=signing,
            signature=signature, authority=authority, expires_at=expires_at)
        if retained is None:
            return None
        if (type(retained) is not RetainedEffect
            or not callable(getattr(self.custody, "deliver_retained", None))
            or not callable(getattr(self.custody, "confirm_retained", None))):
            raise SignerRefused("operation_not_served")
        signed = {"signing": base64.b64encode(signing).decode(), "signature": base64.b64encode(signature).decode()}
        try:
            retained.require_matches(operation.operation_id, signed, expires_at)
            if retained.delivery.audience != operation.audience:
                raise ValueError()
        except (ValueError, TypeError):
            raise SignerRefused("operation_mismatch") from None
        return retained

    async def _load_retained(self, row):
        """Recheck original artifact and UV bound; loading never authorizes release."""
        try:
            request = _json(row["request"])
            operation = owner_act_operation(self._operation(request))
            retained = RetainedEffect.from_fields(_json(row["retained_effect"]))
            until = row["expires_at"]
            if "expires_at" in request["artifact"]:
                until = min(until, _time(request["artifact"]["expires_at"]))
            if row["evidence_ref"] is not None:
                evidence = await self.passkeys.retained_proof(row["evidence_ref"])
                metadata = evidence.metadata
                if (metadata.get("purpose") != "approve" or metadata.get("approval_id") != row["approval_id"]
                    or metadata.get("request_sha256") != row["digest"]):
                    raise ValueError()
                until = min(until, _time(metadata["challenge_issued_at"]) + timedelta(seconds=300),
                    _time(metadata["challenge_expires_at"]))
            retained.require_matches(row["operation_id"], _json(row["signed_result"]), until)
            if retained.signing != signing_bytes(operation, request["artifact"]) or retained.delivery.audience != operation.audience:
                raise ValueError()
            verify_did_key_signature(did_key=authority_key(operation, request["artifact"]),
                payload=retained.signing, signature_b64=base64.b64encode(retained.signature).decode())
            return operation, request, retained
        except (ValueError, TypeError, KeyError):
            raise SignerRefused("evidence_unavailable") from None

    async def _retained_uv(self, tx, row, actor):
        if row["evidence_ref"] is None:
            return
        if type(actor) is not AdmittedHuman:
            raise SignerRefused("scope_refused")
        held = await self.passkeys.prepare_current_approvers(tx, [(actor.b3_scope, actor.subject)])
        evidence = await self.passkeys.retained_proof(row["evidence_ref"], tx=tx)
        if (evidence.metadata.get("subject") != actor.subject or evidence.context.get("scope") != actor.b3_scope
            or any(evidence.context.get(k) != v for k, v in actor.context.fields().items())):
            raise SignerRefused("proof_invalid")
        if (not await self.passkeys.check_current_approver(tx, held, scope=actor.b3_scope, subject=actor.subject)
            or not await self._credential_current(tx, actor, evidence.credential_id)):
            raise SignerRefused("approval_spent")

    async def _reconcile_retained(self, operation_id, actor, *, may_send, human_session=None):
        """One committed bundle, one release claim, then read-only confirmation."""
        row = await self._authorized(operation_id, actor, "receipt", human_session=human_session)
        if row["result"] is not None or row["refusal_code"] is not None:
            return self._receipt(row)
        operation, request, retained = await self._load_retained(row)
        cap = _checked_self_removal(actor, operation=operation)
        if cap is not None and cap.read_only:
            may_send = False
        confirm = getattr(self.custody, "confirm_retained", None)
        deliver = getattr(self.custody, "deliver_retained", None)
        if not callable(confirm) or not callable(deliver):
            raise SignerRefused("operation_not_served")

        async def observe_confirmation():
            started = self.clock()
            observed = await confirm(operation, retained)
            if observed is None:
                return None
            try:
                if type(observed) is not EffectConfirmation:
                    raise ValueError()
                observed.require_matches(retained, self.clock())
                return min(observed.valid_until, started + timedelta(seconds=60))
            except (ValueError, TypeError):
                raise SignerRefused("evidence_unavailable") from None

        confirmed_until = await observe_confirmation()
        if confirmed_until is None and may_send and row["delivery_claim"] is None and self.clock() < retained.expires_at:
            provider = self._effect_provider(operation)
            extra = await provider.observe(operation, actor, purpose="execute") if provider is not None else None
            fence = await self.authority.observe(actor.context, purpose="execute")
            claim = None
            async with self.db.transaction() as tx:
                row = await self._lock(tx, operation_id)
                await fence.prepare(tx, actor)
                await self._hold_session(tx, actor, human_session)
                if row["result"] is not None or row["refusal_code"] is not None or row["delivery_claim"] is not None:
                    await self._check_session(tx, human_session)
                    await fence.check(tx, actor)
                    fence.require_fresh()
                    self._session_fresh(human_session)
                    return self._receipt(row)
                if fence.team_key_did != authority_key(operation, request["artifact"]):
                    raise SignerRefused("authority_changed")
                if extra is not None:
                    await extra.check(tx, request)
                await self._check_prepared_policy(tx, request)
                await self._retained_uv(tx, row, actor)
                claim = str(uuid.uuid4())
                await tx.execute("UPDATE {{tables.protected_signer_operations}} SET delivery_claim=$2 WHERE operation_id=$1",
                    operation_id, claim)
                if extra is not None:
                    await extra.check(tx, request)
                    extra.require_fresh()
                await self._retained_uv(tx, row, actor)
                await self._check_session(tx, human_session)
                await fence.check(tx, actor)
                await self._check_prepared_policy(tx, request)
                fence.require_fresh()
                if extra is not None:
                    extra.require_fresh()
                self._session_fresh(human_session)
                if self.clock() >= retained.expires_at:
                    raise SignerRefused("operation_expired")
            if claim is not None:
                if self.clock() >= retained.expires_at:
                    return OperationReceipt(operation_id, "unknown", code="external_effect_unresolved")
                async with asyncio.timeout((retained.expires_at - self.clock()).total_seconds()):
                    await deliver(operation, retained)
                confirmed_until = await observe_confirmation()
        if confirmed_until is not None:
            fence = await self.authority.observe(actor.context, purpose="receipt")
            async with self.db.transaction() as tx:
                row = await self._lock(tx, operation_id)
                await fence.prepare(tx, actor)
                await self._hold_session(tx, actor, human_session)
                if row["result"] is not None or row["refusal_code"] is not None:
                    await self._check_session(tx, human_session)
                    await fence.check(tx, actor)
                    fence.require_fresh()
                    self._session_fresh(human_session)
                    return self._receipt(row)
                provider = self._effect_provider(operation)
                commit = operation.spec.effect.confirmation_commit
                if commit is not None:
                    await getattr(provider, commit)(tx, operation)
                await tx.execute("UPDATE {{tables.protected_signer_operations}} SET result=$2::jsonb,committed_at=$3 WHERE operation_id=$1",
                    operation_id, json.dumps(retained.applied_result()), self.clock())
                await self._emit(AuditKind.PROTECTED_OPERATION_APPLIED, tx, row, actor.principal)
                await self._check_session(tx, human_session)
                await fence.check(tx, actor)
                fence.require_fresh()
                self._session_fresh(human_session)
                if self.clock() >= confirmed_until:
                    raise SignerRefused("evidence_unavailable")
            return OperationReceipt(operation_id, "committed", result=retained.applied_result())
        if self.clock() >= retained.expires_at:
            return OperationReceipt(operation_id, "unknown", code="external_effect_unresolved")
        return self._receipt(row)

    def _sign_artifact(self, operation, artifact):
        adapter = getattr(self.custody, owner_act_operation(operation).spec.signing_port, None)
        if not callable(adapter):
            raise SignerRefused("operation_not_served")
        return adapter(operation, artifact)

    async def _claim_verification(self, operation_id, human, *, human_session=None):
        # A durable phase claim serializes the decision, not its authority. B3
        # verification commits separately, with no caller locks or connection
        # held. A crash remains pending until the original deadline; if B2's
        # decision committed, a retry can proceed directly to the effect.
        fence = await self.authority.observe(human.context, purpose="execute")
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            await fence.prepare(tx, human)
            await self._hold_session(tx, human, human_session)
            if (
                row["verification_claim"] is not None
                or row["result"] is not None
                or row["refusal_code"] is not None
            ):
                await self._check_session(tx, human_session)
                await fence.check(tx, human)
                fence.require_fresh()
                self._session_fresh(human_session)
                return None, row
            if self.clock() >= row["expires_at"]:
                raise SignerRefused("operation_expired")
            claim = str(uuid.uuid4())
            await tx.execute(
                "UPDATE {{tables.protected_signer_operations}} SET verification_claim=$2 WHERE operation_id=$1",
                operation_id,
                claim,
            )
            await self._check_session(tx, human_session)
            await fence.check(tx, human)
            fence.require_fresh()
            self._session_fresh(human_session)
            return claim, row

    async def _refuse_verification(self, operation_id, claim, code):
        # Narrow only this worker's phase. No effect can be concurrent while
        # its B2 approval is still pending and this claim owns verification.
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row["result"] is None and row["verification_claim"] == claim:
                await tx.execute(
                    "UPDATE {{tables.protected_signer_operations}} SET refusal_code=$2,"
                    "candidate_links='{}'::jsonb WHERE operation_id=$1",
                    operation_id,
                    code,
                )

    async def _credential_current(self, tx, human, credential_id):
        return bool(
            await tx.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM {{tables.passkey_credentials}} "
                "WHERE credential_id=$1 AND subject=$2 AND revoked_at IS NULL)",
                credential_id,
                human.subject,
            )
        )

    def _operation(self, request):
        from .http import parse_operation

        return parse_operation(
            {
                key: request[key]
                for key in (
                    "operation_id",
                    "operation",
                    "variant",
                    "scope",
                    "audience",
                    "subject",
                    "redirect_uri",
                )
                if key in request
            }
        )

    def _receipt(self, row):
        if row["result"] is not None:
            return OperationReceipt(row["operation_id"], "committed", result=_json(row["result"]))
        if row["refusal_code"] is not None:
            return OperationReceipt(row["operation_id"], "refused", code=row["refusal_code"])
        if self.clock() >= row["expires_at"]:
            if row.get("signed_result") is not None:
                return OperationReceipt(row["operation_id"], "unknown", code="external_effect_unresolved")
            return OperationReceipt(row["operation_id"], "refused", code="operation_expired")
        return OperationReceipt(
            row["operation_id"],
            "pending",
            code="effect_in_progress"
            if row["verification_claim"] is not None or row.get("signed_result") is not None
            else "awaiting_execute" if row["approval_id"] is None else "awaiting_human",
            expires_at=_stamp(row["expires_at"]),
        )

    async def receipt(
        self, operation_id: str, *, reader: ReceiptReader | AdmittedHuman, human_session=None
    ) -> OperationReceipt:
        if type(reader) not in (ReceiptReader, AdmittedHuman):
            raise SignerRefused("scope_refused")
        row = await self._authorized(operation_id, reader, "receipt", human_session=human_session)
        if row.get("retained_effect") is not None and row["result"] is None:
            return await self._reconcile_retained(operation_id, reader, may_send=False, human_session=human_session)
        if (row["result"] is None and row["refusal_code"] is None and row["approval_id"] is not None
            and owner_act_operation(self._operation(_json(row["request"]))).spec.receipt_uv_expiry):
            approval = await self.store.get(row["approval_id"])
            if approval is not None and approval.state is ApprovalState.APPROVED and approval.decided_by is not None:
                retained = await self.passkeys.retained_proof(approval.decided_by.evidence_ref)
                metadata = retained.metadata
                if (metadata.get("purpose") != "approve" or metadata.get("approval_id") != approval.approval_id
                    or metadata.get("request_sha256") != row["digest"]):
                    raise SignerRefused("evidence_unavailable")
                deadline = min(_time(metadata["challenge_issued_at"]) + timedelta(seconds=300),
                    _time(metadata["challenge_expires_at"]), row["expires_at"])
                if self.clock() >= deadline:
                    return await self._execution_refusal(operation_id, reader, SignerRefused("approval_expired"),
                        human_session=human_session)
        if row["signed_result"] is not None and row["result"] is None:
            return await self._reconcile_admission(operation_id, reader, may_send=False, human_session=human_session)
        return self._receipt(row)
