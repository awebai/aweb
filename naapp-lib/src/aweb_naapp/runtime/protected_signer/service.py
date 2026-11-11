"""Single-consume protected owner-act signing over the existing B2/B3 engines."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from awid.signing import canonical_json_bytes, verify_did_key_signature
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
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
)
from aweb_naapp.runtime.audit import AuditEvent, AuditKind, AuditSink
from aweb_naapp.runtime.passkeys import Passkeys, passkey_evidence_commitment

from .types import (
    AdmittedHuman,
    AuthorityProvider,
    ControllerCustody,
    OperationReceipt,
    PreparedOperation,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
)

POLICY_REF = "aweb.human-assurance/1"


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _stamp(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


def _stable_context(context):
    return {k: v for k, v in context.fields().items() if k != "generation"}


class ProtectedSigner:
    """Shared local executor. Unimplemented catalog operations fail closed.

    Passkeys owns UV/challenges/proofs, Approvals owns decisions/consume, and
    the embedding owns current authority and isolated custody. This slice
    executes human-role.revoke only. It does not apply the act remotely.
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
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.db, self.passkeys, self.policies, self.audit = db, passkeys, policies, audit
        self.authority, self.custody, self.clock = authority, custody, clock
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

    async def _lock(self, tx, operation_id):
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise SignerRefused("request_invalid") from None
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

    async def _emit(self, kind, tx, row, actor, *, evidence=None):
        await self.audit.emit(
            AuditEvent(
                kind=kind,
                actor=actor,
                subject=row["operation_id"],
                occurred_at=self.clock(),
                approval_id=row["approval_id"],
                details={
                    "operation": "human-role.revoke",
                    "operation_id": row["operation_id"],
                    "request_sha256": row["digest"],
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
        self, operation: RevokeHumanRole, *, requester: RestrictedRequester
    ) -> PreparedOperation:
        if type(operation) is not RevokeHumanRole or type(requester) is not RestrictedRequester:
            raise SignerRefused("operation_refused")
        if requester.context != operation.context or not requester.principal:
            raise SignerRefused("scope_refused")
        intent = canonical_json_bytes(operation.intent())
        fence = await self.authority.observe(operation.context, purpose="prepare")
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
            fields = {
                "v": 1,
                "type": "aweb.owner-act",
                "act": "human-role.revoke",
                "team_id": operation.context.authority_id,
                "team_key_did": fence.team_key_did,
                "aud": operation.audience,
                "subject": operation.intent()["subject"],
                "nonce": uuid.uuid4().hex,
                "issued_at": _stamp(now),
                "expires_at": _stamp(now + timedelta(seconds=600)),
            }
            owner_act_signing_bytes(fields)  # Existing closed wire validation, no raw-byte route.
            request = {
                **operation.intent(),
                "requester": requester.principal,
                "policy_ref": POLICY_REF,
                "policy_version": policy.version,
                "artifact": fields,
            }
            pending = await self.approvals.mint(
                request=request,
                policy_ref=POLICY_REF,
                requested_by=requester.principal,
                expires_at=_time(fields["expires_at"]),
                tx=tx,
            )
            if pending.approval.policy_version != policy.version:
                raise SignerRefused("policy_changed")
            # B2's candidate link is private server presentation state. It never
            # reaches a requester and cannot replace B3 PASSKEY assurance.
            links = {d.approver.subject: d.link_token for d in pending.deliveries}
            await tx.execute(
                "INSERT INTO {{tables.protected_signer_operations}} "
                "(operation_id,handoff_id,requester,intent,request,digest,approval_id,"
                "candidate_links,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)",
                operation.operation_id,
                str(uuid.uuid4()),
                requester.principal,
                intent,
                canonical_json_bytes(request),
                pending.approval.request_sha256,
                pending.approval.approval_id,
                json.dumps(links),
                pending.approval.expires_at,
            )
            row = await self._lock(tx, operation.operation_id)
            await self._emit(AuditKind.PROTECTED_OPERATION_PREPARED, tx, row, requester.principal)
            await fence.check(tx, requester)
            fence.require_fresh()
            return self._prepared(row)

    async def _authorized(self, operation_id, actor, purpose):
        fence = await self.authority.observe(actor.context, purpose=purpose)
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row is None:
                raise SignerRefused("operation_not_found")
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
            if not isinstance(actor, AdmittedHuman) and row["requester"] != actor.principal:
                raise SignerRefused("scope_refused")
            await fence.check(tx, actor)
            fence.require_fresh()
            return row

    def _link(self, row, human):
        if type(human) is not AdmittedHuman or human.principal != human.context.human_id:
            raise SignerRefused("scope_refused")
        link = _json(row["candidate_links"]).get(human.subject)
        if not link:
            raise SignerRefused("scope_refused")
        return link

    async def approval_options(
        self, operation_id: str, *, human: AdmittedHuman
    ) -> Mapping[str, Any]:
        row = await self._authorized(operation_id, human, "approval")
        if row["refusal_code"] is not None:
            raise SignerRefused(row["refusal_code"])
        link = self._link(row, human)
        if row["result"] is not None or self.clock() >= row["expires_at"]:
            raise SignerRefused("operation_expired")
        return await self.approvals.challenge(
            row["approval_id"],
            Decision.APPROVE,
            Assurance.PASSKEY,
            link_token=link,
        )

    async def execute(
        self, operation_id: str, proof: Mapping[str, Any], *, human: AdmittedHuman
    ) -> OperationReceipt:
        if type(human) is not AdmittedHuman:
            raise SignerRefused("scope_refused")
        row = await self._authorized(operation_id, human, "execute")
        if row["result"] is not None or row["refusal_code"] is not None:
            return self._receipt(row)
        link = self._link(row, human)
        approval = await self.store.get(row["approval_id"])
        if approval is None:
            raise SignerRefused("approval_spent")
        if approval.state is ApprovalState.PENDING:
            claim, phase = await self._claim_verification(operation_id, human)
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
                    await self._refuse_verification(operation_id, claim, "proof_invalid")
                    raise SignerRefused("proof_invalid") from exc
        decided = approval.decided_by
        if decided is None or (decided.subject, decided.scope, decided.assurance) != (
            human.subject,
            human.b3_scope,
            Assurance.PASSKEY,
        ):
            raise SignerRefused("scope_refused")
        fence = await self.authority.observe(human.context, purpose="execute")
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            if row is None:
                raise SignerRefused("operation_not_found")
            await fence.prepare(tx, human)
            if row["result"] is not None:
                await fence.check(tx, human)
                fence.require_fresh()
                return self._receipt(row)
            request = _json(row["request"])
            if fence.team_key_did != request["artifact"]["team_key_did"]:
                raise SignerRefused("authority_changed")
            held = await self.passkeys.prepare_current_approvers(
                tx, [(human.b3_scope, human.subject)]
            )
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
            signature = self.custody.sign_owner_act(operation, request["artifact"])
            signing = owner_act_signing_bytes(request["artifact"])
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
            await tx.execute(
                "UPDATE {{tables.protected_signer_operations}} SET result=$2::jsonb,"
                "evidence_ref=$3,committed_at=$4,candidate_links='{}'::jsonb WHERE operation_id=$1",
                operation_id,
                json.dumps(result),
                decided.evidence_ref,
                self.clock(),
            )
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
            await fence.check(tx, human)  # Final await: caller's held F6/authority checks.
            fence.require_fresh()
            if self.clock() >= deadline:
                raise SignerRefused("gesture_expired")
        return OperationReceipt(operation_id, "committed", result=result)

    async def _claim_verification(self, operation_id, human):
        # A durable phase claim serializes the decision, not its authority. B3
        # verification commits separately, with no caller locks or connection
        # held. A crash remains pending until the original deadline; if B2's
        # decision committed, a retry can proceed directly to the effect.
        fence = await self.authority.observe(human.context, purpose="execute")
        async with self.db.transaction() as tx:
            row = await self._lock(tx, operation_id)
            await fence.prepare(tx, human)
            if (
                row["verification_claim"] is not None
                or row["result"] is not None
                or row["refusal_code"] is not None
            ):
                await fence.check(tx, human)
                fence.require_fresh()
                return None, row
            if self.clock() >= row["expires_at"]:
                raise SignerRefused("operation_expired")
            claim = str(uuid.uuid4())
            await tx.execute(
                "UPDATE {{tables.protected_signer_operations}} SET verification_claim=$2 WHERE operation_id=$1",
                operation_id,
                claim,
            )
            await fence.check(tx, human)
            fence.require_fresh()
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
        from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext

        c, a, h = request["scope"], request["scope"]["authority"], request["scope"]["human"]
        context = ProtectedKeyContext(
            c["service_id"], a["kind"], a["id"], a["domain"], h["id"], h["domain"], c["generation"]
        )
        s = request["subject"]
        return RevokeHumanRole(
            request["operation_id"],
            context,
            request["audience"],
            s["app_id"],
            s["installation_id"],
            s["role"],
            s["principal"],
        )

    def _receipt(self, row):
        if row["result"] is not None:
            return OperationReceipt(row["operation_id"], "committed", result=_json(row["result"]))
        if row["refusal_code"] is not None:
            return OperationReceipt(row["operation_id"], "refused", code=row["refusal_code"])
        if self.clock() >= row["expires_at"]:
            return OperationReceipt(row["operation_id"], "refused", code="operation_expired")
        return OperationReceipt(
            row["operation_id"],
            "pending",
            code="effect_in_progress"
            if row["verification_claim"] is not None
            else "awaiting_human",
            expires_at=_stamp(row["expires_at"]),
        )

    async def receipt(
        self, operation_id: str, *, reader: ReceiptReader | AdmittedHuman
    ) -> OperationReceipt:
        if type(reader) not in (ReceiptReader, AdmittedHuman):
            raise SignerRefused("scope_refused")
        return self._receipt(await self._authorized(operation_id, reader, "receipt"))
