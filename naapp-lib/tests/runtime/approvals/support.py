"""App-side adapters and fixtures for approval tests.

The primitive runs unmodified against a real PostgreSQL store. What is supplied
here is what an app supplies: its policies, its designated approver, its mailer,
an audit sink, a clock, and an authenticator that verifies real Ed25519
signatures over the primitive's challenge binding.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    Approvals,
    Approver,
    Assurance,
    AuthenticationFailed,
    Candidate,
    Decision,
    DeliveryStatus,
    Evidence,
    PgApprovalStore,
    Purpose,
    TaskAnswerEvidence,
    TaskAnswerRejected,
    challenge_binding,
)
from aweb_naapp.runtime.audit import AuditEvent

SCOPE = "installation-1"
APPROVER = Approver(
    scope=SCOPE,
    subject="human-1",
    subject_type="app_local",
    contact="owner@example.com",
    principal_did="did:aw:human-1",
)
SUCCESSOR = Approver(
    scope=SCOPE,
    subject="human-2",
    subject_type="app_local",
    contact="new@example.com",
    principal_did="did:aw:human-2",
)


def policy(**changes) -> ActionPolicy:
    values = dict(
        policy_ref="send-charge",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=10),
        approver_scopes=(SCOPE,),
    )
    values.update(changes)
    return ActionPolicy(**values)


class Policies:
    def __init__(self, *policies: ActionPolicy) -> None:
        self.by_ref = {p.policy_ref: p for p in policies}

    def set(self, p: ActionPolicy) -> None:
        self.by_ref[p.policy_ref] = p

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        return self.by_ref.get(policy_ref)


class Directory:
    """The app's designations: at most one approver per scope."""

    def __init__(self, approver: Approver | None) -> None:
        self.by_scope: dict[str, Approver] = {}
        self.approver = approver

    @property
    def approver(self) -> Approver | None:
        """The approver designated in `SCOPE`."""
        return self.by_scope.get(SCOPE)

    @approver.setter
    def approver(self, approver: Approver | None) -> None:
        self.by_scope.pop(SCOPE, None)
        if approver is not None:
            self.designate(approver)

    def designate(self, approver: Approver) -> None:
        self.by_scope[approver.scope] = approver

    def undesignate(self, approver: Approver) -> None:
        if self.by_scope.get(approver.scope) == approver:
            del self.by_scope[approver.scope]

    async def candidates(self, policy: ActionPolicy, request) -> list[Approver]:
        return [self.by_scope[s] for s in policy.approver_scopes if s in self.by_scope]

    async def is_current(self, scope: str, subject: str) -> bool:
        current = self.by_scope.get(scope)
        return current is not None and current.subject == subject


@dataclass
class Mailbox:
    """The approver's mailbox: the only place a link token arrives."""

    sent: list[tuple[Approver, str]] = field(default_factory=list)
    by_approval: dict[str, str] = field(default_factory=dict)
    links: dict[tuple[str, str], str] = field(default_factory=dict)
    status: DeliveryStatus = DeliveryStatus.DELIVERED

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus:
        self.sent.append((approver, link_token))
        self.by_approval[approval.approval_id] = link_token
        self.links[(approval.approval_id, approver.subject)] = link_token
        return self.status

    def last_token(self) -> str:
        return self.sent[-1][1]


class AuditOutbox:
    """An app's audit outbox table, written in the transaction of each change."""

    def __init__(self, db) -> None:
        self.db = db

    async def create(self) -> None:
        await self.db.execute(
            "CREATE TABLE {{tables.audit_outbox}} (id SERIAL PRIMARY KEY, kind TEXT NOT NULL, "
            "actor TEXT NOT NULL, subject TEXT NOT NULL, approval_id TEXT, details TEXT NOT NULL)"
        )

    async def emit(self, event: AuditEvent, transaction) -> None:
        await TransactionManager(transaction.connection, self.db).execute(
            "INSERT INTO {{tables.audit_outbox}} (kind, actor, subject, approval_id, details) "
            "VALUES ($1, $2, $3, $4, $5)",
            event.kind.value,
            event.actor,
            event.subject,
            event.approval_id,
            json.dumps(dict(event.details), sort_keys=True),
        )

    async def rows(self) -> list[dict]:
        return await self.db.fetch_all("SELECT * FROM {{tables.audit_outbox}} ORDER BY id")

    async def kinds(self) -> list[str]:
        return [row["kind"] for row in await self.rows()]


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class KeyAuthenticator:
    """Verifies an Ed25519 signature by a registered human over a challenge the
    adapter issued for exactly this approval, candidate, purpose and task
    answer. The evidence names whoever signed, so a signature by someone other
    than the candidate is the primitive's to refuse."""

    def __init__(self, assurance: Assurance) -> None:
        self.assurance = assurance
        self.keys: dict[str, VerifyKey] = {}
        self.issued: dict[bytes, tuple[str, str, Purpose, str | None, bytes]] = {}
        # Runs once a proof has verified, before the primitive records anything:
        # a test makes something else commit at exactly that point.
        self.after_verify: Callable[[], Awaitable[None]] | None = None

    def register(self, subject: str) -> SigningKey:
        key = SigningKey.generate()
        self.keys[subject] = key.verify_key
        return key

    async def challenge(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        task_answer_ref: str | None,
    ) -> dict:
        nonce = uuid.uuid4().bytes
        binding = challenge_binding(approval, candidate, purpose, nonce, task_answer_ref)
        self.issued[binding] = (
            approval.approval_id,
            candidate.subject,
            purpose,
            task_answer_ref,
            nonce,
        )
        return {"challenge": binding.hex()}

    async def verify(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        proof,
        task_answer_ref: str | None,
    ) -> Evidence:
        binding = bytes.fromhex(proof["challenge"])
        issued = self.issued.pop(binding, None)
        if issued is None:
            raise AuthenticationFailed("unknown challenge")
        approval_id, issued_subject, issued_purpose, issued_answer, nonce = issued
        if (approval_id, issued_subject, issued_purpose, issued_answer) != (
            approval.approval_id,
            candidate.subject,
            purpose,
            task_answer_ref,
        ):
            raise AuthenticationFailed("challenge issued for another purpose")
        if challenge_binding(approval, candidate, purpose, nonce, task_answer_ref) != binding:
            raise AuthenticationFailed("approval changed since the challenge")
        key = self.keys.get(proof["subject"])
        if key is None:
            raise AuthenticationFailed("unknown subject")
        try:
            key.verify(binding, bytes.fromhex(proof["signature"]))
        except BadSignatureError as exc:
            raise AuthenticationFailed("bad signature") from exc
        if self.after_verify is not None:
            await self.after_verify()
        return Evidence(
            assurance=self.assurance,
            subject=proof["subject"],
            subject_type="app_local",
            evidence_ref=f"evidence-{uuid.uuid4()}",
        )


class TaskAnswers:
    """Stands in for the app's verification of a member-signed task answer and
    its authoritative receipt: answers it has verified, by reference."""

    def __init__(self) -> None:
        self.verified: dict[str, TaskAnswerEvidence] = {}

    def record(
        self,
        ref: str,
        approval: Approval,
        decision: Decision,
        answered_by: str | None = APPROVER.principal_did,
    ) -> None:
        assert answered_by is not None
        self.verified[ref] = TaskAnswerEvidence(
            task_answer_ref=ref,
            approval_id=approval.approval_id,
            decision=decision,
            request_sha256=approval.request_sha256,
            answered_by=answered_by,
        )

    async def verify(
        self, approval: Approval, decision: Decision, task_answer_ref: str
    ) -> TaskAnswerEvidence:
        evidence = self.verified.get(task_answer_ref)
        if evidence is None:
            raise TaskAnswerRejected(task_answer_ref)
        return evidence


def sign(key: SigningKey, subject: str, challenge: dict) -> dict:
    binding = bytes.fromhex(challenge["challenge"])
    return {
        "challenge": challenge["challenge"],
        "subject": subject,
        "signature": key.sign(binding).signature.hex(),
    }


@dataclass
class World:
    approvals: Approvals
    store: PgApprovalStore
    policies: Policies
    directory: Directory
    mailbox: Mailbox
    audit: AuditOutbox
    clock: Clock
    passkey: KeyAuthenticator
    session: KeyAuthenticator
    approver_key: SigningKey
    approver_session_key: SigningKey
    task_answers: TaskAnswers


async def build_world(db) -> World:
    store = PgApprovalStore(db)
    await store.migrate()
    audit = AuditOutbox(db)
    await audit.create()
    passkey = KeyAuthenticator(Assurance.PASSKEY)
    session = KeyAuthenticator(Assurance.MEMBER_SESSION)
    world = World(
        approvals=None,  # type: ignore[arg-type]
        store=store,
        policies=Policies(
            policy(), policy(policy_ref="internal-edit", min_assurance=Assurance.MEMBER_SESSION)
        ),
        directory=Directory(APPROVER),
        mailbox=Mailbox(),
        audit=audit,
        clock=Clock(),
        passkey=passkey,
        session=session,
        approver_key=passkey.register(APPROVER.subject),
        approver_session_key=session.register(APPROVER.subject),
        task_answers=TaskAnswers(),
    )
    world.approvals = Approvals(
        store=store,
        policies=world.policies,
        approvers=world.directory,
        delivery=world.mailbox,
        authenticators=[passkey, session],
        task_answers=world.task_answers,
        audit=world.audit,
        clock=world.clock,
    )
    return world
