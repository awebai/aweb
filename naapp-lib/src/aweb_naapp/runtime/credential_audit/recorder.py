"""B3 authorization associations and signed governance in the original effect tx.

Preparation fetches only a registration view and admitted G1 context before
locks. It grants no authority. Completion's explicit effect fence holds F6
before B3 and checks live state after the signed enqueue, before commit.

The app answers two questions in the original transaction: the catalog role
of one of its scopes (``role_of``), and, only when its scopes can be
designated or changed by an owner approval rather than an owner act, how that
approval is read and which scopes hold owner authority (``approvals``). An
app that keeps its own record of governance takes each signed event in the
transaction that enqueued it (``after_enqueue``); its failure rolls the whole
effect back.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager
from webauthn.helpers import base64url_to_bytes

from aweb_naapp.hooks.owner_act import PREFIX, HumanCredential, VerifiedOwnerAct
from aweb_naapp.hooks.producer import HookProducerFactory, RegistrationView
from aweb_naapp.roles import HoldingRecord, holding_record_of_scope, holding_scope
from aweb_naapp.runtime.approvals import Approval, ApprovalState, Assurance
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationDispatchFence,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.links import link_verifier
from aweb_naapp.runtime.passkeys import (
    ContactChangeRefused,
    CredentialChangeRefused,
    EnrolmentRefused,
    OwnerApproval,
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    Passkeys,
    ProofContextResolver,
    ProofContextUnavailable,
    contact_sha256,
    prepare_retirement,
)
from aweb_naapp.runtime.passkeys.credential_change import PreparedCredentialChange

if TYPE_CHECKING:
    from aweb_naapp.console import ConsoleSession
    from aweb_naapp.runtime.credential_audit.narrowing import PreparedContainment
    from aweb_naapp.runtime.team_auth import Principal


_HOOK = "post-governance-hook"
_SYSTEM = {"authority_mode": "system", "attestations": []}
_LOCAL = {AuditKind.APPROVER_LOGGED_IN, AuditKind.APPROVER_ENROLMENT_REISSUED}

_CREDENTIAL_KINDS = frozenset(
    {
        AuditKind.APPROVER_DESIGNATED,
        AuditKind.APPROVER_REDESIGNATED,
        AuditKind.APPROVER_ENROLLED,
        AuditKind.APPROVER_ENROLMENT_REISSUED,
        AuditKind.APPROVER_RETIRED,
        AuditKind.APPROVER_PASSKEY_REVOKED,
        AuditKind.APPROVER_PASSKEY_ADDED,
        AuditKind.APPROVER_PASSKEY_REPLACED,
        AuditKind.APPROVER_CONTACT_CHANGE_SCHEDULED,
        AuditKind.APPROVER_CONTACT_CHANGE_BY_OWNER_SCHEDULED,
        AuditKind.APPROVER_CONTACT_CHANGE_CANCELLED,
        AuditKind.APPROVER_CONTACT_PROVEN,
        AuditKind.APPROVER_LOGGED_IN,
    }
)
_CHANGE_KINDS = frozenset(
    {
        AuditKind.APPROVAL_REQUESTED,
        AuditKind.APPROVAL_DECIDED,
        AuditKind.APPROVAL_REVOKED,
        AuditKind.DISPATCH_ADMITTED,
        AuditKind.DISPATCH_OUTCOME,
    }
)


def is_credential_event(event: AuditEvent) -> bool:
    return event.kind in _CREDENTIAL_KINDS


class RoleOf(Protocol):
    async def __call__(
        self, tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
    ) -> str | None:
        """The catalog role of the app's ``scope`` in ``admitted``, or None."""
        ...


class ApprovalGovernance(Protocol):
    """How the app's owner approvals govern credentials: its change policy's
    prefix, the plain B2 reader on the original transaction, and which scopes
    hold owner authority in an installation."""

    policy_prefix: str

    async def approval(self, tx: TransactionManager, approval_id: str) -> Approval | None: ...

    async def is_authority_scope(
        self, tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
    ) -> bool: ...


class GovernanceUnavailable(RuntimeError):
    code = "release_context_unavailable"
    status = 503

    def __init__(self) -> None:
        super().__init__("credential governance context unavailable")


@dataclass(frozen=True, repr=False)
class _OwnerActContext:
    owner: CredentialAudit
    admitted: AdmittedInstallation
    view: RegistrationView | None
    signing: bytes
    signature: str


# The owner act each designation event is paired with, by whether the scope's
# role is declared with the human-role acts (human-role-holders.md, What the
# credential audit retains). Neither pairing stands in for the other.
_DESIGNATION_ACTS = {
    False: {
        AuditKind.APPROVER_DESIGNATED: "app-role.designate",
        AuditKind.APPROVER_REDESIGNATED: "app-credential.recover",
    },
    True: {
        AuditKind.APPROVER_DESIGNATED: "human-role.designate",
        AuditKind.APPROVER_REDESIGNATED: "human-credential.replace",
    },
}


def _new_credential_ref() -> str:
    """An opaque reference for a key's receipts, never derived from the key."""
    return "key_" + uuid4().hex


def _owner_act_actor(event: AuditEvent) -> dict:
    return {"authority_mode": "owner_act", "did_key": event.actor, "attestations": []}


@dataclass(frozen=True, repr=False)
class _ApprovalContext:
    owner: CredentialAudit
    admitted: AdmittedInstallation
    view: RegistrationView | None
    evidence: OwnerApproval


@dataclass(repr=False)
class PreparedEnrolment:
    """One root context, one capability and one original B3 effect transaction."""

    owner: CredentialAudit
    admitted: AdmittedInstallation
    view: RegistrationView | None
    enrolment_id: str
    subject: str
    _fence: InstallationDispatchFence = field(init=False)
    _tx: TransactionManager | None = field(init=False, default=None)
    _event: AuditEvent | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._fence = self.owner.fence.for_installation(self.admitted)

    async def prepare(self, tx: TransactionManager) -> None:
        if self._tx is not None:
            raise GovernanceUnavailable()
        try:
            await self._fence.prepare(tx)
            # Hold the designation before B3's enrolment/credential writes.
            await tx.fetch_one(
                "SELECT subject FROM {{tables.passkey_approvers}} WHERE subject=$1 FOR SHARE",
                self.subject,
            )
            await tx.fetch_one(
                "SELECT enrolment_id FROM {{tables.passkey_enrolments}} WHERE enrolment_id=$1 FOR UPDATE",
                self.enrolment_id,
            )
            row = await self.owner._completion(tx, self)
            await self._fence.check(tx, None)
            self.owner._valid_completion(row, self, after=False)
        except InstallationRefused:
            raise EnrolmentRefused("enrolment authority unavailable") from None
        self._tx = tx

    async def check(self, tx: TransactionManager) -> None:
        if self._tx is not tx or self._event is None:
            raise GovernanceUnavailable()
        try:
            row = await self.owner._completion(tx, self)
            await self._fence.check(tx, None)
            # Sample time after the final awaited read, not before a lock wait.
            self.owner._valid_completion(row, self, after=True)
        except InstallationRefused:
            raise EnrolmentRefused("enrolment authority unavailable") from None


@dataclass(repr=False)
class PreparedContactProof:
    """Reachability completion of one historically authorized candidate."""

    owner: CredentialAudit
    admitted: AdmittedInstallation
    view: RegistrationView | None
    proof_id: str
    subject: str
    _fence: InstallationDispatchFence = field(init=False)
    _tx: TransactionManager | None = field(init=False, default=None)
    _event: AuditEvent | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._fence = self.owner.fence.for_installation(self.admitted)

    async def prepare(self, tx: TransactionManager) -> None:
        if self._tx is not None:
            raise GovernanceUnavailable()
        try:
            await self._fence.prepare(tx)
            # B3 also takes the approver before its contact-proof row.
            await tx.fetch_one(
                "SELECT subject FROM {{tables.passkey_approvers}} WHERE subject=$1 FOR UPDATE",
                self.subject,
            )
            await tx.fetch_one(
                "SELECT proof_id FROM {{tables.passkey_contact_proofs}} WHERE proof_id=$1 FOR UPDATE",
                self.proof_id,
            )
            row = await self.owner._contact_completion(tx, self)
            await self._fence.check(tx, None)
            self.owner._valid_contact_completion(row, self, after=False)
        except InstallationRefused:
            raise ContactChangeRefused("contact_proof_unavailable") from None
        self._tx = tx

    async def check(self, tx: TransactionManager) -> None:
        if self._tx is not tx or self._event is None:
            raise GovernanceUnavailable()
        try:
            row = await self.owner._contact_completion(tx, self)
            await self._fence.check(tx, None)
            self.owner._valid_contact_completion(row, self, after=True)
        except InstallationRefused:
            raise ContactChangeRefused("contact_proof_unavailable") from None


@dataclass(repr=False)
class PreparedCredentialChangeAudit:
    """The recorder's credential-change fence for one scope, in one original
    B3 effect transaction.

    `prepare` takes, in order: F6 (the installation fence), the installation's
    retirement gate, the app's `role_holds` (role and holding locks only,
    never B3 or session ones), then B3's write preparation, then checks F6;
    it returns B3's handle. An app that holds sessions takes S4 after prepare
    returns. Where the change also runs under the shared protected-operation
    receipt, that operation's lock is taken before this prepare, never after.
    `check` rechecks F6 after the event was recorded in this transaction."""

    owner: CredentialAudit
    admitted: AdmittedInstallation
    view: RegistrationView | None
    scope: str
    role_holds: Callable[[TransactionManager], Awaitable[None]] | None = None
    _fence: InstallationDispatchFence = field(init=False)
    _tx: TransactionManager | None = field(init=False, default=None)
    _event: AuditEvent | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._fence = self.owner.fence.for_installation(self.admitted)

    async def prepare(self, tx: TransactionManager) -> PreparedCredentialChange:
        if self._tx is not None:
            raise GovernanceUnavailable()
        try:
            await self._fence.prepare(tx)
            await prepare_retirement(tx, installation=self.admitted)
            if self.role_holds is not None:
                await self.role_holds(tx)
            prepared = await self.owner._passkeys().prepare_credential_change(tx, scope=self.scope)
            await self._fence.check(tx, None)
        except InstallationRefused:
            raise CredentialChangeRefused("completion_authority_unavailable") from None
        self._tx = tx
        return prepared

    async def check(self, tx: TransactionManager) -> None:
        if self._tx is not tx or self._event is None:
            raise GovernanceUnavailable()
        try:
            await self._fence.check(tx, None)
        except InstallationRefused:
            raise CredentialChangeRefused("completion_authority_unavailable") from None


class CredentialAudit:
    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        app_id: str,
        fence: InstallationFence,
        contexts: ProofContextResolver,
        owner_act_scope: str,
        producer: HookProducerFactory,
        passkeys: Callable[[], Passkeys],
        role_of: RoleOf,
        registration_view: Callable[[str], Awaitable[RegistrationView | None]],
        max_backlog_age: timedelta,
        migration_module: str,
        approvals: ApprovalGovernance | None = None,
        after_enqueue: Callable[[TransactionManager, UUID], Awaitable[None]] | None = None,
        ungated_acts: frozenset[str] = frozenset(),
        human_roles: frozenset[str] = frozenset(),
    ) -> None:
        if ungated_acts and after_enqueue is None:
            raise ValueError(
                "an act recorded with no registered target must be written to the app's"
                " own record in the transaction that enqueued it"
            )
        if (
            not app_id
            or app_id != fence.app_id
            or not owner_act_scope
            or max_backlog_age <= timedelta(0)
            or not migration_module
        ):
            raise ValueError(
                "credential governance requires its exact app, verifier and backlog bound"
            )
        self.db, self.fence = db, fence
        self._app_id, self._contexts, self._owner_act_scope = app_id, contexts, owner_act_scope
        self._producer, self._passkeys = producer, passkeys
        self._role_of, self._approvals = role_of, approvals
        self._view, self._max_backlog_age = registration_view, max_backlog_age
        self._migration_module, self._after_enqueue = migration_module, after_enqueue
        # Fixed in the app's reviewed code, never configuration (ruling ed36580d).
        self._ungated_acts = ungated_acts
        # The roles the app declares with the human-role acts, fixed in its
        # reviewed code: the declaration, never a stored row, decides which
        # owner acts a scope's events pair with.
        self._human_roles = human_roles
        self._prepared: ContextVar[
            _OwnerActContext
            | _ApprovalContext
            | PreparedEnrolment
            | PreparedContactProof
            | PreparedCredentialChangeAudit
            | PreparedContainment
            | None
        ] = ContextVar("credential_governance", default=None)

    async def migrate(self) -> None:
        await AsyncMigrationManager(
            self.db,
            migrations_path=str(Path(__file__).with_name("migrations")),
            module_name=self._migration_module,
        ).apply_pending_migrations()

    def is_change_approval(self, event: AuditEvent) -> bool:
        return (
            self._approvals is not None
            and event.kind in _CHANGE_KINDS
            and event.details.get("policy_ref", "").split("|", 1)[0]
            == self._approvals.policy_prefix
        )

    @contextmanager
    def prepared(
        self,
        context: _OwnerActContext
        | _ApprovalContext
        | PreparedEnrolment
        | PreparedContactProof
        | PreparedCredentialChangeAudit
        | PreparedContainment
        | None,
    ) -> Iterator[None]:
        if context is not None and context.owner is not self:
            raise GovernanceUnavailable()
        token = self._prepared.set(context)
        try:
            yield
        finally:
            self._prepared.reset(token)

    @contextmanager
    def approved(
        self,
        admitted: AdmittedInstallation,
        evidence: OwnerApproval,
        view: RegistrationView | None,
    ) -> Iterator[None]:
        """Bind the writer's actually admitted B3 evidence and prefetched view."""
        if (
            self._approvals is None
            or admitted.app_id != self._app_id
            or not isinstance(evidence, OwnerApproval)
        ):
            raise GovernanceUnavailable()
        with self.prepared(_ApprovalContext(self, admitted, view, evidence)):
            yield

    async def prepare_containment(
        self,
        tx: TransactionManager,
        *,
        admitted: AdmittedInstallation,
        principal: Principal | None = None,
        session: ConsoleSession | None = None,
        signed_trace_id: str | None = None,
    ) -> PreparedContainment:
        from aweb_naapp.runtime.credential_audit.narrowing import prepare_containment

        return await prepare_containment(
            self,
            tx,
            admitted=admitted,
            principal=principal,
            session=session,
            signed_trace_id=signed_trace_id,
        )

    async def record_role_revoked(
        self,
        tx: TransactionManager,
        *,
        context: PreparedContainment,
        role: str,
        subject_ref: str,
        occurred_at: datetime,
    ) -> UUID:
        from aweb_naapp.runtime.credential_audit.narrowing import record_role_revoked

        return await record_role_revoked(
            self,
            tx,
            context=context,
            role=role,
            subject_ref=subject_ref,
            occurred_at=occurred_at,
        )

    async def prepare_owner_act(
        self, admitted: AdmittedInstallation, *, signing: bytes, signature: str
    ) -> _OwnerActContext:
        if admitted.app_id != self._app_id:
            raise GovernanceUnavailable()
        return _OwnerActContext(
            self, admitted, await self._view(admitted.team_id), signing, signature
        )

    async def record_owner_act(
        self,
        tx: TransactionManager,
        act: VerifiedOwnerAct,
        payload: Mapping[str, Any],
        *,
        occurred_at: datetime,
    ) -> UUID:
        """Record the governance event of one of the app's own owner acts in the
        effect's transaction ``tx``, under the act prepared by
        :meth:`prepare_owner_act` and consumed in ``tx``. ``payload`` is the
        event's act fields; the recorder adds the owner-act authority and the
        act's digest. A widening act needs a current registered target unless
        the app exempts it."""
        context = self._prepared.get()
        if not isinstance(context, _OwnerActContext) or context.owner is not self:
            raise GovernanceUnavailable()
        digest = hashlib.sha256(context.signing).hexdigest()
        consumed = await tx.fetch_one(
            "SELECT nonce FROM {{tables.owner_act_nonces}} WHERE scope=$1 AND team_id=$2 AND act_sha256=$3",
            self._owner_act_scope,
            context.admitted.team_id,
            digest,
        )
        if (
            consumed is None
            or consumed["nonce"] != act.nonce
            or act.team_id != context.admitted.team_id
            or act.transaction_id != await tx.fetch_value("SELECT txid_current()")
            or {"authority", "owner_act_sha256"} & set(payload)
        ):
            raise GovernanceUnavailable()
        actor = {
            "authority_mode": "owner_act",
            "did_key": act.fields["team_key_did"],
            "attestations": [],
        }
        return await self._enqueue(
            tx,
            context.admitted,
            {**payload, "authority": "owner_act", "owner_act_sha256": digest},
            actor,
            occurred_at,
            context.view,
        )

    async def prepare_enrolment(self, token: str) -> PreparedEnrolment:
        row = await self.db.fetch_one(
            "SELECT a.*,c.enrolment_id FROM {{tables.credential_authorizations}} a "
            "JOIN {{tables.credential_completion_links}} c USING(subject) WHERE c.verifier_sha256=$1",
            link_verifier(token),
        )
        if row is None:
            raise EnrolmentRefused("enrolment authorization unavailable")
        # Refresh the ONE shared source before opening the completion tx.
        try:
            current = (await self.fence.permit(row["team_id"])).admitted
        except InstallationRefused:
            raise EnrolmentRefused("enrolment authority unavailable") from None
        if current != self._admitted(row):
            raise EnrolmentRefused("enrolment authority changed")
        return PreparedEnrolment(
            self, current, await self._view(current.team_id), row["enrolment_id"], row["subject"]
        )

    async def prepare_credential_change(
        self,
        scope: str,
        *,
        role_holds: Callable[[TransactionManager], Awaitable[None]] | None = None,
    ) -> PreparedCredentialChangeAudit:
        """The fence of one scope's credential change, resolved and refreshed
        before any lock: the scope's installation, admitted now, and its
        registration view. `role_holds` takes the app's role and holding locks."""
        try:
            async with self.db.transaction() as tx:
                resolved = await self._contexts(scope, tx=tx)
            current = (await self.fence.permit(resolved.team_id)).admitted
        except (ProofContextUnavailable, InstallationRefused):
            raise CredentialChangeRefused("completion_authority_unavailable") from None
        if resolved.fields() != {
            "app_id": current.app_id,
            "team_id": current.team_id,
            "installation_id": current.installation_id,
            "generation": current.generation,
        }:
            raise CredentialChangeRefused("completion_authority_unavailable")
        return PreparedCredentialChangeAudit(
            self, current, await self._view(current.team_id), scope, role_holds
        )

    async def prepare_contact_proof(self, token: str) -> PreparedContactProof:
        row = await self.db.fetch_one(
            "SELECT * FROM {{tables.credential_contact_candidates}} WHERE verifier_sha256=$1",
            link_verifier(token),
        )
        if row is None:
            raise ContactChangeRefused("contact_proof_unavailable")
        try:
            current = (await self.fence.permit(row["team_id"])).admitted
        except InstallationRefused:
            raise ContactChangeRefused("contact_proof_unavailable") from None
        if current != self._admitted(row):
            raise ContactChangeRefused("contact_proof_unavailable")
        return PreparedContactProof(
            self, current, await self._view(current.team_id), row["proof_id"], row["subject"]
        )

    @staticmethod
    def _admitted(row) -> AdmittedInstallation:
        return AdmittedInstallation(
            team_id=row["team_id"],
            app_id=row["app_id"],
            installation_id=row["installation_id"],
            generation=row["generation"],
        )

    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        tx = transaction
        if self.is_change_approval(event):
            # B2 change ceremonies are local audit. The writer signs the actual
            # governance effect with its retained APPROVE in the same commit.
            assert self._approvals is not None  # is_change_approval holds only with approvals
            approval = (
                await self._approvals.approval(tx, event.approval_id) if event.approval_id else None
            )
            if approval is None or (
                approval.policy_ref != event.details.get("policy_ref")
                or approval.request_sha256 != event.details.get("request_sha256")
                or str(approval.policy_version) != event.details.get("policy_version")
            ):
                raise GovernanceUnavailable()
        elif event.kind in {AuditKind.APPROVER_DESIGNATED, AuditKind.APPROVER_REDESIGNATED}:
            await self._designated(event, tx)
        elif event.kind is AuditKind.APPROVER_ENROLLED:
            await self._enrolled(event, tx)
        elif event.kind is AuditKind.APPROVER_CONTACT_CHANGE_BY_OWNER_SCHEDULED:
            await self._contact_scheduled(event, tx)
        elif event.kind is AuditKind.APPROVER_CONTACT_PROVEN:
            await self._contact_proven(event, tx)
        elif event.kind in {AuditKind.APPROVER_PASSKEY_ADDED, AuditKind.APPROVER_PASSKEY_REPLACED}:
            await self._credential_changed(event, tx)
        elif event.kind in {AuditKind.APPROVER_RETIRED, AuditKind.APPROVER_PASSKEY_REVOKED}:
            from aweb_naapp.runtime.credential_audit.narrowing import record_narrowing

            await record_narrowing(self, event, tx, self._prepared.get())
        elif event.kind not in _LOCAL:
            # No kind is silently dropped or allowed through another producer.
            raise GovernanceUnavailable()
        elif event.kind is AuditKind.APPROVER_ENROLMENT_REISSUED:
            await self._associate_links(tx, event.subject)
        await tx.execute(
            "INSERT INTO {{tables.credential_audit_events}} "
            "(kind,actor,subject,occurred_at,approval_id,details) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
            event.kind.value,
            event.actor,
            event.subject,
            event.occurred_at,
            event.approval_id,
            json.dumps(dict(event.details)),
        )

    async def _designated(self, event: AuditEvent, tx: TransactionManager) -> None:
        context = self._prepared.get()
        if not isinstance(context, (_OwnerActContext, _ApprovalContext)):
            raise GovernanceUnavailable()
        scope = event.details.get("scope")
        if not isinstance(scope, str) or not scope:
            raise GovernanceUnavailable()
        await self._require_scope(tx, scope, context.admitted)
        holder = await tx.fetch_one(
            "SELECT * FROM {{tables.passkey_approvers}} WHERE subject=$1 AND scope=$2 AND superseded_at IS NULL",
            event.subject,
            scope,
        )
        if holder is None or holder["designated_by"] != event.actor:
            raise GovernanceUnavailable()
        role = await self._role(tx, scope, context.admitted)
        human = role in self._human_roles
        approval_id, signing, signature, retained = None, None, None, None
        if isinstance(context, _OwnerActContext):
            digest = await self._consumed_act(
                tx, context, event, _DESIGNATION_ACTS[human][event.kind]
            )
            authority, signing, signature = "owner_act", context.signing, context.signature
            actor = _owner_act_actor(event)
        elif human:
            # An approval never designates or replaces a human-role holder.
            raise GovernanceUnavailable()
        else:
            digest, retained = await self._approved_proof(tx, context, event, scope)
            authority, approval_id, actor = "passkey_session", context.evidence.approval_id, _SYSTEM
        if human:
            assert isinstance(context, _OwnerActContext)
            model = await self._holder_model(tx, context, event, holder, scope, role)
        elif holder["principal"] is not None:
            raise GovernanceUnavailable()
        else:
            model = (contact_sha256(holder["contact"]), None, None, None, None)
        await tx.execute(
            "INSERT INTO {{tables.credential_authorizations}} "
            "(subject,scope,app_id,team_id,installation_id,generation,role,contact_sha256,effective_at,"
            "authority,commitment,approval_id,signing,signature,retained_proof,created_at,"
            "principal,credential_sha256,notice_contact_sha256,credential_ref) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20)",
            event.subject,
            scope,
            self._app_id,
            context.admitted.team_id,
            context.admitted.installation_id,
            context.admitted.generation,
            role,
            model[0],
            holder["effective_at"],
            authority,
            digest,
            approval_id,
            signing,
            signature,
            retained,
            event.occurred_at,
            *model[1:],
        )
        await self._associate_links(tx, event.subject)
        payload = dict(
            act="role.designated"
            if event.kind is AuditKind.APPROVER_DESIGNATED
            else "credential.recovered",
            direction="widening",
            subject_ref=event.subject,
            role=role,
            **self._authority_payload(
                dict(authority=authority, commitment=digest, approval_id=approval_id)
            ),
        )
        await self._enqueue(tx, context.admitted, payload, actor, event.occurred_at, context.view)

    async def _holder_model(self, tx, context, event, holder, scope, role):
        """The human model's authorization columns for a holder the consumed act
        binds: its principal, its credential and notice contact as the act names
        them, and a new opaque key reference. Each is checked against the act's
        own subject and the stored credential, never taken from the event."""
        signed = self.signed_subject(context)
        record = await self.human_record(tx, scope, context.admitted, signed)
        if record is None or record.role != role or holder["principal"] != record.principal:
            raise GovernanceUnavailable()
        keys = await tx.fetch_all(
            "SELECT credential_id,public_key,rp_id FROM {{tables.passkey_credentials}} "
            "WHERE subject=$1 AND revoked_at IS NULL",
            event.subject,
        )
        notice = signed.get("notice_contact_sha256")
        if (
            len(keys) != 1
            or keys[0]["rp_id"] is None
            or HumanCredential(
                bytes(keys[0]["credential_id"]), bytes(keys[0]["public_key"]), keys[0]["rp_id"]
            ).sha256
            != signed.get("credential_sha256")
            or (holder["contact"] is None) != (notice is None)
            or (holder["contact"] is not None and contact_sha256(holder["contact"]) != notice)
        ):
            raise GovernanceUnavailable()
        return (None, record.principal, signed["credential_sha256"], notice, _new_credential_ref())

    @staticmethod
    def signed_document(context: _OwnerActContext) -> dict[str, Any]:
        """The prepared act as signed, from its retained signing bytes, which
        the consumed nonce's digest binds."""
        if not context.signing.startswith(PREFIX):
            raise GovernanceUnavailable()
        document = json.loads(context.signing[len(PREFIX) :])
        if not isinstance(document, dict):
            raise GovernanceUnavailable()
        return document

    @classmethod
    def signed_subject(cls, context: _OwnerActContext) -> dict[str, Any]:
        """The subject of the prepared act, as signed."""
        subject = cls.signed_document(context).get("subject")
        if not isinstance(subject, dict):
            raise GovernanceUnavailable()
        return subject

    async def human_record(
        self, tx, scope: str, admitted: AdmittedInstallation, signed: Mapping[str, Any]
    ) -> HoldingRecord | None:
        """The holding record the consumed act names, when ``scope`` is exactly
        that holding's scope in the admitted installation and its role is
        declared human; None when the scope is not a human-declared holding's.
        A scope that is not the act's own holding refuses."""
        record = await self.declared_human_record(tx, scope)
        if record is None:
            return None
        try:
            named = holding_scope(
                admitted.installation_id, admitted.team_id, signed["role"], signed["principal"]
            )
        except (KeyError, TypeError, ValueError):
            raise GovernanceUnavailable() from None
        if (
            signed.get("app_id") != self._app_id
            or signed.get("installation_id") != admitted.installation_id
            or scope != named
            or (record.installation_id, record.team_id, record.role, record.principal)
            != (admitted.installation_id, admitted.team_id, signed["role"], signed["principal"])
        ):
            raise GovernanceUnavailable()
        return record

    async def scope_role(self, tx, scope: str) -> str | None:
        """The role ``scope`` belongs to, current or ended: its holding
        record's, or else the role retained with its latest authorization."""
        if self._human_roles:
            record = await holding_record_of_scope(tx, scope)
            if record is not None:
                return record.role
        return await tx.fetch_value(
            "SELECT role FROM {{tables.credential_authorizations}} WHERE scope=$1 "
            "ORDER BY created_at DESC LIMIT 1",
            scope,
        )

    async def declared_human_record(self, tx, scope: str) -> HoldingRecord | None:
        """The installation's holding record for ``scope`` when its role is
        declared with the human-role acts; None for any other scope."""
        if not self._human_roles:
            return None
        record = await holding_record_of_scope(tx, scope)
        return record if record is not None and record.role in self._human_roles else None

    async def _consumed_act(self, tx, context: _OwnerActContext, event, expected_act) -> str:
        """The SHA-256 of the prepared act, which this event names and which
        was consumed for this team under this app's owner-act scope. The act
        it signs, not only the event's label for it, is ``expected_act``."""
        digest = hashlib.sha256(context.signing).hexdigest()
        nonce = await tx.fetch_one(
            "SELECT nonce FROM {{tables.owner_act_nonces}} WHERE scope=$1 AND team_id=$2 AND act_sha256=$3",
            self._owner_act_scope,
            context.admitted.team_id,
            digest,
        )
        if (
            nonce is None
            or event.details.get("owner_act_id") != f"{context.admitted.team_id}:{nonce['nonce']}"
            or event.details.get("owner_act_kind") != expected_act
            or self.signed_document(context).get("act") != expected_act
        ):
            raise GovernanceUnavailable()
        return digest

    async def _approved_proof(self, tx, context, event, scope):
        evidence = context.evidence
        if event.kind is AuditKind.APPROVER_DESIGNATED:
            bound = (
                event.details.get("owner_act_id") == f"approval:{evidence.approval_id}:{scope}"
                and event.details.get("owner_act_kind") == "app-role.designate"
            )
        elif event.kind is AuditKind.APPROVER_CONTACT_CHANGE_BY_OWNER_SCHEDULED:
            bound = event.details.get("owner_approval_id") == evidence.approval_id
        else:
            bound = False
        if (
            not bound
            or evidence.transaction_id != await tx.fetch_value("SELECT txid_current()")
            or event.actor != evidence.approver_subject
        ):
            raise GovernanceUnavailable()
        # This is the shared store's non-locking reader on the original tx.
        approval = await self._approvals.approval(tx, evidence.approval_id)
        if (
            approval is None
            or approval.state is not ApprovalState.CONSUMED
            or not approval.consumed_operation_id
            or approval.decided_by is None
            or approval.decided_by.assurance is not Assurance.PASSKEY
            or (approval.decided_by.scope, approval.decided_by.subject)
            != (evidence.approver_scope, evidence.approver_subject)
        ):
            raise GovernanceUnavailable()
        if not await self._approvals.is_authority_scope(
            tx, scope=evidence.approver_scope, admitted=context.admitted
        ):
            raise GovernanceUnavailable()
        passkeys = self._passkeys()
        try:
            proof = await passkeys.retained_proof(approval.decided_by.evidence_ref, tx=tx)
            if any(
                proof.metadata.get(name) != expected
                for name, expected in (
                    ("approval_id", approval.approval_id),
                    ("request_sha256", approval.request_sha256),
                    ("policy_ref", approval.policy_ref),
                    ("policy_version", approval.policy_version),
                )
            ):
                raise GovernanceUnavailable()
            commitment = await passkeys.evidence_commitment(
                approval.decided_by.evidence_ref,
                context=PasskeyInstallationContext(
                    context.admitted.app_id,
                    context.admitted.team_id,
                    context.admitted.installation_id,
                    context.admitted.generation,
                ),
                scope=evidence.approver_scope,
                subject=evidence.approver_subject,
                purpose="approve",
                tx=tx,
            )
        except PasskeyProofUnavailable:
            raise GovernanceUnavailable() from None
        return commitment, json.dumps(proof.export())

    async def _require_scope(self, tx, scope, admitted) -> None:
        try:
            resolved = await self._contexts(scope, tx=tx)
        except ProofContextUnavailable:
            raise GovernanceUnavailable() from None
        if resolved.fields() != {
            "app_id": admitted.app_id,
            "team_id": admitted.team_id,
            "installation_id": admitted.installation_id,
            "generation": admitted.generation,
        }:
            raise GovernanceUnavailable()

    @staticmethod
    def _authority_payload(row):
        if row["authority"] == "owner_act":
            return {"authority": "owner_act", "owner_act_sha256": row["commitment"]}
        return {
            "authority": "passkey_session",
            "approval_id": row["approval_id"],
            "approval_evidence_sha256": row["commitment"],
        }

    async def _role(self, tx, scope, admitted) -> str:
        role = await self._role_of(tx, scope=scope, admitted=admitted)
        if role is None:
            raise GovernanceUnavailable()
        return role

    async def _associate_links(self, tx, subject) -> None:
        if not await tx.fetch_value(
            "SELECT 1 FROM {{tables.credential_authorizations}} WHERE subject=$1", subject
        ):
            raise GovernanceUnavailable()
        await tx.execute(
            "INSERT INTO {{tables.credential_completion_links}} (enrolment_id,subject,verifier_sha256,expires_at) "
            "SELECT enrolment_id,subject,verifier_sha256,expires_at FROM {{tables.passkey_enrolments}} "
            "WHERE subject=$1 AND used_at IS NULL AND revoked_at IS NULL ON CONFLICT(enrolment_id) DO NOTHING",
            subject,
        )

    async def _completion(self, tx, context):
        return await tx.fetch_one(
            "SELECT a.*,c.completed_at,c.expires_at AS bound_expiry,e.used_at,e.revoked_at,e.expires_at,"
            "e.verifier_sha256 AS actual_verifier,c.verifier_sha256 AS bound_verifier,"
            "p.contact AS actual_contact,p.scope AS actual_scope,p.effective_at AS actual_effective_at,p.superseded_at,"
            "k.subject AS key_subject,k.created_at AS key_created_at,k.revoked_at AS key_revoked_at "
            "FROM {{tables.credential_authorizations}} a "
            "JOIN {{tables.credential_completion_links}} c USING(subject) "
            "JOIN {{tables.passkey_enrolments}} e ON e.enrolment_id=c.enrolment_id AND e.subject=a.subject "
            "JOIN {{tables.passkey_approvers}} p ON p.subject=a.subject "
            "LEFT JOIN {{tables.passkey_credentials}} k ON k.credential_id=c.credential_id "
            "WHERE c.enrolment_id=$1 AND a.subject=$2",
            context.enrolment_id,
            context.subject,
        )

    def _valid_completion(self, row, context, *, after):
        now = datetime.now(UTC)
        if (
            row is None
            or self._admitted(row) != context.admitted
            or row["actual_scope"] != row["scope"]
            or row["superseded_at"] is not None
            or row["actual_effective_at"] != row["effective_at"]
            or contact_sha256(row["actual_contact"]) != row["contact_sha256"]
            or row["actual_verifier"] != row["bound_verifier"]
            or row["expires_at"] != row["bound_expiry"]
            or row["expires_at"] <= now
            or row["revoked_at"] is not None
            or (not after and (row["used_at"] is not None or row["completed_at"] is not None))
            or (
                after
                and (
                    context._event is None
                    or row["used_at"] != context._event.occurred_at
                    or row["completed_at"] != context._event.occurred_at
                    or row["key_subject"] != context.subject
                    or row["key_created_at"] != context._event.occurred_at
                    or row["key_revoked_at"] is not None
                )
            )
        ):
            raise EnrolmentRefused("enrolment authorization unavailable")

    async def _enrolled(self, event, tx):
        context = self._prepared.get()
        if (
            not isinstance(context, PreparedEnrolment)
            or context._tx is not tx
            or context._event is not None
            or event.subject != context.subject
        ):
            raise GovernanceUnavailable()
        row = await self._completion(tx, context)
        # The shared B3 operation has consumed the capability in this same tx.
        if row is None or row["used_at"] != event.occurred_at or row["completed_at"] is not None:
            raise GovernanceUnavailable()
        try:
            credential_id = base64url_to_bytes(event.details["credential_id"])
        except (KeyError, ValueError, TypeError):
            raise GovernanceUnavailable() from None
        if not await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_credentials}} WHERE credential_id=$1 AND subject=$2 "
            "AND created_at=$3 AND revoked_at IS NULL",
            credential_id,
            context.subject,
            event.occurred_at,
        ):
            raise GovernanceUnavailable()
        context._event = event
        credential_ref = "key_" + uuid4().hex
        await tx.execute(
            "UPDATE {{tables.credential_completion_links}} SET completed_at=$2,credential_ref=$3,credential_id=$4 WHERE enrolment_id=$1",
            context.enrolment_id,
            event.occurred_at,
            credential_ref,
            credential_id,
        )
        payload = dict(
            act="credential.enrolled",
            direction="widening",
            subject_ref=event.subject,
            role=row["role"],
            resource_type="passkey",
            resource_ref=credential_ref,
            **self._authority_payload(row),
        )
        await self._enqueue(tx, context.admitted, payload, _SYSTEM, event.occurred_at, context.view)

    async def _contact_scheduled(self, event, tx):
        context = self._prepared.get()
        scope = event.details.get("scope")
        if not isinstance(context, _ApprovalContext) or not isinstance(scope, str) or not scope:
            raise GovernanceUnavailable()
        await self._require_scope(tx, scope, context.admitted)
        row = await tx.fetch_one(
            "SELECT p.pending_contact,p.pending_contact_at,e.* "
            "FROM {{tables.passkey_approvers}} p JOIN {{tables.passkey_contact_proofs}} e "
            "ON e.subject=p.subject WHERE p.subject=$1 AND p.scope=$2 AND p.superseded_at IS NULL "
            "AND e.created_at=$3 AND e.revoked_at IS NULL AND e.used_at IS NULL",
            event.subject,
            scope,
            event.occurred_at,
        )
        if (
            row is None
            or not isinstance(row["pending_contact"], str)
            or contact_sha256(row["pending_contact"]) != row["contact_sha256"]
            or row["pending_contact_at"] != row["expires_at"]
            or row["expires_at"] <= datetime.now(UTC)
            or event.details.get("effective_at") != row["pending_contact_at"].isoformat()
        ):
            raise GovernanceUnavailable()
        commitment, retained = await self._approved_proof(tx, context, event, scope)
        role = await self._role(tx, scope, context.admitted)
        resource_ref, state_ref = "contact_" + uuid4().hex, "state_" + uuid4().hex
        await tx.execute(
            "INSERT INTO {{tables.credential_contact_candidates}} "
            "(proof_id,subject,scope,app_id,team_id,installation_id,generation,role,contact_sha256,"
            "effective_at,verifier_sha256,expires_at,resource_ref,scheduled_ref,approval_id,"
            "commitment,retained_proof,created_at) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18)",
            row["proof_id"],
            event.subject,
            scope,
            context.admitted.app_id,
            context.admitted.team_id,
            context.admitted.installation_id,
            context.admitted.generation,
            role,
            row["contact_sha256"],
            row["pending_contact_at"],
            row["verifier_sha256"],
            row["expires_at"],
            resource_ref,
            state_ref,
            context.evidence.approval_id,
            commitment,
            retained,
            event.occurred_at,
        )
        payload = dict(
            act="credential.enrolled",
            direction="widening",
            subject_ref=event.subject,
            role=role,
            resource_type="pending_contact",
            resource_ref=resource_ref,
            after_ref=state_ref,
            reason_code="contact_change_scheduled",
            authority="passkey_session",
            approval_id=context.evidence.approval_id,
            approval_evidence_sha256=commitment,
        )
        await self._enqueue(tx, context.admitted, payload, _SYSTEM, event.occurred_at, context.view)

    async def _contact_completion(self, tx, context):
        return await tx.fetch_one(
            "SELECT c.*,e.used_at,e.revoked_at,e.verifier_sha256 AS actual_verifier,"
            "e.expires_at AS actual_expiry,e.contact_sha256 AS actual_proof_contact,"
            "p.scope AS actual_scope,p.pending_contact AS actual_contact,"
            "p.pending_contact_at AS actual_effective_at,p.pending_contact_proven_at,p.superseded_at "
            "FROM {{tables.credential_contact_candidates}} c "
            "JOIN {{tables.passkey_contact_proofs}} e ON e.proof_id=c.proof_id AND e.subject=c.subject "
            "JOIN {{tables.passkey_approvers}} p ON p.subject=c.subject "
            "WHERE c.proof_id=$1 AND c.subject=$2",
            context.proof_id,
            context.subject,
        )

    def _valid_contact_completion(self, row, context, *, after):
        now = datetime.now(UTC)
        if (
            row is None
            or self._admitted(row) != context.admitted
            or row["actual_scope"] != row["scope"]
            or row["superseded_at"] is not None
            or not isinstance(row["actual_contact"], str)
            or contact_sha256(row["actual_contact"]) != row["contact_sha256"]
            or row["actual_proof_contact"] != row["contact_sha256"]
            or row["actual_effective_at"] != row["effective_at"]
            or row["actual_verifier"] != row["verifier_sha256"]
            or row["actual_expiry"] != row["expires_at"]
            or row["expires_at"] <= now
            or row["effective_at"] <= now
            or row["revoked_at"] is not None
            or (
                not after
                and any(
                    row[name] is not None
                    for name in ("used_at", "completed_at", "pending_contact_proven_at")
                )
            )
            or (
                after
                and (
                    context._event is None
                    or row["used_at"] != context._event.occurred_at
                    or row["completed_at"] != context._event.occurred_at
                    or row["pending_contact_proven_at"] != context._event.occurred_at
                    or row["proven_ref"] is None
                )
            )
        ):
            raise ContactChangeRefused("contact_proof_unavailable")

    async def _contact_proven(self, event, tx):
        context = self._prepared.get()
        if (
            not isinstance(context, PreparedContactProof)
            or context._tx is not tx
            or context._event is not None
            or event.subject != context.subject
        ):
            raise GovernanceUnavailable()
        row = await self._contact_completion(tx, context)
        if (
            row is None
            or row["used_at"] != event.occurred_at
            or row["pending_contact_proven_at"] != event.occurred_at
            or row["completed_at"] is not None
            or event.details.get("scope") != row["scope"]
            or event.details.get("effective_at") != row["effective_at"].isoformat()
        ):
            raise GovernanceUnavailable()
        context._event = event
        state_ref = "state_" + uuid4().hex
        await tx.execute(
            "UPDATE {{tables.credential_contact_candidates}} SET completed_at=$2,proven_ref=$3 "
            "WHERE proof_id=$1",
            context.proof_id,
            event.occurred_at,
            state_ref,
        )
        payload = dict(
            act="credential.enrolled",
            direction="widening",
            subject_ref=event.subject,
            role=row["role"],
            resource_type="pending_contact",
            resource_ref=row["resource_ref"],
            before_ref=row["scheduled_ref"],
            after_ref=state_ref,
            reason_code="contact_proven",
            authority="passkey_session",
            approval_id=row["approval_id"],
            approval_evidence_sha256=row["commitment"],
        )
        await self._enqueue(tx, context.admitted, payload, _SYSTEM, event.occurred_at, context.view)

    async def _credential_changed(self, event: AuditEvent, tx: TransactionManager) -> None:
        """A holding's own credential change, recorded under the retained
        proof of the current credential's assertion that approved it, bound to
        the exact credential rows this transaction wrote."""
        context = self._prepared.get()
        scope = event.details.get("scope")
        evidence_ref = event.details.get("evidence_ref")
        if (
            not isinstance(context, PreparedCredentialChangeAudit)
            or context._tx is not tx
            or context._event is not None
            or scope != context.scope
            or not isinstance(evidence_ref, str)
        ):
            raise GovernanceUnavailable()
        try:
            credential_id = base64url_to_bytes(event.details["credential_id"])
        except (KeyError, TypeError, ValueError):
            raise GovernanceUnavailable() from None
        txid = await tx.fetch_value("SELECT txid_current()")
        added = await tx.fetch_one(
            "SELECT * FROM {{tables.passkey_credentials}} WHERE credential_id = $1", credential_id
        )
        # The credential this very transaction added, by this evidence, once.
        if (
            added is None
            or added["subject"] != event.subject
            or added["added_by_evidence"] != evidence_ref
            or added["added_in"] != txid
            or added["revoked_at"] is not None
            or (added["replaced_credential_id"] is None)
            != (event.kind is AuditKind.APPROVER_PASSKEY_ADDED)
        ):
            raise GovernanceUnavailable()
        # The scope's approver is current, and in effect.
        if not await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_approvers}} WHERE subject = $1 AND scope = $2 "
            "AND superseded_at IS NULL AND effective_at <= $3",
            event.subject,
            scope,
            event.occurred_at,
        ):
            raise GovernanceUnavailable()
        passkeys = self._passkeys()
        admitted = context.admitted
        try:
            proof = await passkeys.retained_proof(evidence_ref, tx=tx)
            commitment = await passkeys.evidence_commitment(
                evidence_ref,
                context=PasskeyInstallationContext(
                    admitted.app_id, admitted.team_id, admitted.installation_id, admitted.generation
                ),
                scope=scope,
                subject=event.subject,
                purpose="credential_change",
                tx=tx,
            )
        except PasskeyProofUnavailable:
            raise GovernanceUnavailable() from None
        # The assertion answered the challenge this row records, and spent it.
        if proof.expected_challenge != bytes(
            added["added_by_challenge"]
        ) or not await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_challenges}} WHERE challenge = $1 "
            "AND purpose = 'credential_change' AND used_at IS NOT NULL",
            added["added_by_challenge"],
        ):
            raise GovernanceUnavailable()
        # The digests the approval signed are those of the stored credentials,
        # at their effective relying party.
        fields = json.loads(proof.challenge_preimage.split(b"\n", 1)[1])
        retired_id = added["replaced_credential_id"]
        # The operation the holder signed is the one B3 wrote.
        if fields.get("operation") != ("add" if retired_id is None else "replace") or (
            retired_id is None and "retire_credential_sha256" in fields
        ):
            raise GovernanceUnavailable()
        rp_id = passkeys.rp.rp_id
        if HumanCredential(
            credential_id, bytes(added["public_key"]), added["rp_id"] or rp_id
        ).sha256 != fields.get("credential_sha256"):
            raise GovernanceUnavailable()
        if retired_id is not None:
            retired = await tx.fetch_one(
                "SELECT * FROM {{tables.passkey_credentials}} WHERE credential_id = $1", retired_id
            )
            if (
                retired is None
                or retired["subject"] != event.subject
                or retired["revoked_in"] != txid
                or HumanCredential(
                    bytes(retired_id), bytes(retired["public_key"]), retired["rp_id"] or rp_id
                ).sha256
                != fields.get("retire_credential_sha256")
            ):
                raise GovernanceUnavailable()
        role = await self._role(tx, scope, admitted)
        credential_ref = _new_credential_ref()
        await tx.execute(
            "INSERT INTO {{tables.credential_added_keys}} (credential_id,subject,scope,app_id,"
            "team_id,installation_id,generation,credential_ref,evidence_ref,commitment,"
            "retained_proof,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)",
            credential_id,
            event.subject,
            scope,
            admitted.app_id,
            admitted.team_id,
            admitted.installation_id,
            admitted.generation,
            credential_ref,
            evidence_ref,
            commitment,
            json.dumps(proof.export()),
            event.occurred_at,
        )
        context._event = event
        authority = {"authority": "passkey_session", "approval_evidence_sha256": commitment}
        enrolled = dict(
            act="credential.enrolled",
            direction="widening",
            subject_ref=event.subject,
            role=role,
            resource_type="passkey",
            resource_ref=credential_ref,
            **authority,
        )
        await self._enqueue(tx, admitted, enrolled, _SYSTEM, event.occurred_at, context.view)
        if retired_id is not None:
            from aweb_naapp.runtime.credential_audit.narrowing import key_ref

            revoked = dict(
                act="credential.revoked",
                direction="narrowing",
                subject_ref=event.subject,
                role=role,
                resource_type="passkey",
                resource_ref=await key_ref(tx, event.subject, bytes(retired_id)),
                **authority,
            )
            await self._enqueue(tx, admitted, revoked, _SYSTEM, event.occurred_at, None)

    async def _enqueue(
        self, tx, admitted, payload, actor, occurred_at, view, *, signed_trace_id=None
    ):
        producer = self._producer(
            installation_id=admitted.installation_id, generation=admitted.generation
        )
        if (
            producer.producer.app_id,
            producer.producer.installation_id,
            producer.producer.generation,
        ) != (admitted.app_id, admitted.installation_id, admitted.generation):
            raise GovernanceUnavailable()
        if payload["act"] in self._ungated_acts:
            event_id = await producer.enqueue_self_recorded(
                tx,
                team_id=admitted.team_id,
                payload=payload,
                actor=actor,
                occurred_at=occurred_at,
                signed_trace_id=signed_trace_id,
            )
            await self._after_enqueue(tx, event_id)
            return event_id
        if payload["direction"] == "widening":
            await producer.require_admission(
                tx,
                team_id=admitted.team_id,
                hook=_HOOK,
                occurred_at=occurred_at,
                view=view,
                max_backlog_age=self._max_backlog_age,
            )
        event_id = await producer.enqueue(
            tx,
            hook=_HOOK,
            team_id=admitted.team_id,
            payload=payload,
            actor=actor,
            occurred_at=occurred_at,
            result_status="success",
            signed_trace_id=signed_trace_id,
            view=view,
        )
        if self._after_enqueue is not None:
            await self._after_enqueue(tx, event_id)
        return event_id
