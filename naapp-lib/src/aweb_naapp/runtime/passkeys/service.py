"""App-local passkey approvers, verified with py_webauthn at the app's own origin.

A team owner act designates an approver: `app-role.designate` for the first
approver of a scope, `app-credential.recover` to replace one. The act is a
`VerifiedOwnerAct` that the owner-act verifier consumed in the caller's
transaction; it names the scope and commits to the approver's contact by hash,
and it takes effect once. For a scope the app does not count as an owner
scope, an owner's decided approval, admitted in the same transaction, may
designate the scope's first approver instead. Designation runs in the
caller's transaction, and its link and notices go out only when the caller
delivers them after the commit. The enrolment link goes only to that contact, and whoever first
completes enrolment through it registers the passkey: trust on first use,
recorded as such in the audit event.

Recovery replaces the approver after a lockout. It retires the previous
approver at once, with its passkeys, unused enrolment links and live
approvals. The new approver takes effect only after the cooling-off period,
during which no approver of the scope can request or give approvals, and
every contact previously recorded for the scope is told. A contact change
needs the approver's own passkey, takes effect after a delay, and is told to
both the old and the new contact.

Designation is the owner's attestation of one natural person. The primitive
cannot detect sharing: a passkey or contact that several people share makes
every approval attributable only to the group.

A passkey proves an app-local human holds the enrolled authenticator. It says
nothing about AWID membership, team identity or key custody.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from awid.signing import canonical_json_bytes
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager
from webauthn import generate_authentication_options, generate_registration_options
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json_dict,
    parse_client_data_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from aweb_naapp.hooks.owner_act import VerifiedOwnerAct
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    Approvals,
    Approver,
    ApproverRetirement,
    Assurance,
    AuthenticationFailed,
    Candidate,
    DeliveryStatus,
    DispatchOutcome,
    Evidence,
    Purpose,
    challenge_binding,
)
from aweb_naapp.runtime.audit import AuditEvent, AuditKind, AuditSink
from aweb_naapp.runtime.links import LinkLifetime, link_verifier, new_link_token
from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.runtime.passkeys.webauthn import (
    WebAuthnRefused,
    verify_assertion,
    verify_registration,
)

logger = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).parent / "migrations"
MIGRATION_MODULE = "aweb_naapp_passkeys"
SUBJECT_TYPE = "app_local"
ENROLMENT_PREFIX = b"aweb.passkey-enrolment/1\n"
CONTACT_CHANGE_PREFIX = b"aweb.passkey-contact-change/1\n"
CONTACT_CANCEL_PREFIX = b"aweb.passkey-contact-cancel/1\n"
CONTACT_CHANGE_ACT = "approver-contact.change"
LOGIN_PREFIX = b"aweb.passkey-login/1\n"
TRUST_ON_FIRST_USE = "trust_on_first_use"
# Outstanding unused challenges kept per subject and purpose; issuing another
# evicts the oldest, so requests that need no authentication, such as a login,
# cannot grow the challenge store without bound.
MAX_OUTSTANDING_CHALLENGES = 8


class EnrolmentRefused(Exception):
    """The enrolment link or registration could not be accepted."""


class DesignationRefused(Exception):
    """The owner evidence does not authorise this designation or retirement."""


class ContactChangeRefused(Exception):
    """A contact change, its cancellation or its proof is not allowed now.
    `reason` is `last_owner_protected`, `contact_change_pending`,
    `no_pending_contact_change` or `contact_proof_unavailable`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


DESIGNATE_ACT = "app-role.designate"
RECOVER_ACT = "app-credential.recover"
REVOKE_ACT = "app-role.revoke"


@dataclass(frozen=True)
class OwnerApproval:
    """An owner's decided approval, admitted and completed in one transaction.

    Only :meth:`Passkeys.owner_approval` returns one, and it is evidence only in
    the transaction it was admitted in. Whether the approved request asks for
    a given designation is the app's to check: only the app can read its own
    request."""

    approval_id: str
    approver_subject: str
    approver_scope: str
    transaction_id: int


# The shortest protections any deployment may run with. Deploy configuration can
# raise them (`Passkeys(lockout_floor=...)`); app or owner policy can lengthen
# them; nothing can shorten them.
RECOVERY_COOLING_OFF_FLOOR = timedelta(hours=72)
CONTACT_CHANGE_DELAY_FLOOR = timedelta(hours=24)


@dataclass(frozen=True)
class LockoutPolicy:
    """Protections around replacing an approver or its contact. Each duration
    is at least its floor; a shorter one is refused at construction."""

    recovery_cooling_off: timedelta = RECOVERY_COOLING_OFF_FLOOR
    contact_change_delay: timedelta = CONTACT_CHANGE_DELAY_FLOOR

    def __post_init__(self) -> None:
        self.require_at_least(
            RECOVERY_COOLING_OFF_FLOOR, CONTACT_CHANGE_DELAY_FLOOR, "the protection floor"
        )

    def require_at_least(
        self, recovery_cooling_off: timedelta, contact_change_delay: timedelta, floor: str
    ) -> None:
        if self.recovery_cooling_off < recovery_cooling_off:
            raise ValueError(f"recovery cooling-off is shorter than {floor}")
        if self.contact_change_delay < contact_change_delay:
            raise ValueError(f"contact-change delay is shorter than {floor}")


class NoticeKind(StrEnum):
    RECOVERY_STARTED = "recovery_started"
    CONTACT_CHANGE_SCHEDULED = "contact_change_scheduled"
    CONTACT_CHANGE_CANCELLED = "contact_change_cancelled"


@dataclass(frozen=True)
class Notice:
    kind: NoticeKind
    scope: str
    effective_at: datetime


class PasskeyDelivery(Protocol):
    """Sends links and notices to registered contacts, and nowhere else."""

    async def deliver_enrolment_link(
        self, approver: Approver, link_token: str
    ) -> DeliveryStatus: ...

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus: ...

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        """Send the single-use proof a new contact's holder uses to confirm it,
        to that contact only."""
        ...


@dataclass(frozen=True)
class Designation:
    """A committed designation's approver, and what is still to be sent: its
    enrolment link and, for a recovery, the notices to earlier contacts. The
    caller sends them with :meth:`Passkeys.deliver` after the commit."""

    approver: Approver
    effective_at: datetime
    notices: tuple[tuple[str, Notice], ...] = ()
    link_token: str = field(default="", repr=False)


@dataclass(frozen=True)
class ContactChange:
    """A scheduled contact change and what is still to send: the notices to
    both contacts and the proof to the new one. The caller sends them with
    :meth:`Passkeys.send_notices` after the commit."""

    scope: str
    effective_at: datetime
    notices: tuple[tuple[str, Notice], ...]
    new_contact: str
    proof_token: str = field(repr=False)


@dataclass(frozen=True)
class PasskeyLogin:
    """A verified login by a scope's in-effect approver. What the login opens,
    a session or anything else, is the caller's."""

    subject: str
    contact: str
    evidence_ref: str


@dataclass(frozen=True)
class PasskeyEvidence:
    """The restricted record behind a decision's `decided_by.evidence_ref`."""

    evidence_ref: str
    subject: str
    credential_id: bytes
    purpose: str
    approval_id: str | None
    request_sha256: str | None
    policy_ref: str | None
    policy_version: int | None
    task_answer_ref: str | None
    sign_count: int
    verified_at: datetime


async def _transaction_id(tx: TransactionManager) -> int:
    return int(await tx.fetch_value("SELECT txid_current()"))


def _utcnow() -> datetime:
    return datetime.now(UTC)


def contact_sha256(contact: str) -> str:
    return hashlib.sha256(contact.encode("utf-8")).hexdigest()


def _client_challenge(credential: Mapping[str, Any]) -> bytes:
    client_data = base64url_to_bytes(credential["response"]["clientDataJSON"])
    return parse_client_data_json(client_data).challenge


def _enrolment_challenge(enrolment_id: str, subject: str, nonce: bytes) -> bytes:
    fields = {"enrolment_id": enrolment_id, "nonce": nonce.hex(), "subject": subject}
    return hashlib.sha256(ENROLMENT_PREFIX + canonical_json_bytes(fields)).digest()


def _login_challenge(scope: str, subject: str, nonce: bytes) -> bytes:
    fields = {"nonce": nonce.hex(), "scope": scope, "subject": subject}
    return hashlib.sha256(LOGIN_PREFIX + canonical_json_bytes(fields)).digest()


def _contact_cancel_challenge(subject: str, pending_contact_sha256: str, nonce: bytes) -> bytes:
    fields = {
        "subject": subject,
        "pending_contact_sha256": pending_contact_sha256,
        "nonce": nonce.hex(),
    }
    return hashlib.sha256(CONTACT_CANCEL_PREFIX + canonical_json_bytes(fields)).digest()


def _contact_change_challenge(subject: str, new_contact_sha256: str, nonce: bytes) -> bytes:
    fields = {"contact_sha256": new_contact_sha256, "nonce": nonce.hex(), "subject": subject}
    return hashlib.sha256(CONTACT_CHANGE_PREFIX + canonical_json_bytes(fields)).digest()


_CURRENT = "superseded_at IS NULL AND effective_at <= $2"
# A pending contact takes effect once its delay has passed AND its holder has
# proven it; an unproven one lapses and the contact stays. So an approver's
# effective contact is always proven: by enrolment through it, or by a proof.
_EFFECTIVE_CONTACT = (
    "CASE WHEN pending_contact_at IS NOT NULL AND pending_contact_at <= $2 "
    "AND pending_contact_proven_at IS NOT NULL THEN pending_contact ELSE contact END"
)


class Passkeys:
    """Approver designation, enrolment and passkey assertions for one app.

    It is the app's `ApproverDirectory`, and `authenticator()` is its passkey
    `Authenticator` for the approval primitive. `retirement` revokes a retired
    approver's live approvals inside the retiring transaction.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        rp: RelyingParty,
        delivery: PasskeyDelivery,
        audit: AuditSink,
        retirement: ApproverRetirement,
        enrolment_ttl: timedelta,
        challenge_ttl: timedelta,
        lockout: LockoutPolicy | None = None,
        lockout_floor: LockoutPolicy | None = None,
        clock: Callable[[], datetime] = _utcnow,
        owner_scopes: Callable[[str], bool] = lambda scope: True,
    ) -> None:
        """`lockout` is the app's or owner's policy; `lockout_floor` is the
        deployment's, at or above the module floors. The policy must meet the
        deployment floor. `owner_scopes` says which scopes are owner scopes:
        their approvers are designated only by a team owner act, and only their
        approvers' decisions are owner approvals. By default every scope is."""
        self.db = db
        self.rp = rp
        self._delivery = delivery
        self._audit = audit
        self._retirement = retirement
        self._enrolment_ttl = enrolment_ttl
        self._challenge_ttl = challenge_ttl
        self._owner_scopes = owner_scopes
        floor = lockout_floor or LockoutPolicy()
        self._lockout = lockout or floor
        self._lockout.require_at_least(
            floor.recovery_cooling_off, floor.contact_change_delay, "the deployment floor"
        )
        self._clock = clock

    async def migrate(self) -> None:
        await AsyncMigrationManager(
            self.db, migrations_path=str(MIGRATIONS), module_name=MIGRATION_MODULE
        ).apply_pending_migrations()

    def authenticator(self) -> PasskeyAuthenticator:
        return PasskeyAuthenticator(self)

    # The owner

    async def designate(
        self,
        tx: TransactionManager,
        *,
        scope: str,
        contact: str,
        evidence: VerifiedOwnerAct | OwnerApproval,
    ) -> Designation:
        """Designate the approver of `scope` in the caller's transaction.

        A `VerifiedOwnerAct` consumed in this transaction is evidence for any
        scope: `app-role.designate` designates the first approver, at once;
        `app-credential.recover` replaces the current one after the cooling-off.
        An `OwnerApproval` admitted in this transaction designates only the
        first approver of a scope that is not an owner scope. Each act takes
        effect once, and an approval once per scope. Nothing is sent: deliver
        the returned designation after the commit.
        """
        if isinstance(evidence, VerifiedOwnerAct):
            if evidence.act not in (DESIGNATE_ACT, RECOVER_ACT):
                raise DesignationRefused(f"{evidence.act} designates nobody")
            if evidence.subject.get("role") != scope or evidence.subject.get(
                "contact_sha256"
            ) != contact_sha256(contact):
                raise DesignationRefused("owner act names another scope or contact")
            if evidence.transaction_id != await _transaction_id(tx):
                raise DesignationRefused("the owner act was consumed in another transaction")
            kind = evidence.act
            act_id = f"{evidence.team_id}:{evidence.nonce}"
            actor = str(evidence.fields["team_key_did"])
        elif isinstance(evidence, OwnerApproval):
            if self._owner_scopes(scope):
                raise DesignationRefused("an owner scope's approver needs a team owner act")
            if evidence.transaction_id != await _transaction_id(tx):
                raise DesignationRefused("the owner approval was admitted in another transaction")
            kind = DESIGNATE_ACT
            act_id = f"approval:{evidence.approval_id}:{scope}"
            actor = evidence.approver_subject
        else:
            raise TypeError("designation needs a verified owner act or an owner approval")
        if await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_owner_acts}} WHERE act_id = $1", act_id
        ):
            raise DesignationRefused("this evidence has already taken effect")
        now = self._clock()
        previous = await tx.fetch_one(
            "SELECT subject FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
            scope,
        )
        if previous is None and kind != DESIGNATE_ACT:
            raise DesignationRefused("the first approver needs app-role.designate")
        if previous is not None and kind != RECOVER_ACT:
            raise DesignationRefused("replacing an approver needs app-credential.recover")
        approver = Approver(
            scope=scope, subject=str(uuid.uuid4()), subject_type=SUBJECT_TYPE, contact=contact
        )
        effective_at = now
        notified: list[str] = []
        if previous is not None:
            effective_at = now + self._lockout.recovery_cooling_off
            notified = await self._recorded_contacts(tx, scope)
            await self._retire(tx, previous["subject"], actor, now)
        await tx.execute(
            "INSERT INTO {{tables.passkey_approvers}} (subject, scope, contact, "
            "designated_by, designated_at, effective_at) VALUES ($1, $2, $3, $4, $5, $6)",
            approver.subject,
            scope,
            contact,
            actor,
            now,
            effective_at,
        )
        await tx.execute(
            "INSERT INTO {{tables.passkey_owner_acts}} "
            "(act_id, kind, signer, scope, subject, used_at) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            act_id,
            kind,
            actor,
            scope,
            approver.subject,
            now,
        )
        token = await self._issue_enrolment(tx, approver.subject, now)
        details = {
            "scope": scope,
            "owner_act_id": act_id,
            "owner_act_kind": kind,
            "effective_at": effective_at.isoformat(),
        }
        if previous is not None:
            details["previous_subject"] = previous["subject"]
        await self._audit.emit(
            AuditEvent(
                kind=AuditKind.APPROVER_REDESIGNATED
                if previous is not None
                else AuditKind.APPROVER_DESIGNATED,
                actor=actor,
                subject=approver.subject,
                occurred_at=now,
                details=details,
            ),
            tx,
        )
        notice = Notice(NoticeKind.RECOVERY_STARTED, scope, effective_at)
        return Designation(
            approver=approver,
            effective_at=effective_at,
            notices=tuple((recorded, notice) for recorded in notified),
            link_token=token,
        )

    async def retire(
        self, tx: TransactionManager, *, scope: str, evidence: VerifiedOwnerAct
    ) -> None:
        """End `scope`'s designation in the caller's transaction, on an
        `app-role.revoke` act consumed in this transaction that names the
        approver it revokes as its `subject_ref`.

        The current approver, or a recovery's pending one, is superseded, its
        passkeys and unused enrolment links revoked and its live approvals
        voided. The scope then has no approver: its next designation is a first
        one, and the retired passkeys stay dead. Each act takes effect once.
        """
        if not isinstance(evidence, VerifiedOwnerAct):
            raise TypeError("retirement needs a verified owner act")
        if evidence.act != REVOKE_ACT:
            raise DesignationRefused(f"{evidence.act} retires nobody")
        if evidence.subject.get("role") != scope:
            raise DesignationRefused("owner act names another scope")
        if evidence.transaction_id != await _transaction_id(tx):
            raise DesignationRefused("the owner act was consumed in another transaction")
        act_id = f"{evidence.team_id}:{evidence.nonce}"
        actor = str(evidence.fields["team_key_did"])
        if await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_owner_acts}} WHERE act_id = $1", act_id
        ):
            raise DesignationRefused("this evidence has already taken effect")
        current = await tx.fetch_one(
            "SELECT subject FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
            scope,
        )
        if current is None:
            raise DesignationRefused("the scope has no approver to retire")
        # The act names the holder it revokes; checked under the lock, so a
        # recovery committed after the act was signed cannot redirect it.
        if evidence.subject.get("subject_ref") != current["subject"]:
            raise DesignationRefused("owner act names another approver")
        now = self._clock()
        await self._retire(tx, current["subject"], actor, now)
        await tx.execute(
            "INSERT INTO {{tables.passkey_owner_acts}} "
            "(act_id, kind, signer, scope, subject, used_at) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            act_id,
            REVOKE_ACT,
            actor,
            scope,
            current["subject"],
            now,
        )
        await self._audit.emit(
            AuditEvent(
                kind=AuditKind.APPROVER_RETIRED,
                actor=actor,
                subject=current["subject"],
                occurred_at=now,
                details={"scope": scope, "owner_act_id": act_id, "owner_act_kind": REVOKE_ACT},
            ),
            tx,
        )

    async def owner_approval(
        self,
        tx: TransactionManager,
        approvals: Approvals,
        *,
        approval_id: str,
        request: Mapping[str, Any],
        operation_id: str,
    ) -> OwnerApproval:
        """Admit an owner's decided approval of `request` in `tx` as designation evidence.

        B2 admits it once, checking its bytes, its current approver and its
        assurance; the admission is completed in the same transaction, since
        the designations it authorises happen there. Only an approval decided
        by an owner scope's approver is owner evidence.
        """
        admission = await approvals.admit(approval_id, request, operation_id, tx=tx)
        if not admission.first:
            raise DesignationRefused("the owner approval has already been used")
        approval = await approvals.get(approval_id)
        assert approval is not None and approval.decided_by is not None
        decider = approval.decided_by
        if not self._owner_scopes(decider.scope):
            raise DesignationRefused("the approval was not decided by an owner")
        await approvals.record_outcome(
            approval_id,
            operation_id,
            DispatchOutcome.COMPLETED,
            response_status="designation",
            tx=tx,
        )
        return OwnerApproval(
            approval_id=approval_id,
            approver_subject=decider.subject,
            approver_scope=decider.scope,
            transaction_id=await _transaction_id(tx),
        )

    async def reissue_enrolment(self, tx: TransactionManager, *, scope: str) -> Designation:
        """A new enrolment link for the scope's current approver, while it has
        not enrolled, revoking any earlier link; during a recovery, the notices
        to earlier contacts again. It changes nothing about who the approver is,
        so it needs no owner evidence. Deliver it after the commit."""
        now = self._clock()
        current = await tx.fetch_one(
            "SELECT subject, contact, effective_at FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
            scope,
        )
        if current is None:
            raise EnrolmentRefused("the scope has no approver")
        if await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_credentials}} "
            "WHERE subject = $1 AND revoked_at IS NULL",
            current["subject"],
        ):
            raise EnrolmentRefused("the approver has already enrolled")
        await tx.execute(
            "UPDATE {{tables.passkey_enrolments}} SET revoked_at = $2 "
            "WHERE subject = $1 AND revoked_at IS NULL AND used_at IS NULL",
            current["subject"],
            now,
        )
        token = await self._issue_enrolment(tx, current["subject"], now)
        await self._audit.emit(
            AuditEvent(
                kind=AuditKind.APPROVER_ENROLMENT_REISSUED,
                actor=current["subject"],
                subject=current["subject"],
                occurred_at=now,
                details={"scope": scope},
            ),
            tx,
        )
        notices: tuple[tuple[str, Notice], ...] = ()
        if current["effective_at"] > now:
            recorded = await self._recorded_contacts(tx, scope, excluding=current["subject"])
            notice = Notice(NoticeKind.RECOVERY_STARTED, scope, current["effective_at"])
            notices = tuple((contact, notice) for contact in recorded)
        approver = Approver(
            scope=scope,
            subject=current["subject"],
            subject_type=SUBJECT_TYPE,
            contact=current["contact"],
        )
        return Designation(
            approver=approver,
            effective_at=current["effective_at"],
            notices=notices,
            link_token=token,
        )

    async def deliver(self, designation: Designation) -> DeliveryStatus:
        """Send a committed designation's enrolment link and notices. Returns
        how the link's delivery went."""
        status = await self._send(
            self._delivery.deliver_enrolment_link(designation.approver, designation.link_token)
        )
        for contact, notice in designation.notices:
            await self._send(self._delivery.deliver_notice(contact, notice))
        return status

    async def _issue_enrolment(self, tx: TransactionManager, subject: str, now: datetime) -> str:
        token, verifier = new_link_token()
        await tx.execute(
            "INSERT INTO {{tables.passkey_enrolments}} "
            "(enrolment_id, subject, verifier_sha256, created_at, expires_at) "
            "VALUES ($1, $2, $3, $4, $5)",
            str(uuid.uuid4()),
            subject,
            verifier,
            now,
            now + self._enrolment_ttl,
        )
        return token

    async def _send(self, sending: Any) -> DeliveryStatus:
        try:
            return await sending
        except Exception:
            logger.exception("passkey delivery failed")
            return DeliveryStatus.FAILED

    async def _recorded_contacts(
        self, tx: TransactionManager, scope: str, *, excluding: str | None = None
    ) -> list[str]:
        """The proven contacts ever recorded for `scope`'s approvers, for
        security notices: a registered contact once an enrolment completed
        through it, a pending one once its holder proved it. An unproven
        address gets nothing but its own proof."""
        rows = await tx.fetch_all(
            "SELECT a.contact FROM {{tables.passkey_approvers}} a "
            "WHERE a.scope = $1 AND a.subject IS DISTINCT FROM $2 AND EXISTS ("
            "SELECT 1 FROM {{tables.passkey_credentials}} c WHERE c.subject = a.subject) "
            "UNION SELECT pending_contact FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND subject IS DISTINCT FROM $2 "
            "AND pending_contact_proven_at IS NOT NULL",
            scope,
            excluding,
        )
        return sorted({row["contact"] for row in rows})

    async def _retire(
        self, tx: TransactionManager, subject: str, retired_by: str, now: datetime
    ) -> None:
        await tx.execute(
            "UPDATE {{tables.passkey_approvers}} SET superseded_at = $2 WHERE subject = $1",
            subject,
            now,
        )
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET revoked_at = $2 "
            "WHERE subject = $1 AND revoked_at IS NULL",
            subject,
            now,
        )
        await tx.execute(
            "UPDATE {{tables.passkey_enrolments}} SET revoked_at = $2 "
            "WHERE subject = $1 AND revoked_at IS NULL AND used_at IS NULL",
            subject,
            now,
        )
        await self._retirement.approver_retired(subject, retired_by=retired_by, tx=tx)

    async def recovery_pending_until(self, scope: str) -> datetime | None:
        """When a recovery's cooling-off ends, while it runs. Apps freeze their
        own widening changes for the scope until then."""
        return await self.db.fetch_value(
            "SELECT effective_at FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND superseded_at IS NULL AND effective_at > $2",
            scope,
            self._clock(),
        )

    # The directory

    async def designated_approver(self, scope: str) -> Approver | None:
        """The scope's current approver, once in effect and enrolled."""
        row = await self.db.fetch_one(
            f"SELECT subject, {_EFFECTIVE_CONTACT} AS contact "
            "FROM {{tables.passkey_approvers}} a "
            f"WHERE scope = $1 AND {_CURRENT} AND EXISTS ("
            "SELECT 1 FROM {{tables.passkey_credentials}} c "
            "WHERE c.subject = a.subject AND c.revoked_at IS NULL)",
            scope,
            self._clock(),
        )
        if row is None:
            return None
        return Approver(
            scope=scope, subject=row["subject"], subject_type=SUBJECT_TYPE, contact=row["contact"]
        )

    async def candidates(self, policy: ActionPolicy, request: Mapping[str, Any]) -> list[Approver]:
        """The current approver of each of the policy's scopes that has one."""
        found = [await self.designated_approver(scope) for scope in policy.approver_scopes]
        return [approver for approver in found if approver is not None]

    async def is_current(self, scope: str, subject: str) -> bool:
        return bool(
            await self.db.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM {{tables.passkey_approvers}} "
                f"WHERE subject = $1 AND {_CURRENT} AND scope = $3)",
                subject,
                self._clock(),
                scope,
            )
        )

    async def can_log_in(self, scope: str, subject: str) -> bool:
        """Whether `subject` is `scope`'s in-effect approver and still holds an
        unrevoked passkey: what a login needs, and what a session it opened
        keeps needing for as long as it lasts."""
        return bool(
            await self.db.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM {{tables.passkey_approvers}} "
                f"WHERE subject = $1 AND {_CURRENT} AND scope = $3 AND EXISTS ("
                "SELECT 1 FROM {{tables.passkey_credentials}} c "
                "WHERE c.subject = $1 AND c.revoked_at IS NULL))",
                subject,
                self._clock(),
                scope,
            )
        )

    # Enrolment through the link

    async def _usable_enrolment(self, link_token: str) -> dict[str, Any]:
        row = await self.db.fetch_one(
            "SELECT e.enrolment_id, e.subject, e.expires_at, e.revoked_at, e.used_at, "
            "a.contact, a.scope "
            "FROM {{tables.passkey_enrolments}} e JOIN {{tables.passkey_approvers}} a "
            "ON a.subject = e.subject "
            "WHERE e.verifier_sha256 = $1 AND a.superseded_at IS NULL",
            link_verifier(link_token),
        )
        if row is None:
            raise EnrolmentRefused("enrolment link unavailable")
        lifetime = LinkLifetime(row["expires_at"], row["revoked_at"], row["used_at"])
        if not lifetime.usable_at(self._clock()):
            raise EnrolmentRefused("enrolment link unavailable")
        return row

    async def _issue_challenge(
        self,
        challenge: bytes,
        purpose: str,
        subject: str,
        nonce: bytes,
        *,
        enrolment_id: str | None = None,
        approval_id: str | None = None,
        task_answer_ref: str | None = None,
        new_contact_sha256: str | None = None,
    ) -> None:
        now = self._clock()
        async with self.db.transaction() as tx:
            await tx.execute(
                "DELETE FROM {{tables.passkey_challenges}} WHERE expires_at <= $1", now
            )
            await tx.execute(
                "INSERT INTO {{tables.passkey_challenges}} (challenge, purpose, subject, "
                "enrolment_id, approval_id, task_answer_ref, contact_sha256, nonce, created_at, "
                "expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                challenge,
                purpose,
                subject,
                enrolment_id,
                approval_id,
                task_answer_ref,
                new_contact_sha256,
                nonce,
                now,
                now + self._challenge_ttl,
            )
            await tx.execute(
                "DELETE FROM {{tables.passkey_challenges}} WHERE challenge IN ("
                "SELECT challenge FROM {{tables.passkey_challenges}} "
                "WHERE subject = $1 AND purpose = $2 AND used_at IS NULL "
                "ORDER BY issued_seq DESC OFFSET $3)",
                subject,
                purpose,
                MAX_OUTSTANDING_CHALLENGES,
            )

    async def _take_challenge(self, challenge: bytes, purpose: str) -> dict[str, Any] | None:
        """Use up a challenge, whether or not the ceremony then verifies."""
        row = await self.db.fetch_one(
            "UPDATE {{tables.passkey_challenges}} SET used_at = $3 "
            "WHERE challenge = $1 AND purpose = $2 AND used_at IS NULL "
            "RETURNING subject, enrolment_id, approval_id, task_answer_ref, contact_sha256, "
            "nonce, expires_at",
            challenge,
            purpose,
            self._clock(),
        )
        if row is None or self._clock() >= row["expires_at"]:
            return None
        return row

    async def enrolment_options(self, link_token: str) -> Mapping[str, Any]:
        """Registration options for the approver opening the enrolment link."""
        enrolment = await self._usable_enrolment(link_token)
        nonce = secrets.token_bytes(32)
        challenge = _enrolment_challenge(enrolment["enrolment_id"], enrolment["subject"], nonce)
        await self._issue_challenge(
            challenge,
            "enrolment",
            enrolment["subject"],
            nonce,
            enrolment_id=enrolment["enrolment_id"],
        )
        options = generate_registration_options(
            rp_id=self.rp.rp_id,
            rp_name=self.rp.name,
            user_id=enrolment["subject"].encode("utf-8"),
            user_name=enrolment["contact"],
            user_display_name=enrolment["contact"],
            challenge=challenge,
            timeout=int(self._challenge_ttl.total_seconds() * 1000),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return options_to_json_dict(options)

    async def complete_enrolment(self, link_token: str, credential: Mapping[str, Any]) -> Approver:
        """Verify the registration answering this enrolment's challenge and
        register the passkey. The enrolment link is then used up."""
        enrolment = await self._usable_enrolment(link_token)
        try:
            challenge = _client_challenge(credential)
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise EnrolmentRefused("malformed registration") from exc
        issued = await self._take_challenge(challenge, "enrolment")
        if (
            issued is None
            or issued["enrolment_id"] != enrolment["enrolment_id"]
            or _enrolment_challenge(
                enrolment["enrolment_id"], enrolment["subject"], issued["nonce"]
            )
            != challenge
        ):
            raise EnrolmentRefused("registration does not answer this enrolment")
        try:
            verified = verify_registration(credential, challenge=challenge, rp=self.rp)
        except WebAuthnRefused as exc:
            raise EnrolmentRefused("registration did not verify") from exc

        now = self._clock()
        async with self.db.transaction() as tx:
            used = await tx.fetch_value(
                "UPDATE {{tables.passkey_enrolments}} e SET used_at = $2 "
                "FROM {{tables.passkey_approvers}} a "
                "WHERE e.enrolment_id = $1 AND a.subject = e.subject AND a.superseded_at IS NULL "
                "AND e.used_at IS NULL AND e.revoked_at IS NULL RETURNING e.subject",
                enrolment["enrolment_id"],
                now,
            )
            if used is None:
                raise EnrolmentRefused("enrolment link unavailable")
            await tx.execute(
                "INSERT INTO {{tables.passkey_credentials}} "
                "(credential_id, subject, public_key, sign_count, created_at) "
                "VALUES ($1, $2, $3, $4, $5)",
                verified.credential_id,
                enrolment["subject"],
                verified.public_key,
                verified.sign_count,
                now,
            )
            await self._audit.emit(
                AuditEvent(
                    kind=AuditKind.APPROVER_ENROLLED,
                    actor=enrolment["subject"],
                    subject=enrolment["subject"],
                    occurred_at=now,
                    details={
                        "trust": TRUST_ON_FIRST_USE,
                        "credential_id": bytes_to_base64url(verified.credential_id),
                    },
                ),
                tx,
            )
        return Approver(
            scope=enrolment["scope"],
            subject=enrolment["subject"],
            subject_type=SUBJECT_TYPE,
            contact=enrolment["contact"],
        )

    # Assertions

    async def _active_credentials(self, subject: str) -> list[dict[str, Any]]:
        return await self.db.fetch_all(
            "SELECT c.credential_id, c.public_key, c.sign_count "
            "FROM {{tables.passkey_credentials}} c JOIN {{tables.passkey_approvers}} a "
            "ON a.subject = c.subject "
            "WHERE c.subject = $1 AND c.revoked_at IS NULL AND a.superseded_at IS NULL",
            subject,
        )

    async def _assertion_options(self, subject: str, challenge: bytes) -> Mapping[str, Any]:
        credentials = await self._active_credentials(subject)
        options = generate_authentication_options(
            rp_id=self.rp.rp_id,
            challenge=challenge,
            timeout=int(self._challenge_ttl.total_seconds() * 1000),
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=c["credential_id"]) for c in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return options_to_json_dict(options)

    async def _verify_assertion(
        self,
        subject: str,
        challenge: bytes,
        proof: Mapping[str, Any],
        purpose: Purpose | str,
        approval: Approval | None = None,
        task_answer_ref: str | None = None,
        audit: tuple[AuditKind, dict[str, str]] | None = None,
    ) -> str:
        """Verify an assertion of `subject`'s current passkey over `challenge`,
        advance its counter and record the evidence, with `audit`'s event in
        the same transaction. Return the evidence ref."""
        try:
            credential_id = base64url_to_bytes(proof["rawId"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        credential = next(
            (
                c
                for c in await self._active_credentials(subject)
                if c["credential_id"] == credential_id
            ),
            None,
        )
        if credential is None:
            raise AuthenticationFailed("credential is not the approver's current passkey")
        try:
            verified = verify_assertion(
                proof,
                challenge=challenge,
                rp=self.rp,
                credential_id=credential_id,
                public_key=credential["public_key"],
                sign_count=credential["sign_count"],
            )
        except WebAuthnRefused as exc:
            raise AuthenticationFailed("assertion did not verify") from exc

        evidence_ref = str(uuid.uuid4())
        async with self.db.transaction() as tx:
            advanced = await tx.fetch_value(
                "UPDATE {{tables.passkey_credentials}} SET sign_count = $2 "
                "WHERE credential_id = $1 AND revoked_at IS NULL "
                "AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0)) RETURNING credential_id",
                credential_id,
                verified.new_sign_count,
            )
            if advanced is None:
                raise AuthenticationFailed("authenticator counter did not advance")
            await tx.execute(
                "INSERT INTO {{tables.passkey_assertions}} (evidence_ref, subject, credential_id, "
                "purpose, approval_id, request_sha256, policy_ref, policy_version, "
                "task_answer_ref, sign_count, verified_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                evidence_ref,
                subject,
                credential_id,
                str(purpose),
                approval.approval_id if approval else None,
                approval.request_sha256 if approval else None,
                approval.policy_ref if approval else None,
                approval.policy_version if approval else None,
                task_answer_ref,
                verified.new_sign_count,
                self._clock(),
            )
            if audit is not None:
                kind, details = audit
                await self._audit.emit(
                    AuditEvent(
                        kind=kind,
                        actor=subject,
                        subject=subject,
                        occurred_at=self._clock(),
                        details={**details, "evidence_ref": evidence_ref},
                    ),
                    tx,
                )
        return evidence_ref

    async def approval_options(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        task_answer_ref: str | None,
    ) -> Mapping[str, Any]:
        """Assertion options for one candidate, listing only their passkeys."""
        if candidate.subject_type != SUBJECT_TYPE:
            raise AuthenticationFailed("candidate is not an app-local passkey holder")
        if not await self._active_credentials(candidate.subject):
            raise AuthenticationFailed("candidate has no current passkey")
        nonce = secrets.token_bytes(32)
        challenge = challenge_binding(approval, candidate, purpose, nonce, task_answer_ref)
        await self._issue_challenge(
            challenge,
            purpose.value,
            candidate.subject,
            nonce,
            approval_id=approval.approval_id,
            task_answer_ref=task_answer_ref,
        )
        return await self._assertion_options(candidate.subject, challenge)

    async def verify_approval_assertion(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        proof: Mapping[str, Any],
        task_answer_ref: str | None,
    ) -> Evidence:
        try:
            challenge = _client_challenge(proof)
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        issued = await self._take_challenge(challenge, purpose.value)
        if (
            issued is None
            or issued["approval_id"] != approval.approval_id
            or issued["subject"] != candidate.subject
            or issued["task_answer_ref"] != task_answer_ref
            or challenge_binding(approval, candidate, purpose, issued["nonce"], task_answer_ref)
            != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this challenge")
        evidence_ref = await self._verify_assertion(
            candidate.subject, challenge, proof, purpose, approval, task_answer_ref
        )
        return Evidence(
            assurance=Assurance.PASSKEY,
            subject=candidate.subject,
            subject_type=SUBJECT_TYPE,
            evidence_ref=evidence_ref,
        )

    # Login

    async def login_options(self, scope: str) -> Mapping[str, Any]:
        """Assertion options for the scope's in-effect approver to log in.

        It needs no prior authentication. A scope without an enrolled, in-effect
        approver is refused, which tells the caller so; scope names are fixed by
        the app, so that is deliberate. The bound on outstanding challenges
        protects storage, not availability: a sustained flood can keep evicting
        the real approver's challenge, so the caller must rate-limit its login
        route per client and meter request volume per scope."""
        approver = await self._current_approver(scope)
        if not await self._active_credentials(approver["subject"]):
            raise AuthenticationFailed("approver has no current passkey")
        nonce = secrets.token_bytes(32)
        challenge = _login_challenge(scope, approver["subject"], nonce)
        await self._issue_challenge(challenge, "login", approver["subject"], nonce)
        return await self._assertion_options(approver["subject"], challenge)

    async def verify_login(self, scope: str, proof: Mapping[str, Any]) -> PasskeyLogin:
        """Verify the in-effect approver's login assertion for `scope`, under the
        same user-verification, origin, single-use and counter rules as every
        other assertion."""
        approver = await self._current_approver(scope)
        try:
            challenge = _client_challenge(proof)
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        issued = await self._take_challenge(challenge, "login")
        if (
            issued is None
            or issued["subject"] != approver["subject"]
            or _login_challenge(scope, approver["subject"], issued["nonce"]) != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this login")
        evidence_ref = await self._verify_assertion(
            approver["subject"],
            challenge,
            proof,
            "login",
            audit=(AuditKind.APPROVER_LOGGED_IN, {"scope": scope}),
        )
        return PasskeyLogin(
            subject=approver["subject"], contact=approver["contact"], evidence_ref=evidence_ref
        )

    # The approver's own contact

    async def _current_approver(self, scope: str) -> dict[str, Any]:
        row = await self.db.fetch_one(
            f"SELECT subject, {_EFFECTIVE_CONTACT} AS contact "
            f"FROM {{{{tables.passkey_approvers}}}} WHERE scope = $1 AND {_CURRENT}",
            scope,
            self._clock(),
        )
        if row is None:
            raise AuthenticationFailed("no approver in effect for this scope")
        return row

    async def contact_change_options(self, scope: str, new_contact: str) -> Mapping[str, Any]:
        """Assertion options for the current approver to change its own contact."""
        approver = await self._current_approver(scope)
        nonce = secrets.token_bytes(32)
        digest = contact_sha256(new_contact)
        challenge = _contact_change_challenge(approver["subject"], digest, nonce)
        await self._issue_challenge(
            challenge, "contact_change", approver["subject"], nonce, new_contact_sha256=digest
        )
        return await self._assertion_options(approver["subject"], challenge)

    async def change_contact(
        self, scope: str, new_contact: str, proof: Mapping[str, Any]
    ) -> datetime:
        """Schedule the approver's new contact, proven with its own passkey.
        It takes effect after the contact-change delay; both contacts are told.
        Returns when it takes effect."""
        approver = await self._current_approver(scope)
        digest = contact_sha256(new_contact)
        try:
            challenge = _client_challenge(proof)
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        issued = await self._take_challenge(challenge, "contact_change")
        if (
            issued is None
            or issued["subject"] != approver["subject"]
            or issued["contact_sha256"] != digest
            or _contact_change_challenge(approver["subject"], digest, issued["nonce"]) != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this contact change")
        evidence_ref = await self._verify_assertion(
            approver["subject"], challenge, proof, "contact_change"
        )
        async with self.db.transaction() as tx:
            change = await self._schedule_contact(
                tx,
                scope,
                new_contact,
                kind=AuditKind.APPROVER_CONTACT_CHANGE_SCHEDULED,
                actor=approver["subject"],
                details={"evidence_ref": evidence_ref},
            )
        await self.send_notices(change)
        return change.effective_at

    async def change_contact_by_owner(
        self,
        tx: TransactionManager,
        *,
        scope: str,
        new_contact: str,
        evidence: OwnerApproval,
    ) -> ContactChange:
        """Schedule a new contact for `scope`'s approver on an owner's approval
        admitted in this transaction, as an owner-confirmed change set does.

        It changes the contact only: no authenticator is enrolled, re-enrolled
        or revoked, and nothing is sent to the new contact but the notice. It
        takes effect after the contact-change delay, and the approver can
        cancel it with their own passkey. The last owner's own contact changes
        only through that owner's passkey or a recovery. Send the returned
        notices after the commit."""
        if not isinstance(evidence, OwnerApproval):
            raise TypeError("an owner contact change needs an owner approval")
        if evidence.transaction_id != await _transaction_id(tx):
            raise DesignationRefused("the owner approval was admitted in another transaction")
        act_id = f"approval:{evidence.approval_id}:contact:{scope}"
        if self._owner_scopes(scope) and await self._last_owner(tx, scope):
            raise ContactChangeRefused("last_owner_protected")
        change = await self._schedule_contact(
            tx,
            scope,
            new_contact,
            kind=AuditKind.APPROVER_CONTACT_CHANGE_BY_OWNER_SCHEDULED,
            actor=evidence.approver_subject,
            details={"owner_approval_id": evidence.approval_id},
        )
        await tx.execute(
            "INSERT INTO {{tables.passkey_owner_acts}} "
            "(act_id, kind, signer, scope, subject, used_at) "
            "SELECT $1, $2, $3, $4, subject, $5 FROM {{tables.passkey_approvers}} "
            "WHERE scope = $4 AND superseded_at IS NULL",
            act_id,
            CONTACT_CHANGE_ACT,
            evidence.approver_subject,
            scope,
            self._clock(),
        )
        return change

    async def _last_owner(self, tx: TransactionManager, scope: str) -> bool:
        """Whether `scope` holds the only owner with an approver in effect and
        an enrolled passkey. Such an owner's contact is proven: an effective
        contact always is, by its enrolment or by its holder's proof."""
        rows = await tx.fetch_all(
            "SELECT DISTINCT a.scope FROM {{tables.passkey_approvers}} a "
            "WHERE a.scope <> $1 AND a.superseded_at IS NULL AND a.effective_at <= $2 "
            "AND EXISTS (SELECT 1 FROM {{tables.passkey_credentials}} c "
            "WHERE c.subject = a.subject AND c.revoked_at IS NULL)",
            scope,
            self._clock(),
        )
        return not any(self._owner_scopes(row["scope"]) for row in rows)

    async def _schedule_contact(
        self,
        tx: TransactionManager,
        scope: str,
        new_contact: str,
        *,
        kind: AuditKind,
        actor: str,
        details: dict[str, str],
    ) -> ContactChange:
        """Record `scope`'s approver's pending contact, refusing while another
        change is pending, and issue the single-use proof its holder must use
        before it can take effect. Return the notices to both contacts and the
        proof for the new one."""
        now = self._clock()
        row = await tx.fetch_one(
            f"SELECT subject, {_EFFECTIVE_CONTACT} AS contact, pending_contact_at "
            f"FROM {{{{tables.passkey_approvers}}}} WHERE scope = $1 AND {_CURRENT} FOR UPDATE",
            scope,
            now,
        )
        if row is None:
            raise AuthenticationFailed("no approver in effect for this scope")
        if row["pending_contact_at"] is not None and row["pending_contact_at"] > now:
            raise ContactChangeRefused("contact_change_pending")
        effective_at = now + self._lockout.contact_change_delay
        await tx.execute(
            "UPDATE {{tables.passkey_approvers}} SET contact = $2, pending_contact = $3, "
            "pending_contact_at = $4, pending_contact_proven_at = NULL "
            "WHERE subject = $1 AND superseded_at IS NULL",
            row["subject"],
            row["contact"],
            new_contact,
            effective_at,
        )
        await self._revoke_contact_proofs(tx, row["subject"], now)
        proof_token, verifier = new_link_token()
        await tx.execute(
            "INSERT INTO {{tables.passkey_contact_proofs}} "
            "(proof_id, subject, contact_sha256, verifier_sha256, created_at, expires_at) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            str(uuid.uuid4()),
            row["subject"],
            contact_sha256(new_contact),
            verifier,
            now,
            effective_at,
        )
        await self._audit.emit(
            AuditEvent(
                kind=kind,
                actor=actor,
                subject=row["subject"],
                occurred_at=now,
                details={"scope": scope, "effective_at": effective_at.isoformat(), **details},
            ),
            tx,
        )
        notice = Notice(NoticeKind.CONTACT_CHANGE_SCHEDULED, scope, effective_at)
        return ContactChange(
            scope=scope,
            effective_at=effective_at,
            notices=tuple((c, notice) for c in sorted({row["contact"], new_contact})),
            new_contact=new_contact,
            proof_token=proof_token,
        )

    async def send_notices(self, change: ContactChange) -> None:
        """Send a committed contact change's notices to the old and new contact,
        and its proof to the new contact only."""
        for contact, notice in change.notices:
            await self._send(self._delivery.deliver_notice(contact, notice))
        await self._send(
            self._delivery.deliver_contact_proof(change.new_contact, change.proof_token)
        )

    async def _revoke_contact_proofs(
        self, tx: TransactionManager, subject: str, now: datetime
    ) -> None:
        await tx.execute(
            "UPDATE {{tables.passkey_contact_proofs}} SET revoked_at = $2 "
            "WHERE subject = $1 AND revoked_at IS NULL AND used_at IS NULL",
            subject,
            now,
        )

    async def prove_contact(self, proof_token: str) -> datetime:
        """The new contact's holder confirms it with the proof sent there. The
        pending contact then takes effect at its time; unproven, it lapses.
        Returns when it takes effect."""
        now = self._clock()
        verifier = link_verifier(proof_token)
        async with self.db.transaction() as tx:
            # The approver row first, then the proof: the order every contact
            # change and cancel takes, so they serialise instead of deadlocking.
            subject = await tx.fetch_value(
                "SELECT subject FROM {{tables.passkey_contact_proofs}} WHERE verifier_sha256 = $1",
                verifier,
            )
            approver = await tx.fetch_one(
                "SELECT subject, scope, pending_contact, pending_contact_at "
                "FROM {{tables.passkey_approvers}} "
                "WHERE subject = $1 AND superseded_at IS NULL FOR UPDATE",
                subject,
            )
            proof = await tx.fetch_one(
                "SELECT proof_id, contact_sha256 FROM {{tables.passkey_contact_proofs}} "
                "WHERE verifier_sha256 = $1 AND used_at IS NULL AND revoked_at IS NULL "
                "AND expires_at > $2 FOR UPDATE",
                verifier,
                now,
            )
            if (
                approver is None
                or proof is None
                or approver["pending_contact_at"] is None
                or approver["pending_contact_at"] <= now
                or contact_sha256(approver["pending_contact"]) != proof["contact_sha256"]
            ):
                raise ContactChangeRefused("contact_proof_unavailable")
            await tx.execute(
                "UPDATE {{tables.passkey_contact_proofs}} SET used_at = $2 WHERE proof_id = $1",
                proof["proof_id"],
                now,
            )
            await tx.execute(
                "UPDATE {{tables.passkey_approvers}} SET pending_contact_proven_at = $2 "
                "WHERE subject = $1 AND superseded_at IS NULL",
                approver["subject"],
                now,
            )
            await self._audit.emit(
                AuditEvent(
                    kind=AuditKind.APPROVER_CONTACT_PROVEN,
                    actor=approver["subject"],
                    subject=approver["subject"],
                    occurred_at=now,
                    details={
                        "scope": approver["scope"],
                        "effective_at": approver["pending_contact_at"].isoformat(),
                    },
                ),
                tx,
            )
        return approver["pending_contact_at"]

    async def _pending_contact(self, scope: str) -> dict[str, Any]:
        now = self._clock()
        row = await self.db.fetch_one(
            f"SELECT subject, contact, pending_contact, pending_contact_at "
            f"FROM {{{{tables.passkey_approvers}}}} WHERE scope = $1 AND {_CURRENT}",
            scope,
            now,
        )
        if row is None:
            raise AuthenticationFailed("no approver in effect for this scope")
        if row["pending_contact_at"] is None or row["pending_contact_at"] <= now:
            raise ContactChangeRefused("no_pending_contact_change")
        return row

    async def contact_cancel_options(self, scope: str) -> Mapping[str, Any]:
        """Assertion options for the approver to cancel its pending contact
        change, whoever scheduled it."""
        pending = await self._pending_contact(scope)
        nonce = secrets.token_bytes(32)
        digest = contact_sha256(pending["pending_contact"])
        challenge = _contact_cancel_challenge(pending["subject"], digest, nonce)
        await self._issue_challenge(
            challenge, "contact_change", pending["subject"], nonce, new_contact_sha256=digest
        )
        return await self._assertion_options(pending["subject"], challenge)

    async def cancel_pending_contact(self, scope: str, proof: Mapping[str, Any]) -> None:
        """Cancel the approver's pending contact change with its own passkey,
        whether the approver or an owner scheduled it. The approver's cancel
        wins; both contacts are told."""
        pending = await self._pending_contact(scope)
        digest = contact_sha256(pending["pending_contact"])
        try:
            challenge = _client_challenge(proof)
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        issued = await self._take_challenge(challenge, "contact_change")
        if (
            issued is None
            or issued["subject"] != pending["subject"]
            or issued["contact_sha256"] != digest
            or _contact_cancel_challenge(pending["subject"], digest, issued["nonce"]) != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this cancellation")
        evidence_ref = await self._verify_assertion(
            pending["subject"], challenge, proof, "contact_change"
        )
        now = self._clock()
        async with self.db.transaction() as tx:
            cancelled = await tx.fetch_value(
                "UPDATE {{tables.passkey_approvers}} SET pending_contact = NULL, "
                "pending_contact_at = NULL, pending_contact_proven_at = NULL "
                "WHERE subject = $1 AND superseded_at IS NULL "
                "AND pending_contact = $2 AND pending_contact_at > $3 RETURNING subject",
                pending["subject"],
                pending["pending_contact"],
                now,
            )
            if cancelled is None:
                raise ContactChangeRefused("no_pending_contact_change")
            await self._revoke_contact_proofs(tx, pending["subject"], now)
            await self._audit.emit(
                AuditEvent(
                    kind=AuditKind.APPROVER_CONTACT_CHANGE_CANCELLED,
                    actor=pending["subject"],
                    subject=pending["subject"],
                    occurred_at=now,
                    details={"scope": scope, "evidence_ref": evidence_ref},
                ),
                tx,
            )
        notice = Notice(NoticeKind.CONTACT_CHANGE_CANCELLED, scope, pending["pending_contact_at"])
        for contact in sorted({pending["contact"], pending["pending_contact"]}):
            await self._send(self._delivery.deliver_notice(contact, notice))

    async def evidence(self, evidence_ref: str) -> PasskeyEvidence | None:
        row = await self.db.fetch_one(
            "SELECT * FROM {{tables.passkey_assertions}} WHERE evidence_ref = $1", evidence_ref
        )
        return PasskeyEvidence(**row) if row else None


class PasskeyAuthenticator:
    """The approval primitive's `passkey` assurance adapter."""

    assurance = Assurance.PASSKEY

    def __init__(self, passkeys: Passkeys) -> None:
        self._passkeys = passkeys

    async def challenge(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        task_answer_ref: str | None,
    ) -> Mapping[str, Any]:
        return await self._passkeys.approval_options(approval, candidate, purpose, task_answer_ref)

    async def verify(
        self,
        approval: Approval,
        candidate: Candidate,
        purpose: Purpose,
        proof: Mapping[str, Any],
        task_answer_ref: str | None,
    ) -> Evidence:
        return await self._passkeys.verify_approval_assertion(
            approval, candidate, purpose, proof, task_answer_ref
        )
