"""App-local passkey approvers, verified with py_webauthn at the app's own origin.

Only a verified team owner act designates an approver: `app-role.designate`
for the first approver of a scope, `app-credential.recover` to replace one.
The act names the scope and commits to the approver's contact by hash, and it
is used once. The enrolment link goes only to that contact, and whoever first
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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import asyncpg
from awid.signing import canonical_json_bytes
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
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

from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    Approver,
    ApproverRetirement,
    Assurance,
    AuthenticationFailed,
    DeliveryStatus,
    Evidence,
    Purpose,
    challenge_binding,
)
from aweb_naapp.runtime.audit import AuditEvent, AuditKind, AuditSink
from aweb_naapp.runtime.links import LinkLifetime, link_verifier, new_link_token
from aweb_naapp.runtime.passkeys.rp import RelyingParty

logger = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).parent / "migrations"
MIGRATION_MODULE = "aweb_naapp_passkeys"
SUBJECT_TYPE = "app_local"
ENROLMENT_PREFIX = b"aweb.passkey-enrolment/1\n"
CONTACT_CHANGE_PREFIX = b"aweb.passkey-contact-change/1\n"
LOGIN_PREFIX = b"aweb.passkey-login/1\n"
TRUST_ON_FIRST_USE = "trust_on_first_use"


class EnrolmentRefused(Exception):
    """The enrolment link or registration could not be accepted."""


class DesignationRefused(Exception):
    """The owner act does not authorise this designation."""


class OwnerActKind(StrEnum):
    DESIGNATE = "app-role.designate"
    RECOVER = "app-credential.recover"


@runtime_checkable
class OwnerActEvidence(Protocol):
    """A verified team owner act (`aweb.owner-act/1`).

    Only the owner-act verifier produces these; until it exists this protocol
    is the seam it will fill. Member or admin authority never satisfies it.
    OwnerActEvidence is a structural placeholder until acgh.1's owner-act
    verifier lands. No production app may expose designate() as owner-gated
    until it is replaced by the verifier's concrete type.
    """

    act_id: str
    kind: OwnerActKind
    signer: str
    scope: str
    contact_sha256: str


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


@dataclass(frozen=True)
class Designation:
    approver: Approver
    delivery_status: DeliveryStatus
    effective_at: datetime


@dataclass(frozen=True)
class PasskeyLogin:
    """A verified login by a scope's in-effect approver. What the login opens,
    a session or anything else, is the caller's."""

    subject: str
    contact: str
    evidence_ref: str


@dataclass(frozen=True)
class PasskeyEvidence:
    """The restricted record behind an `auth_evidence_ref`."""

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


def _contact_change_challenge(subject: str, new_contact_sha256: str, nonce: bytes) -> bytes:
    fields = {"contact_sha256": new_contact_sha256, "nonce": nonce.hex(), "subject": subject}
    return hashlib.sha256(CONTACT_CHANGE_PREFIX + canonical_json_bytes(fields)).digest()


_CURRENT = "superseded_at IS NULL AND effective_at <= $2"
_EFFECTIVE_CONTACT = (
    "CASE WHEN pending_contact_at IS NOT NULL AND pending_contact_at <= $2 "
    "THEN pending_contact ELSE contact END"
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
    ) -> None:
        """`lockout` is the app's or owner's policy; `lockout_floor` is the
        deployment's, at or above the module floors. The policy must meet the
        deployment floor."""
        self.db = db
        self.rp = rp
        self._delivery = delivery
        self._audit = audit
        self._retirement = retirement
        self._enrolment_ttl = enrolment_ttl
        self._challenge_ttl = challenge_ttl
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
        self, *, scope: str, contact: str, owner_act: OwnerActEvidence
    ) -> Designation:
        """Designate the approver of `scope` on the strength of a verified owner
        act, and send its enrolment link to `contact`.

        `app-role.designate` designates the first approver; it takes effect at
        once. `app-credential.recover` replaces the current one after a
        lockout; it takes effect after the cooling-off period.
        """
        if not isinstance(owner_act, OwnerActEvidence):
            raise TypeError("designation needs verified owner-act evidence")
        if owner_act.scope != scope or owner_act.contact_sha256 != contact_sha256(contact):
            raise DesignationRefused("owner act names another scope or contact")
        now = self._clock()
        approver = Approver(subject=str(uuid.uuid4()), subject_type=SUBJECT_TYPE, contact=contact)
        token, verifier = new_link_token()
        try:
            async with self.db.transaction() as tx:
                previous = await tx.fetch_one(
                    "SELECT subject FROM {{tables.passkey_approvers}} "
                    "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
                    scope,
                )
                if previous is None and owner_act.kind is not OwnerActKind.DESIGNATE:
                    raise DesignationRefused("the first approver needs app-role.designate")
                if previous is not None and owner_act.kind is not OwnerActKind.RECOVER:
                    raise DesignationRefused("replacing an approver needs app-credential.recover")
                effective_at = now
                notified: list[str] = []
                if previous is not None:
                    effective_at = now + self._lockout.recovery_cooling_off
                    notified = await self._recorded_contacts(tx, scope)
                    await self._retire(tx, previous["subject"], owner_act.signer, now)
                await tx.execute(
                    "INSERT INTO {{tables.passkey_approvers}} (subject, scope, contact, "
                    "designated_by, designated_at, effective_at) VALUES ($1, $2, $3, $4, $5, $6)",
                    approver.subject,
                    scope,
                    contact,
                    owner_act.signer,
                    now,
                    effective_at,
                )
                await tx.execute(
                    "INSERT INTO {{tables.passkey_owner_acts}} "
                    "(act_id, kind, signer, scope, subject, used_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6)",
                    owner_act.act_id,
                    owner_act.kind.value,
                    owner_act.signer,
                    scope,
                    approver.subject,
                    now,
                )
                await tx.execute(
                    "INSERT INTO {{tables.passkey_enrolments}} "
                    "(enrolment_id, subject, verifier_sha256, created_at, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5)",
                    str(uuid.uuid4()),
                    approver.subject,
                    verifier,
                    now,
                    now + self._enrolment_ttl,
                )
                details = {
                    "scope": scope,
                    "owner_act_id": owner_act.act_id,
                    "owner_act_kind": owner_act.kind.value,
                    "effective_at": effective_at.isoformat(),
                }
                if previous is not None:
                    details["previous_subject"] = previous["subject"]
                await self._audit.emit(
                    AuditEvent(
                        kind=AuditKind.APPROVER_REDESIGNATED
                        if previous is not None
                        else AuditKind.APPROVER_DESIGNATED,
                        actor=owner_act.signer,
                        subject=approver.subject,
                        occurred_at=now,
                        details=details,
                    ),
                    tx,
                )
        except asyncpg.exceptions.UniqueViolationError as exc:
            if await self._act_used(owner_act.act_id):
                raise DesignationRefused("owner act already used") from exc
            raise
        status = await self._send(self._delivery.deliver_enrolment_link(approver, token))
        notice = Notice(NoticeKind.RECOVERY_STARTED, scope, effective_at)
        for recorded in notified:
            await self._send(self._delivery.deliver_notice(recorded, notice))
        return Designation(approver=approver, delivery_status=status, effective_at=effective_at)

    async def _act_used(self, act_id: str) -> bool:
        return bool(
            await self.db.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM {{tables.passkey_owner_acts}} WHERE act_id = $1)",
                act_id,
            )
        )

    async def _send(self, sending: Any) -> DeliveryStatus:
        try:
            return await sending
        except Exception:
            logger.exception("passkey delivery failed")
            return DeliveryStatus.FAILED

    async def _recorded_contacts(self, tx: TransactionManager, scope: str) -> list[str]:
        rows = await tx.fetch_all(
            "SELECT contact FROM {{tables.passkey_approvers}} WHERE scope = $1 "
            "UNION SELECT pending_contact FROM {{tables.passkey_approvers}} "
            "WHERE scope = $1 AND pending_contact IS NOT NULL",
            scope,
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

    async def designated_approver(self, policy: ActionPolicy) -> Approver | None:
        """The current approver for the policy's scope, once in effect and enrolled."""
        row = await self.db.fetch_one(
            f"SELECT subject, {_EFFECTIVE_CONTACT} AS contact "
            "FROM {{tables.passkey_approvers}} a "
            f"WHERE scope = $1 AND {_CURRENT} AND EXISTS ("
            "SELECT 1 FROM {{tables.passkey_credentials}} c "
            "WHERE c.subject = a.subject AND c.revoked_at IS NULL)",
            policy.approver_scope,
            self._clock(),
        )
        if row is None:
            return None
        return Approver(subject=row["subject"], subject_type=SUBJECT_TYPE, contact=row["contact"])

    async def is_current(self, approver_subject: str, policy: ActionPolicy) -> bool:
        return bool(
            await self.db.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM {{tables.passkey_approvers}} "
                f"WHERE subject = $1 AND {_CURRENT} AND scope = $3)",
                approver_subject,
                self._clock(),
                policy.approver_scope,
            )
        )

    # Enrolment through the link

    async def _usable_enrolment(self, link_token: str) -> dict[str, Any]:
        row = await self.db.fetch_one(
            "SELECT e.enrolment_id, e.subject, e.expires_at, e.revoked_at, e.used_at, a.contact "
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
        await self.db.execute(
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
            verified = verify_registration_response(
                credential=dict(credential),
                expected_challenge=challenge,
                expected_rp_id=self.rp.rp_id,
                expected_origin=self.rp.origin,
                require_user_verification=True,
            )
        except WebAuthnException as exc:
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
                verified.credential_public_key,
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
            subject=enrolment["subject"], subject_type=SUBJECT_TYPE, contact=enrolment["contact"]
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
            verified = verify_authentication_response(
                credential=dict(proof),
                expected_challenge=challenge,
                expected_rp_id=self.rp.rp_id,
                expected_origin=self.rp.origin,
                credential_public_key=credential["public_key"],
                credential_current_sign_count=credential["sign_count"],
                require_user_verification=True,
            )
        except WebAuthnException as exc:
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
        self, approval: Approval, purpose: Purpose, task_answer_ref: str | None
    ) -> Mapping[str, Any]:
        if approval.approver_subject_type != SUBJECT_TYPE:
            raise AuthenticationFailed("approver is not an app-local passkey holder")
        if not await self._active_credentials(approval.approver_subject):
            raise AuthenticationFailed("approver has no current passkey")
        nonce = secrets.token_bytes(32)
        challenge = challenge_binding(approval, purpose, nonce, task_answer_ref)
        await self._issue_challenge(
            challenge,
            purpose.value,
            approval.approver_subject,
            nonce,
            approval_id=approval.approval_id,
            task_answer_ref=task_answer_ref,
        )
        return await self._assertion_options(approval.approver_subject, challenge)

    async def verify_approval_assertion(
        self,
        approval: Approval,
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
            or issued["subject"] != approval.approver_subject
            or issued["task_answer_ref"] != task_answer_ref
            or challenge_binding(approval, purpose, issued["nonce"], task_answer_ref) != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this challenge")
        evidence_ref = await self._verify_assertion(
            approval.approver_subject, challenge, proof, purpose, approval, task_answer_ref
        )
        return Evidence(
            assurance=Assurance.PASSKEY,
            subject=approval.approver_subject,
            subject_type=SUBJECT_TYPE,
            evidence_ref=evidence_ref,
        )

    # Login

    async def login_options(self, scope: str) -> Mapping[str, Any]:
        """Assertion options for the scope's in-effect approver to log in."""
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
        now = self._clock()
        effective_at = now + self._lockout.contact_change_delay
        async with self.db.transaction() as tx:
            await tx.execute(
                "UPDATE {{tables.passkey_approvers}} SET contact = $2, pending_contact = $3, "
                "pending_contact_at = $4 WHERE subject = $1 AND superseded_at IS NULL",
                approver["subject"],
                approver["contact"],
                new_contact,
                effective_at,
            )
            await self._audit.emit(
                AuditEvent(
                    kind=AuditKind.APPROVER_CONTACT_CHANGE_SCHEDULED,
                    actor=approver["subject"],
                    subject=approver["subject"],
                    occurred_at=now,
                    details={
                        "scope": scope,
                        "evidence_ref": evidence_ref,
                        "effective_at": effective_at.isoformat(),
                    },
                ),
                tx,
            )
        notice = Notice(NoticeKind.CONTACT_CHANGE_SCHEDULED, scope, effective_at)
        for contact in sorted({approver["contact"], new_contact}):
            await self._send(self._delivery.deliver_notice(contact, notice))
        return effective_at

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
        self, approval: Approval, purpose: Purpose, task_answer_ref: str | None
    ) -> Mapping[str, Any]:
        return await self._passkeys.approval_options(approval, purpose, task_answer_ref)

    async def verify(
        self,
        approval: Approval,
        purpose: Purpose,
        proof: Mapping[str, Any],
        task_answer_ref: str | None,
    ) -> Evidence:
        return await self._passkeys.verify_approval_assertion(
            approval, purpose, proof, task_answer_ref
        )
