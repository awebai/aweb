"""App-local passkey approvers, verified with py_webauthn at the app's own origin.

The owner designates the approver for a scope and registers the approver's
contact. The enrolment link goes only to that contact, and whoever first
completes enrolment through it registers the passkey: trust on first use,
recorded as such in the audit event. Recovery is the owner designating the
approver again, which retires the previous approver's passkeys and links.

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
from pathlib import Path
from typing import Any, Protocol

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
    Assurance,
    AuthenticationFailed,
    Decision,
    DeliveryStatus,
    Evidence,
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
TRUST_ON_FIRST_USE = "trust_on_first_use"


class EnrolmentRefused(Exception):
    """The enrolment link or registration could not be accepted."""


class EnrolmentDelivery(Protocol):
    """Sends an enrolment link to the approver's registered contact, and nowhere else."""

    async def deliver_enrolment_link(
        self, approver: Approver, link_token: str
    ) -> DeliveryStatus: ...


@dataclass(frozen=True)
class Designation:
    approver: Approver
    delivery_status: DeliveryStatus


@dataclass(frozen=True)
class PasskeyEvidence:
    """The restricted record behind an approval's `auth_evidence_ref`."""

    evidence_ref: str
    subject: str
    credential_id: bytes
    approval_id: str
    decision: Decision
    request_sha256: str
    policy_ref: str
    policy_version: int
    sign_count: int
    verified_at: datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _client_challenge(credential: Mapping[str, Any]) -> bytes:
    client_data = base64url_to_bytes(credential["response"]["clientDataJSON"])
    return parse_client_data_json(client_data).challenge


def _enrolment_challenge(enrolment_id: str, subject: str, nonce: bytes) -> bytes:
    fields = {"enrolment_id": enrolment_id, "nonce": nonce.hex(), "subject": subject}
    return hashlib.sha256(ENROLMENT_PREFIX + canonical_json_bytes(fields)).digest()


class Passkeys:
    """Approver designation, enrolment and passkey assertions for one app.

    It is the app's `ApproverDirectory`, and `authenticator()` is its passkey
    `Authenticator` for the approval primitive.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        rp: RelyingParty,
        delivery: EnrolmentDelivery,
        audit: AuditSink,
        enrolment_ttl: timedelta,
        challenge_ttl: timedelta,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.db = db
        self.rp = rp
        self._delivery = delivery
        self._audit = audit
        self._enrolment_ttl = enrolment_ttl
        self._challenge_ttl = challenge_ttl
        self._clock = clock

    async def migrate(self) -> None:
        await AsyncMigrationManager(
            self.db, migrations_path=str(MIGRATIONS), module_name=MIGRATION_MODULE
        ).apply_pending_migrations()

    def authenticator(self) -> PasskeyAuthenticator:
        return PasskeyAuthenticator(self)

    # The owner

    async def designate(self, *, scope: str, contact: str, designated_by: str) -> Designation:
        """Make a new approver current for `scope` and send its enrolment link
        to `contact`. A previous approver of the scope is retired with its
        passkeys and unused enrolment links: this is also how the owner
        recovers from a lost device."""
        now = self._clock()
        approver = Approver(subject=str(uuid.uuid4()), subject_type=SUBJECT_TYPE, contact=contact)
        token, verifier = new_link_token()
        async with self.db.transaction() as tx:
            previous = await tx.fetch_value(
                "SELECT subject FROM {{tables.passkey_approvers}} "
                "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
                scope,
            )
            if previous is not None:
                await self._retire(tx, previous, now)
            await tx.execute(
                "INSERT INTO {{tables.passkey_approvers}} "
                "(subject, scope, contact, designated_by, designated_at) VALUES ($1, $2, $3, $4, $5)",
                approver.subject,
                scope,
                contact,
                designated_by,
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
            details = {"scope": scope}
            if previous is not None:
                details["previous_subject"] = previous
            await self._audit.emit(
                AuditEvent(
                    kind=AuditKind.APPROVER_REDESIGNATED
                    if previous is not None
                    else AuditKind.APPROVER_DESIGNATED,
                    actor=designated_by,
                    subject=approver.subject,
                    occurred_at=now,
                    details=details,
                ),
                tx,
            )
        try:
            status = await self._delivery.deliver_enrolment_link(approver, token)
        except Exception:
            logger.exception("enrolment link delivery failed for approver %s", approver.subject)
            status = DeliveryStatus.FAILED
        return Designation(approver=approver, delivery_status=status)

    async def _retire(self, tx: TransactionManager, subject: str, now: datetime) -> None:
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

    async def designated_approver(self, policy: ActionPolicy) -> Approver | None:
        """The current approver for the policy's scope, once it has a passkey."""
        row = await self.db.fetch_one(
            "SELECT a.subject, a.contact FROM {{tables.passkey_approvers}} a "
            "WHERE a.scope = $1 AND a.superseded_at IS NULL AND EXISTS ("
            "SELECT 1 FROM {{tables.passkey_credentials}} c "
            "WHERE c.subject = a.subject AND c.revoked_at IS NULL)",
            policy.approver_scope,
        )
        if row is None:
            return None
        return Approver(subject=row["subject"], subject_type=SUBJECT_TYPE, contact=row["contact"])

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

    async def enrolment_options(self, link_token: str) -> Mapping[str, Any]:
        """Registration options for the approver opening the enrolment link."""
        enrolment = await self._usable_enrolment(link_token)
        now = self._clock()
        nonce = secrets.token_bytes(32)
        challenge = _enrolment_challenge(enrolment["enrolment_id"], enrolment["subject"], nonce)
        await self.db.execute(
            "INSERT INTO {{tables.passkey_challenges}} "
            "(challenge, purpose, subject, enrolment_id, nonce, created_at, expires_at) "
            "VALUES ($1, 'enrolment', $2, $3, $4, $5, $6)",
            challenge,
            enrolment["subject"],
            enrolment["enrolment_id"],
            nonce,
            now,
            now + self._challenge_ttl,
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

    async def _take_challenge(self, challenge: bytes, purpose: str) -> dict[str, Any] | None:
        """Use up a challenge, whether or not the ceremony then verifies."""
        row = await self.db.fetch_one(
            "UPDATE {{tables.passkey_challenges}} SET used_at = $3 "
            "WHERE challenge = $1 AND purpose = $2 AND used_at IS NULL "
            "RETURNING subject, enrolment_id, approval_id, decision, nonce, expires_at",
            challenge,
            purpose,
            self._clock(),
        )
        if row is None or self._clock() >= row["expires_at"]:
            return None
        return row

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

    # Assertions for approval decisions

    async def _active_credentials(self, subject: str) -> list[dict[str, Any]]:
        return await self.db.fetch_all(
            "SELECT c.credential_id, c.public_key, c.sign_count "
            "FROM {{tables.passkey_credentials}} c JOIN {{tables.passkey_approvers}} a "
            "ON a.subject = c.subject "
            "WHERE c.subject = $1 AND c.revoked_at IS NULL AND a.superseded_at IS NULL",
            subject,
        )

    async def assertion_options(self, approval: Approval, decision: Decision) -> Mapping[str, Any]:
        if approval.approver_subject_type != SUBJECT_TYPE:
            raise AuthenticationFailed("approver is not an app-local passkey holder")
        credentials = await self._active_credentials(approval.approver_subject)
        if not credentials:
            raise AuthenticationFailed("approver has no current passkey")
        now = self._clock()
        nonce = secrets.token_bytes(32)
        challenge = challenge_binding(approval, decision, nonce)
        await self.db.execute(
            "INSERT INTO {{tables.passkey_challenges}} "
            "(challenge, purpose, subject, approval_id, decision, nonce, created_at, expires_at) "
            "VALUES ($1, 'assertion', $2, $3, $4, $5, $6, $7)",
            challenge,
            approval.approver_subject,
            approval.approval_id,
            decision.value,
            nonce,
            now,
            now + self._challenge_ttl,
        )
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

    async def verify_assertion(
        self, approval: Approval, decision: Decision, proof: Mapping[str, Any]
    ) -> Evidence:
        try:
            challenge = _client_challenge(proof)
            credential_id = base64url_to_bytes(proof["rawId"])
        except (KeyError, TypeError, ValueError, WebAuthnException) as exc:
            raise AuthenticationFailed("malformed assertion") from exc
        issued = await self._take_challenge(challenge, "assertion")
        if (
            issued is None
            or issued["approval_id"] != approval.approval_id
            or issued["decision"] != decision.value
            or issued["subject"] != approval.approver_subject
            or challenge_binding(approval, decision, issued["nonce"]) != challenge
        ):
            raise AuthenticationFailed("assertion does not answer this decision's challenge")
        credential = next(
            (
                c
                for c in await self._active_credentials(approval.approver_subject)
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

        now = self._clock()
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
                "approval_id, decision, request_sha256, policy_ref, policy_version, sign_count, "
                "verified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                evidence_ref,
                approval.approver_subject,
                credential_id,
                approval.approval_id,
                decision.value,
                approval.request_sha256,
                approval.policy_ref,
                approval.policy_version,
                verified.new_sign_count,
                now,
            )
        return Evidence(
            assurance=Assurance.PASSKEY,
            subject=approval.approver_subject,
            subject_type=SUBJECT_TYPE,
            evidence_ref=evidence_ref,
        )

    async def evidence(self, evidence_ref: str) -> PasskeyEvidence | None:
        row = await self.db.fetch_one(
            "SELECT * FROM {{tables.passkey_assertions}} WHERE evidence_ref = $1", evidence_ref
        )
        if row is None:
            return None
        return PasskeyEvidence(**{**row, "decision": Decision(row["decision"])})


class PasskeyAuthenticator:
    """The approval primitive's `passkey` assurance adapter."""

    assurance = Assurance.PASSKEY

    def __init__(self, passkeys: Passkeys) -> None:
        self._passkeys = passkeys

    async def challenge(self, approval: Approval, decision: Decision) -> Mapping[str, Any]:
        return await self._passkeys.assertion_options(approval, decision)

    async def verify(
        self, approval: Approval, decision: Decision, proof: Mapping[str, Any]
    ) -> Evidence:
        return await self._passkeys.verify_assertion(approval, decision, proof)
