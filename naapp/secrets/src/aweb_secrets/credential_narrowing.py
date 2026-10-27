"""Caller-authorized B3 narrowing, including its nested effect savepoints."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from aweb_naapp.console import ConsoleSession
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext, PasskeyProofUnavailable
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager
from webauthn.helpers import base64url_to_bytes

from aweb_secrets.credential_audit import GovernanceUnavailable

if TYPE_CHECKING:
    from aweb_secrets.credential_audit import CredentialAudit


@dataclass(frozen=True, repr=False)
class PreparedContainment:
    """The caller has held F6 and authorized this actual member or S4 session.

    Preparation exports evidence only. It grants no action authority and takes
    no new authority locks. The caller retains its final session/F6 checks.
    A SQL transaction ID, rather than a wrapper identity, binds B3 savepoints.
    """

    owner: CredentialAudit
    admitted: AdmittedInstallation
    transaction_id: int
    authorized_by: str
    authority: str
    actor_json: str
    commitment: str | None
    retained_json: str | None
    signed_trace_id: str | None


async def prepare_containment(
    owner: CredentialAudit,
    tx: TransactionManager,
    *,
    admitted: AdmittedInstallation,
    principal: Principal | None = None,
    session: ConsoleSession | None = None,
    signed_trace_id: str | None = None,
) -> PreparedContainment:
    if admitted.app_id != owner._app_id or (principal is None) == (session is None):
        raise GovernanceUnavailable()
    commitment, retained = None, None
    if principal is not None:
        if principal.team_id != admitted.team_id:
            raise GovernanceUnavailable()
        authorized_by = principal_key(principal).principal_did
        authority = "team_cert"
        actor = dict(
            authority_mode="team_cert",
            attestations=[],
            did_key=principal.did_key,
            certificate_id=principal.certificate_id,
        )
        if principal.did_aw is not None:
            actor["did_aw"] = principal.did_aw
    else:
        assert session is not None
        try:
            passkeys = owner._passkeys()
            commitment = await passkeys.evidence_commitment(
                session.evidence_ref,
                context=PasskeyInstallationContext(
                    admitted.app_id, admitted.team_id, admitted.installation_id, admitted.generation
                ),
                scope=session.scope,
                subject=session.subject,
                purpose="login",
                tx=tx,
            )
            retained = json.dumps(
                (await passkeys.retained_proof(session.evidence_ref, tx=tx)).export()
            )
        except PasskeyProofUnavailable:
            raise GovernanceUnavailable() from None
        authorized_by, authority = session.subject, "passkey_session"
        actor = {"authority_mode": "system", "attestations": []}
    transaction_id = await tx.fetch_value("SELECT txid_current()")
    if session is not None and session.expires_at <= datetime.now(UTC):
        raise GovernanceUnavailable()
    return PreparedContainment(
        owner,
        admitted,
        transaction_id,
        authorized_by,
        authority,
        json.dumps(actor),
        commitment,
        retained,
        signed_trace_id,
    )


async def record_role_revoked(
    owner: CredentialAudit,
    tx: TransactionManager,
    *,
    context: PreparedContainment,
    role: str,
    subject_ref: str,
    occurred_at: datetime,
) -> UUID:
    """Record an actual user-role removal under the caller's retained authority.

    The caller owns authorization and the membership row lock. No B3 person
    designation is implied by the removed member's subject_ref.
    """
    if (
        not isinstance(context, PreparedContainment)
        or context.owner is not owner
        or context.transaction_id != await tx.fetch_value("SELECT txid_current()")
        or context.admitted.app_id != owner._app_id
        or not isinstance(context.authorized_by, str)
        or not context.authorized_by
        or not isinstance(role, str)
        or not role
        or not isinstance(subject_ref, str)
        or not subject_ref
    ):
        raise GovernanceUnavailable()
    payload = dict(
        act="role.revoked",
        direction="narrowing",
        role=role,
        subject_ref=subject_ref,
        authority=context.authority,
    )
    if context.commitment is not None:
        payload["approval_evidence_sha256"] = context.commitment
    event_id = await owner._enqueue(
        tx,
        context.admitted,
        payload,
        json.loads(context.actor_json),
        occurred_at,
        None,
        signed_trace_id=context.signed_trace_id,
    )
    await tx.execute(
        "INSERT INTO {{tables.credential_narrowing_authority}} "
        "(event_id,subject,app_id,team_id,installation_id,generation,authority,actor,"
        "commitment,retained_proof,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11)",
        event_id,
        subject_ref,
        context.admitted.app_id,
        context.admitted.team_id,
        context.admitted.installation_id,
        context.admitted.generation,
        context.authority,
        context.actor_json,
        context.commitment,
        context.retained_json,
        occurred_at,
    )
    return event_id


async def record_narrowing(
    owner: CredentialAudit, event: AuditEvent, tx: TransactionManager, context: Any
) -> None:
    if (
        not isinstance(context, PreparedContainment)
        or context.owner is not owner
        or context.transaction_id != await tx.fetch_value("SELECT txid_current()")
        or event.actor != context.authorized_by
    ):
        raise GovernanceUnavailable()
    # Containment removes application approver metadata before B3. The frozen
    # designation association survives that removal; no live resolver is used.
    row = await tx.fetch_one(
        "SELECT a.*,p.superseded_at FROM {{tables.credential_authorizations}} a "
        "JOIN {{tables.passkey_approvers}} p USING(subject) WHERE a.subject=$1 AND p.scope=a.scope",
        event.subject,
    )
    if (
        row is None
        or owner._admitted(row) != context.admitted
        or event.details.get("scope") != row["scope"]
    ):
        raise GovernanceUnavailable()
    payload = dict(
        act="role.revoked",
        direction="narrowing",
        subject_ref=event.subject,
        role=row["role"],
        authority=context.authority,
    )
    if event.kind is AuditKind.APPROVER_RETIRED:
        if row["superseded_at"] != event.occurred_at:
            raise GovernanceUnavailable()
    else:
        try:
            credential_id = base64url_to_bytes(event.details["credential_id"])
        except (KeyError, TypeError, ValueError):
            raise GovernanceUnavailable() from None
        key = await tx.fetch_one(
            "SELECT c.credential_ref,k.revoked_at FROM {{tables.credential_completion_links}} c "
            "JOIN {{tables.passkey_credentials}} k ON k.credential_id=c.credential_id "
            "AND k.subject=c.subject WHERE c.subject=$1 AND c.credential_id=$2",
            event.subject,
            credential_id,
        )
        if key is None or key["revoked_at"] != event.occurred_at or key["credential_ref"] is None:
            raise GovernanceUnavailable()
        payload.update(
            act="credential.revoked", resource_type="passkey", resource_ref=key["credential_ref"]
        )
    if context.commitment is not None:
        payload["approval_evidence_sha256"] = context.commitment
    event_id = await owner._enqueue(
        tx,
        context.admitted,
        payload,
        json.loads(context.actor_json),
        event.occurred_at,
        None,
        signed_trace_id=context.signed_trace_id,
    )
    await tx.execute(
        "INSERT INTO {{tables.credential_narrowing_authority}} "
        "(event_id,subject,app_id,team_id,installation_id,generation,authority,actor,"
        "commitment,retained_proof,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11)",
        event_id,
        event.subject,
        context.admitted.app_id,
        context.admitted.team_id,
        context.admitted.installation_id,
        context.admitted.generation,
        context.authority,
        context.actor_json,
        context.commitment,
        context.retained_json,
        event.occurred_at,
    )
