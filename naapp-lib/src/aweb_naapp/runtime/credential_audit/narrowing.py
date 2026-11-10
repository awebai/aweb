"""B3 narrowing, authorized by the caller or by a consumed owner act, including
its nested effect savepoints."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from pgdbm.core import TransactionManager
from webauthn.helpers import base64url_to_bytes

from aweb_naapp.hooks.owner_act import HumanCredential
from aweb_naapp.roles import HoldingRecord, principal_key
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.credential_audit.recorder import (
    GovernanceUnavailable,
    _owner_act_actor,
    _OwnerActContext,
)
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext, PasskeyProofUnavailable

if TYPE_CHECKING:
    from aweb_naapp.console import ConsoleSession
    from aweb_naapp.runtime.credential_audit.recorder import CredentialAudit
    from aweb_naapp.runtime.team_auth import Principal


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


@dataclass(frozen=True, repr=False)
class _NarrowingAuthority:
    admitted: AdmittedInstallation
    authority: str
    actor: dict
    commitment: str | None
    retained_json: str | None
    signing: bytes | None
    signature: str | None
    signed_trace_id: str | None
    # The human-role holding a consumed human-role.revoke ends, bound to the act.
    holding: HoldingRecord | None = None


# The payload field that carries each authority's commitment.
_COMMITMENT_FIELDS = {
    "passkey_session": "approval_evidence_sha256",
    "owner_act": "owner_act_sha256",
}


async def _narrowing_authority(
    owner: CredentialAudit, event: AuditEvent, tx: TransactionManager, context: Any
) -> _NarrowingAuthority:
    if isinstance(context, PreparedContainment):
        if (
            context.owner is not owner
            or context.transaction_id != await tx.fetch_value("SELECT txid_current()")
            or event.actor != context.authorized_by
        ):
            raise GovernanceUnavailable()
        return _NarrowingAuthority(
            context.admitted,
            context.authority,
            json.loads(context.actor_json),
            context.commitment,
            context.retained_json,
            None,
            None,
            context.signed_trace_id,
        )
    # An owner act revokes a role; it never revokes one passkey. A scope whose
    # role is declared human pairs only with human-role.revoke, bound to the
    # holding the act names; any other scope only with app-role.revoke.
    if (
        isinstance(context, _OwnerActContext)
        and context.owner is owner
        and event.kind is AuditKind.APPROVER_RETIRED
    ):
        scope = event.details.get("scope")
        if not isinstance(scope, str) or not scope:
            raise GovernanceUnavailable()
        holding = await owner.declared_human_record(tx, scope)
        if holding is not None:
            holding = await owner.human_record(
                tx, scope, context.admitted, owner.signed_subject(context)
            )
        expected = "app-role.revoke" if holding is None else "human-role.revoke"
        digest = await owner._consumed_act(tx, context, event, expected)
        return _NarrowingAuthority(
            context.admitted,
            "owner_act",
            _owner_act_actor(event),
            digest,
            None,
            context.signing,
            context.signature,
            None,
            holding,
        )
    raise GovernanceUnavailable()


async def record_narrowing(
    owner: CredentialAudit, event: AuditEvent, tx: TransactionManager, context: Any
) -> None:
    authority = await _narrowing_authority(owner, event, tx, context)
    if authority.holding is not None:
        await _require_holding_ended(tx, event, authority.holding)
        role = authority.holding.role
    else:
        role = await _require_narrowed_subject(owner, tx, event, authority)
    payload = dict(
        act="role.revoked",
        direction="narrowing",
        subject_ref=event.subject,
        role=role,
        authority=authority.authority,
    )
    if event.kind is AuditKind.APPROVER_PASSKEY_REVOKED:
        payload.update(
            act="credential.revoked",
            resource_type="passkey",
            resource_ref=await _revoked_key_ref(tx, event),
        )
    if authority.commitment is not None:
        payload[_COMMITMENT_FIELDS[authority.authority]] = authority.commitment
    event_id = await owner._enqueue(
        tx,
        authority.admitted,
        payload,
        authority.actor,
        event.occurred_at,
        None,
        signed_trace_id=authority.signed_trace_id,
    )
    await tx.execute(
        "INSERT INTO {{tables.credential_narrowing_authority}} "
        "(event_id,subject,app_id,team_id,installation_id,generation,authority,actor,"
        "commitment,retained_proof,signing,signature,occurred_at) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11,$12,$13)",
        event_id,
        event.subject,
        authority.admitted.app_id,
        authority.admitted.team_id,
        authority.admitted.installation_id,
        authority.admitted.generation,
        authority.authority,
        json.dumps(authority.actor),
        authority.commitment,
        authority.retained_json,
        authority.signing,
        authority.signature,
        event.occurred_at,
    )


async def _require_holding_ended(
    tx: TransactionManager, event: AuditEvent, holding: HoldingRecord
) -> None:
    """A human-role.revoke's narrowing is the end of the holding the act names,
    in this very transaction. Its subject is the holding's latest approver,
    retired now or earlier by containment, or the principal of a holding that
    never had an approver; nothing is made up for either."""
    if holding.ended_in is None or holding.ended_in != await tx.fetch_value(
        "SELECT txid_current()"
    ):
        raise GovernanceUnavailable()
    latest = await tx.fetch_one(
        "SELECT subject,superseded_at FROM {{tables.passkey_approvers}} "
        "WHERE scope=$1 ORDER BY designated_at DESC LIMIT 1",
        holding.b3_scope,
    )
    if latest is None:
        if event.subject != holding.principal:
            raise GovernanceUnavailable()
        return
    if (
        event.subject != latest["subject"]
        or latest["superseded_at"] is None
        or latest["superseded_at"] > event.occurred_at
        or not await tx.fetch_value(
            "SELECT 1 FROM {{tables.credential_authorizations}} WHERE subject=$1 AND scope=$2",
            event.subject,
            holding.b3_scope,
        )
    ):
        raise GovernanceUnavailable()


async def _require_narrowed_subject(
    owner: CredentialAudit,
    tx: TransactionManager,
    event: AuditEvent,
    authority: _NarrowingAuthority,
) -> str:
    """The designation a narrowing retires or revokes a key of, retired at the
    event's own time; its role."""
    # Containment removes application approver metadata before B3. The frozen
    # designation association survives that removal; no live resolver is used.
    row = await tx.fetch_one(
        "SELECT a.*,p.superseded_at FROM {{tables.credential_authorizations}} a "
        "JOIN {{tables.passkey_approvers}} p USING(subject) WHERE a.subject=$1 AND p.scope=a.scope",
        event.subject,
    )
    if (
        row is None
        or owner._admitted(row) != authority.admitted
        or event.details.get("scope") != row["scope"]
    ):
        raise GovernanceUnavailable()
    if event.kind is AuditKind.APPROVER_RETIRED and row["superseded_at"] != event.occurred_at:
        raise GovernanceUnavailable()
    return row["role"]


async def _revoked_key_ref(tx: TransactionManager, event: AuditEvent) -> str:
    """The opaque reference of the key a PASSKEY_REVOKED event revoked at its
    own time: an enrolled key's from its completion link, a human-role
    holder's from its authorization, matched by the credential digest."""
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
    if key is None:
        key = await tx.fetch_one(
            "SELECT a.credential_ref,a.credential_sha256,k.revoked_at,k.public_key,k.rp_id "
            "FROM {{tables.credential_authorizations}} a "
            "JOIN {{tables.passkey_credentials}} k ON k.subject=a.subject "
            "WHERE a.subject=$1 AND k.credential_id=$2 AND a.credential_ref IS NOT NULL",
            event.subject,
            credential_id,
        )
        if (
            key is not None
            and HumanCredential(credential_id, bytes(key["public_key"]), key["rp_id"]).sha256
            != key["credential_sha256"]
        ):
            raise GovernanceUnavailable()
    if key is None or key["revoked_at"] != event.occurred_at or key["credential_ref"] is None:
        raise GovernanceUnavailable()
    return key["credential_ref"]
