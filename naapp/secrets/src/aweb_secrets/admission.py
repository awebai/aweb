"""Admission of a member's use of a secret, in the order of §4.1.

B1 has authenticated the request, matched it to a declared tool and checked the
tool's scopes against the installed grant. Admission then runs in the caller's
transaction, and every step refuses rather than guesses:

1. the installation fence binds the request to the grant's installation and
   generation (refusals pass through as :class:`InstallationRefused`);
2. the principal is S5's stable principal of the verified certificate;
3. the request's ``request_id`` is claimed for this installation and principal,
   so a replay returns the first intent and is never admitted again;
4. the secret must be enabled and confirmed, and a grant to the principal or one
   of its secrets roles must cover the request;
5. that grant's policy must admit it: the action, the time window, the
   attestation predicates, then one token from each rate bucket.

Candidate grants are tried in a fixed order, grants to the principal before
grants to its roles, each by grant id. The first that admits is used and only
its policy's buckets are charged; when none admits, the first candidate's
refusal is returned. The intent records the grant, policy, secret version and
installation generation admitted.
"""

from __future__ import annotations

import secrets as random
from dataclasses import dataclass
from datetime import datetime, timedelta

from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired, claim
from aweb_naapp.roles import principal_key, roles_of
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import records
from aweb_secrets.grant import GrantRecord, is_secrets_role
from aweb_secrets.policy import AttestationFacts, Policy
from aweb_secrets.rate import RateLimited, charge

# How long a request id keeps answering with its first intent (§11.2).
IDEMPOTENCY_RETENTION = timedelta(days=30)


class AdmissionRefused(Exception):
    """The request is not admitted; ``code`` is the frozen refusal code."""

    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class UseRequest:
    """What a member asks to do with a secret: a named operation, or an open request."""

    secret_ref: str
    request_id: str
    request_sha256: bytes
    operation_id: str | None


@dataclass(frozen=True)
class Admission:
    intent_id: str
    replayed: bool
    approval_required: bool
    grant_id: str
    policy_digest: str
    installation: AdmittedInstallation


def mint_intent_id() -> str:
    return "int_" + random.token_urlsafe(16)


def _covers(
    grant: GrantRecord, policy: Policy, request: UseRequest, sensitivity: str
) -> str | None:
    """The refusal code when the grant and its policy do not cover the action, else None."""
    if request.operation_id is None:
        if sensitivity != "standard" or not grant.open_request or not policy.body["open_request"]:
            return "open_request_not_allowed"
        return None
    return "operation_not_allowed"


async def _replayed(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    intent_id: str,
    principal_did: str,
    roles: list[str],
) -> Admission:
    row = await tx.fetch_one(
        """
        SELECT secret_id, grant_id, policy_digest, approval_required FROM {{tables.intents}}
        WHERE intent_id = $1 AND installation_id = $2
        """,
        intent_id,
        installation.installation_id,
    )
    if row is None:
        raise RuntimeError("an idempotency key stands for an intent that cannot be read")
    still_granted = await records.active_grants(
        tx, installation.installation_id, row["secret_id"], principal_did=principal_did, roles=roles
    )
    if row["grant_id"] not in {grant.grant_id for grant in still_granted}:
        raise AdmissionRefused("grant_revoked")
    return Admission(
        intent_id=intent_id,
        replayed=True,
        approval_required=row["approval_required"],
        grant_id=row["grant_id"],
        policy_digest=row["policy_digest"],
        installation=installation,
    )


async def admit_use(
    tx: TransactionManager,
    *,
    fence: InstallationFence,
    grant: Grant,
    principal: Principal,
    request: UseRequest,
    attestation: AttestationFacts | None,
    now: datetime,
) -> Admission:
    """Admit ``request`` in the caller's transaction, or raise :class:`AdmissionRefused`.

    ``attestation`` is the verified principal attestation that accompanied the
    request, or None when it carried none.
    """
    installation = await fence.admit(tx, grant)
    key = principal_key(principal)
    roles = [role for role in await roles_of(tx, key) if is_secrets_role(role)]
    intent_id = mint_intent_id()
    try:
        receipt = await claim(
            tx,
            key=(installation.installation_id, key.principal_did, request.request_id),
            request_hash=request.request_sha256,
            receipt_ref=intent_id,
            retention=IDEMPOTENCY_RETENTION,
        )
    except IdempotencyConflict:
        raise AdmissionRefused("idempotency_conflict", 409) from None
    except IdempotencyExpired:
        raise AdmissionRefused("idempotency_expired", 410) from None
    if not receipt.created:
        return await _replayed(tx, installation, receipt.receipt_ref, key.principal_did, roles)

    stored = await records.secret_by_ref(
        tx, installation.installation_id, installation.team_id, request.secret_ref
    )
    grants = (
        []
        if stored is None
        else await records.active_grants(
            tx,
            installation.installation_id,
            stored.record.secret_id,
            principal_did=key.principal_did,
            roles=roles,
        )
    )
    candidates = sorted(
        (g for g in grants if g.capability == "use"),
        key=lambda g: (g.subject_principal is None, g.grant_id),
    )
    if stored is None or not candidates:
        raise AdmissionRefused("grant_missing")
    if stored.state != "active" or stored.active_version is None:
        raise AdmissionRefused("secret_disabled")

    first_refusal: AdmissionRefused | None = None
    for candidate in candidates:
        policy = await records.policy(tx, installation.installation_id, candidate.policy_digest)
        if policy is None:
            raise RuntimeError("a grant references a policy that cannot be read")
        refusal = _covers(candidate, policy, request, stored.record.sensitivity)
        if refusal is None and not policy.window_open(now):
            refusal = "policy_window_closed"
        if refusal is None and not policy.attestation_satisfied(attestation):
            refusal = "attestation_unavailable"
        if refusal is None:
            try:
                await charge(
                    tx,
                    installation.installation_id,
                    stored.record.secret_id,
                    key.principal_did,
                    policy.body["rate"],
                    now=now,
                )
            except RateLimited:
                refusal = RateLimited.code
        if refusal is not None:
            first_refusal = first_refusal or AdmissionRefused(
                refusal, RateLimited.status if refusal == RateLimited.code else 403
            )
            continue
        approval_required = policy.body["approval"] == "per_use" or stored.record.approve_only
        await tx.execute(
            """
            INSERT INTO {{tables.intents}} (
                intent_id, installation_id, install_generation, team_id, principal_did,
                member_did_key, certificate_id, request_id, request_sha256, secret_id,
                secret_version, grant_id, policy_digest, action, operation_id,
                operation_digest, approval_required
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            """,
            intent_id,
            installation.installation_id,
            installation.generation,
            installation.team_id,
            key.principal_did,
            principal.did_key,
            principal.certificate_id,
            request.request_id,
            request.request_sha256,
            stored.record.secret_id,
            stored.active_version,
            candidate.grant_id,
            policy.digest,
            "open_request" if request.operation_id is None else "operation",
            None,
            None,
            approval_required,
        )
        return Admission(
            intent_id=intent_id,
            replayed=False,
            approval_required=approval_required,
            grant_id=candidate.grant_id,
            policy_digest=policy.digest,
            installation=installation,
        )
    raise first_refusal or RuntimeError("no candidate grant was evaluated")
