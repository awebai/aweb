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
   attestation predicates, then one token from each of its rate buckets, taken
   through the shared :mod:`aweb_naapp.ratelimit`.

Candidate grants are tried in a fixed order, grants to the principal before
grants to its roles, each by grant id. The first that admits is used and only
its policy's buckets are charged; when none admits, the first candidate's
refusal is returned. The intent records the grant, policy, secret version and
installation generation admitted.
"""

from __future__ import annotations

import secrets as random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from aweb_naapp import ratelimit
from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired, claim
from aweb_naapp.roles import PrincipalKey, hold_role, principal_key, roles_of
from aweb_naapp.runtime.attestation import VerifiedAttestation
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, records
from aweb_secrets.derived_capture import DEFAULT_MAX_TTL_S
from aweb_secrets.grant import GrantRecord, is_secrets_role
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy

# How long a request id keeps answering with its first intent (§11.2).
IDEMPOTENCY_RETENTION = timedelta(days=30)


RATE_LIMITED = "policy_rate_limited"


class AdmissionRefused(Exception):
    """The request is not admitted; ``code`` is the frozen refusal code.

    A rate refusal carries ``retry_after_s``, the whole seconds until the
    policy's buckets hold a token again; any other refusal carries 0.
    """

    def __init__(self, code: str, status: int = 403, *, retry_after_s: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after_s = retry_after_s


def _charges(
    installation: AdmittedInstallation, secret_id: str, principal_did: str, policy: Policy
) -> list[ratelimit.Charge]:
    """One charge per bucket of the policy's rate (§4.4), keyed by the policy as well,
    so admissions under one policy never refill another policy's buckets."""
    charges = []
    for bucket in policy.body["rate"]:
        parts = [installation.installation_id, policy.digest, secret_id]
        if bucket["per"] == "principal_secret":
            parts.append(principal_did)
        charges.append(
            ratelimit.Charge(
                bucket=f"secrets.{bucket['per']}",
                key="\x1f".join(parts),
                capacity=bucket["capacity"],
                window_s=bucket["window_s"],
            )
        )
    return charges


@dataclass(frozen=True)
class UseRequest:
    """What a member asks to do with a secret: a named operation, or an open request."""

    secret_ref: str
    request_id: str
    request_sha256: bytes
    operation_id: str | None
    params: Mapping[str, Any] | None


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
    grant: GrantRecord,
    policy: Policy,
    request: UseRequest,
    sensitivity: str,
    operation: OperationTemplate | None,
) -> str | None:
    """The refusal code when the grant and its policy do not cover the action, else None.

    A named operation is covered at its current digest only, so an edited
    operation is covered by no grant made before the edit.
    """
    if request.operation_id is None:
        if sensitivity != "standard" or not grant.open_request or not policy.body["open_request"]:
            return "open_request_not_allowed"
        return None
    if operation is None:
        return "operation_not_allowed"
    pinned = (operation.operation_id, operation.digest)
    if not grant.covers_operation(*pinned) or pinned not in policy.allowed_operations:
        return "operation_not_allowed"
    if sensitivity == "sensitive" and operation.projection is None:
        return "operation_not_allowed"
    if operation.token_issuing and operation.after["result_handling"] == "deny":
        return "token_issuing_denied"
    if request.params is None or not operation.params_valid(request.params):
        return "params_invalid"
    return None


async def _replayed(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    intent_id: str,
    principal_did: str,
    roles: list[str],
    clock: Callable[[], datetime],
    derived_max_ttl_s: int,
) -> Admission:
    row = await tx.fetch_one(
        """
        SELECT secret_id, grant_id, policy_digest, approval_required, install_generation
        FROM {{tables.intents}}
        WHERE intent_id = $1 AND installation_id = $2
        """,
        intent_id,
        installation.installation_id,
    )
    if row is None:
        raise RuntimeError("an idempotency key stands for an intent that cannot be read")
    if row["install_generation"] != installation.generation:
        raise InstallationRefused(
            "generation_superseded", 409, "The request was admitted under an older generation"
        )
    nodes = await derived_lineage.lock_ancestry(
        tx, installation.installation_id, installation.team_id, row["secret_id"]
    )
    still_granted = await records.active_grants(
        tx,
        installation.installation_id,
        row["secret_id"],
        principal_did=principal_did,
        roles=roles,
        lock=False,
    )
    alive = await _check_lineage(
        tx, nodes, clock, derived_max_ttl_s, [g.grant_id for g in still_granted]
    )
    if row["grant_id"] not in alive or row["grant_id"] not in {
        grant.grant_id for grant in still_granted
    }:
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
    attestation: VerifiedAttestation | None,
    now: datetime,
    derived_max_ttl_s: int = DEFAULT_MAX_TTL_S,
    clock: Callable[[], datetime] = derived_lineage.utc_now,
) -> Admission:
    """Admit ``request`` in the caller's transaction, or raise :class:`AdmissionRefused`.

    ``clock`` stays live across database waits; it is separate from the policy
    and rate timestamp ``now``. Pass the current deployment's derived TTL cap.

    ``attestation`` is the verified principal attestation that accompanied the
    request, or None when it carried none. The principal's secrets roles are
    held until the caller's transaction ends, after the installation fence and
    before anything else, so a role cannot be withdrawn under an admission.
    Everything after that runs in a savepoint: a refusal leaves no claimed
    request id, no charged bucket and no intent behind, so a caller may record
    the denial in the same transaction and commit.
    """
    installation = await fence.admit(tx, grant)
    key = principal_key(principal)
    roles = [
        role
        for role in await roles_of(tx, key)
        if is_secrets_role(role) and await hold_role(tx, key, role)
    ]
    async with tx.transaction() as attempt:
        return await _admit_once(
            attempt,
            installation,
            key,
            roles,
            principal,
            request,
            attestation,
            now,
            derived_max_ttl_s,
            clock,
        )


async def _check_lineage(
    tx: TransactionManager,
    nodes: Sequence[derived_lineage.LineageNode],
    clock: Callable[[], datetime],
    max_ttl_s: int,
    grant_ids: Sequence[str],
) -> frozenset[str]:
    try:
        return await derived_lineage.check_ancestry(
            tx,
            nodes,
            clock=clock,
            max_ttl_s=max_ttl_s,
            candidate_grant_ids=grant_ids,
        )
    except derived_lineage.LineageRefused as refused:
        raise AdmissionRefused(refused.code) from None


async def _ancestor_charges(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    nodes: Sequence[derived_lineage.LineageNode],
) -> list[ratelimit.Charge]:
    charges = []
    for node in nodes:
        if node.policy_digest is None:
            continue
        policy = await records.policy(tx, installation.installation_id, node.policy_digest)
        if policy is None:
            raise AdmissionRefused("operation_not_allowed")
        assert node.parent_secret_id is not None and node.issuing_principal is not None
        charges.extend(
            _charges(installation, node.parent_secret_id, node.issuing_principal, policy)
        )
    return charges


async def _admit_once(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    key: PrincipalKey,
    roles: list[str],
    principal: Principal,
    request: UseRequest,
    attestation: VerifiedAttestation | None,
    now: datetime,
    derived_max_ttl_s: int,
    clock: Callable[[], datetime],
) -> Admission:
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
        return await _replayed(
            tx,
            installation,
            receipt.receipt_ref,
            key.principal_did,
            roles,
            clock,
            derived_max_ttl_s,
        )

    stored = await records.secret_by_ref(
        tx, installation.installation_id, installation.team_id, request.secret_ref, lock=False
    )
    nodes = (
        ()
        if stored is None
        else await derived_lineage.lock_ancestry(
            tx,
            installation.installation_id,
            installation.team_id,
            stored.record.secret_id,
        )
    )
    if nodes:
        stored = nodes[-1].secret
    grants = (
        []
        if stored is None
        else await records.active_grants(
            tx,
            installation.installation_id,
            stored.record.secret_id,
            principal_did=key.principal_did,
            roles=roles,
            lock=False,
        )
    )
    candidates = sorted(
        (g for g in grants if g.capability == "use"),
        key=lambda g: (g.subject_principal is None, g.grant_id),
    )
    if stored is None or not candidates:
        raise AdmissionRefused("grant_missing")
    alive = await _check_lineage(
        tx, nodes, clock, derived_max_ttl_s, [g.grant_id for g in candidates]
    )
    candidates = [candidate for candidate in candidates if candidate.grant_id in alive]
    if not candidates:
        raise AdmissionRefused("grant_missing")
    if stored.state != "active" or stored.active_version is None:
        raise AdmissionRefused("secret_disabled")
    operation = (
        None
        if request.operation_id is None
        else await derived_lineage.current_operation(tx, nodes, request.operation_id)
    )
    inherited = await _ancestor_charges(tx, installation, nodes)

    policies: list[Policy] = []
    for candidate in candidates:
        policy = await records.policy(tx, installation.installation_id, candidate.policy_digest)
        if policy is None:
            raise RuntimeError("a grant references a policy that cannot be read")
        policies.append(policy)

    first_refusal: AdmissionRefused | None = None
    for candidate, policy in zip(candidates, policies, strict=True):
        refusal = _covers(candidate, policy, request, stored.record.sensitivity, operation)
        if refusal is None and not policy.window_open(now):
            refusal = "policy_window_closed"
        if refusal is None and not policy.attestation_satisfied(attestation):
            refusal = "attestation_unavailable"
        retry_after_s = 0
        if refusal is None:
            charges = _charges(installation, stored.record.secret_id, key.principal_did, policy)
            # Preserve the original ancestor secret/principal/policy keys, and
            # charge a repeated bucket once even through multiple derivations.
            charges = list(
                {(charge.bucket, charge.key): charge for charge in [*charges, *inherited]}.values()
            )
            # Candidates take their buckets one after another. The installation
            # fence's row lock, taken first, serializes every admission that can
            # charge these buckets, which are all keyed by this installation, so
            # their lock order across candidates cannot cycle.
            decision = await ratelimit.take(tx, charges, now=now) if charges else None
            if decision is not None and decision.throttled:
                refusal = RATE_LIMITED
                retry_after_s = decision.retry_after_s
        if refusal is not None:
            first_refusal = first_refusal or AdmissionRefused(
                refusal, 429 if refusal == RATE_LIMITED else 403, retry_after_s=retry_after_s
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
            "open_request" if operation is None else "operation",
            None if operation is None else operation.operation_id,
            None if operation is None else operation.digest,
            approval_required,
        )
        # SQL reads/writes may block after the first authority check. Keep
        # this last check inside the admission savepoint so expiry rolls back
        # the intent, idempotency claim and all tentative rate charges.
        await _check_lineage(tx, nodes, clock, derived_max_ttl_s, [candidate.grant_id])
        return Admission(
            intent_id=intent_id,
            replayed=False,
            approval_required=approval_required,
            grant_id=candidate.grant_id,
            policy_digest=policy.digest,
            installation=installation,
        )
    raise first_refusal or RuntimeError("no candidate grant was evaluated")
