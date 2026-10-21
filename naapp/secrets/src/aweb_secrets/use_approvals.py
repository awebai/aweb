"""approve_only use approvals on B2 (secrets §10, decision 63).

A use that needs approval is put to the approvers its policy lists that also
cover the secret, as one B2 approval in the caller's transaction (S11's intent
transaction). Its B2 policy reference names the installation, team, grant and
policy digest, and resolves only while that grant is active and still names
that digest. The approved use is admitted exactly once, also in the caller's
transaction, at the secret version it was approved for.

Every function takes the caller's transaction and refuses with the codes of the
hook-actions vector. `admit_approved_use` returns its refusal rather than raise
it, so a void it makes commits with the caller's dispatch close.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Admission,
    ApprovalRefused,
    Approvals,
    ApprovalState,
    Approver,
    Assurance,
    PendingApproval,
    Refusal,
)
from aweb_naapp.runtime.passkeys import Passkeys
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, records
from aweb_secrets.admission import Admission as UseAdmitted
from aweb_secrets.approvers import approvers_for_secrets
from aweb_secrets.derived_capture import DEFAULT_MAX_TTL_S
from aweb_secrets.owners import OwnerDirectory, approver_scope, is_owner_scope, owner_scope
from aweb_secrets.policy import Policy
from aweb_secrets.use_approval import (
    REQUEST_TYPE,
    BrokerOpen,
    BrokerOperation,
    RunJob,
    UseApprovalRefused,
    use_approval_request,
)

MIGRATIONS = Path(__file__).parent / "use_approval_migrations"
MIGRATION_MODULE = "aweb_secrets_use_approvals"
POLICY_PREFIX = "secrets.use"
POLICY_VERSION = 1
OWNER_ENTRY = "owner:"


async def apply_use_approval_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS), module_name=MIGRATION_MODULE
    ).apply_pending_migrations()


def use_policy_ref(installation_id: str, team_id: str, grant_id: str, policy_digest: str) -> str:
    return "|".join((POLICY_PREFIX, installation_id, team_id, grant_id, policy_digest))


def _approver_scopes(installation_id: str, team_id: str, policy: Policy) -> tuple[str, ...]:
    """The scopes of the approvers a policy lists: an approver record's ref, or
    `owner:<principal_did>` for an owner."""
    scopes = []
    for entry in policy.body["approvers"]:
        if entry.startswith(OWNER_ENTRY):
            scopes.append(owner_scope(installation_id, team_id, entry[len(OWNER_ENTRY) :]))
        else:
            scopes.append(approver_scope(installation_id, team_id, entry))
    return tuple(scopes)


async def _granted_policy(
    tx: TransactionManager, installation_id: str, team_id: str, grant_id: str, digest: str
) -> Policy | None:
    """The policy, while the grant is active and still names its digest."""
    current = await tx.fetch_value(
        "SELECT 1 FROM {{tables.grants}} WHERE grant_id = $1 AND installation_id = $2 "
        "AND team_id = $3 AND policy_digest = $4 AND revoked_at IS NULL",
        grant_id,
        installation_id,
        team_id,
        digest,
    )
    return await records.policy(tx, installation_id, digest) if current else None


async def _action_policy(tx: TransactionManager, policy_ref: str) -> ActionPolicy | None:
    """The B2 policy behind a use-approval reference, while its grant is active
    and still names its digest; None otherwise, which voids its approvals."""
    parts = policy_ref.split("|")
    if len(parts) != 5 or parts[0] != POLICY_PREFIX:
        return None
    _, installation_id, team_id, grant_id, digest = parts
    policy = await _granted_policy(tx, installation_id, team_id, grant_id, digest)
    if policy is None:
        return None
    return _b2_policy(policy_ref, installation_id, team_id, policy)


def _b2_policy(
    policy_ref: str, installation_id: str, team_id: str, policy: Policy
) -> ActionPolicy | None:
    scopes = _approver_scopes(installation_id, team_id, policy)
    if not scopes:
        return None
    return ActionPolicy(
        policy_ref=policy_ref,
        version=POLICY_VERSION,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(seconds=policy.body["approval_ttl_s"]),
        approver_scopes=scopes,
        allow_requester_approval=policy.body["distinct_approver"] != "required",
    )


class UsePolicies:
    """B2's policy source for use approvals."""

    def __init__(self, db: AsyncDatabaseManager) -> None:
        self._db = db

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        async with self._db.transaction() as tx:
            return await _action_policy(tx, policy_ref)


class UseApprovers:
    """B2's approver directory for use approvals: the approver records covering
    the request's secret or a recorded ancestor, and the owners. B2 keeps only those in the policy's
    scopes, so a candidate is both listed and covering (decision 63); an owner
    has no covers and counts whenever listed."""

    def __init__(
        self, db: AsyncDatabaseManager, passkeys: Passkeys, owners: OwnerDirectory
    ) -> None:
        self._db = db
        self._passkeys = passkeys
        self._owners = owners

    async def candidates(self, policy: ActionPolicy, request: Mapping[str, Any]) -> list[Approver]:
        if request.get("type") != REQUEST_TYPE:
            return []
        async with self._db.transaction() as tx:
            ids = await derived_lineage.ancestry_ids(
                tx, request["installation_id"], request["team_id"], request["secret"]["secret_id"]
            )
            covering = await approvers_for_secrets(
                tx,
                installation_id=request["installation_id"],
                team_id=request["team_id"],
                secret_ids=ids,
            )
        found: list[Approver] = []
        for record in covering:
            approver = await self._passkeys.designated_approver(record.scope)
            if approver is not None:
                found.append(replace(approver, principal_did=record.principal_did))
        owners = tuple(scope for scope in policy.approver_scopes if is_owner_scope(scope))
        if owners:
            owner_policy = replace(policy, approver_scopes=owners, allow_requester_approval=True)
            found.extend(await self._owners.candidates(owner_policy, request))
        return found

    async def is_current(self, scope: str, subject: str) -> bool:
        if is_owner_scope(scope):
            return await self._owners.is_current(scope, subject)
        return await self._passkeys.is_current(scope, subject)


@dataclass(frozen=True)
class PendingUseApproval:
    """A use approval minted in the caller's transaction. Send its links with
    `Approvals.deliver(pending)` after the commit; the requester gets
    `approval_ref`, never a link."""

    pending: PendingApproval
    approval_ref: str


@dataclass(frozen=True)
class UseAdmission:
    """The admitted dispatch, or the refusal code; never both."""

    admission: Admission | None
    refusal: str | None


@dataclass(frozen=True)
class UseApprovalStatus:
    """What the requester may see: the approval's state, and, once approved,
    that re-submitting the same request_id dispatches it."""

    state: str
    next: str | None


async def _locked_ancestry(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    grant_id: str,
    max_ttl_s: int,
) -> tuple[tuple[derived_lineage.LineageNode, ...], str | None]:
    """Keep an authority refusal until stable retrieval has been classified.
    All ancestry and grant locks precede covering-record and B2 locks."""
    nodes: tuple[derived_lineage.LineageNode, ...] = ()
    try:
        nodes = await derived_lineage.lock_ancestry(tx, installation_id, team_id, secret_id)
        await derived_lineage.check_ancestry(
            tx, nodes, now=approvals.now(), max_ttl_s=max_ttl_s, candidate_grant_ids=[grant_id]
        )
    except derived_lineage.LineageRefused as exc:
        return nodes, exc.code
    return nodes, None


async def _covering_scopes(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    secret_ids: Sequence[str],
    policy: ActionPolicy | None,
) -> frozenset[str]:
    covering = await approvers_for_secrets(
        tx, installation_id=installation_id, team_id=team_id, secret_ids=secret_ids
    )
    if policy is None:
        return frozenset()
    # Owners have no covers; they count only while explicitly policy-listed.
    scopes = {record.scope for record in covering}
    scopes.update(scope for scope in policy.approver_scopes if is_owner_scope(scope))
    return frozenset(scopes.intersection(policy.approver_scopes))


async def request_use_approval(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    admission: UseAdmitted,
    dispatch_id: uuid.UUID,
    principal: Principal,
    action: BrokerOperation | BrokerOpen | RunJob,
    reason: str,
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
) -> PendingUseApproval:
    """Put an admitted use to its approvers, in the caller's transaction.

    Caller holds the installation fence (and any role hold) first. Ancestry,
    source/candidate grants and covering approver records stay locked through
    mint. Pass the deployment's derived-secret TTL cap as max_ttl_s.
    Asking again for the same intent returns its approval and mints nothing."""
    existing = await tx.fetch_one(
        "SELECT approval_id, approval_ref FROM {{tables.use_approvals}} WHERE intent_id = $1",
        admission.intent_id,
    )
    if existing is not None:
        approval = await approvals.get(existing["approval_id"])
        assert approval is not None
        view = await approvals.requester_view(
            existing["approval_ref"], principal_key(principal).principal_did
        )
        return PendingUseApproval(
            pending=PendingApproval(view=view, approval=approval, deliveries=()),
            approval_ref=existing["approval_ref"],
        )
    intent = await tx.fetch_one(
        "SELECT * FROM {{tables.intents}} WHERE intent_id = $1", admission.intent_id
    )
    assert intent is not None
    nodes, refusal = await _locked_ancestry(
        tx,
        approvals,
        installation_id=intent["installation_id"],
        team_id=intent["team_id"],
        secret_id=intent["secret_id"],
        grant_id=intent["grant_id"],
        max_ttl_s=max_ttl_s,
    )
    if refusal is not None:
        raise UseApprovalRefused(refusal, "the secret's ancestry no longer permits this use")
    stored = nodes[-1].secret
    if stored.active_version != intent["secret_version"]:
        raise UseApprovalRefused("secret_version_changed", "the value changed after admission")
    policy_ref = use_policy_ref(
        intent["installation_id"], intent["team_id"], intent["grant_id"], intent["policy_digest"]
    )
    granted = await _granted_policy(
        tx,
        intent["installation_id"],
        intent["team_id"],
        intent["grant_id"],
        intent["policy_digest"],
    )
    if granted is None:
        raise UseApprovalRefused("grant_revoked", "the grant or its policy changed")
    policy = _b2_policy(policy_ref, intent["installation_id"], intent["team_id"], granted)
    if policy is None:
        raise UseApprovalRefused("no_eligible_approver", "the policy lists no approver")
    scopes = await _covering_scopes(
        tx,
        installation_id=intent["installation_id"],
        team_id=intent["team_id"],
        secret_ids=[node.secret.record.secret_id for node in nodes],
        policy=policy,
    )
    if not scopes:
        raise UseApprovalRefused("no_eligible_approver", "no listed approver covers the ancestry")
    request = use_approval_request(
        installation_id=intent["installation_id"],
        install_generation=intent["install_generation"],
        team_id=intent["team_id"],
        requester=principal,
        secret=stored.record,
        secret_version=intent["secret_version"],
        policy_digest=intent["policy_digest"],
        grant_id=intent["grant_id"],
        request_id=intent["request_id"],
        reason=reason,
        issued_at=approvals.now(),
        ttl=policy.ttl,
        action=action,
    )
    try:
        pending = await approvals.mint(
            request=request,
            policy_ref=policy_ref,
            requested_by=principal_key(principal).principal_did,
            expires_at=datetime.fromisoformat(request["expires_at"]),
            tx=tx,
        )
    except ApprovalRefused as exc:
        if exc.reason is Refusal.NO_ELIGIBLE_APPROVER:
            raise UseApprovalRefused("no_eligible_approver", "no approver can decide") from exc
        if exc.reason is Refusal.POLICY_UNKNOWN:
            raise UseApprovalRefused("grant_revoked", "the grant or policy changed") from exc
        raise
    if any(candidate.scope not in scopes for candidate in pending.approval.candidates):
        raise UseApprovalRefused("no_eligible_approver", "coverage changed while minting")
    await tx.execute(
        "INSERT INTO {{tables.use_approvals}} (intent_id, dispatch_id, installation_id, team_id, "
        "secret_id, secret_version, approval_id, approval_ref, request) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        admission.intent_id,
        dispatch_id,
        intent["installation_id"],
        intent["team_id"],
        intent["secret_id"],
        intent["secret_version"],
        pending.approval.approval_id,
        pending.view.request_id,
        json.dumps(request),
    )
    return PendingUseApproval(pending=pending, approval_ref=pending.view.request_id)


_STATE_REFUSALS = {
    ApprovalState.PENDING: "approval_pending",
    ApprovalState.REJECTED: "approval_denied",
}


async def _void(
    tx: TransactionManager, approvals: Approvals, approval_id: str, reason: str
) -> None:
    await approvals.revoke_many([approval_id], revoked_by="secrets", reason=reason, tx=tx)


async def admit_approved_use(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    intent_id: str,
    dispatch_id: uuid.UUID,
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
) -> UseAdmission:
    """Admit the approved use's one dispatch, in the caller's transaction.

    The same dispatch asked again retrieves its admission; any other dispatch
    is refused as `approval_consumed`. A moved secret version refuses new
    admissions and not_sent transport retries, while preserving retrieval of
    an already admitted dispatch. A changed grant, policy or approver voids
    any approval that has not yet been dispatched. Caller holds the installation
    fence and any role hold first; ancestry, grants, covering records, then B2
    are locked in that order. max_ttl_s is the deployment's current derived cap."""
    link = await tx.fetch_one(
        "SELECT * FROM {{tables.use_approvals}} WHERE intent_id = $1 FOR UPDATE", intent_id
    )
    if link is None:
        return UseAdmission(admission=None, refusal="approval_pending")
    approval_id = link["approval_id"]
    request = json.loads(link["request"])
    nodes, refusal = await _locked_ancestry(
        tx,
        approvals,
        installation_id=link["installation_id"],
        team_id=link["team_id"],
        secret_id=link["secret_id"],
        grant_id=request["grant_id"],
        max_ttl_s=max_ttl_s,
    )
    if refusal is None and nodes[-1].secret.active_version != link["secret_version"]:
        refusal = "secret_version_changed"
    granted = await _granted_policy(
        tx, link["installation_id"], link["team_id"], request["grant_id"], request["policy_digest"]
    )
    policy = (
        None
        if granted is None
        else _b2_policy(
            use_policy_ref(
                link["installation_id"],
                link["team_id"],
                request["grant_id"],
                request["policy_digest"],
            ),
            link["installation_id"],
            link["team_id"],
            granted,
        )
    )
    if policy is None:
        refusal = refusal or "grant_revoked"
    scopes = await _covering_scopes(
        tx,
        installation_id=link["installation_id"],
        team_id=link["team_id"],
        secret_ids=[node.secret.record.secret_id for node in nodes],
        policy=policy,
    )
    try:
        # retrieve holds B2's row lock in tx even when it returns None. Only
        # after this classification may an authority refusal void the attempt.
        retrieved = await approvals.retrieve(approval_id, request, str(dispatch_id), tx=tx)
        if retrieved is not None:
            return UseAdmission(admission=retrieved, refusal=None)
        approval = await approvals.get(approval_id)
        assert approval is not None
        if approval.state in (
            ApprovalState.PENDING,
            ApprovalState.APPROVED,
            ApprovalState.CONSUMED,
        ):
            if approval.decided_by is not None:
                eligible = approval.decided_by.scope in scopes
            else:
                eligible = any(candidate.scope in scopes for candidate in approval.candidates)
            if not eligible:
                refusal = refusal or "approval_revoked"
        if refusal is not None:
            await _void(tx, approvals, approval_id, refusal)
            return UseAdmission(admission=None, refusal=refusal)
        admitted = await approvals.admit(approval_id, request, str(dispatch_id), tx=tx)
    except ApprovalRefused as exc:
        return UseAdmission(
            admission=None, refusal=await _refusal(tx, approvals, approval_id, exc.reason)
        )
    return UseAdmission(admission=admitted, refusal=None)


async def _refusal(
    tx: TransactionManager, approvals: Approvals, approval_id: str, reason: Refusal
) -> str:
    if reason is Refusal.CONSUMED:
        return "approval_consumed"
    if reason is Refusal.UNRECONCILED_DISPATCH:
        return "reconciliation_pending"
    if reason in (Refusal.POLICY_UNKNOWN, Refusal.POLICY_CHANGED):
        await _void(tx, approvals, approval_id, "grant_revoked")
        return "grant_revoked"
    if reason in (Refusal.APPROVER_RETIRED, Refusal.ASSURANCE_INSUFFICIENT):
        await _void(tx, approvals, approval_id, "approval_revoked")
        return "approval_revoked"
    if reason is Refusal.EXPIRED:
        return "approval_expired"
    if reason is Refusal.NOT_APPROVED:
        approval = await approvals.get(approval_id)
        assert approval is not None
        return _STATE_REFUSALS.get(approval.state, "approval_revoked")
    return "approval_revoked"


async def void_use_approvals(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    current_version: int,
    revoked_by: str,
) -> Sequence[str]:
    """Void the secret's use approvals made for any other version, pending or
    approved and not yet dispatched, when its value is replaced or its
    external item changes. Returns the approvals voided."""
    rows = await tx.fetch_all(
        "SELECT approval_id FROM {{tables.use_approvals}} WHERE installation_id = $1 "
        "AND team_id = $2 AND secret_id = $3 AND secret_version <> $4",
        installation_id,
        team_id,
        secret_id,
        current_version,
    )
    revoked = await approvals.revoke_many(
        [row["approval_id"] for row in rows],
        revoked_by=revoked_by,
        reason="secret_version_changed",
        tx=tx,
    )
    return [approval.approval_id for approval in revoked]


async def revoke_use_approvals(
    tx: TransactionManager,
    approvals: Approvals,
    *,
    installation_id: str,
    team_id: str,
    secret_ids: Sequence[str],
    revoked_by: str,
    reason: str,
) -> Sequence[str]:
    """Revoke all versions for exactly these scoped secret IDs, in the
    caller's containment transaction. The caller selects descendants through
    stored lineage and holds the installation/ancestry/grant fences first.
    Consumed attempts stay retrievable; NOT_SENT transport retries stop."""
    rows = await tx.fetch_all(
        "SELECT approval_id FROM {{tables.use_approvals}} WHERE installation_id=$1 "
        "AND team_id=$2 AND secret_id=ANY($3::text[])",
        installation_id,
        team_id,
        list(secret_ids),
    )
    revoked = await approvals.revoke_many(
        [row["approval_id"] for row in rows], revoked_by=revoked_by, reason=reason, tx=tx
    )
    return [approval.approval_id for approval in revoked]


_STATUS = {
    ApprovalState.PENDING: ("awaiting_approval", None),
    ApprovalState.APPROVED: ("approved", "resubmit"),
    ApprovalState.REJECTED: ("denied", None),
    ApprovalState.EXPIRED: ("expired", None),
    ApprovalState.REVOKED: ("revoked", None),
    ApprovalState.CONSUMED: ("admitted", None),
}


async def use_approval_status(
    approvals: Approvals,
    *,
    approval_ref: str,
    principal: Principal,
) -> UseApprovalStatus:
    """The requester's view of its use approval. It only reports: re-submitting
    the same request_id is what dispatches an approved use."""
    try:
        view = await approvals.requester_view(approval_ref, principal_key(principal).principal_did)
    except ApprovalRefused as exc:
        raise UseApprovalRefused("not_found", "no such approval for this requester") from exc
    state, next_step = _STATUS[view.approval_state]
    return UseApprovalStatus(state=state, next=next_step)


__all__ = [
    "PendingUseApproval",
    "UseAdmission",
    "UseApprovalRefused",
    "UseApprovalStatus",
    "UseApprovers",
    "UsePolicies",
    "admit_approved_use",
    "apply_use_approval_migrations",
    "request_use_approval",
    "revoke_use_approvals",
    "use_approval_status",
    "use_policy_ref",
    "void_use_approvals",
]
