"""Check the original dispatch's authority at publication, without admitting again.

A continuation, the one repeat of a dispatch whose outcome is unknown, is
checked against the same consumed approval with every exact check, at
``outcome_unknown`` instead of ``dispatching``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

import asyncpg
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals.model import (
    ActionPolicy,
    Approval,
    ApprovalRefused,
    ApprovalState,
    DispatchOutcome,
    Refusal,
)
from aweb_naapp.runtime.approvals.request import request_sha256

if TYPE_CHECKING:
    from aweb_naapp.runtime.approvals.service import Approvals


@dataclass(frozen=True)
class DispatchBinding:
    approval_id: str
    request: Mapping[str, Any]
    operation_id: str


@dataclass(frozen=True)
class DispatchAuthorityState:
    policy: ActionPolicy | None
    decider_current: bool


class DispatchAuthority(Protocol):
    """App authority for an entire publication, always on the supplied tx.

    prepare holds the complete authority/covering union in the app's lock order,
    idempotently if already prepared. read uses only that authority: no new
    locks, network or refresh. Missing authority must fail closed. The app's
    installation, forest and sole-publication checks remain its responsibility.
    """

    async def prepare(self, tx: TransactionManager, approvals: Sequence[Approval]) -> None: ...

    async def read(self, tx: TransactionManager, approval: Approval) -> DispatchAuthorityState: ...


@dataclass(frozen=True)
class PreparedDispatch:
    """Private app handle for checks in one live caller transaction.

    expires_at is the original deadline for the app's final aggregate expiry
    check after all awaited work. This handle never grants may_send. The check
    requires the approval's dispatch outcome to be the one it was prepared for.
    """

    approval_id: str
    operation_id: str
    expires_at: datetime
    _approval: Approval = field(repr=False)
    _service: Approvals = field(repr=False)
    _tx: TransactionManager = field(repr=False)
    _transaction_id: int = field(repr=False)
    _guard_key: int = field(repr=False)
    _authority: DispatchAuthority = field(repr=False)
    _outcome: DispatchOutcome = field(repr=False)


def _live(tx: TransactionManager) -> bool:
    try:
        return tx.connection.is_in_transaction()
    except asyncpg.InterfaceError:
        return False


async def _guard_live(tx: TransactionManager, transaction_id: int, key: int) -> bool:
    """Observe a unique prepare-time lock; never reacquire it after rollback.

    tx identity/XID alone would miss a rollback-to-savepoint that released
    preparation locks while leaving the caller's outer transaction alive.
    """
    return bool(
        await tx.fetch_value(
            "SELECT txid_current_if_assigned()=$1 AND EXISTS ("
            "SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' "
            "AND classid=$2::oid AND objid=$3::oid AND objsubid=1 "
            "AND mode='ExclusiveLock' AND granted)",
            transaction_id,
            key >> 32,
            key & 0xFFFFFFFF,
        )
    )


def _associated(approval: Approval | None, binding: DispatchBinding) -> Approval:
    if approval is None:
        raise ApprovalRefused(Refusal.NOT_FOUND)
    digest = request_sha256(
        {
            "policy": {"ref": approval.policy_ref, "version": approval.policy_version},
            "request": binding.request,
        }
    )
    if digest != approval.request_sha256:
        raise ApprovalRefused(Refusal.REQUEST_MISMATCH)
    if (
        approval.state is not ApprovalState.CONSUMED
        or approval.consumed_operation_id != binding.operation_id
    ):
        raise ApprovalRefused(Refusal.OPERATION_MISMATCH)
    return approval


async def prepare_dispatches(
    service: Approvals,
    tx: TransactionManager,
    dispatches: Sequence[DispatchBinding],
    *,
    authority: DispatchAuthority,
    outcome: DispatchOutcome = DispatchOutcome.DISPATCHING,
) -> tuple[PreparedDispatch, ...]:
    if not _live(tx) or await tx.fetch_value("SHOW transaction_isolation") != "read committed":
        raise ApprovalRefused(Refusal.DISPATCH_NOT_PREPARED)
    # Keep batch membership fixed; revalidate requests after blocking preparation.
    bindings = tuple(dispatches)
    initial = tuple(
        [
            _associated(await service._store.get_in(binding.approval_id, tx), binding)
            for binding in bindings
        ]
    )
    if not initial:
        return ()
    await authority.prepare(tx, initial)
    # Entire authority union, then entire row union, then entire request union.
    # A caller that already admitted in tx must have prepared the app union
    # before that admission; its adapter's prepare must be idempotent here.
    await service._store.lock_many([a.approval_id for a in initial], tx)
    current = tuple(
        [
            _associated(await service._store.get_in(binding.approval_id, tx), binding)
            for binding in bindings
        ]
    )
    await service._store.lock_requests([a.request_sha256 for a in current], tx)
    guard = uuid.uuid4().int & ((1 << 63) - 1)
    await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", guard)
    xid = int(await tx.fetch_value("SELECT txid_current()"))
    # Warm the guard read's relation locks before the final no-new-lock phase.
    if not await _guard_live(tx, xid, guard):
        raise ApprovalRefused(Refusal.DISPATCH_NOT_PREPARED)
    return tuple(
        PreparedDispatch(
            a.approval_id,
            b.operation_id,
            a.expires_at,
            a,
            service,
            tx,
            xid,
            guard,
            authority,
            outcome,
        )
        for a, b in zip(current, bindings, strict=True)
    )


async def prepare_continuation(
    service: Approvals,
    tx: TransactionManager,
    binding: DispatchBinding,
    *,
    authority: DispatchAuthority,
) -> PreparedDispatch:
    (prepared,) = await prepare_dispatches(
        service, tx, [binding], authority=authority, outcome=DispatchOutcome.OUTCOME_UNKNOWN
    )
    if prepared._approval.dispatch_outcome is not DispatchOutcome.OUTCOME_UNKNOWN:
        raise ApprovalRefused(Refusal.OUTCOME_INVALID)
    return prepared


async def check_dispatch(
    service: Approvals,
    tx: TransactionManager,
    prepared: PreparedDispatch,
) -> None:
    if (
        prepared._service is not service
        or prepared._tx is not tx
        or not _live(tx)
        or not await _guard_live(tx, prepared._transaction_id, prepared._guard_key)
    ):
        raise ApprovalRefused(Refusal.DISPATCH_NOT_PREPARED)
    approval = await service._store.get_in(prepared.approval_id, tx)
    if approval is None:
        raise ApprovalRefused(Refusal.NOT_FOUND)
    original = prepared._approval
    if (
        approval.request_ref,
        approval.request_sha256,
        approval.policy_ref,
        approval.policy_version,
    ) != (
        original.request_ref,
        original.request_sha256,
        original.policy_ref,
        original.policy_version,
    ):
        raise ApprovalRefused(Refusal.REQUEST_MISMATCH)
    if approval.revoked_at is not None or approval.state is ApprovalState.REVOKED:
        raise ApprovalRefused(Refusal.REVOKED)
    if (
        approval.state is not ApprovalState.CONSUMED
        or approval.consumed_operation_id != prepared.operation_id
    ):
        raise ApprovalRefused(Refusal.OPERATION_MISMATCH)
    if approval.dispatch_outcome is not prepared._outcome:
        raise ApprovalRefused(Refusal.OUTCOME_INVALID)
    state = await prepared._authority.read(tx, approval)
    policy = state.policy
    if policy is None:
        raise ApprovalRefused(Refusal.POLICY_UNKNOWN)
    if policy.policy_ref != approval.policy_ref or policy.version != approval.policy_version:
        raise ApprovalRefused(Refusal.POLICY_CHANGED)
    decider = approval.decided_by
    candidate = None if decider is None else approval.candidate(decider.subject)
    if (
        decider is None
        or decider != original.decided_by
        or not state.decider_current
        or candidate is None
        or candidate.retired_at is not None
        or decider.scope not in policy.approver_scopes
    ):
        raise ApprovalRefused(Refusal.APPROVER_RETIRED)
    if not decider.assurance.satisfies(policy.min_assurance):
        raise ApprovalRefused(Refusal.ASSURANCE_INSUFFICIENT)
    if not policy.allow_requester_approval and approval.requested_by in (
        candidate.subject,
        candidate.principal_did,
    ):
        raise ApprovalRefused(Refusal.NO_ELIGIBLE_APPROVER)
    # No await after this sample: time can advance during any preceding read.
    if service.now() >= min(prepared.expires_at, approval.expires_at):
        raise ApprovalRefused(Refusal.EXPIRED)
