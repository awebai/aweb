"""Approval storage: the interface the primitive needs, and its pgdbm implementation.

Every state change happens under `locked()`, which holds the approval row and
serialises all approvals of the same request digest until the transaction ends.
That makes decision, revocation, admission and outcome compare-and-set.

A caller may pass its own pgdbm transaction. The change then commits or rolls
back with the caller's other writes, such as an audit outbox entry, and the
locks are held until the caller's transaction ends.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals.model import (
    Approval,
    ApprovalState,
    Assurance,
    Candidate,
    DecidedBy,
    DeliveryStatus,
    DispatchOutcome,
    PresentationKind,
)
from aweb_naapp.runtime.links import LinkLifetime

MIGRATIONS = Path(__file__).parent / "migrations"
MIGRATION_MODULE = "aweb_naapp_approvals"


@dataclass(frozen=True)
class StoredRequest:
    request_ref: str
    request_sha256: str
    canonical: bytes
    created_at: datetime


@dataclass(frozen=True)
class ApprovalLink:
    link_id: str
    approval_id: str
    candidate_subject: str
    request_sha256: str
    verifier_sha256: str
    created_at: datetime
    lifetime: LinkLifetime


class LinkAlreadyUsed(Exception):
    """The decision's link was already used or revoked."""


class LockedApproval(Protocol):
    approval: Approval | None
    transaction: TransactionManager

    async def unreconciled_dispatch_exists(self) -> bool: ...

    async def set_decision(
        self,
        state: ApprovalState,
        decided_by: DecidedBy,
        task_answer_ref: str | None,
        link_id: str | None,
        at: datetime,
    ) -> Approval: ...

    async def revoke(self, at: datetime) -> Approval: ...

    async def consume(self, operation_id: str, at: datetime) -> Approval: ...

    async def set_outcome(
        self, outcome: DispatchOutcome, response_status: str | None, at: datetime
    ) -> Approval: ...


class ApprovalStore(Protocol):
    async def create(
        self,
        request: StoredRequest,
        approval: Approval,
        links: Sequence[ApprovalLink],
        tx: TransactionManager,
    ) -> None: ...

    def transaction(
        self, tx: TransactionManager | None
    ) -> AbstractAsyncContextManager[TransactionManager]: ...

    async def get(self, approval_id: str) -> Approval | None: ...

    async def get_by_request(self, request_ref: str) -> Approval | None: ...

    async def request_canonical(self, request_ref: str) -> bytes: ...

    async def find_link(self, verifier_sha256: str) -> ApprovalLink | None: ...

    async def set_delivery_status(self, approval_id: str, status: DeliveryStatus) -> None: ...

    def locked(
        self, approval_id: str, tx: TransactionManager | None
    ) -> AbstractAsyncContextManager[LockedApproval]: ...

    async def revoke_many(
        self, approval_ids: Sequence[str], at: datetime, tx: TransactionManager
    ) -> list[Approval]: ...

    async def retire_candidate(
        self, subject: str, at: datetime, tx: TransactionManager
    ) -> list[Approval]: ...


_APPROVAL_COLUMNS = (
    "approval_id, request_sha256, request_ref, policy_ref, policy_version, requested_by, "
    "decided_scope, decided_subject, authenticator, auth_evidence_ref, "
    "presentation_kind, presentation_ref, task_answer_ref, state, delivery_status, "
    "created_at, expires_at, decided_at, revoked_at, consumed_operation_id, dispatch_outcome, "
    "response_status"
)
_CANDIDATE_COLUMNS = "subject, scope, subject_type, principal_did, retired_at"
_LINK_COLUMNS = (
    "link_id, approval_id, candidate_subject, request_sha256, verifier_sha256, created_at, "
    "expires_at, revoked_at, used_at"
)


def _candidate(row: dict[str, Any]) -> Candidate:
    return Candidate(
        scope=row["scope"],
        subject=row["subject"],
        subject_type=row["subject_type"],
        principal_did=row["principal_did"],
        retired_at=row["retired_at"],
    )


async def _with_candidates(
    conn: AsyncDatabaseManager | TransactionManager, row: dict[str, Any] | None
) -> Approval | None:
    if row is None:
        return None
    rows = await conn.fetch_all(
        f"SELECT {_CANDIDATE_COLUMNS} FROM {{{{tables.approval_candidates}}}} "
        "WHERE approval_id = $1 ORDER BY position",
        row["approval_id"],
    )
    return _approval(row, tuple(_candidate(r) for r in rows))


def _approval(row: dict[str, Any], candidates: tuple[Candidate, ...]) -> Approval:
    decided_by = None
    if row["decided_subject"] is not None:
        decided_by = DecidedBy(
            scope=row["decided_scope"],
            subject=row["decided_subject"],
            assurance=Assurance(row["authenticator"]),
            evidence_ref=row["auth_evidence_ref"],
        )
    return Approval(
        approval_id=row["approval_id"],
        request_sha256=row["request_sha256"],
        request_ref=row["request_ref"],
        policy_ref=row["policy_ref"],
        policy_version=row["policy_version"],
        requested_by=row["requested_by"],
        candidates=candidates,
        decided_by=decided_by,
        presentation_kind=PresentationKind(row["presentation_kind"]),
        presentation_ref=row["presentation_ref"],
        task_answer_ref=row["task_answer_ref"],
        state=ApprovalState(row["state"]),
        delivery_status=DeliveryStatus(row["delivery_status"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        decided_at=row["decided_at"],
        revoked_at=row["revoked_at"],
        consumed_operation_id=row["consumed_operation_id"],
        dispatch_outcome=DispatchOutcome(row["dispatch_outcome"])
        if row["dispatch_outcome"]
        else None,
        response_status=row["response_status"],
    )


def _link(row: dict[str, Any] | None) -> ApprovalLink | None:
    if row is None:
        return None
    return ApprovalLink(
        link_id=row["link_id"],
        approval_id=row["approval_id"],
        candidate_subject=row["candidate_subject"],
        request_sha256=row["request_sha256"],
        verifier_sha256=row["verifier_sha256"],
        created_at=row["created_at"],
        lifetime=LinkLifetime(
            expires_at=row["expires_at"], revoked_at=row["revoked_at"], used_at=row["used_at"]
        ),
    )


async def _revoke_links(tx: TransactionManager, approval_ids: list[str], at: datetime) -> None:
    await tx.execute(
        "UPDATE {{tables.approval_links}} SET revoked_at = $2 "
        "WHERE approval_id = ANY($1::text[]) AND revoked_at IS NULL",
        approval_ids,
        at,
    )


class _PgLockedApproval:
    def __init__(self, tx: TransactionManager, approval: Approval | None) -> None:
        self.transaction = tx
        self.approval = approval

    async def _update(self, assignments: str, *args: Any) -> Approval:
        assert self.approval is not None
        row = await self.transaction.fetch_one(
            f"UPDATE {{{{tables.approvals}}}} SET {assignments} "
            f"WHERE approval_id = $1 RETURNING {_APPROVAL_COLUMNS}",
            self.approval.approval_id,
            *args,
        )
        self.approval = await _with_candidates(self.transaction, row)
        assert self.approval is not None
        return self.approval

    async def unreconciled_dispatch_exists(self) -> bool:
        assert self.approval is not None
        return bool(
            await self.transaction.fetch_value(
                "SELECT EXISTS (SELECT 1 FROM {{tables.approvals}} "
                "WHERE request_sha256 = $1 AND approval_id <> $2 "
                "AND dispatch_outcome IN ('dispatching', 'outcome_unknown'))",
                self.approval.request_sha256,
                self.approval.approval_id,
            )
        )

    async def set_decision(
        self,
        state: ApprovalState,
        decided_by: DecidedBy,
        task_answer_ref: str | None,
        link_id: str | None,
        at: datetime,
    ) -> Approval:
        """Record the one decision, use the decider's link, and revoke every
        other candidate's link."""
        approval = await self._update(
            "state = $2, decided_scope = $3, decided_subject = $4, authenticator = $5, "
            "auth_evidence_ref = $6, task_answer_ref = $7, decided_at = $8",
            state.value,
            decided_by.scope,
            decided_by.subject,
            decided_by.assurance.value,
            decided_by.evidence_ref,
            task_answer_ref,
            at,
        )
        if link_id is not None:
            used = await self.transaction.fetch_value(
                "UPDATE {{tables.approval_links}} SET used_at = $2 "
                "WHERE link_id = $1 AND approval_id = $3 AND used_at IS NULL "
                "AND revoked_at IS NULL RETURNING link_id",
                link_id,
                at,
                approval.approval_id,
            )
            if used is None:
                raise LinkAlreadyUsed(link_id)
        await _revoke_links(self.transaction, [approval.approval_id], at)
        return approval

    async def revoke(self, at: datetime) -> Approval:
        approval = await self._update(
            "state = CASE WHEN state = 'consumed' THEN state ELSE 'revoked' END, revoked_at = $2",
            at,
        )
        await _revoke_links(self.transaction, [approval.approval_id], at)
        return approval

    async def consume(self, operation_id: str, at: datetime) -> Approval:
        return await self._update(
            "state = 'consumed', consumed_operation_id = $2, consumed_at = $3, "
            "dispatch_outcome = 'dispatching', outcome_at = $3",
            operation_id,
            at,
        )

    async def set_outcome(
        self, outcome: DispatchOutcome, response_status: str | None, at: datetime
    ) -> Approval:
        return await self._update(
            "dispatch_outcome = $2, response_status = $3, outcome_at = $4",
            outcome.value,
            response_status,
            at,
        )


class PgApprovalStore:
    """Approval storage in the app's own pgdbm database and schema.

    A caller transaction must be on the same database; the store renders its own
    table names on that transaction's connection.
    """

    def __init__(self, db: AsyncDatabaseManager) -> None:
        self.db = db

    async def migrate(self) -> None:
        await AsyncMigrationManager(
            self.db, migrations_path=str(MIGRATIONS), module_name=MIGRATION_MODULE
        ).apply_pending_migrations()

    @asynccontextmanager
    async def transaction(self, tx: TransactionManager | None) -> AsyncIterator[TransactionManager]:
        if tx is None:
            async with self.db.transaction() as own:
                yield own
        else:
            async with TransactionManager(tx.connection, self.db).transaction() as nested:
                yield nested

    async def create(
        self,
        request: StoredRequest,
        approval: Approval,
        links: Sequence[ApprovalLink],
        tx: TransactionManager,
    ) -> None:
        await tx.execute(
            "INSERT INTO {{tables.approval_requests}} "
            "(request_ref, request_sha256, canonical, created_at) VALUES ($1, $2, $3, $4)",
            request.request_ref,
            request.request_sha256,
            request.canonical,
            request.created_at,
        )
        await tx.execute(
            f"INSERT INTO {{{{tables.approvals}}}} ({_APPROVAL_COLUMNS}) VALUES "
            "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, "
            "$17, $18, $19, $20, $21, $22)",
            approval.approval_id,
            approval.request_sha256,
            approval.request_ref,
            approval.policy_ref,
            approval.policy_version,
            approval.requested_by,
            None,
            None,
            None,
            None,
            approval.presentation_kind.value,
            approval.presentation_ref,
            approval.task_answer_ref,
            approval.state.value,
            approval.delivery_status.value,
            approval.created_at,
            approval.expires_at,
            approval.decided_at,
            approval.revoked_at,
            approval.consumed_operation_id,
            approval.dispatch_outcome.value if approval.dispatch_outcome else None,
            approval.response_status,
        )
        for position, candidate in enumerate(approval.candidates):
            await tx.execute(
                "INSERT INTO {{tables.approval_candidates}} "
                "(approval_id, subject, scope, subject_type, principal_did, position) "
                "VALUES ($1, $2, $3, $4, $5, $6)",
                approval.approval_id,
                candidate.subject,
                candidate.scope,
                candidate.subject_type,
                candidate.principal_did,
                position,
            )
        for link in links:
            await tx.execute(
                f"INSERT INTO {{{{tables.approval_links}}}} ({_LINK_COLUMNS}) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                link.link_id,
                link.approval_id,
                link.candidate_subject,
                link.request_sha256,
                link.verifier_sha256,
                link.created_at,
                link.lifetime.expires_at,
                link.lifetime.revoked_at,
                link.lifetime.used_at,
            )

    async def get(self, approval_id: str) -> Approval | None:
        return await _with_candidates(
            self.db,
            await self.db.fetch_one(
                f"SELECT {_APPROVAL_COLUMNS} FROM {{{{tables.approvals}}}} WHERE approval_id = $1",
                approval_id,
            ),
        )

    async def get_by_request(self, request_ref: str) -> Approval | None:
        return await _with_candidates(
            self.db,
            await self.db.fetch_one(
                f"SELECT {_APPROVAL_COLUMNS} FROM {{{{tables.approvals}}}} WHERE request_ref = $1",
                request_ref,
            ),
        )

    async def request_canonical(self, request_ref: str) -> bytes:
        return await self.db.fetch_value(
            "SELECT canonical FROM {{tables.approval_requests}} WHERE request_ref = $1",
            request_ref,
        )

    async def find_link(self, verifier_sha256: str) -> ApprovalLink | None:
        return _link(
            await self.db.fetch_one(
                f"SELECT {_LINK_COLUMNS} FROM {{{{tables.approval_links}}}} "
                "WHERE verifier_sha256 = $1",
                verifier_sha256,
            )
        )

    async def set_delivery_status(self, approval_id: str, status: DeliveryStatus) -> None:
        await self.db.execute(
            "UPDATE {{tables.approvals}} SET delivery_status = $2 WHERE approval_id = $1",
            approval_id,
            status.value,
        )

    @asynccontextmanager
    async def locked(
        self, approval_id: str, tx: TransactionManager | None
    ) -> AsyncIterator[LockedApproval]:
        async with self.transaction(tx) as t:
            approval = await _with_candidates(
                t,
                await t.fetch_one(
                    f"SELECT {_APPROVAL_COLUMNS} FROM {{{{tables.approvals}}}} "
                    "WHERE approval_id = $1 FOR UPDATE",
                    approval_id,
                ),
            )
            if approval is not None:
                await t.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    f"{MIGRATION_MODULE}:{approval.request_sha256}",
                )
            yield _PgLockedApproval(t, approval)

    async def revoke_many(
        self, approval_ids: Sequence[str], at: datetime, tx: TransactionManager
    ) -> list[Approval]:
        """Revoke those of the given approvals that are still pending or approved,
        and stop the transport retry of those consumed but never sent."""
        return await self._revoke_live(tx, "approval_id = ANY($1::text[])", list(approval_ids), at)

    async def retire_candidate(
        self, subject: str, at: datetime, tx: TransactionManager
    ) -> list[Approval]:
        """A retired approver stops being a candidate of every approval still
        pending, and loses their link to it; the approvals they decided and
        that are not yet dispatched are revoked. Returns those revoked."""
        # Lock every approval this touches first, in a fixed order, so that a
        # decision on any of them serialises with the retirement.
        await tx.fetch_all(
            "SELECT a.approval_id FROM {{tables.approvals}} a "
            "WHERE a.decided_subject = $1 OR (a.state = 'pending' AND EXISTS ("
            "SELECT 1 FROM {{tables.approval_candidates}} c "
            "WHERE c.approval_id = a.approval_id AND c.subject = $1)) "
            "ORDER BY a.approval_id FOR UPDATE",
            subject,
        )
        retired = await tx.fetch_all(
            "UPDATE {{tables.approval_candidates}} c SET retired_at = $2 "
            "FROM {{tables.approvals}} a "
            "WHERE c.subject = $1 AND c.retired_at IS NULL AND a.approval_id = c.approval_id "
            "AND a.state = 'pending' AND a.revoked_at IS NULL RETURNING c.approval_id",
            subject,
            at,
        )
        await tx.execute(
            "UPDATE {{tables.approval_links}} SET revoked_at = $3 "
            "WHERE approval_id = ANY($1::text[]) AND candidate_subject = $2 AND revoked_at IS NULL",
            [row["approval_id"] for row in retired],
            subject,
            at,
        )
        return await self._revoke_live(tx, "decided_subject = $1", subject, at)

    async def _revoke_live(
        self, tx: TransactionManager, selection: str, argument: Any, at: datetime
    ) -> list[Approval]:
        rows = await tx.fetch_all(
            f"UPDATE {{{{tables.approvals}}}} SET revoked_at = $2, "
            "state = CASE WHEN state = 'consumed' THEN state ELSE 'revoked' END "
            f"WHERE {selection} AND revoked_at IS NULL "
            "AND (state IN ('pending', 'approved') "
            "OR (state = 'consumed' AND dispatch_outcome = 'not_sent')) "
            f"RETURNING {_APPROVAL_COLUMNS}",
            argument,
            at,
        )
        revoked = [a for a in [await _with_candidates(tx, row) for row in rows] if a is not None]
        await _revoke_links(tx, [a.approval_id for a in revoked], at)
        return revoked
