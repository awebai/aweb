"""One requester's approval requests and mail, bounded.

The requester is the stable principal the authority admitted, scoped to the
signer and its authority, so a new operation id, operation kind or requester
key does not reset either bound.

Open requests: an agent requester holds at most OPEN_REQUEST_LIMIT requests
waiting for a human at once (an owner's page request is not counted). Past it prepare is refused before any approval state is
created, so neither the owner's lists nor the stored operations grow without
bound, and a real request cannot be buried. A decided or expired request frees
its place.

Mail: each prepared operation that needs a human reserves its notices, one per
approver it would mail, inside the prepare transaction and under a lock on the
requester, so concurrent prepares cannot overspend. Past NOTICE_BUDGET within
NOTICE_WINDOW the operation is still created and waits for its approver; its
notices are not mailed, and the signer records that instead. The budget is
never less than one full round, so a scope with more approvers than the budget
still mails its first request.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .types import SignerRefused

NOTICE_BUDGET = 10
NOTICE_WINDOW = timedelta(hours=1)
OPEN_REQUEST_LIMIT = 20


async def admit_open_request(tx, *, service_id: str, authority_id: str, requester: str, now: datetime) -> None:
    """Refuse a new request that needs a human while the requester already has
    OPEN_REQUEST_LIMIT waiting. Called in the transaction that creates it,
    before any approval state; the lock is held until that transaction ends."""
    await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                     "\n".join(("protected-open-requests", service_id, authority_id, requester)))
    waiting = await tx.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}} "
        "WHERE requester=$1 AND approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL "
        "AND signed_result IS NULL AND expires_at > $2 "
        "AND scope->>'service_id'=$3 AND scope->'authority'->>'id'=$4",
        requester, now, service_id, authority_id,
    )
    if waiting >= OPEN_REQUEST_LIMIT:
        raise SignerRefused("open_requests_limit_reached")


async def reserve_notices(tx, *, operation_id: str, service_id: str, authority_id: str, requester: str,
                          notices: int, now: datetime) -> bool:
    """Reserve `notices` for one new operation; True when they may be sent,
    False when the budget suppresses them. Called once per operation, in the
    transaction that creates it."""
    await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                     "\n".join(("protected-notice", service_id, authority_id, requester)))
    used = await tx.fetch_value(
        "SELECT coalesce(sum(notices), 0) FROM {{tables.protected_signer_notice_reservations}} "
        "WHERE service_id=$1 AND authority_id=$2 AND requester=$3 AND reserved_at > $4",
        service_id, authority_id, requester, now - NOTICE_WINDOW,
    )
    suppressed = used + notices > max(NOTICE_BUDGET, notices)
    await tx.execute(
        "INSERT INTO {{tables.protected_signer_notice_reservations}} "
        "(operation_id,service_id,authority_id,requester,notices,suppressed,reserved_at) "
        "VALUES($1,$2,$3,$4,$5,$6,$7)",
        operation_id, service_id, authority_id, requester, 0 if suppressed else notices, suppressed, now,
    )
    return not suppressed
