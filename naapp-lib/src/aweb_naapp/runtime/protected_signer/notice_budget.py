"""One requester's approval mail, bounded.

Each prepared operation that needs a human reserves its notices, one per
approver it would mail, inside the prepare transaction and under a lock on the
requester, so concurrent prepares cannot overspend. Past NOTICE_BUDGET within
NOTICE_WINDOW the operation is still created and waits for its approver; its
its notices are not mailed; the signer records that instead. The requester is the stable
principal the authority admitted, scoped to the signer and its authority, so a
new operation id, operation kind or requester key does not reset it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

NOTICE_BUDGET = 10
NOTICE_WINDOW = timedelta(hours=1)


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
    suppressed = used + notices > NOTICE_BUDGET
    await tx.execute(
        "INSERT INTO {{tables.protected_signer_notice_reservations}} "
        "(operation_id,service_id,authority_id,requester,notices,suppressed,reserved_at) "
        "VALUES($1,$2,$3,$4,$5,$6,$7)",
        operation_id, service_id, authority_id, requester, 0 if suppressed else notices, suppressed, now,
    )
    return not suppressed
