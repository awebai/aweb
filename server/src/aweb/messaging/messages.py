from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from aweb.messaging.recipient_lookup import (
    get_agent_by_id as get_agent_by_id,
    resolve_agent_by_did as resolve_agent_by_did,
)


from datetime import datetime
from aweb.member_team_key import (
    MemberProjection,
    MemberReadLock,
    member_projection_columns_sql,
)
from aweb.messaging.recipient import Recipient

from aweb.messaging.delivery_policy import (
    DeliveryAttempt,
    DeliverySender,
    authorize_delivery,
)
from aweb.service_errors import (
    NotFoundError,
)


def utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601, UTC, second precision with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def policy_rows_for_participant(
    db, participant: dict, *, read_lock: MemberReadLock = MemberReadLock.NONE
) -> list[Recipient]:
    """Policy evidence for an existing participant, never new routing authority."""
    did = str(participant.get("did") or "").strip()
    if not did:
        return []
    if not isinstance(read_lock, MemberReadLock):
        raise TypeError("Policy reads require a named MemberReadLock")
    lock_sql = " FOR SHARE OF a" if read_lock is MemberReadLock.SHARE else ""
    rows = await db.get_manager("aweb").fetch_all(
        "SELECT "
        + member_projection_columns_sql("a")
        + """
        FROM {{tables.agents}} a WHERE a.deleted_at IS NULL
          AND (a.did_key=$1 OR a.did_aw=$1)
        ORDER BY a.agent_id
        """
        + lock_sql,
        did,
    )
    # All raw-claim matches must pass policy; none selects a recipient or route.
    return [
        Recipient.from_member_projection(MemberProjection.from_row(row)) for row in rows
    ]


async def authorize_message_delivery(
    db,
    *,
    recipient_agent: Mapping[str, Any],
    sender_did: str,
    sender_address: str | None,
    sender_verified_dids: list[str] | tuple[str, ...] | None = None,
    stored_route_continuation: bool = False,
    registry_client,
) -> None:
    """Compatibility entry; current memberships come only from the shared owner."""
    await authorize_delivery(
        db,
        recipient=recipient_agent,
        registry_client=registry_client,
        sender=DeliverySender(
            did=sender_did,
            address=sender_address,
            verified_dids=tuple(sender_verified_dids or ()),
        ),
        attempt=DeliveryAttempt.STORED_ROUTE
        if stored_route_continuation
        else DeliveryAttempt.FIRST_CONTACT,
    )


async def admit_message_delivery(
    db,
    *,
    recipient: Mapping[str, Any],
    recipient_did: str,
    to_agent_id: str | None,
    sender_did: str,
    sender_address: str | None,
    sender_verified_dids,
    stored_route_continuation: bool,
    registry_client,
) -> None:
    """The recipient's delivery policy for this sender; raises when it refuses."""
    if recipient.get("external") and not (
        stored_route_continuation and not recipient.get("delivery_origin")
    ):
        return
    policies: Sequence[Mapping[str, Any]] = [recipient]
    if stored_route_continuation:
        policies = await policy_rows_for_participant(
            db,
            {
                "agent_id": to_agent_id or recipient.get("agent_id"),
                "did": recipient_did,
            },
        )
        if not policies:
            # Mail has one recipient; absence is not a policy denial and
            # must not create a local delivery to a retired projection.
            raise NotFoundError("Recipient agent not found")
    for policy_recipient in policies:
        await authorize_message_delivery(
            db,
            recipient_agent=policy_recipient,
            registry_client=registry_client,
            sender_did=sender_did,
            sender_address=sender_address,
            sender_verified_dids=sender_verified_dids,
            stored_route_continuation=stored_route_continuation,
        )
