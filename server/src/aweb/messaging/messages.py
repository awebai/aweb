from __future__ import annotations

from aweb.messaging.recipient_lookup import (
    get_agent_by_id as get_agent_by_id,
    get_agent_by_alias as get_agent_by_alias,
    resolve_agent_by_did as resolve_agent_by_did,
)


from datetime import datetime

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


async def policy_rows_for_participant(db, participant: dict) -> list[dict]:
    """Policy evidence for an existing participant, never new routing authority."""
    did = str(participant.get("did") or "").strip()
    if not did:
        return []
    rows = await db.get_manager("aweb").fetch_all(
        """
        SELECT agent_id, team_id, alias, did_key,
               CASE WHEN did_aw_verified_key=did_key THEN did_aw END AS did_aw,
               CASE WHEN did_aw_verified_key=did_key THEN address END AS address,
               identity_scope, (NULLIF(did_aw,'') IS NOT NULL) AS has_global_claim,
               did_aw AS policy_did_aw, inbound_mode
        FROM {{tables.agents}} WHERE deleted_at IS NULL
          AND (did_key=$1 OR did_aw=$1)
        ORDER BY agent_id
        """,
        did,
    )
    # All raw-claim matches must pass policy; none selects a recipient or route.
    return [dict(row) for row in rows]


async def authorize_message_delivery(
    db,
    *,
    recipient_agent: dict,
    sender_did: str,
    sender_address: str | None,
    sender_team_id: str | None = None,
    sender_verified_team_id: str | None = None,
    sender_verified_dids: list[str] | tuple[str, ...] | None = None,
    stored_route_continuation: bool = False,
) -> None:
    """Compatibility entry; current memberships come only from the shared owner."""
    await authorize_delivery(
        db,
        recipient=recipient_agent,
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
    recipient: dict,
    recipient_did: str,
    to_agent_id: str | None,
    sender_did: str,
    sender_address: str | None,
    team_id: str | None,
    sender_verified_team_id: str | None,
    sender_verified_dids,
    stored_route_continuation: bool,
) -> None:
    """The recipient's delivery policy for this sender; raises when it refuses."""
    if recipient.get("external") and not (
        stored_route_continuation and not recipient.get("delivery_origin")
    ):
        return
    policies = [recipient]
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
            sender_did=sender_did,
            sender_address=sender_address,
            sender_team_id=team_id,
            sender_verified_team_id=sender_verified_team_id,
            sender_verified_dids=sender_verified_dids,
            stored_route_continuation=stored_route_continuation,
        )
