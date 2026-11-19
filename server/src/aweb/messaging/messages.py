from __future__ import annotations

from aweb.human_kind import human_predicate_sql, effective_agent_type


from datetime import datetime
from uuid import UUID

from aweb.messaging.delivery_policy import (
    DeliveryAttempt,
    DeliverySender,
    authorize_delivery,
)
from aweb.service_errors import (
    NotFoundError,
    ValidationError,
)


def utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601, UTC, second precision with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_uuid(v: str, *, field_name: str) -> UUID:
    v = str(v).strip()
    if not v:
        raise ValidationError(f"Missing {field_name}")
    try:
        return UUID(v)
    except Exception:
        raise ValidationError(f"Invalid {field_name} format")


async def get_agent_by_id(
    db, *, agent_id: str, team_id: str | None = None
) -> dict | None:
    """Look up an agent by agent_id, optionally scoped to a team."""
    aweb_db = db.get_manager("aweb")
    if team_id is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
            team_id,
        )
    if not row:
        return None
    return {**dict(row), "agent_type": effective_agent_type(row)}


async def get_agent_by_alias(db, *, team_id: str, alias: str) -> dict | None:
    """Look up an agent by alias within a team."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        f"""
        SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
        FROM {{{{tables.agents}}}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
          AND NOT {human_predicate_sql()}
        """,
        team_id,
        alias,
    )
    if not row:
        return None
    return {**dict(row), "agent_type": effective_agent_type(row)}


async def resolve_agent_by_did(db, did: str) -> dict | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND ((did_aw = $1 AND did_aw_verified_key = did_key) OR did_key = $1)
        ORDER BY CASE WHEN did_aw = $1 THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        """,
        did,
    )
    return None if not row else {**dict(row), "agent_type": effective_agent_type(row)}


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
