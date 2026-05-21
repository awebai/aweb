from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from aweb.messaging.contacts import has_exact_active_identity_contact, normalize_owner_dids
from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError, ValidationError

MessagePriority = Literal["low", "normal", "high", "urgent"]


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


async def get_agent_by_id(db, *, agent_id: str, team_id: str | None = None) -> dict | None:
    """Look up an agent by agent_id, optionally scoped to a team."""
    aweb_db = db.get_manager("aweb")
    if team_id is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, did_aw, address, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, did_aw, address, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
            team_id,
        )
    if not row:
        return None
    return dict(row)


async def get_agent_by_alias(db, *, team_id: str, alias: str) -> dict | None:
    """Look up an agent by alias within a team."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, did_aw, address, inbound_mode, status, deleted_at
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
          AND COALESCE(agent_type, 'agent') != 'human'
        """,
        team_id,
        alias,
    )
    if not row:
        return None
    return dict(row)


async def resolve_agent_by_did(db, did: str) -> dict | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, did_aw, address, inbound_mode, status, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_aw = $1 OR did_key = $1)
        ORDER BY CASE WHEN did_aw = $1 THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        """,
        did,
    )
    return None if not row else dict(row)


INBOUND_MODE_OPEN = "open"
INBOUND_MODE_CONTACTS_OR_TEAMMATES = "contacts_or_teammates"
INBOUND_MODE_CONTACTS_ONLY = "contacts_only"
INBOUND_MODES = {INBOUND_MODE_OPEN, INBOUND_MODE_CONTACTS_OR_TEAMMATES, INBOUND_MODE_CONTACTS_ONLY}


def _is_global_recipient(recipient_agent: dict) -> bool:
    return str(recipient_agent.get("did_aw") or "").strip().startswith("did:aw:")


def _effective_inbound_mode(recipient_agent: dict) -> str:
    mode = str(recipient_agent.get("inbound_mode") or "").strip().lower()
    if mode in INBOUND_MODES:
        return mode

    raise ForbiddenError("Recipient inbound_mode migration required")


async def _recipient_has_exact_sender_contact(
    db,
    *,
    recipient_agent: dict,
    sender_address: str | None,
) -> bool:
    owner_dids = normalize_owner_dids(
        owner_dids=[
            recipient_agent.get("did_aw"),
            recipient_agent.get("did_key"),
        ]
    )
    if not owner_dids:
        raise ForbiddenError("Recipient identity is incomplete")
    return await has_exact_active_identity_contact(
        db,
        owner_dids=owner_dids,
        contact_address=sender_address,
    )


async def authorize_message_delivery(
    db,
    *,
    recipient_agent: dict,
    sender_did: str,
    sender_address: str | None,
    sender_team_id: str | None = None,
    sender_verified_team_id: str | None = None,
    stored_route_continuation: bool = False,
) -> None:
    del sender_did  # sender identity binding is verified by the caller/signature path.

    if _is_global_recipient(recipient_agent):
        mode = _effective_inbound_mode(recipient_agent)
        if mode == INBOUND_MODE_OPEN:
            return
        if await _recipient_has_exact_sender_contact(
            db,
            recipient_agent=recipient_agent,
            sender_address=sender_address,
        ):
            return
        recipient_team_id = str(recipient_agent.get("team_id") or "").strip()
        verified_team_id = str(sender_verified_team_id or "").strip()
        if mode == INBOUND_MODE_CONTACTS_OR_TEAMMATES and verified_team_id and verified_team_id == recipient_team_id:
            return
        if mode == INBOUND_MODE_CONTACTS_OR_TEAMMATES:
            raise ForbiddenError("Recipient only accepts messages from exact active contacts or verified teammates")
        raise ForbiddenError("Recipient only accepts messages from exact active contacts")

    if stored_route_continuation:
        return

    recipient_team_id = str(recipient_agent.get("team_id") or "").strip()
    sender_team = str(sender_team_id or "").strip()
    if sender_team and recipient_team_id and sender_team == recipient_team_id:
        return

    if await _recipient_has_exact_sender_contact(
        db,
        recipient_agent=recipient_agent,
        sender_address=sender_address,
    ):
        return

    raise ForbiddenError(
        "Local recipient only accepts same-team, exact-contact, or stored-route continuation delivery"
    )


async def deliver_message(
    db,
    *,
    registry_client=None,
    recipient_agent: dict | None = None,
    from_did: str,
    to_did: str,
    from_alias: str | None,
    to_alias: str | None,
    subject: str,
    body: str,
    priority: MessagePriority,
    sender_address: str | None = None,
    team_id: str | None = None,
    sender_verified_team_id: str | None = None,
    from_agent_id: str | None = None,
    to_agent_id: str | None = None,
    signature: str | None = None,
    signed_payload: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
    conversation_id: str | UUID | None = None,
    skip_policy_check: bool = False,
) -> tuple[UUID, datetime]:
    """Deliver a message between identities, not within a team."""
    sender_did = str(from_did or "").strip()
    recipient_did = str(to_did or "").strip()
    if not sender_did:
        raise ValidationError("Missing from_did")
    if not recipient_did:
        raise ValidationError("Missing to_did")

    recipient = await resolve_agent_by_did(db, recipient_did) or recipient_agent
    if recipient is None:
        raise NotFoundError("Recipient agent not found")

    if not skip_policy_check and not recipient.get("external"):
        await authorize_message_delivery(
            db,
            recipient_agent=recipient,
            sender_did=sender_did,
            sender_address=sender_address,
            sender_team_id=team_id,
            sender_verified_team_id=sender_verified_team_id,
        )

    if created_at is None:
        created_at = datetime.now(timezone.utc)
    if message_id is None:
        message_id = uuid_mod.uuid4()

    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id") if conversation_id else None
    from_uuid = _parse_uuid(from_agent_id, field_name="from_agent_id") if from_agent_id else None
    to_uuid = _parse_uuid(to_agent_id, field_name="to_agent_id") if to_agent_id else (
        UUID(str(recipient["agent_id"])) if recipient.get("agent_id") else None
    )
    from_alias_value = (from_alias or sender_address or sender_did).strip()
    from_address_value = (sender_address or "").strip() or None
    to_alias_value = (to_alias or recipient.get("alias") or recipient.get("address") or recipient_did).strip()

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, from_address, to_alias, subject, body,
             priority, team_id, from_agent_id, to_agent_id, signature, signed_payload, created_at,
             conversation_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING message_id, created_at
        """,
        message_id,
        sender_did,
        recipient_did,
        from_alias_value,
        from_address_value,
        to_alias_value,
        subject,
        body,
        priority,
        team_id,
        from_uuid,
        to_uuid,
        signature,
        signed_payload,
        created_at,
        conversation_uuid,
    )
    if not row:
        raise ServiceError("Failed to create message")

    return UUID(str(row["message_id"])), row["created_at"]
