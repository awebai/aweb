from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts, normalize_owner_dids
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
            SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, status, deleted_at
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
        SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, status, deleted_at
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
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
        SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, status, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_aw = $1 OR did_key = $1)
        ORDER BY CASE WHEN did_aw = $1 THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        """,
        did,
    )
    return None if not row else dict(row)


async def evaluate_messaging_policy(
    db,
    *,
    registry_client,
    recipient_agent: dict,
    sender_did: str,
    sender_address: str | None,
) -> None:
    policy = (recipient_agent.get("messaging_policy") or "everyone").strip().lower()
    if policy == "everyone":
        return
    if policy == "nobody":
        raise ForbiddenError("Recipient does not accept messages")
    if policy == "contacts":
        owner_dids = normalize_owner_dids(
            owner_dids=[
                recipient_agent.get("did_aw"),
                recipient_agent.get("did_key"),
            ]
        )
        if not owner_dids:
            raise ForbiddenError("Recipient identity is incomplete")
        contacts = await get_contact_addresses(db, owner_dids=owner_dids)
        if sender_address and is_address_in_contacts(sender_address, contacts):
            return
        raise ForbiddenError("Recipient only accepts messages from contacts")

    if registry_client is None:
        raise ForbiddenError("Recipient policy requires team membership verification")

    aweb_db = db.get_manager("aweb")
    recipient_team_rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT a.team_id, t.namespace, t.team_name
        FROM {{tables.agents}} a
        JOIN {{tables.teams}} t ON t.team_id = a.team_id
        WHERE a.deleted_at IS NULL
          AND (a.did_aw = $1 OR a.did_key = $1)
        """,
        (recipient_agent.get("did_aw") or recipient_agent.get("did_key") or "").strip(),
    )
    recipient_team_ids = [str(row["team_id"]) for row in recipient_team_rows]
    if not recipient_team_ids:
        raise ForbiddenError("Recipient team context is unavailable")

    async def _sender_has_active_cert_for(row: dict) -> bool:
        certs = await registry_client.list_team_certificates(
            row["namespace"],
            row["team_name"],
            active_only=True,
        )
        for cert in certs:
            member_did_aw = (cert.member_did_aw or "").strip()
            member_did_key = (cert.member_did_key or "").strip()
            if sender_did == member_did_aw or sender_did == member_did_key:
                return True
        return False

    if policy == "team":
        for row in recipient_team_rows:
            if await _sender_has_active_cert_for(row):
                return
        raise ForbiddenError("Recipient only accepts messages from shared-team members")

    if policy == "org":
        recipient_namespaces = {row["namespace"] for row in recipient_team_rows}
        namespace_rows = await aweb_db.fetch_all(
            """
            SELECT team_id, namespace, team_name
            FROM {{tables.teams}}
            WHERE namespace = ANY($1::text[])
            """,
            list(recipient_namespaces),
        )
        for row in namespace_rows:
            if await _sender_has_active_cert_for(row):
                return
        raise ForbiddenError("Recipient only accepts messages from the same org")

    raise ForbiddenError(f"Unsupported messaging policy: {policy}")


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
    from_agent_id: str | None = None,
    to_agent_id: str | None = None,
    signature: str | None = None,
    signed_payload: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
) -> tuple[UUID, datetime]:
    """Deliver a message between identities, not within a team."""
    sender_did = str(from_did or "").strip()
    recipient_did = str(to_did or "").strip()
    if not sender_did:
        raise ValidationError("Missing from_did")
    if not recipient_did:
        raise ValidationError("Missing to_did")

    sender = await resolve_agent_by_did(db, sender_did)
    recipient = await resolve_agent_by_did(db, recipient_did) or recipient_agent
    if recipient is None:
        raise NotFoundError("Recipient agent not found")

    if not recipient.get("external"):
        await evaluate_messaging_policy(
            db,
            registry_client=registry_client,
            recipient_agent=recipient,
            sender_did=sender_did,
            sender_address=sender_address,
        )

    if created_at is None:
        created_at = datetime.now(timezone.utc)
    if message_id is None:
        message_id = uuid_mod.uuid4()

    from_uuid = _parse_uuid(from_agent_id, field_name="from_agent_id") if from_agent_id else (
        UUID(str(sender["agent_id"])) if sender is not None else None
    )
    to_uuid = _parse_uuid(to_agent_id, field_name="to_agent_id") if to_agent_id else (
        UUID(str(recipient["agent_id"])) if recipient.get("agent_id") else None
    )
    from_alias_value = (from_alias or sender_address or (sender.get("alias") if sender else "") or sender_did).strip()
    from_address_value = (sender_address or "").strip() or None
    to_alias_value = (to_alias or recipient.get("alias") or recipient.get("address") or recipient_did).strip()

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, from_address, to_alias, subject, body,
             priority, team_id, from_agent_id, to_agent_id, signature, signed_payload, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
    )
    if not row:
        raise ServiceError("Failed to create message")

    return UUID(str(row["message_id"])), row["created_at"]
