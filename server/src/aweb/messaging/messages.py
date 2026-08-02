from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from aweb.messaging.contacts import has_exact_active_identity_contact, normalize_owner_dids
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError, ValidationError

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
INBOUND_MODE_TEAM_AND_CONTACTS = "team_and_contacts"
INBOUND_MODE_CONTACTS_ONLY_LEGACY = "contacts_only"
INBOUND_MODES = {INBOUND_MODE_OPEN, INBOUND_MODE_TEAM_AND_CONTACTS}


def _is_global_recipient(recipient_agent: dict) -> bool:
    return str(recipient_agent.get("did_aw") or "").strip().startswith("did:aw:")


def _effective_inbound_mode(recipient_agent: dict) -> str:
    mode = str(recipient_agent.get("inbound_mode") or "").strip().lower()
    if mode == INBOUND_MODE_CONTACTS_ONLY_LEGACY:
        return INBOUND_MODE_TEAM_AND_CONTACTS
    if mode in INBOUND_MODES:
        return mode

    raise ForbiddenError("Recipient inbound_mode migration required")


def _identity_dids_from_agent(agent: dict) -> list[str]:
    dids: list[str] = []
    for value in (agent.get("did_aw"), agent.get("did_key")):
        did = str(value or "").strip()
        if did and did not in dids:
            dids.append(did)
    return dids


def _normalize_dids(dids: list[str] | tuple[str, ...] | None) -> list[str]:
    normalized: list[str] = []
    for value in dids or []:
        did = str(value or "").strip()
        if did and did not in normalized:
            normalized.append(did)
    return normalized


async def _active_team_ids_for_identity(db, dids: list[str]) -> set[str]:
    dids = _normalize_dids(dids)
    if not dids:
        return set()
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT team_id
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_aw = ANY($1::text[]) OR did_key = ANY($1::text[]))
        """,
        dids,
    )
    return {str(row["team_id"]) for row in rows if row.get("team_id")}


async def _has_verified_same_team_membership(
    db,
    *,
    recipient_agent: dict,
    sender_verified_team_id: str | None,
    sender_verified_dids: list[str] | tuple[str, ...] | None,
) -> bool:
    recipient_team_ids = await _active_team_ids_for_identity(db, _identity_dids_from_agent(recipient_agent))
    if not recipient_team_ids:
        return False

    sender_team_ids: set[str] = set()
    verified_team = str(sender_verified_team_id or "").strip()
    if verified_team:
        sender_team_ids.add(verified_team)
    sender_team_ids.update(await _active_team_ids_for_identity(db, _normalize_dids(sender_verified_dids)))

    return bool(sender_team_ids & recipient_team_ids)


async def _recipient_has_exact_sender_contact(
    db,
    *,
    recipient_agent: dict,
    sender_address: str | None,
    sender_did: str,
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
        contact_did_aw=sender_did,
    )


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
    sender_stable_did = next(
        (
            str(value).strip()
            for value in (sender_verified_dids or ())
            if str(value).strip().startswith("did:aw:")
        ),
        str(sender_did or "").strip(),
    )

    if _is_global_recipient(recipient_agent):
        mode = _effective_inbound_mode(recipient_agent)
        if mode == INBOUND_MODE_OPEN:
            return
        if await _has_verified_same_team_membership(
            db,
            recipient_agent=recipient_agent,
            sender_verified_team_id=sender_verified_team_id,
            sender_verified_dids=sender_verified_dids,
        ):
            return
        if await _recipient_has_exact_sender_contact(
            db,
            recipient_agent=recipient_agent,
            sender_address=sender_address,
            sender_did=sender_stable_did,
        ):
            return
        raise ForbiddenError("Recipient only accepts messages from verified team members or exact active contacts")

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
        sender_did=sender_stable_did,
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
    sender_verified_dids: list[str] | tuple[str, ...] | None = None,
    stored_route_continuation: bool = False,
    from_agent_id: str | None = None,
    to_agent_id: str | None = None,
    signature: str | None = None,
    signed_payload: str | None = None,
    content_mode: str = "legacy_plaintext_v1",
    message_version: int = 1,
    encrypted_envelope: dict | None = None,
    encrypted_metadata: dict | None = None,
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
            sender_verified_dids=sender_verified_dids,
            stored_route_continuation=stored_route_continuation,
        )

    # The sender-attested time remains in signed_payload or encrypted_envelope.
    # created_at is when this server received the message for ordering, so the
    # two values intentionally use different clocks and may disagree.
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
    if content_mode == "encrypted_v2":
        subject = ""
        body = ""
        message_version = 2
        if encrypted_envelope is None:
            raise ValidationError("Missing encrypted envelope")
        encrypted_metadata = encrypted_metadata or {}
    else:
        content_mode = "legacy_plaintext_v1"
        message_version = 1
        encrypted_envelope = None
        encrypted_metadata = {}

    aweb_db = db.get_manager("aweb")
    if content_mode == "encrypted_v2":
        signed_envelope_hash = str(encrypted_metadata.get("signed_envelope_hash") or "").strip()
        existing = await aweb_db.fetch_one(
            """
            SELECT message_id, created_at, content_mode, signed_envelope_hash
            FROM {{tables.messages}}
            WHERE message_id = $1
            """,
            message_id,
        )
        if existing:
            if (
                str(existing["content_mode"] or "") == "encrypted_v2"
                and str(existing["signed_envelope_hash"] or "").strip() == signed_envelope_hash
            ):
                return UUID(str(existing["message_id"])), existing["created_at"]
            raise ConflictError("message_id already exists with a different encrypted envelope")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, from_address, to_alias, subject, body,
             priority, team_id, from_agent_id, to_agent_id, signature, signed_payload, created_at,
             conversation_id, message_version, content_mode, encrypted_envelope,
             encrypted_ciphertext, encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
             encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id,
             signed_envelope_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19::jsonb, $20, $21::jsonb, $22, $23, $24, $25, $26, $27, $28)
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
        message_version,
        content_mode,
        json.dumps(encrypted_envelope, sort_keys=True, separators=(",", ":")) if encrypted_envelope is not None else None,
        encrypted_metadata.get("encrypted_ciphertext"),
        json.dumps(encrypted_metadata.get("encrypted_key_wraps"), sort_keys=True, separators=(",", ":")) if encrypted_metadata.get("encrypted_key_wraps") is not None else None,
        encrypted_metadata.get("encrypted_ciphertext_hash"),
        encrypted_metadata.get("encrypted_ciphertext_size"),
        encrypted_metadata.get("encrypted_key_wraps_hash"),
        encrypted_metadata.get("encrypted_inner_header_hash"),
        encrypted_metadata.get("encrypted_suite"),
        encrypted_metadata.get("encrypted_signing_key_id"),
        encrypted_metadata.get("signed_envelope_hash"),
    )
    if not row:
        raise ServiceError("Failed to create message")

    return UUID(str(row["message_id"])), row["created_at"]
