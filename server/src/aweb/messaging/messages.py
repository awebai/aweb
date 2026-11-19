from __future__ import annotations

from aweb.human_kind import human_predicate_sql, effective_agent_type

from aweb.agent_wake import record_did_wakes
from aweb.attachment_service import attachment_transaction

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from aweb.messaging.delivery_policy import (
    DeliveryAttempt,
    DeliverySender,
    authorize_delivery,
)
from aweb.service_errors import (
    ConflictError,
    NotFoundError,
    ServiceError,
    ValidationError,
)

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


@attachment_transaction("mail")
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
    id_chain: dict | None = None,
    content_mode: str = "legacy_plaintext_v1",
    message_version: int = 1,
    encrypted_envelope: dict | None = None,
    encrypted_metadata: dict | None = None,
    message_id: UUID | None = None,
    conversation_id: str | UUID | None = None,
    skip_policy_check: bool = False,
    signed_recipient_did: str | None = None,
    known_new: bool = False,
) -> tuple[UUID, datetime]:
    """Deliver a message between identities, not within a team."""
    sender_did = str(from_did or "").strip()
    recipient_did = str(to_did or "").strip()
    if not sender_did:
        raise ValidationError("Missing from_did")
    if not recipient_did:
        raise ValidationError("Missing to_did")

    recipient = recipient_agent or await resolve_agent_by_did(db, recipient_did)
    if recipient is None:
        raise NotFoundError("Recipient agent not found")

    if not skip_policy_check:
        await admit_message_delivery(
            db,
            recipient=recipient,
            recipient_did=recipient_did,
            to_agent_id=to_agent_id,
            sender_did=sender_did,
            sender_address=sender_address,
            team_id=team_id,
            sender_verified_team_id=sender_verified_team_id,
            sender_verified_dids=sender_verified_dids,
            stored_route_continuation=stored_route_continuation,
        )

    # The sender-attested time remains in signed_payload or encrypted_envelope.
    # created_at is when this server received the message for ordering, so the
    # two values intentionally use different clocks and may disagree.
    created_at = datetime.now(timezone.utc)
    if message_id is None:
        # A freshly generated id names no stored message.
        message_id = uuid_mod.uuid4()
        known_new = True

    conversation_uuid = (
        _parse_uuid(conversation_id, field_name="conversation_id")
        if conversation_id
        else None
    )
    from_uuid = (
        _parse_uuid(from_agent_id, field_name="from_agent_id")
        if from_agent_id
        else None
    )
    if to_agent_id:
        to_uuid = _parse_uuid(to_agent_id, field_name="to_agent_id")
    elif recipient.get("agent_id"):
        to_uuid = UUID(str(recipient["agent_id"]))
    else:
        to_uuid = None
    from_alias_value = (from_alias or sender_address or sender_did).strip()
    from_address_value = (sender_address or "").strip() or None
    to_alias_value = (
        to_alias or recipient.get("alias") or recipient.get("address") or recipient_did
    ).strip()
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
    # known_new: the caller looked this message_id up in this request and
    # found no row, so the same lookup is not repeated here.
    existing = (
        None
        if known_new
        else await aweb_db.fetch_one(
            """
        SELECT message_id, created_at, content_mode, signed_envelope_hash,
               from_did, signed_payload
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
            message_id,
        )
    )
    if content_mode == "encrypted_v2":
        signed_envelope_hash = str(
            encrypted_metadata.get("signed_envelope_hash") or ""
        ).strip()
        if existing:
            if (
                str(existing["content_mode"] or "") == "encrypted_v2"
                and str(existing["signed_envelope_hash"] or "").strip()
                == signed_envelope_hash
            ):
                return UUID(str(existing["message_id"])), existing["created_at"]
            raise ConflictError(
                "message_id already exists with a different encrypted envelope"
            )
    elif existing:
        if (
            existing["content_mode"] == "legacy_plaintext_v1"
            and existing["from_did"] == sender_did
            and signed_payload
            and existing["signed_payload"] == signed_payload
        ):
            return UUID(str(existing["message_id"])), existing["created_at"]
        raise ConflictError(
            "message_id already exists with a different sender or signed payload"
        )

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, from_address, to_alias, subject, body,
             priority, team_id, from_agent_id, to_agent_id, signature, signed_payload, created_at,
             conversation_id, message_version, content_mode, encrypted_envelope,
             encrypted_ciphertext, encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
             encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id,
             signed_envelope_hash, id_chain)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19::jsonb, $20, $21::jsonb, $22, $23, $24, $25, $26, $27, $28, $29::jsonb)
        RETURNING message_id, created_at
        """,
        message_id,
        sender_did,
        # A validated same-account succession may deliver to the successor
        # while preserving its predecessor as the original signed target.
        # Policy and residence above always use the current delivery identity.
        signed_recipient_did or recipient_did,
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
        json.dumps(encrypted_envelope, sort_keys=True, separators=(",", ":"))
        if encrypted_envelope is not None
        else None,
        encrypted_metadata.get("encrypted_ciphertext"),
        json.dumps(
            encrypted_metadata.get("encrypted_key_wraps"),
            sort_keys=True,
            separators=(",", ":"),
        )
        if encrypted_metadata.get("encrypted_key_wraps") is not None
        else None,
        encrypted_metadata.get("encrypted_ciphertext_hash"),
        encrypted_metadata.get("encrypted_ciphertext_size"),
        encrypted_metadata.get("encrypted_key_wraps_hash"),
        encrypted_metadata.get("encrypted_inner_header_hash"),
        encrypted_metadata.get("encrypted_suite"),
        encrypted_metadata.get("encrypted_signing_key_id"),
        encrypted_metadata.get("signed_envelope_hash"),
        json.dumps(id_chain) if id_chain is not None else None,
    )
    if not row:
        raise ServiceError("Failed to create message")

    # Wake the identity this delivery resolved, never a stored address field.
    record_did_wakes((recipient.get("did_aw"), recipient.get("did_key")), "mail")

    return UUID(str(row["message_id"])), row["created_at"]
