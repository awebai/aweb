"""Canonical persistence of an admitted chat message and its sender receipt.

Transport admission remains with the native/federation caller. This writer
stores the attestation unchanged. See Direct Address Send Protocol
(docs/identity-messaging-contract.md:148-160).
"""

from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from aweb.agent_wake import record_did_wakes
from aweb.attachment_service import attachment_transaction
from aweb.messaging.kinds import ContentMode
from aweb.messaging.sender_address import sender_address_for_storage


def parse_optional_uuid(value: str | UUID | None) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    text = str(value).strip()
    if not text:
        return None
    return UUID(text)


@attachment_transaction("chat")
async def store_chat(
    db,
    *,
    session_id: UUID,
    sender_did: str,
    body: str,
    sender_agent_id: str | UUID | None = None,
    sender_address: str | None = None,
    reply_to: UUID | None = None,
    leaving: bool = False,
    hang_on: bool = False,
    signature: str | None = None,
    signed_payload: str | None = None,
    id_chain: dict[str, Any] | None = None,
    content_mode: str = ContentMode.PLAINTEXT,
    message_version: int = 1,
    encrypted_envelope: dict[str, Any] | None = None,
    encrypted_metadata: dict[str, Any] | None = None,
    message_id: UUID | None = None,
    wake_dids: tuple[str | None, ...] | None = None,
) -> dict[str, Any] | None:
    """Store an admitted chat message and sender receipt in one statement.

    Native sends wake stored peers by default. An ingress owner that holds
    separately validated recipient identity supplies its explicit wake set;
    an empty set leaves publication to that transaction owner.
    """
    aweb_db = db.get_manager("aweb")
    # The sender-attested time remains in signed_payload or encrypted_envelope.
    # created_at is when this server received the message for ordering, so the
    # two values intentionally use different clocks and may disagree.
    effective_created_at = datetime.now(timezone.utc)
    effective_message_id = message_id if message_id is not None else uuid_mod.uuid4()
    sender_agent_uuid = parse_optional_uuid(sender_agent_id)
    encrypted_metadata = encrypted_metadata or {}

    # One statement inserts the message and the sender's read receipt for it,
    # and names the participants to wake.
    inserted = await aweb_db.fetch_one(
        """
        WITH message AS (
            INSERT INTO {{tables.chat_messages}}
                (message_id, session_id, from_agent_id, from_did, from_alias, from_address,
                 body, sender_leaving, hang_on, reply_to, signature, signed_payload,
                 content_mode, message_version, encrypted_envelope, encrypted_ciphertext,
                 encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
                 encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite,
                 encrypted_signing_key_id, signed_envelope_hash, created_at, id_chain)
            SELECT $1, p.session_id, COALESCE($3::uuid, p.agent_id), p.did, p.alias,
                   $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                   $18, $19, $20, $21, $22, $23, $24, $25::jsonb
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = $2 AND p.did = $4
            RETURNING message_id, created_at, seq, from_did, from_agent_id
        ), receipt AS (
            INSERT INTO {{tables.chat_read_receipts}}
                (session_id, did, agent_id, last_read_message_id, last_read_at)
            SELECT $2, from_did, from_agent_id, message_id, created_at FROM message
            ON CONFLICT (session_id, did) DO UPDATE
            SET last_read_message_id = EXCLUDED.last_read_message_id,
                agent_id = EXCLUDED.agent_id,
                last_read_at = EXCLUDED.last_read_at
            WHERE {{tables.chat_read_receipts}}.last_read_at IS NULL
               OR EXCLUDED.last_read_at > {{tables.chat_read_receipts}}.last_read_at
        )
        SELECT message.message_id, message.created_at, message.seq,
               ARRAY(
                   SELECT p.did FROM {{tables.chat_participants}} p
                   WHERE p.session_id = $2 AND p.did <> $4
               ) AS wake_dids
        FROM message
        """,
        effective_message_id,
        session_id,
        sender_agent_uuid,
        sender_did,
        sender_address_for_storage(sender_address),
        body,
        bool(leaving),
        bool(hang_on),
        reply_to,
        signature,
        signed_payload,
        content_mode,
        int(message_version or 1),
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
        effective_created_at,
        json.dumps(id_chain) if id_chain is not None else None,
    )
    if inserted is None:
        return None
    msg_row = {
        "message_id": inserted["message_id"],
        "created_at": inserted["created_at"],
        "seq": inserted["seq"],
    }

    # Departed participants are woken too: leaving does not end their pending state.
    if wake_dids is None:
        wake_dids = tuple(inserted["wake_dids"] or ())
    record_did_wakes((did for did in wake_dids if did), "chat")

    return dict(msg_row)
