"""Persist admitted mail; delivery policy belongs to messaging.delivery_policy.

The caller admits the selected identity before creating a conversation or row
(docs/identity-messaging-contract.md:69-93). Storage receives the attestation
unchanged and chooses only the canonical persisted content shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, ClassVar, Mapping, NamedTuple, Protocol
from uuid import UUID, uuid4

from aweb.agent_wake import record_did_wakes
from aweb.attachment_service import attachment_transaction
from aweb.messaging.kinds import ContentMode, MessagePriorityValue
from aweb.service_errors import ConflictError, ServiceError, ValidationError


@dataclass(frozen=True, kw_only=True)
class MailSender:
    did: str
    alias: str | None = None
    address: str | None = None
    agent_id: str | None = None
    team_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "did", self.did.strip())
        object.__setattr__(self, "address", (self.address or "").strip() or None)

    @property
    def display_alias(self) -> str:
        return (self.alias or self.address or self.did).strip()


@dataclass(frozen=True, kw_only=True)
class MailRecipient:
    did: str
    alias: str | None = None
    address: str | None = None
    agent_id: str | None = None
    signed_did: str | None = None
    wake_dids: tuple[str | None, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "did", self.did.strip())

    @property
    def display_alias(self) -> str:
        return (self.alias or self.address or self.did).strip()


@dataclass(frozen=True, kw_only=True)
class MailAttestation:
    signature: str | None = None
    signed_payload: str | None = None
    id_chain: dict | None = None


@dataclass(frozen=True, kw_only=True)
class PlaintextMailContent:
    subject: str
    body: str
    mode: ClassVar[ContentMode] = ContentMode.PLAINTEXT
    version: ClassVar[int] = 1
    envelope: ClassVar[None] = None
    metadata: Mapping[str, Any] = field(default_factory=dict, init=False)


@dataclass(frozen=True, kw_only=True)
class EncryptedMailContent:
    envelope: dict
    metadata: Mapping[str, Any]
    subject: ClassVar[str] = ""
    body: ClassVar[str] = ""
    mode: ClassVar[ContentMode] = ContentMode.ENCRYPTED
    version: ClassVar[int] = 2


class MailContentRequest(Protocol):
    content_mode: str | None
    subject: str
    body: str
    encrypted_envelope: dict | None


def mail_content_for_storage(
    payload: MailContentRequest, *, encrypted_metadata: Mapping[str, Any] | None
) -> PlaintextMailContent | EncryptedMailContent:
    """Keep canonical plaintext storage without narrowing accepted metadata.

    docs/aw-hooks-sot.md:92 retains received metadata in callbacks and signed
    bytes; migration003 defines the two persisted content shapes.
    """
    if payload.content_mode == ContentMode.ENCRYPTED:
        if payload.encrypted_envelope is None:
            raise ValidationError("Missing encrypted envelope")
        return EncryptedMailContent(
            envelope=payload.encrypted_envelope, metadata=encrypted_metadata or {}
        )
    return PlaintextMailContent(subject=payload.subject, body=payload.body)


class MailIdAvailability(Enum):
    UNDETERMINED = auto()
    CONFIRMED_UNUSED = auto()


@dataclass(frozen=True, kw_only=True)
class MailStorageInput:
    sender: MailSender
    recipient: MailRecipient
    content: PlaintextMailContent | EncryptedMailContent
    attestation: MailAttestation
    priority: MessagePriorityValue
    message_id: UUID | None = None
    conversation_id: str | UUID | None = None
    id_availability: MailIdAvailability = MailIdAvailability.UNDETERMINED


class StoredMail(NamedTuple):
    # The attachment transaction wrapper also consumes this pair by index.
    message_id: UUID
    created_at: datetime


def _optional_uuid(value: str | UUID | None, *, field: str) -> UUID | None:
    if value is None or value == "":
        return None
    try:
        return value if isinstance(value, UUID) else UUID(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"Invalid {field} format") from exc


def _require_same_stored_mail(existing, *, message: MailStorageInput) -> StoredMail:
    content = message.content
    if isinstance(content, EncryptedMailContent):
        same = (
            existing["content_mode"] == ContentMode.ENCRYPTED
            and str(existing["signed_envelope_hash"] or "").strip()
            == str(content.metadata.get("signed_envelope_hash") or "").strip()
        )
        detail = "message_id already exists with a different encrypted envelope"
    else:
        same = (
            existing["content_mode"] == ContentMode.PLAINTEXT
            and existing["from_did"] == message.sender.did
            and bool(message.attestation.signed_payload)
            and existing["signed_payload"] == message.attestation.signed_payload
        )
        detail = "message_id already exists with a different sender or signed payload"
    if not same:
        raise ConflictError(detail)
    return StoredMail(UUID(str(existing["message_id"])), existing["created_at"])


@attachment_transaction("mail")
async def store_mail(db, *, message: MailStorageInput) -> StoredMail:
    """Write one already admitted mail and retain its exact attestation.

    created_at records server receipt; the signed payload keeps sender time
    (docs/mail-and-chat.md:309-312). Idempotent storage never emits a new wake.
    """
    if not message.sender.did.strip():
        raise ValidationError("Missing from_did")
    if not message.recipient.did.strip():
        raise ValidationError("Missing to_did")
    message_id = message.message_id or uuid4()
    created_at = datetime.now(timezone.utc)
    aweb_db = db.get_manager("aweb")
    if (
        message.message_id is not None
        and message.id_availability is MailIdAvailability.UNDETERMINED
    ):
        existing = await aweb_db.fetch_one(
            """SELECT message_id, created_at, content_mode, signed_envelope_hash,
                      from_did, signed_payload
               FROM {{tables.messages}} WHERE message_id=$1""",
            message_id,
        )
        if existing is not None:
            return _require_same_stored_mail(existing, message=message)
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
        message.sender.did,
        # A validated same-account succession may deliver to the successor
        # while preserving its predecessor as the original signed target.
        # The send path admits the current delivery identity before storage.
        message.recipient.signed_did or message.recipient.did,
        message.sender.display_alias,
        message.sender.address,
        message.recipient.display_alias,
        message.content.subject,
        message.content.body,
        message.priority,
        message.sender.team_id,
        _optional_uuid(message.sender.agent_id, field="from_agent_id"),
        _optional_uuid(message.recipient.agent_id, field="to_agent_id"),
        message.attestation.signature,
        message.attestation.signed_payload,
        created_at,
        _optional_uuid(message.conversation_id, field="conversation_id"),
        message.content.version,
        message.content.mode,
        json.dumps(message.content.envelope, sort_keys=True, separators=(",", ":"))
        if message.content.envelope is not None
        else None,
        message.content.metadata.get("encrypted_ciphertext"),
        json.dumps(
            message.content.metadata.get("encrypted_key_wraps"),
            sort_keys=True,
            separators=(",", ":"),
        )
        if message.content.metadata.get("encrypted_key_wraps") is not None
        else None,
        message.content.metadata.get("encrypted_ciphertext_hash"),
        message.content.metadata.get("encrypted_ciphertext_size"),
        message.content.metadata.get("encrypted_key_wraps_hash"),
        message.content.metadata.get("encrypted_inner_header_hash"),
        message.content.metadata.get("encrypted_suite"),
        message.content.metadata.get("encrypted_signing_key_id"),
        message.content.metadata.get("signed_envelope_hash"),
        json.dumps(message.attestation.id_chain)
        if message.attestation.id_chain is not None
        else None,
    )
    if not row:
        raise ServiceError("Failed to create message")

    record_did_wakes(message.recipient.wake_dids, "mail")
    return StoredMail(UUID(str(row["message_id"])), row["created_at"])
