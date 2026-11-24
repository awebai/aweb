"""Mail recipient resolution and sends, for every adapter."""

from __future__ import annotations

from aweb.messaging.refusals import RecipientIdentityBindingError

import json
import logging
from collections.abc import Mapping, Sequence
from aweb.messaging.mail_storage import (
    MailIdAvailability,
    MailStorageInput,
    MailSender,
    MailRecipient,
    MailAttestation,
    mail_content_for_storage,
    store_mail,
    StoredMail,
)
from dataclasses import dataclass
from aweb.messaging.recipient import Recipient
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, TypedDict, NoReturn
from uuid import UUID

import asyncpg
from awid.registry import RegistryError
from aweb.messaging.refusals import (
    encrypted_message_refusal,
    DeliveryRefusal,
    SignedRecipientMismatch,
    recipient_selector_mismatch,
    MailConversationExists,
)
from http import HTTPStatus
from pgdbm.errors import QueryError
from aweb.messaging.write_conflicts import is_unique_write_conflict
from aweb.messaging.message_replay import (
    StoredMessageClaim,
    StoredMessageState,
    read_stored_message,
    replay_artifact,
)

from aweb.agent_wake import agent_wake_scope
from aweb.attachment_service import confirm_accepted_attachment_refs, refuse_remote_attachments
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.message_vocabulary import MessageInputSource, observe_message_vocabulary
from aweb.db import TransactionInfra
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    encrypted_message_storage_metadata,
    validate_e2ee_mail_envelope,
)
from aweb.federation.envelope import (
    FederationEnvelope,
    FederationEnvelopeError,
    enforce_message_timestamp_skew,
    verify_federation_envelope_integrity,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.federation.replay import (
    PlaintextProjectionClaim,
    read_plaintext_projection,
)
from aweb.hooks import fire_mutation_callback
from aweb.event_types import MutationEventType
from aweb.message_events import MailSentContext
from aweb.identity_auth_deps import MessagingAuth, auth_dids, participant_dids
from aweb.identity_binding import observe_current_identity_binding
from aweb.member_team_key import recipient_not_found
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_own_route,
    verified_signed_payload_json,
)
from aweb.messaging.alias_targets import (
    derive_team_address,
    resolve_alias_target,
    team_exists,
)
from aweb.messaging.contacts import (
    resolve_local_namespace_controller_did,
    upsert_successful_identity_contact,
)
from aweb.messaging.conversations import (
    create_conversation,
    ConversationParticipant,
    get_conversation,
    touch_conversation_activity,
)
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.messaging.mail_routing import (
    MailContinuationContext,
    explicit_mail_target_matches_participant,
    mail_continuation_context,
    participant_is_remote,
    recipient_for_conversation_participant,
    remote_recipient_from_participant,
)
from aweb.messaging.messages import (
    admit_message_delivery,
    authorize_message_delivery,
    get_agent_by_id,
)
from aweb.messaging.messages import (
    utc_iso as _utc_iso,
)
from aweb.messaging.participant_succession import predecessor_target_for_mail
from aweb.messaging.participants import messaging_participant_by_alias
from aweb.messaging.recipient_bindings import (
    signed_recipient_matches,
    RecipientSelectorField,
)
from aweb.messaging.recipient_lookup import resolve_recipient_by_did
from aweb.messaging.kinds import (
    MessageKind,
    MessagePriorityValue,
    ContentMode,
    MessageTransport,
)
from aweb.messaging.recipients import (
    RecipientIdentityBinding,
    resolve_address_recipient,
)
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.delivery_policy import DeliverySender, DeliveryPolicyRefused
from aweb.messaging.refusals import DeliveryRefusalCode
from aweb.messaging.sender_address import sender_address as _sender_address
from aweb.messaging.sender_address import sender_signature_address
from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
    require_verified_message_signature,
)
from aweb.service_errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
    IdentityBindingCode,
    IdentityBindingError,
)

if TYPE_CHECKING:
    from aweb.messaging.mail_models import SendMessageRequest


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SentMail:
    """A stored mail send, as its sender is told of it."""

    message_id: str
    conversation_id: str | None
    status: str
    delivered_at: str


def _timestamp_refusal(
    detail: str,
    *,
    code: DeliveryRefusalCode | None = None,
) -> DeliveryRefusal:
    """Log a content-free timestamp refusal with a signing action."""
    logger.warning("mail_timestamp_refused reason=%s", detail)
    return DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail=detail + ". Sign the message again with the current UTC time and retry.",
        headers={"X-AWEB-Error-Code": code.value} if code is not None else None,
        code=code,
    )


def _parse_signed_timestamp(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _timestamp_refusal("Invalid timestamp format") from exc
    if dt.tzinfo is None:
        raise _timestamp_refusal("timestamp must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond != 0:
        raise _timestamp_refusal("timestamp must be second precision")
    try:
        enforce_message_timestamp_skew(dt)
    except FederationEnvelopeError as exc:
        raise _timestamp_refusal(
            str(exc),
            code=DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW,
        ) from exc
    return dt


def _require_fresh_mail_attestation(payload: SendMessageRequest) -> None:
    """Require fresh attestation only after excluding an exact stored retry.

    docs/identity-messaging-contract.md, Receiver-Wide Replay And Contact
    Compatibility: answering an identical stored send is not a new attestation.
    """
    if payload.signature is None:
        return
    if payload.timestamp is None:
        raise _timestamp_refusal("timestamp is required for a signed message")
    _parse_signed_timestamp(payload.timestamp)


class _MailSignatureFields(TypedDict):
    """Validated native field inputs forwarded unchanged to the signature rule."""

    signature: str
    signed_payload: str | None
    recipient: Mapping[str, Any] | None
    to_agent_id: str | None
    to_alias: str | None
    requested_to_alias: str | None
    from_alias: str | None
    from_address: str | None
    from_stable_id: str | None
    priority: MessagePriorityValue
    subject: str
    body: str
    from_did: str
    message_id: str
    timestamp: str
    conversation_id: str | None
    signer_did_key: str | None


def _validate_signed_mail_payload(
    *,
    signature: str,
    signed_payload: str | None,
    recipient: Mapping[str, Any] | None,
    to_agent_id: str | None,
    to_alias: str | None,
    requested_to_alias: str | None,
    from_alias: str | None,
    from_address: str | None,
    from_stable_id: str | None,
    priority: MessagePriorityValue,
    subject: str,
    body: str,
    from_did: str,
    message_id: str,
    timestamp: str,
    conversation_id: str | None = None,
    signer_did_key: str | None = None,
) -> None:
    if signed_payload is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload is required when signature is provided",
        )
    try:
        payload = json.loads(signed_payload)
    except (json.JSONDecodeError, TypeError) as exc:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload must be valid JSON",
        ) from exc
    if not isinstance(payload, dict):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload must be a JSON object",
        )
    if payload.get("type") != "mail":
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload type must be mail",
        )
    allowed_from_values = {
        value
        for value in (
            str(from_alias or "").strip(),
            str(from_address or "").strip(),
            str(from_did or "").strip(),
            str(from_stable_id or "").strip(),
        )
        if value
    }
    signed_from = str(payload.get("from") or "").strip()
    if signed_from and signed_from not in allowed_from_values:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload from must match the authenticated sender",
        )
    recipient_alias = (recipient or {}).get("alias") or ""
    recipient_address = (recipient or {}).get("address") or ""
    recipient_stable_id = (recipient or {}).get("did_aw") or ""
    recipient_current_did = (recipient or {}).get("did_key") or ""
    alias_values = (
        ()
        if "~" in str(requested_to_alias or "")
        else (str(to_alias or "").strip(), str(recipient_alias).strip())
    )
    allowed_to_values = {
        value
        for value in (
            str(to_agent_id or "").strip(),
            str(requested_to_alias or "").strip(),
            str(recipient_address).strip(),
            str(recipient_stable_id).strip(),
            str(recipient_current_did).strip(),
            *alias_values,
        )
        if value
    }
    if not signed_recipient_matches(
        payload, recipients=[recipient or {}], allowed_to=allowed_to_values
    ):
        raise SignedRecipientMismatch(kind=MessageKind.MAIL)
    if (payload.get("priority") or "normal") != priority:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload priority must match the mail message",
        )
    if payload.get("subject", "") != subject:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload subject must match the mail subject",
        )
    if payload.get("body") != body:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload body must match the mail body",
        )
    if payload.get("from_did") != from_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload from_did must match the authenticated sender",
        )
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload from_stable_id must match the authenticated sender",
        )
    if payload.get("message_id") != message_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload message_id must match the mail message",
        )
    if payload.get("timestamp") != timestamp:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload timestamp must match the mail message",
        )
    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if conversation_id is not None:
        if not signed_conversation_id:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="signed_payload conversation_id is required",
            )
        if signed_conversation_id != conversation_id:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="signed_payload conversation_id must match",
            )
    elif signed_conversation_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="signed_payload conversation_id must match",
        )
    try:
        validate_ed25519_message_signature(signature)
    except MessageSignatureShapeError as exc:
        raise DeliveryRefusal(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    require_verified_message_signature(
        signed_payload=signed_payload,
        signature=signature,
        did_key=signer_did_key or from_did,
    )


def _recipient_envelope_address(
    recipient: Mapping[str, Any] | None, payload: SendMessageRequest
) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    return requested_address or None


def _require_remote_mail_signature(payload: SendMessageRequest) -> None:
    if not payload.signature or not payload.signed_payload:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated mail delivery requires a sender-signed payload",
        )
    if not payload.from_did or not payload.from_did.strip():
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="from_did is required for federated mail delivery",
        )
    if not payload.message_id or not payload.timestamp or not payload.conversation_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="message_id, timestamp, and conversation_id are required for federated mail delivery",
        )


def _validate_encrypted_payload(
    payload: SendMessageRequest,
    *,
    auth: MessagingAuth,
    sender_did: str,
    recipient: Mapping[str, Any] | None,
    recipient_did: str,
) -> dict | None:
    if payload.content_mode != ContentMode.ENCRYPTED:
        return None
    if payload.message_id is None or payload.conversation_id is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="message_id and conversation_id are required for encrypted mail",
        )
    expected_recipient_did = str((recipient or {}).get("did_key") or recipient_did).strip()
    recipient_stable_id = str((recipient or {}).get("did_aw") or "").strip()
    recipient_address = _recipient_envelope_address(recipient, payload)
    if expected_recipient_did.startswith("did:key:") and not recipient_stable_id.startswith(
        "did:aw:"
    ):
        # For remote local-only participants, any stored address is a transport
        # hint. It is not an AWID address authority and must not be required in
        # the encrypted recipient binding.
        recipient_address = None
        recipient_stable_id = ""
    try:
        validate_e2ee_mail_envelope(
            payload.encrypted_envelope or {},
            message_id=payload.message_id,
            conversation_id=payload.conversation_id,
            sender_did=(auth.did_key or sender_did).strip(),
            sender_stable_id=(auth.did_aw or "").strip() or None,
            recipient_did=expected_recipient_did,
            recipient_stable_id=recipient_stable_id or None,
            recipient_address=recipient_address,
        )
    except E2EEEnvelopeError as exc:
        raise encrypted_message_refusal(detail=str(exc)) from exc
    return encrypted_message_storage_metadata(payload.encrypted_envelope or {})


def _remote_delivery_origin(recipient: Mapping[str, Any] | None) -> str:
    return str((recipient or {}).get("delivery_origin") or "").strip()


def _concrete_contact_address(recipient: Mapping[str, Any] | None) -> str:
    address = str((recipient or {}).get("address") or "").strip()
    return address if "/" in address else ""


async def record_successful_contact_side_effect(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipient: Mapping[str, Any] | None,
    registry_client=None,
) -> bool:
    """Record an accepted cross-team address contact through its binding owner."""
    recipient_address = _concrete_contact_address(recipient)
    if not recipient_address:
        return False
    recipient_team_id = str((recipient or {}).get("team_id") or "").strip()
    sender_team = str(sender_team_id or "").strip()
    if sender_team and recipient_team_id and sender_team == recipient_team_id:
        return False
    controller_did = str((recipient or {}).get("authority_controller_did") or "").strip()
    if not controller_did and (recipient or {}).get("requires_local_address_authority"):
        controller_did = (
            await resolve_local_namespace_controller_did(
                registry_client,
                contact_address=recipient_address,
                contact_did_aw=str((recipient or {}).get("did_aw") or ""),
                contact_current_did_key=str((recipient or {}).get("did_key") or ""),
            )
            or ""
        )
    return await upsert_successful_identity_contact(
        db,
        owner_did=owner_did,
        contact_address=recipient_address,
        contact_did_aw=str((recipient or {}).get("did_aw") or "").strip() or None,
        binding_controller_did=controller_did or None,
        label=str((recipient or {}).get("alias") or recipient_address),
    )


@dataclass(frozen=True, kw_only=True)
class _PreparedRemoteMail:
    envelope: FederationEnvelope
    signature: str
    sender_routing_did: str
    sender_current_did: str
    target_current_did: str
    target_address: str


def _prepare_remote_mail_envelope(
    *,
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    auth: MessagingAuth,
    recipient: Mapping[str, Any],
    recipient_did: str,
    sender_did: str,
    sender_address: str | None,
    delivery_origin: str,
) -> _PreparedRemoteMail:
    """Bind the outbound envelope to the preserved sender signature and target.

    Receiver-Wide Replay And Contact Compatibility
    (docs/identity-messaging-contract.md:338-348) separates the protected artifact
    from transport routing and persistence. This preparation performs no send.
    """
    is_encrypted = payload.content_mode == ContentMode.ENCRYPTED
    if not is_encrypted:
        _require_remote_mail_signature(payload)
    federation_signature = (
        str((payload.encrypted_envelope or {}).get("signature") or "").strip()
        if is_encrypted
        else str(payload.signature or "").strip()
    )
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated mail delivery requires a sender identity",
        )
    sender_current_did = (
        ((payload.encrypted_envelope or {}).get("from") or {}).get("did")
        if is_encrypted
        else payload.from_did
    ) or sender_did
    sender_current_did = str(sender_current_did).strip()
    if sender_current_did not in set(auth_dids(auth)):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="from_did must match the authenticated sender",
        )
    target_current_did = str(recipient.get("did_key") or "").strip()
    target_stable_id = str(recipient.get("did_aw") or recipient_did or "").strip()
    target_address = str(
        recipient.get("address") or payload.to_address or target_stable_id or ""
    ).strip()
    if not target_current_did or not target_stable_id or not target_address:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated mail delivery requires a resolved target identity",
        )
    try:
        envelope = FederationEnvelope(
            type="mail",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address or None,
            sender_delivery_origin=runtime.public_origin,
            target_address=target_address,
            target_did_aw=target_stable_id,
            target_current_did_key=target_current_did,
            target_delivery_origin=delivery_origin,
            body="" if is_encrypted else payload.body,
            message_id=payload.message_id,
            timestamp=payload.timestamp
            or ((payload.encrypted_envelope or {}).get("created_at") if is_encrypted else None),
            signed_payload=payload.signed_payload if not is_encrypted else None,
            conversation_id=payload.conversation_id,
            subject="" if is_encrypted else payload.subject,
            priority=payload.priority,
            content_mode=payload.content_mode,
            message_version=payload.message_version,
            encrypted_envelope=payload.encrypted_envelope,
        )
        verify_federation_envelope_integrity(
            envelope,
            federation_signature,
            expected={
                "type": "mail",
                "target_address": target_address,
                "target_did_aw": target_stable_id,
                "target_current_did_key": target_current_did,
                "message_id": payload.message_id,
                "conversation_id": payload.conversation_id,
            },
        )
    except FederationEnvelopeError as exc:
        raise DeliveryRefusal(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _PreparedRemoteMail(
        envelope=envelope,
        signature=federation_signature,
        sender_routing_did=sender_routing_did,
        sender_current_did=sender_current_did,
        target_current_did=target_current_did,
        target_address=target_address,
    )


async def deliver_remote_mail_and_project_locally(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    recipient: Mapping[str, Any],
    recipient_did: str,
    to_agent_id: str | None,
    to_alias: str | None,
    msg_uuid: UUID | None,
) -> SentMail:
    """Deliver a signed remote send, then retain its local thread and message projection."""
    refuse_remote_attachments()
    delivery_origin = _remote_delivery_origin(recipient)
    if not delivery_origin:
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Recipient address has no federated delivery origin",
        )
    local = await local_recipient_for_own_route(db, recipient, runtime)
    if local is not None:
        return await send_mail_conversation_continuation(
            runtime,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            conversation_id=payload.conversation_id,
            local_recipient=local,
        )
    encrypted_metadata = _validate_encrypted_payload(
        payload,
        auth=auth,
        sender_did=sender_did,
        recipient=recipient,
        recipient_did=recipient_did,
    )
    if encrypted_metadata is not None:
        await require_non_custodial_recipients(
            db,
            payload.encrypted_envelope or {},
            [recipient] if recipient else [],
            sender=auth,
        )
    prepared = _prepare_remote_mail_envelope(
        runtime=runtime,
        payload=payload,
        auth=auth,
        recipient=recipient,
        recipient_did=recipient_did,
        sender_did=sender_did,
        sender_address=sender_address,
        delivery_origin=delivery_origin,
    )
    envelope = prepared.envelope
    federation_signature = prepared.signature
    sender_routing_did = prepared.sender_routing_did
    sender_current_did = prepared.sender_current_did
    target_current_did = prepared.target_current_did
    target_address = prepared.target_address
    is_encrypted = payload.content_mode == ContentMode.ENCRYPTED
    if not is_encrypted:
        projection = await read_plaintext_projection(
            db,
            claim=PlaintextProjectionClaim.from_envelope(envelope, signature=federation_signature),
        )
        if projection.message is None:
            _require_fresh_mail_attestation(payload)
            projection.refuse_conflicting_message_id()

    try:
        remote = await deliver_federated_message(
            delivery_origin=delivery_origin,
            envelope=envelope,
            signature=federation_signature,
            id_chain=id_chain,
            transport=runtime.mail_transport,
            own_origins=runtime.public_origins,
        )
    except FederatedMailDeliveryError as exc:
        raise DeliveryRefusal(status_code=exc.status_code, detail=str(exc)) from exc

    conversation_id = str(remote.get("conversation_id") or payload.conversation_id or "").strip()
    message_id = str(remote.get("message_id") or payload.message_id or "").strip()
    delivered_at = str(remote.get("delivered_at") or (payload.timestamp or "")).strip()
    if conversation_id != payload.conversation_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Federated mail response conversation_id mismatch",
        )
    if message_id != payload.message_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Federated mail response message_id mismatch",
        )

    aweb_db = db.get_manager("aweb")
    if not is_encrypted:
        if projection.message is None:
            projection = await read_plaintext_projection(
                db,
                claim=PlaintextProjectionClaim.from_envelope(
                    envelope, signature=federation_signature
                ),
            )
            projection.refuse_conflicting_message_id()
        existing_projection = projection.message
    else:
        existing_projection = (
            await aweb_db.fetch_one(
                """
            SELECT message_id, conversation_id, created_at
            FROM {{tables.messages}}
            WHERE message_id = $1
            """,
                msg_uuid,
            )
            if msg_uuid is not None
            else None
        )
    if existing_projection:
        return SentMail(
            message_id=str(existing_projection["message_id"]),
            conversation_id=str(existing_projection["conversation_id"]),
            status=str(remote.get("status") or "delivered"),
            delivered_at=delivered_at or _utc_iso(existing_projection["created_at"]),
        )

    existing_conversation = await aweb_db.fetch_one(
        """
        SELECT conversation_id
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        UUID(conversation_id),
    )
    if existing_conversation:
        conversation = {"conversation_id": str(existing_conversation["conversation_id"])}
    else:
        conversation = await _create_mail_conversation(
            db,
            created_by_did=sender_did,
            conversation_id=conversation_id,
            initiator={
                "did": sender_did,
                "agent_id": auth.agent_id,
                "alias": auth.alias or sender_address or sender_did,
                "address": sender_address,
                "current_did_key": sender_current_did,
                "transport_hint": "local",
            },
            recipients=[
                {
                    "did": recipient_did,
                    "agent_id": to_agent_id,
                    "alias": to_alias or recipient.get("alias") or recipient_did,
                    "address": target_address,
                    "delivery_origin": delivery_origin,
                    "current_did_key": target_current_did,
                    "transport_hint": "federation:" + delivery_origin,
                }
            ],
            team_id=auth.team_id,
        )
    with agent_wake_scope(runtime.agent_wake_publisher):
        local_message_id, local_created_at = await store_mail(
            db,
            message=MailStorageInput(
                local_team_id=auth.team_id,
                sender=MailSender(
                    did=sender_did,
                    alias=auth.alias,
                    address=sender_address,
                    agent_id=auth.agent_id,
                ),
                recipient=MailRecipient(
                    did=recipient_did,
                    alias=to_alias or recipient.get("alias"),
                    address=recipient.get("address"),
                    agent_id=to_agent_id or recipient.get("agent_id"),
                    signed_did=None,
                    wake_dids=(recipient.get("did_aw"), recipient.get("did_key")),
                ),
                content=mail_content_for_storage(payload, encrypted_metadata=encrypted_metadata),
                attestation=MailAttestation(
                    signature=None if is_encrypted else payload.signature,
                    signed_payload=None if is_encrypted else payload.signed_payload,
                    id_chain=id_chain,
                ),
                priority=payload.priority,
                message_id=msg_uuid,
                conversation_id=conversation["conversation_id"],
            ),
        )

    await record_successful_contact_side_effect(
        db,
        owner_did=sender_routing_did,
        sender_team_id=auth.team_id,
        recipient=recipient,
        registry_client=registry_client,
    )

    await fire_mutation_callback(
        runtime.on_mutation,
        MutationEventType.MAIL_SENT.value,
        MailSentContext(
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_did=sender_did,
            from_did_aw=sender_routing_did if sender_routing_did.startswith("did:aw:") else None,
            to_agent_id=to_agent_id,
            from_alias=auth.alias or sender_did,
            message_id=message_id or str(local_message_id),
            conversation_id=conversation_id or conversation["conversation_id"],
            to_alias=to_alias,
            subject=payload.subject,
            priority=payload.priority,
            content_mode=payload.content_mode,
            transport=MessageTransport.FEDERATED,
        ).to_context(),
    )

    return SentMail(
        message_id=message_id or str(local_message_id),
        conversation_id=conversation_id or conversation["conversation_id"],
        status=str(remote.get("status") or "delivered"),
        delivered_at=delivered_at or _utc_iso(local_created_at),
    )


def _lost_send_race(exc: BaseException) -> bool:
    """A concurrent send claimed this message_id or conversation_id and committed first."""
    if isinstance(exc, MailConversationExists):
        return True
    return is_unique_write_conflict(exc)


@dataclass(frozen=True, kw_only=True)
class MailReplayLookup:
    stored: SentMail | None
    availability: MailIdAvailability


async def _stored_exact_send(db, *, payload, sender_did: str) -> MailReplayLookup:
    """What an exact retry of this send already stored, before any new effect.

    Returns the stored send when payload.message_id names a message this
    sender sent with identical signed bytes. A conflicting stored message ID
    follows ordinary admission and refuses before any new effect.
    """
    if not payload.message_id:
        return MailReplayLookup(stored=None, availability=MailIdAvailability.UNDETERMINED)
    try:
        message_uuid = UUID(payload.message_id)
    except ValueError:
        return MailReplayLookup(stored=None, availability=MailIdAvailability.UNDETERMINED)
    lookup = await read_stored_message(
        db,
        claim=StoredMessageClaim(
            kind=MessageKind.MAIL,
            message_id=message_uuid,
            sender_did=sender_did,
            conversation_id=UUID(payload.conversation_id) if payload.conversation_id else None,
            artifact=replay_artifact(
                content_mode=payload.content_mode,
                encrypted_envelope=payload.encrypted_envelope,
                signature=payload.signature,
                signed_payload=payload.signed_payload,
            ),
        ),
    )
    if lookup.message is None:
        return MailReplayLookup(
            stored=None,
            availability=(
                MailIdAvailability.CONFIRMED_UNUSED
                if lookup.state is StoredMessageState.MISSING
                else MailIdAvailability.UNDETERMINED
            ),
        )
    row = lookup.message
    # All callers validate encryption and current delivery policy before this
    # lookup. Bound attachment refs therefore cannot bypass ordinary admission.
    await confirm_accepted_attachment_refs(db, kind=MessageKind.MAIL, message_id=row["message_id"])
    return MailReplayLookup(
        stored=SentMail(
            message_id=str(row["message_id"]),
            conversation_id=str(row["conversation_id"]) if row["conversation_id"] else None,
            status="delivered",
            delivered_at=_utc_iso(row["created_at"]),
        ),
        availability=MailIdAvailability.UNDETERMINED,
    )


async def _create_mail_conversation(
    db,
    *,
    created_by_did: str,
    initiator: ConversationParticipant | dict[str, Any],
    recipients: Sequence[ConversationParticipant | dict[str, Any]],
    conversation_id: str | UUID | None,
    team_id: str | None,
) -> dict[str, Any]:
    """Create the requested mail thread, translating only an insertion race."""
    try:
        return await create_conversation(
            db,
            conversation_type=MessageKind.MAIL.value,
            created_by_did=created_by_did,
            initiator=initiator,
            recipients=recipients,
            conversation_id=conversation_id,
            team_id=team_id,
        )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        # The preflight read cannot exclude a concurrent insertion. Creation is
        # transactional: losing that race must refuse rather than reuse or 500.
        cause = exc.__cause__ if isinstance(exc, QueryError) else exc
        if isinstance(cause, asyncpg.exceptions.UniqueViolationError):
            raise MailConversationExists() from exc
        raise


async def _continuation_signature_recipient(
    runtime: MessagingRuntime,
    *,
    participant: dict,
    recipient: Mapping[str, Any],
    payload: SendMessageRequest,
    sender_did_key: str,
) -> dict:
    """Validate a signed stored-route recipient without changing its routing facts."""
    signed = verified_signed_payload_json(
        signed_payload=payload.signed_payload,
        signature=payload.signature,
        did_key=sender_did_key,
    )
    if signed is None:
        raise DeliveryRefusal(status_code=HTTPStatus.FORBIDDEN, detail="Invalid message signature")
    stable = str(participant.get("did") or "")
    signed_stable = signed.get("to_stable_id") or ""
    signed_key = signed.get("to_did") or ""
    signed_to = signed.get("to") or ""
    if not signed_stable and isinstance(signed_key, str) and signed_key.startswith("did:aw:"):
        signed_stable, signed_key = signed_key, ""
    if not signed_stable and isinstance(signed_to, str) and signed_to.startswith("did:aw:"):
        signed_stable = signed_to
    if not stable.startswith("did:aw:") or signed_stable != stable:
        raise RecipientIdentityBindingError(IdentityBindingCode.MISMATCH)
    address = str(participant.get("address") or "")
    signed_address = signed_to if isinstance(signed_to, str) and "/" in signed_to else ""
    if signed_address and signed_address != address:
        raise RecipientIdentityBindingError(IdentityBindingCode.MISMATCH)
    if not signed_key and isinstance(signed_to, str) and signed_to.startswith("did:key:"):
        signed_key = signed_to
    if not signed_key:
        # Released clients may sign only the stable DID on a stored route.
        # Discover its current key solely for validation, never for delivery.
        if runtime.registry_client is None:
            raise RecipientIdentityBindingError(IdentityBindingCode.UNAVAILABLE)
        try:
            resolved = await runtime.registry_client.resolve_key_fresh(stable)
            signed_key = resolved.current_did_key
        except RegistryError as exc:
            if exc.status_code != 404:
                logging.getLogger(__name__).warning(
                    "Stored mail signature binding dependency failed failure_type=%s",
                    type(exc).__name__,
                )
            code = (
                IdentityBindingCode.MISMATCH
                if exc.status_code == 404
                else IdentityBindingCode.UNAVAILABLE
            )
            raise RecipientIdentityBindingError(code) from exc
        except AWID_DEPENDENCY_ERRORS as exc:
            logging.getLogger(__name__).warning(
                "Stored mail signature binding dependency failed failure_type=%s",
                type(exc).__name__,
            )
            raise RecipientIdentityBindingError(IdentityBindingCode.UNAVAILABLE) from exc
    if not isinstance(signed_key, str) or not signed_key.startswith("did:key:"):
        raise RecipientIdentityBindingError(IdentityBindingCode.MISMATCH)
    try:
        await observe_current_identity_binding(
            runtime.registry_client,
            runtime.identity_binding_cache,
            did_key=signed_key,
            did_aw=stable,
            address=signed_address,
        )
    except IdentityBindingError as exc:
        raise RecipientIdentityBindingError(exc.code, headers=exc.headers) from exc
    # This copy is passed only to the payload validator. The original recipient,
    # participant agent_id, policy rows and all projection markers stay intact.
    return {**recipient, "did_aw": stable, "did_key": signed_key, "address": address}


async def _commit_mail_continuation(
    db,
    *,
    message: MailStorageInput,
    recipient: Mapping[str, Any],
    sender: DeliverySender,
    registry_client,
) -> StoredMail:
    """Recheck stored-route policy and commit the message under its read locks."""
    if message.conversation_id is None:
        raise ValueError("A mail continuation commit requires its stored conversation ID")
    async with db.get_manager("aweb").transaction() as tx:
        send_db = TransactionInfra(db, tx)
        await admit_message_delivery(
            send_db,
            registry_client=registry_client,
            recipient=recipient,
            recipient_did=message.recipient.did,
            to_agent_id=message.recipient.agent_id,
            sender_did=sender.did,
            sender_address=sender.address,
            sender_verified_dids=sender.verified_dids,
            stored_route_continuation=True,
        )
        stored = await store_mail(send_db, message=message)
        await touch_conversation_activity(send_db, conversation_id=message.conversation_id)
    return stored


async def send_mail_conversation_continuation(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    conversation_id: str,
    local_recipient: Mapping[str, Any] | None = None,
    continuation: MailContinuationContext | None = None,
) -> SentMail:
    """Validate a stored participant route and append or acknowledge an exact local mail send."""
    msg_uuid = UUID(payload.message_id) if payload.message_id else None

    if continuation is None:
        continuation = await mail_continuation_context(
            db,
            conversation_id=conversation_id,
            sender_did=sender_did,
            equivalent_dids=participant_dids(auth),
        )
    recipient_participant = continuation.recipient_participant
    if local_recipient is None and participant_is_remote(recipient_participant):
        return await send_federated_mail_conversation_continuation(
            runtime,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            continuation=continuation,
        )
    recipient = local_recipient or await recipient_for_conversation_participant(
        db, recipient_participant
    )
    historical_target = None
    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did is required when signature is provided",
            )
        from_did = payload.from_did.strip()
        if from_did not in set(auth_dids(auth)):
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did must match the authenticated sender",
            )
        if payload.message_id is None or payload.timestamp is None:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="message_id and timestamp are required when signature is provided",
            )
        validation: _MailSignatureFields = dict(
            signer_did_key=auth.did_key,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient=recipient,
            to_agent_id=payload.to_agent_id,
            to_alias=recipient_participant.get("alias"),
            requested_to_alias=payload.to_alias,
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, sender_address),
            from_stable_id=auth.did_aw,
            priority=payload.priority,
            subject=payload.subject,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            conversation_id=conversation_id,
        )
        # Historical target evidence is restricted to this recorded local
        # mail thread. It never supplies sender or current-key authority.
        signed = verified_signed_payload_json(
            signed_payload=payload.signed_payload,
            signature=payload.signature,
            did_key=auth.did_key,
        )
        if signed is not None and payload.encrypted_envelope is None:
            historical_target = await predecessor_target_for_mail(
                db,
                conversation_id=conversation_id,
                successor_did=recipient_participant["did"],
                signed=signed,
            )
        if historical_target is not None:
            validation["recipient"] = historical_target
            validation["to_alias"] = historical_target["alias"]
        elif recipient.get("did_aw") and not recipient.get("did_key"):
            # A canonical stored participant can outlive its key projection.
            # Even a stable-only signed target needs current key evidence.
            validation["recipient"] = await _continuation_signature_recipient(
                runtime,
                participant=recipient_participant,
                recipient=recipient,
                payload=payload,
                sender_did_key=auth.did_key,
            )
        try:
            _validate_signed_mail_payload(**validation)
        except SignedRecipientMismatch:
            validation["recipient"] = await _continuation_signature_recipient(
                runtime,
                participant=recipient_participant,
                recipient=recipient,
                payload=payload,
                sender_did_key=auth.did_key,
            )
            _validate_signed_mail_payload(**validation)
    encrypted_metadata = _validate_encrypted_payload(
        payload,
        auth=auth,
        sender_did=sender_did,
        recipient=recipient,
        recipient_did=recipient_participant["did"],
    )
    if encrypted_metadata is not None:
        await require_non_custodial_recipients(
            db,
            payload.encrypted_envelope or {},
            [recipient] if recipient else [],
            sender=auth,
        )
    # Admission comes before any replay, as for any send.
    await admit_message_delivery(
        db,
        registry_client=runtime.registry_client,
        recipient=recipient,
        recipient_did=recipient_participant["did"],
        to_agent_id=recipient.get("agent_id"),
        sender_did=sender_did,
        sender_address=sender_address,
        sender_verified_dids=auth_dids(auth),
        stored_route_continuation=True,
    )
    replay_lookup = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
    if replay_lookup.stored is not None:
        return replay_lookup.stored
    _require_fresh_mail_attestation(payload)
    try:
        with agent_wake_scope(runtime.agent_wake_publisher):
            message_id, server_received_at = await _commit_mail_continuation(
                db,
                recipient=recipient,
                registry_client=runtime.registry_client,
                sender=DeliverySender(
                    did=sender_did,
                    address=sender_address,
                    verified_dids=tuple(auth_dids(auth)),
                ),
                message=MailStorageInput(
                    local_team_id=continuation.conversation.get("team_id") or auth.team_id,
                    sender=MailSender(
                        did=sender_did,
                        alias=auth.alias,
                        address=sender_address,
                        agent_id=auth.agent_id,
                    ),
                    recipient=MailRecipient(
                        did=recipient_participant["did"],
                        alias=recipient_participant.get("alias") or recipient.get("alias"),
                        address=recipient.get("address"),
                        agent_id=recipient.get("agent_id"),
                        signed_did=historical_target["signed_did"]
                        if historical_target is not None
                        else None,
                        wake_dids=(recipient.get("did_aw"), recipient.get("did_key")),
                    ),
                    content=mail_content_for_storage(
                        payload, encrypted_metadata=encrypted_metadata
                    ),
                    attestation=MailAttestation(
                        signature=payload.signature,
                        signed_payload=payload.signed_payload,
                        id_chain=id_chain,
                    ),
                    priority=payload.priority,
                    message_id=msg_uuid,
                    conversation_id=conversation_id,
                    id_availability=replay_lookup.availability,
                ),
            )
    except (
        MailConversationExists,
        QueryError,
        asyncpg.exceptions.UniqueViolationError,
    ) as exc:
        if not _lost_send_race(exc):
            raise
        replay_lookup = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
        if replay_lookup.stored is None:
            raise
        return replay_lookup.stored
    await fire_mutation_callback(
        runtime.on_mutation,
        MutationEventType.MAIL_SENT.value,
        MailSentContext(
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_did=sender_did,
            from_did_aw=(auth.did_aw or "").strip() or None,
            to_agent_id=recipient_participant.get("agent_id"),
            from_alias=auth.alias or sender_did,
            message_id=str(message_id),
            conversation_id=conversation_id,
            to_alias=recipient_participant.get("alias"),
            subject=payload.subject,
            priority=payload.priority,
            content_mode=payload.content_mode,
        ).to_context(),
    )

    return SentMail(
        message_id=str(message_id),
        conversation_id=conversation_id,
        status="delivered",
        delivered_at=_utc_iso(server_received_at),
    )


async def send_federated_mail_conversation_continuation(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    continuation: MailContinuationContext,
) -> SentMail:
    """Reply through the recorded remote participant without resolving its address as first contact."""
    refuse_remote_attachments()
    recipient_participant = continuation.recipient_participant
    recipient = await remote_recipient_from_participant(registry_client, recipient_participant)
    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    # The remote projection owner checks age after recognizing exact plaintext
    # retries. Encrypted envelope verification retains its existing window.
    return await deliver_remote_mail_and_project_locally(
        runtime,
        payload,
        db,
        auth=auth,
        registry_client=registry_client,
        sender_address=sender_address,
        sender_did=sender_did,
        id_chain=id_chain,
        recipient=recipient,
        recipient_did=recipient_participant["did"],
        to_agent_id=None,
        to_alias=recipient_participant.get("alias"),
        msg_uuid=msg_uuid,
    )


async def _resolve_message_alias(
    db, auth: MessagingAuth, raw_alias: str, *, registry_client
) -> dict | None:
    target = resolve_alias_target(auth.team_id, raw_alias, field="to_alias")
    if "~" in str(raw_alias or "") and not await team_exists(db, target.team_id):
        raise DeliveryRefusal(
            status_code=HTTPStatus.NOT_FOUND, detail=f"Unknown team: {target.team_id}"
        )
    return await messaging_participant_by_alias(
        db,
        team_id=target.team_id,
        alias=target.alias,
        selected_team_id=auth.team_id,
        registry_client=registry_client,
    )


def _raise_bare_did_first_contact_unsupported() -> NoReturn:
    raise DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail="Bare did:aw first-contact is unsupported; use to_address=domain/name or continue an existing conversation",
    )


def _recipient_conversation_address(
    recipient: Mapping[str, Any] | None, payload: SendMessageRequest
) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    if requested_address:
        return requested_address
    return (
        derive_team_address(
            str((recipient or {}).get("team_id") or ""),
            str((recipient or {}).get("alias") or ""),
        )
        or None
    )


def _recipient_identity_matches(
    left: Mapping[str, Any] | None, right: Mapping[str, Any] | None
) -> bool:
    if left is None or right is None:
        return False
    left_did = str(left.get("did_aw") or left.get("did_key") or "").strip()
    right_did = str(right.get("did_aw") or right.get("did_key") or "").strip()
    return bool(left_did and right_did and left_did == right_did)


@dataclass(frozen=True, init=False)
class MailTarget:
    """Where a mail send goes: the recipient of a first message, or the stored conversation it continues."""

    recipient: Recipient | None = None
    recipient_did: str = ""
    to_agent_id: str | None = None
    to_alias: str | None = None
    continuation: MailContinuationContext | None = None

    def __init__(
        self,
        *,
        recipient: Mapping[str, Any] | None = None,
        recipient_did: str = "",
        to_agent_id: str | None = None,
        to_alias: str | None = None,
        continuation: MailContinuationContext | None = None,
    ) -> None:
        object.__setattr__(
            self,
            "recipient",
            Recipient.from_delivery_projection(recipient) if recipient is not None else None,
        )
        object.__setattr__(self, "recipient_did", recipient_did)
        object.__setattr__(self, "to_agent_id", to_agent_id)
        object.__setattr__(self, "to_alias", to_alias)
        object.__setattr__(self, "continuation", continuation)


async def resolve_mail_target(
    db,
    auth: MessagingAuth,
    payload: SendMessageRequest,
    runtime: MessagingRuntime,
    source: str,
    *,
    recipient_binding: RecipientIdentityBinding | None = None,
) -> MailTarget:
    """Resolve whom a send names, before any of it is stored.

    ``payload`` supplies the recipient fields, the conversation id and any
    signature the sender made over the recipient binding. ``source`` keys the
    federation authority's rate bucket for this caller.
    """
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Authenticated identity is missing a routing DID. Reconnect with your current identity credentials and retry.",
        )

    continuation = await _resolve_requested_mail_continuation(
        db, auth=auth, payload=payload, sender_did=sender_did
    )
    if continuation is not None:
        return continuation
    return await _resolve_new_mail_target(
        db,
        auth=auth,
        payload=payload,
        runtime=runtime,
        source=source,
        recipient_binding=recipient_binding,
    )


async def _accepted_encrypted_mail_target_matches_participant(
    db,
    *,
    payload: SendMessageRequest,
    sender_did: str,
    participant: Mapping[str, Any],
) -> bool:
    """Locate an accepted key-only target, without answering or admitting a send.

    Released encrypted attachment retries can omit the outer stable selector.
    Their exact accepted artifact and protected stable binding identify only
    the same recorded party. Ordinary crypto, freshness and current policy
    still run before the stored answer; a new artifact gains no selector.
    """
    if (
        payload.content_mode != ContentMode.ENCRYPTED
        or payload.encrypted_envelope is None
        or payload.to_did is None
        or payload.message_id is None
        or payload.conversation_id is None
        or any(
            value is not None
            for value in (
                payload.to_agent_id,
                payload.to_alias,
                payload.to_address,
                payload.to_stable_id,
            )
        )
    ):
        return False
    routing = payload.encrypted_envelope.get("routing")
    stable_did = str(participant.get("did") or "")
    if (
        not isinstance(routing, Mapping)
        or not stable_did.startswith("did:aw:")
        or routing.get("to_stable_id") != stable_did
        or routing.get("to_did") != payload.to_did.strip()
    ):
        return False
    try:
        message_id = UUID(payload.message_id)
        conversation_id = UUID(payload.conversation_id)
    except ValueError:
        return False
    accepted = await read_stored_message(
        db,
        claim=StoredMessageClaim(
            kind=MessageKind.MAIL,
            message_id=message_id,
            sender_did=sender_did,
            conversation_id=conversation_id,
            artifact=replay_artifact(
                content_mode=payload.content_mode,
                encrypted_envelope=payload.encrypted_envelope,
                signature=payload.signature,
                signed_payload=payload.signed_payload,
            ),
        ),
    )
    return (
        accepted.state is StoredMessageState.EXACT
        and accepted.message is not None
        and accepted.message.get("to_did") == stable_did
    )


async def _resolve_requested_mail_continuation(
    db,
    *,
    auth: MessagingAuth,
    payload: SendMessageRequest,
    sender_did: str,
) -> MailTarget | None:
    """Resolve an existing thread before any first-contact recipient lookup."""
    has_explicit_recipient = any(
        value is not None
        for value in (
            payload.to_agent_id,
            payload.to_alias,
            payload.to_did,
            payload.to_stable_id,
            payload.to_address,
        )
    )

    if payload.conversation_id is not None and not has_explicit_recipient:
        return MailTarget(
            continuation=await mail_continuation_context(
                db,
                conversation_id=payload.conversation_id,
                sender_did=sender_did,
                equivalent_dids=participant_dids(auth),
            )
        )

    if has_explicit_recipient and payload.conversation_id is not None:
        requested_conversation = await get_conversation(db, conversation_id=payload.conversation_id)
        if requested_conversation is not None:
            requested_continuation = await mail_continuation_context(
                db,
                conversation_id=payload.conversation_id,
                sender_did=sender_did,
                equivalent_dids=participant_dids(auth),
            )
            target_matches = await explicit_mail_target_matches_participant(
                db,
                requested_continuation.recipient_participant,
                to_agent_id=payload.to_agent_id,
                to_alias=payload.to_alias,
                to_did=payload.to_did,
                to_stable_id=payload.to_stable_id,
                to_address=payload.to_address,
            )
            if not target_matches:
                target_matches = await _accepted_encrypted_mail_target_matches_participant(
                    db,
                    payload=payload,
                    sender_did=sender_did,
                    participant=requested_continuation.recipient_participant,
                )
            if (
                not target_matches
                and payload.encrypted_envelope is None
                and payload.to_agent_id is None
                and payload.to_alias is None
                and payload.to_address is None
            ):
                signed = verified_signed_payload_json(
                    signed_payload=payload.signed_payload,
                    signature=payload.signature,
                    did_key=auth.did_key,
                )
                historical = (
                    await predecessor_target_for_mail(
                        db,
                        conversation_id=payload.conversation_id,
                        successor_did=requested_continuation.recipient_participant["did"],
                        signed=signed,
                    )
                    if signed is not None
                    else None
                )
                if historical is not None:
                    identities = {historical["did_key"], historical["did_aw"]} - {None}
                    target_matches = all(
                        value is None or value in identities
                        for value in (payload.to_did, payload.to_stable_id)
                    )
            if not target_matches:
                raise DeliveryRefusal(
                    status_code=HTTPStatus.CONFLICT,
                    detail="conversation_id recipient does not match the requested recipient. Use the stored recipient or start a new conversation.",
                )
            return MailTarget(continuation=requested_continuation)

    return None


async def _resolve_new_mail_target(
    db,
    *,
    auth: MessagingAuth,
    payload: SendMessageRequest,
    runtime: MessagingRuntime,
    source: str,
    recipient_binding: RecipientIdentityBinding | None,
) -> MailTarget:
    """Resolve the explicit recipient selectors and require their agreement."""
    registry_client = runtime.registry_client
    recipient: Mapping[str, Any] | None = None
    bound_recipient: Mapping[str, Any] | None
    recipient_did: str | None = None
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if payload.to_address is None and payload.to_stable_id is not None:
        recipient_did = payload.to_stable_id.strip()
        recipient = await resolve_recipient_by_did(db, recipient_did, sender_team_id=auth.team_id)
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise recipient_not_found()
        if payload.to_did is not None and payload.to_did.strip():
            bound_recipient = await resolve_recipient_by_did(
                db, payload.to_did.strip(), sender_team_id=auth.team_id
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.DID,
                    resolved=RecipientSelectorField.STABLE_ID,
                )
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(
                db, auth, payload.to_alias.strip(), registry_client=registry_client
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.ALIAS,
                    resolved=RecipientSelectorField.STABLE_ID,
                )
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is None and payload.to_did is not None:
        requested_recipient_did = payload.to_did.strip()
        recipient = await resolve_recipient_by_did(
            db, requested_recipient_did, sender_team_id=auth.team_id
        )
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if requested_recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise recipient_not_found()
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(
                db, auth, payload.to_alias.strip(), registry_client=registry_client
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.ALIAS,
                    resolved=RecipientSelectorField.DID,
                )
        recipient_did = (
            recipient.get("did_aw") or recipient.get("did_key") or requested_recipient_did
        ).strip()
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is not None:
        address = payload.to_address.strip()
        if "/" not in address:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="to_address must be domain/name. Use a domain/name address and retry.",
            )
        recipient = await resolve_address_recipient(
            db,
            auth,
            runtime,
            address=address,
            source=source,
            kind=MessageKind.MAIL,
            binding=recipient_binding,
            signed_payload=payload.signed_payload,
            signature=payload.signature,
        )
        recipient_did = str(recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        if payload.to_alias is not None and payload.to_alias.strip():
            if recipient.get("external"):
                if payload.to_alias.strip() != recipient["alias"]:
                    raise recipient_selector_mismatch(
                        supplied=RecipientSelectorField.ALIAS,
                        resolved=RecipientSelectorField.ADDRESS,
                    )
            else:
                bound_recipient = await _resolve_message_alias(
                    db, auth, payload.to_alias.strip(), registry_client=registry_client
                )
                if not _recipient_identity_matches(bound_recipient, recipient):
                    raise recipient_selector_mismatch(
                        supplied=RecipientSelectorField.ALIAS,
                        resolved=RecipientSelectorField.ADDRESS,
                    )
        if payload.to_stable_id is not None and payload.to_stable_id.strip():
            if payload.to_stable_id.strip() != str(recipient.get("did_aw") or "").strip():
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.STABLE_ID,
                    resolved=RecipientSelectorField.ADDRESS,
                )
        if payload.to_did is not None and payload.to_did.strip():
            candidate_dids = {
                str(recipient.get("did_aw") or "").strip(),
                str(recipient.get("did_key") or "").strip(),
            }
            if payload.to_did.strip() not in candidate_dids:
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.DID,
                    resolved=RecipientSelectorField.ADDRESS,
                )
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias") or address
    elif to_agent_id is not None:
        recipient = (
            await get_agent_by_id(
                db,
                team_id=auth.team_id,
                agent_id=to_agent_id,
            )
            if auth.team_id
            else await get_agent_by_id(db, agent_id=to_agent_id)
        )
        if recipient is None:
            raise recipient_not_found()
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(
                db, auth, payload.to_alias.strip(), registry_client=registry_client
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise recipient_selector_mismatch(
                    supplied=RecipientSelectorField.ALIAS,
                    resolved=RecipientSelectorField.AGENT_ID,
                )
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_alias = recipient.get("alias")
    elif payload.to_alias is not None:
        recipient = await _resolve_message_alias(
            db, auth, payload.to_alias, registry_client=registry_client
        )
        if recipient is None:
            raise recipient_not_found()
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]
    else:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Must provide to_did, to_address, to_agent_id, or to_alias. Choose a recipient and retry.",
        )

    if payload.to_agent_id and any(
        value is not None for value in (payload.to_address, payload.to_did, payload.to_stable_id)
    ):
        selected_member = await get_agent_by_id(
            db, agent_id=payload.to_agent_id, team_id=auth.team_id
        )
        if recipient.get("external") or not _recipient_identity_matches(selected_member, recipient):
            field = (
                RecipientSelectorField.ADDRESS
                if payload.to_address is not None
                else (
                    RecipientSelectorField.STABLE_ID
                    if payload.to_stable_id is not None
                    else RecipientSelectorField.DID
                )
            )
            raise recipient_selector_mismatch(
                supplied=RecipientSelectorField.AGENT_ID, resolved=field
            )

    return MailTarget(
        recipient=recipient,
        recipient_did=recipient_did or "",
        to_agent_id=to_agent_id,
        to_alias=to_alias,
    )


async def send_mail(
    db,
    auth: MessagingAuth,
    target: MailTarget,
    payload: SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentMail:
    """Store and deliver the signed or encrypted ``payload`` to a resolved target."""
    observe_message_vocabulary(
        source=MessageInputSource.MAIL_SEND,
        content_mode=payload.content_mode,
        priority=payload.priority,
    )
    return await _send_mail_to_resolved_target(
        db,
        auth=auth,
        target=target,
        payload=payload,
        runtime=runtime,
    )


@dataclass(frozen=True, kw_only=True)
class _LocalMailCommit:
    message_id: UUID
    conversation_id: str
    server_received_at: datetime


async def _commit_new_local_mail(
    db,
    *,
    runtime: MessagingRuntime,
    auth: MessagingAuth,
    target: MailTarget,
    payload: SendMessageRequest,
    encrypted_metadata: dict | None,
    replay_lookup: MailReplayLookup,
) -> _LocalMailCommit:
    """Store a new thread and its first message in one native transaction."""
    recipient = target.recipient
    if recipient is None:
        raise ValueError("A new local mail commit requires a resolved recipient")
    recipient_did = target.recipient_did
    to_agent_id = target.to_agent_id
    to_alias = target.to_alias
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    sender_address = _sender_address(auth)
    id_chain = auth.id_chain
    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    async with db.get_manager("aweb").transaction() as tx:
        send_db = TransactionInfra(db, tx)
        # Preflight protects replays; a new write rechecks under the transaction
        # that commits it, keeping membership/contact locks until delivery.
        await authorize_message_delivery(
            send_db,
            registry_client=runtime.registry_client,
            recipient_agent=recipient,
            sender_did=sender_did,
            sender_address=sender_address,
            sender_verified_dids=auth_dids(auth),
        )
        # If an explicit recipient is present, conversation_id is a caller-chosen
        # initial id. Continuations use conversation_id without recipient fields.
        conversation = await _create_mail_conversation(
            send_db,
            created_by_did=sender_did,
            conversation_id=payload.conversation_id,
            initiator={
                "did": sender_did,
                "agent_id": auth.agent_id,
                "alias": auth.alias or sender_address or sender_did,
                "address": sender_address,
                "current_did_key": (auth.did_key or "").strip() or None,
                "transport_hint": "local",
            },
            recipients=[
                {
                    "did": recipient_did or "",
                    "agent_id": to_agent_id,
                    "alias": to_alias or recipient.get("alias") or recipient_did or "",
                    "address": _recipient_conversation_address(recipient, payload),
                    "current_did_key": recipient.get("did_key"),
                    "transport_hint": "local",
                }
            ],
            team_id=auth.team_id,
        )
        message_id, server_received_at = await store_mail(
            send_db,
            message=MailStorageInput(
                local_team_id=auth.team_id,
                sender=MailSender(
                    did=sender_did,
                    alias=auth.alias,
                    address=sender_address,
                    agent_id=auth.agent_id,
                ),
                recipient=MailRecipient(
                    did=recipient_did or "",
                    alias=to_alias or recipient.get("alias"),
                    address=recipient.get("address"),
                    agent_id=to_agent_id or recipient.get("agent_id"),
                    signed_did=None,
                    wake_dids=(
                        recipient.get("did_aw"),
                        recipient.get("did_key"),
                    ),
                ),
                content=mail_content_for_storage(payload, encrypted_metadata=encrypted_metadata),
                attestation=MailAttestation(
                    signature=payload.signature,
                    signed_payload=payload.signed_payload,
                    id_chain=id_chain,
                ),
                priority=payload.priority,
                message_id=msg_uuid,
                conversation_id=conversation["conversation_id"],
                id_availability=replay_lookup.availability,
            ),
        )

    return _LocalMailCommit(
        message_id=message_id,
        conversation_id=conversation["conversation_id"],
        server_received_at=server_received_at,
    )


async def _send_mail_to_resolved_target(
    db,
    *,
    auth: MessagingAuth,
    target: MailTarget,
    payload: SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentMail:
    """Deliver to the selected local recipient or stored/federated route."""
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    sender_address = _sender_address(auth)
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if target.continuation is not None:
        if participant_is_remote(target.continuation.recipient_participant):
            return await send_federated_mail_conversation_continuation(
                runtime,
                payload,
                db,
                auth=auth,
                registry_client=registry_client,
                sender_address=sender_address,
                sender_did=sender_did,
                id_chain=id_chain,
                continuation=target.continuation,
            )
        return await send_mail_conversation_continuation(
            runtime,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            conversation_id=payload.conversation_id,
            continuation=target.continuation,
        )
    recipient = target.recipient
    if recipient is None:
        raise ValueError("A new mail target requires a resolved recipient")
    recipient_did = target.recipient_did
    to_agent_id = target.to_agent_id
    to_alias = target.to_alias

    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did is required when signature is provided",
            )
        from_did = payload.from_did.strip()
        if from_did not in set(auth_dids(auth)):
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did must match the authenticated sender",
            )
        if payload.message_id is None or payload.timestamp is None:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_mail_payload(
            signer_did_key=auth.did_key,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient=recipient,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            requested_to_alias=payload.to_alias,
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, sender_address),
            from_stable_id=auth.did_aw,
            priority=payload.priority,
            subject=payload.subject,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            conversation_id=payload.conversation_id,
        )

    if recipient.get("external"):
        return await deliver_remote_mail_and_project_locally(
            runtime,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            recipient=recipient,
            recipient_did=recipient_did or "",
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            msg_uuid=msg_uuid,
        )

    try:
        if msg_uuid is not None or payload.content_mode == ContentMode.ENCRYPTED:
            await authorize_message_delivery(
                db,
                registry_client=runtime.registry_client,
                recipient_agent=recipient,
                sender_did=sender_did,
                sender_address=sender_address,
                sender_verified_dids=auth_dids(auth),
            )
        encrypted_metadata = _validate_encrypted_payload(
            payload,
            auth=auth,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_did or "",
        )
        if encrypted_metadata is not None:
            await require_non_custodial_recipients(
                db,
                payload.encrypted_envelope or {},
                [recipient] if recipient else [],
                sender=auth,
            )
        replay_lookup = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
        if replay_lookup.stored is not None:
            return replay_lookup.stored
        _require_fresh_mail_attestation(payload)
        try:
            with agent_wake_scope(runtime.agent_wake_publisher):
                # The conversation and its first message commit together: a refused
                # delivery leaves no conversation behind.
                committed = await _commit_new_local_mail(
                    db,
                    runtime=runtime,
                    auth=auth,
                    target=target,
                    payload=payload,
                    encrypted_metadata=encrypted_metadata,
                    replay_lookup=replay_lookup,
                )
                message_id = committed.message_id
                server_received_at = committed.server_received_at
                conversation_id = committed.conversation_id
        except (
            MailConversationExists,
            QueryError,
            asyncpg.exceptions.UniqueViolationError,
        ) as exc:
            # An identical send that ran concurrently committed first; its
            # rollback here leaves nothing of this attempt behind.
            if not _lost_send_race(exc):
                raise
            replay_lookup = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
            if replay_lookup.stored is None:
                raise
            return replay_lookup.stored
    except DeliveryPolicyRefused:
        raise
    except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
        raise DeliveryRefusal(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=(auth.did_aw or sender_did).strip(),
        sender_team_id=auth.team_id,
        recipient=recipient,
        registry_client=registry_client,
    )

    await fire_mutation_callback(
        runtime.on_mutation,
        MutationEventType.MAIL_SENT.value,
        MailSentContext(
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_did=sender_did,
            from_did_aw=(auth.did_aw or "").strip() or None,
            to_agent_id=to_agent_id,
            from_alias=auth.alias or sender_did,
            message_id=str(message_id),
            conversation_id=conversation_id,
            to_alias=to_alias,
            subject=payload.subject,
            priority=payload.priority,
            content_mode=payload.content_mode,
        ).to_context(),
    )

    return SentMail(
        message_id=str(message_id),
        conversation_id=conversation_id,
        status="delivered",
        delivered_at=_utc_iso(server_received_at),
    )
