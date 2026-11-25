"""Chat recipient resolution and sends, for every adapter."""

from __future__ import annotations

from aweb.messaging.delivery_policy import DeliveryPolicyRefused

from aweb.messaging.kinds import ContentMode

import json
import logging
import uuid as uuid_mod
from pgdbm.errors import QueryError
from aweb.messaging.write_conflicts import is_unique_write_conflict
from aweb.messaging.message_replay import (
    ChatReplayControls,
    StoredMessageClaim,
    StoredMessageState,
    read_stored_message,
    replay_artifact,
)
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum, auto
from aweb.messaging.recipient import Recipient
from datetime import datetime, timezone
from typing import Any, NoReturn
from uuid import UUID

import asyncpg.exceptions
from awid.federation_errors import FederationAuthorityError
from aweb.messaging.refusals import (
    encrypted_message_refusal,
    DeliveryRefusalCode,
    signed_chat_payload_refusal,
    registry_dependency_refusal,
)
from aweb.messaging.refusals import DeliveryRefusal, SignedRecipientMismatch
from http import HTTPStatus
from aweb.message_vocabulary import MessageInputSource, observe_message_vocabulary
from aweb.identity_address import require_address_evidence

from aweb.agent_wake import agent_wake_scope
from aweb.application_state import RegistryClientUnavailable
from aweb.attachment_service import confirm_accepted_attachment_refs, refuse_remote_attachments
from aweb.db import TransactionInfra
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    encrypted_message_storage_metadata,
    validate_e2ee_message_envelope,
    verify_e2ee_message_envelope_signature,
)
from aweb.federation.envelope import (
    FederationEnvelope,
    FederationEnvelopeError,
    enforce_message_timestamp_skew,
    verify_federation_envelope_integrity,
)
from aweb.federation.replay import (
    PlaintextProjectionClaim,
    read_plaintext_projection,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.hooks import fire_mutation_callback
from aweb.hooks import HeldMutationEvents
from aweb.member_team_key import MemberReadLock
from aweb.messaging.delivery_policy import (
    DeliveryAttempt,
    DeliverySender,
    authorize_delivery,
    first_contact_sender_restriction,
    refuse_restricted_first_contact_to_route,
)
from aweb.event_types import MutationEventType
from aweb.message_events import ChatMessageSentContext
from aweb.messaging.kinds import ContentModeValue, MessageTransport
from aweb.identity_auth_deps import MessagingAuth, auth_dids, participant_dids
from aweb.member_team_key import (
    read_participant_identity_projection,
    recipient_not_found,
)
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_own_route,
    resolved_recipient_delivery_origin,
)
from aweb.messaging.alias_targets import (
    resolve_alias_target,
    team_exists,
)
from aweb.messaging.chat import (
    ensure_session,
    find_session_between,
    resolve_session_actor_did,
    send_in_session,
    validate_session_id,
)
from aweb.messaging.chat_policy import require_agent_chat
from aweb.messaging.contacts import (
    resolve_local_namespace_controller_did,
    upsert_successful_identity_contact,
)
from aweb.messaging.chat_models import CreateSessionRequest, SendMessageRequest
from aweb.messaging.conversations import close_conversation
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.messaging.mail_routing import _require_live_mail_participant
from aweb.messaging.messages import (
    authorize_message_delivery,
    policy_rows_for_participant,
)
from aweb.messaging.participants import (
    messaging_participant_by_alias,
    messaging_participants_by_aliases,
)
from aweb.messaging.recipient_lookup import resolve_agent_by_did, resolve_recipient_by_did
from aweb.messaging.recipient_bindings import signed_recipient_matches
from aweb.messaging.kinds import MessageKind
from aweb.messaging.recipients import (
    RecipientIdentityBinding,
    resolve_address_recipient,
)
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.sender_address import sender_address as _sender_address
from aweb.messaging.sender_address import sender_signature_address
from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
    require_verified_message_signature,
)
from aweb.messaging.verification import require_conversation_not_legacy_bound
from aweb.messaging.refusals import RecipientIdentityBindingError
from aweb.service_errors import (
    ConflictError,
    IdentityBindingCode,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)

logger = logging.getLogger(__name__)


class ChatSessionChanged(Exception):
    """The session two identities share is not the one a reuse-or-create target was resolved with.

    Nothing was stored or closed: the caller resolves again and sends again.
    """


# What a send answers when the sender is not a participant of the session it wrote to.
SENDER_NOT_IN_SESSION = "Session not found"
LOCAL_DID_KEY_RECIPIENT_UNREACHABLE = (
    "Local did:key recipient requires local resolution or learned return route"
)


def _target_delivery_origin(row: Mapping[str, Any] | None) -> str:
    return str((row or {}).get("delivery_origin") or "").strip()


def _require_remote_chat_signature(
    payload: CreateSessionRequest | SendMessageRequest, *, session_id: str | None
) -> None:
    if not payload.signature or not payload.signed_payload:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated chat delivery requires a sender-signed payload",
        )
    if not payload.from_did or not payload.from_did.strip():
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="from_did is required for federated chat delivery",
        )
    if not payload.message_id or not payload.timestamp or not session_id:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="message_id, timestamp, and session_id are required for federated chat delivery",
        )


def _payload_is_encrypted(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return (
        payload.content_mode == ContentMode.ENCRYPTED
        or payload.message_version == 2
        or payload.encrypted_envelope is not None
    )


def _chat_envelope_recipients(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, str | None]]:
    recipients: list[dict[str, str | None]] = []
    for row in rows:
        recipient_did = str(
            row.get("did_key") or row.get("current_did_key") or row.get("did") or ""
        ).strip()
        if not recipient_did:
            recipient_did = _target_did(row)
        stable_id = str(row.get("did_aw") or "").strip()
        address = str(row.get("address") or "").strip()
        if recipient_did.startswith("did:key:") and not stable_id.startswith("did:aw:"):
            # Remote local-only did:key chat participants can have stored
            # address/alias transport hints. Those are routing hints only, not
            # encrypted identity authority, so do not require them in the v2
            # recipient binding.
            stable_id = ""
            address = ""
        recipients.append(
            {
                "did": recipient_did,
                "stable_id": stable_id or None,
                "address": address or None,
            }
        )
    return recipients


def validate_encrypted_chat_payload(
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    auth: MessagingAuth,
    actor_did: str,
    session_id: str,
    recipient_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Verify protected chat fields and recipients, returning metadata for storage."""
    if not _payload_is_encrypted(payload):
        return None
    if payload.content_mode != ContentMode.ENCRYPTED:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="content_mode must be encrypted_v2 for encrypted chat",
        )
    if payload.message_version != 2:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="message_version must be 2 for encrypted chat",
        )
    if not isinstance(payload.encrypted_envelope, dict):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="encrypted_envelope is required for encrypted chat",
        )
    if _chat_payload_body(payload):
        raise encrypted_message_refusal(detail="Encrypted chat payload body must be empty")
    if payload.signature or payload.signed_payload:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Encrypted chat must not include legacy signature fields",
        )
    if payload.message_id is None or payload.timestamp is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="message_id and timestamp are required for encrypted chat",
        )
    envelope = payload.encrypted_envelope or {}
    try:
        validate_e2ee_message_envelope(
            envelope,
            kind=MessageKind.CHAT,
            message_id=payload.message_id,
            conversation_id=session_id,
            sender_did=(auth.did_key or actor_did).strip(),
            sender_stable_id=(auth.did_aw or "").strip() or None,
            recipients=_chat_envelope_recipients(recipient_rows),
        )
    except E2EEEnvelopeError as exc:
        raise encrypted_message_refusal(detail=str(exc)) from exc
    if str(envelope.get("signature") or "").strip() == "":
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="encrypted envelope signature is required",
        )
    return encrypted_message_storage_metadata(envelope)


def _chat_federation_signature(
    payload: CreateSessionRequest | SendMessageRequest,
) -> str:
    if _payload_is_encrypted(payload):
        return str(((payload.encrypted_envelope or {}).get("signature")) or "").strip()
    return str(payload.signature or "").strip()


async def resolve_stored_remote_chat_route(
    *,
    registry_client,
    recipient: Mapping[str, Any],
) -> dict[str, str]:
    """Read the participant's recorded DID, key and delivery route without an address lookup."""
    address = str(recipient.get("address") or "").strip()
    did_aw = str(recipient.get("did_aw") or "").strip()
    participant_did = str(recipient.get("did") or "").strip()
    if not did_aw and participant_did.startswith("did:aw:"):
        did_aw = participant_did
    delivery_origin = _target_delivery_origin(recipient)
    if not did_aw:
        local_did = participant_did if participant_did.startswith("did:key:") else ""
        if local_did and delivery_origin:
            return {
                "address": address or local_did,
                "did_aw": local_did,
                "current_did_key": local_did,
                "delivery_origin": delivery_origin,
            }
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Remote chat recipient has no stored routable identity",
        )
    current_did = str(recipient.get("current_did_key") or recipient.get("did_key") or "").strip()
    if not current_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Remote chat recipient stored route is missing current did:key",
        )
    if not current_did.startswith("did:key:"):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Remote chat recipient stored route current did:key is invalid",
        )
    if not delivery_origin:
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Remote chat recipient has no delivery origin",
        )
    return {
        "address": address or did_aw,
        "did_aw": did_aw,
        "current_did_key": current_did,
        "delivery_origin": delivery_origin,
        # Existing conversation route metadata is sufficient authority to reply.
    }


def _chat_payload_body(payload: CreateSessionRequest | SendMessageRequest) -> str:
    # A session-creating payload carries its text as ``message``; a message in a session as ``body``.
    return payload.message if hasattr(payload, "message") else payload.body


def _chat_payload_leaving(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return payload.leaving


def _chat_payload_hang_on(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return payload.hang_on


async def deliver_federated_chat(
    runtime: MessagingRuntime,
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    db,
    auth: MessagingAuth,
    sender_address: str | None,
    id_chain: dict | None,
    route: Mapping[str, Any],
    session_id: str,
) -> dict[str, Any]:
    """Verify the sender envelope and deliver through the selected federated route."""
    refuse_remote_attachments()
    if not _payload_is_encrypted(payload):
        _require_remote_chat_signature(payload, session_id=session_id)
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated chat delivery requires a sender identity",
        )
    sender_current_did = (
        ((payload.encrypted_envelope or {}).get("from") or {}).get("did")
        if _payload_is_encrypted(payload)
        else payload.from_did
    )
    sender_current_did = str(sender_current_did or "").strip()
    if sender_current_did not in set(auth_dids(auth)):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="from_did must match the authenticated sender",
        )
    federation_signature = _chat_federation_signature(payload)

    try:
        envelope = FederationEnvelope(
            type="chat",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address or None,
            sender_delivery_origin=runtime.public_origin,
            target_address=route["address"],
            target_did_aw=route["did_aw"],
            target_current_did_key=route["current_did_key"],
            target_delivery_origin=route["delivery_origin"],
            body="" if _payload_is_encrypted(payload) else _chat_payload_body(payload),
            message_id=str(payload.message_id),
            timestamp=str(payload.timestamp),
            signed_payload=None if _payload_is_encrypted(payload) else str(payload.signed_payload),
            conversation_id=session_id,
            content_mode=payload.content_mode,
            message_version=payload.message_version,
            encrypted_envelope=payload.encrypted_envelope,
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            sender_leaving=_chat_payload_leaving(payload),
            hang_on=_chat_payload_hang_on(payload),
        )
        verify_federation_envelope_integrity(
            envelope,
            federation_signature,
            expected={
                "type": "chat",
                "target_address": route["address"],
                "target_did_aw": route["did_aw"],
                "target_current_did_key": route["current_did_key"],
                "message_id": payload.message_id,
                "conversation_id": session_id,
            },
        )
        if not _payload_is_encrypted(payload):
            projection = await read_plaintext_projection(
                db,
                claim=PlaintextProjectionClaim.from_envelope(
                    envelope, signature=federation_signature
                ),
            )
            if projection.message is None:
                _parse_signed_timestamp(str(payload.timestamp))
                projection.refuse_conflicting_message_id()
    except FederationEnvelopeError as exc:
        raise DeliveryRefusal(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    local = await local_recipient_for_own_route(db, route, runtime)
    if local is not None:
        if envelope.target_current_did_key != local.get("did_key"):
            raise RecipientIdentityBindingError(IdentityBindingCode.MISMATCH)
        await require_agent_chat(db, [local])
        await authorize_message_delivery(
            db,
            registry_client=runtime.registry_client,
            recipient_agent=local,
            sender_did=sender_routing_did,
            sender_address=sender_address,
            sender_verified_dids=auth_dids(auth),
            stored_route_continuation=True,
        )
        return {"conversation_id": session_id, "message_id": str(payload.message_id)}

    try:
        return await deliver_federated_message(
            delivery_origin=route["delivery_origin"],
            envelope=envelope,
            signature=federation_signature,
            id_chain=id_chain,
            transport=runtime.chat_transport,
            own_origins=runtime.public_origins,
        )
    except FederatedMailDeliveryError as exc:
        raise DeliveryRefusal(status_code=exc.status_code, detail=str(exc)) from exc


def _target_did(row: Mapping[str, Any]) -> str:
    return (row.get("did_aw") or row.get("did_key") or row.get("did") or "").strip()


def _parse_timestamp(value: str, label: str = "timestamp") -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail=f"Invalid {label} format",
        )
    if dt.tzinfo is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail=f"{label} must be timezone-aware",
        )
    return dt.astimezone(timezone.utc)


def _parse_signed_timestamp(value: str) -> datetime:
    dt = _parse_timestamp(value, "timestamp")
    if dt.microsecond != 0:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="timestamp must be second precision",
        )
    try:
        enforce_message_timestamp_skew(dt)
    except FederationEnvelopeError as exc:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail=str(exc) + ". Sign the message again with the current UTC time and retry.",
            code=DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW,
            headers={"X-AWEB-Error-Code": DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW.value},
        ) from exc
    return dt


def _validate_signed_chat_payload(
    *,
    signature: str,
    signed_payload: str | None,
    recipient_rows: Sequence[Mapping[str, Any]] | None = None,
    requested_to_aliases: list[str] | None = None,
    from_alias: str | None = None,
    from_address: str | None = None,
    from_stable_id: str | None = None,
    body: str,
    from_did: str,
    message_id: str,
    timestamp: str,
    wait_seconds: int | None = None,
    reply_to: str | None = None,
    conversation_id: str | None = None,
    sender_leaving: bool = False,
    hang_on: bool = False,
    signer_did_key: str | None = None,
) -> None:
    if signed_payload is None:
        raise signed_chat_payload_refusal(
            detail="signed_payload is required when signature is provided"
        )
    try:
        payload = json.loads(signed_payload)
    except (ValueError, TypeError):
        raise signed_chat_payload_refusal(detail="signed_payload must be valid JSON")
    if not isinstance(payload, dict):
        raise signed_chat_payload_refusal(detail="signed_payload must be a JSON object")
    if payload.get("type") != "chat":
        raise signed_chat_payload_refusal(detail="signed_payload type must be chat")
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
        raise signed_chat_payload_refusal(
            detail="signed_payload from must match the authenticated sender"
        )
    recipient_rows = recipient_rows or []
    allowed_to_values: set[str] = set()
    requested_aliases = sorted(
        value.strip() for value in requested_to_aliases or [] if value.strip()
    )
    has_cross_team_alias = any("~" in value for value in requested_aliases)
    if requested_aliases and len(requested_aliases) == len(recipient_rows):
        allowed_to_values.add(",".join(requested_aliases))
    if recipient_rows:
        candidate_lists = []
        if not has_cross_team_alias:
            candidate_lists.append([(row.get("alias") or "").strip() for row in recipient_rows])
        candidate_lists.extend(
            (
                [(row.get("address") or "").strip() for row in recipient_rows],
                [(row.get("did_aw") or "").strip() for row in recipient_rows],
                [(row.get("did_key") or "").strip() for row in recipient_rows],
                [(row.get("did") or "").strip() for row in recipient_rows],
            )
        )
        for values in candidate_lists:
            cleaned = sorted(value for value in values if value)
            if cleaned:
                allowed_to_values.add(",".join(cleaned))
    if not signed_recipient_matches(
        payload, recipients=recipient_rows, allowed_to=allowed_to_values
    ):
        raise SignedRecipientMismatch(kind=MessageKind.CHAT)
    if payload.get("body") != body:
        raise signed_chat_payload_refusal(detail="signed_payload body must match the chat message")
    if payload.get("from_did") != from_did:
        raise signed_chat_payload_refusal(
            detail="signed_payload from_did must match the authenticated sender"
        )
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise signed_chat_payload_refusal(
            detail="signed_payload from_stable_id must match the authenticated sender"
        )
    if payload.get("message_id") != message_id:
        raise signed_chat_payload_refusal(
            detail="signed_payload message_id must match the chat message"
        )
    if payload.get("timestamp") != timestamp:
        raise signed_chat_payload_refusal(
            detail="signed_payload timestamp must match the chat message"
        )
    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if conversation_id is not None:
        if not signed_conversation_id:
            raise signed_chat_payload_refusal(detail="signed_payload conversation_id is required")
        if signed_conversation_id != conversation_id:
            raise signed_chat_payload_refusal(detail="signed_payload conversation_id must match")
    elif signed_conversation_id:
        raise signed_chat_payload_refusal(detail="signed_payload conversation_id must match")
    if payload.get("wait_seconds") != wait_seconds:
        raise signed_chat_payload_refusal(
            detail="signed_payload wait_seconds must match the chat message"
        )
    if (payload.get("reply_to") or None) != ((reply_to or "").strip() or None):
        raise signed_chat_payload_refusal(
            detail="signed_payload reply_to must match the chat message"
        )
    if bool(payload.get("sender_leaving")) != sender_leaving:
        raise signed_chat_payload_refusal(
            detail="signed_payload sender_leaving must match the chat message"
        )
    if bool(payload.get("hang_on")) != hang_on:
        raise signed_chat_payload_refusal(
            detail="signed_payload hang_on must match the chat message"
        )
    try:
        validate_ed25519_message_signature(signature)
    except MessageSignatureShapeError as exc:
        raise signed_chat_payload_refusal(detail=str(exc)) from exc
    require_verified_message_signature(
        signed_payload=signed_payload,
        signature=signature,
        did_key=signer_did_key or from_did,
    )


async def _record_successful_chat_contacts(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipients: Sequence[Mapping[str, Any]],
    registry_client=None,
) -> None:
    owner = str(owner_did or "").strip()
    sender_team = str(sender_team_id or "").strip()
    if not owner:
        return
    for recipient in recipients:
        address = str(recipient.get("address") or "").strip()
        if "/" not in address:
            continue
        recipient_team = str(recipient.get("team_id") or "").strip()
        if sender_team and recipient_team and sender_team == recipient_team:
            continue
        controller_did = str(recipient.get("authority_controller_did") or "").strip()
        if not controller_did and recipient.get("requires_local_address_authority"):
            controller_did = (
                await resolve_local_namespace_controller_did(
                    registry_client,
                    contact_address=address,
                    contact_did_aw=str(recipient.get("did_aw") or ""),
                    contact_current_did_key=str(recipient.get("did_key") or ""),
                )
                or ""
            )
        await upsert_successful_identity_contact(
            db,
            owner_did=owner,
            contact_address=address,
            contact_did_aw=str(recipient.get("did_aw") or "").strip() or None,
            binding_controller_did=controller_did or None,
            label=str(recipient.get("alias") or address),
        )


def _signed_payload_conversation_id(signed_payload: str | None) -> str:
    if not signed_payload:
        return ""
    try:
        payload = json.loads(signed_payload)
    except (ValueError, TypeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("conversation_id") or "").strip()


def _sender_bound_fresh_session(
    payload: CreateSessionRequest, auth: MessagingAuth, session_id: UUID | None
) -> bool:
    """Authorize replacement before any close; ciphertext needs verified binding."""
    if session_id is None:
        return False
    if not _payload_is_encrypted(payload):
        return (
            payload.signature is not None
            and payload.from_did in auth_dids(auth)
            and _signed_payload_conversation_id(payload.signed_payload) == str(session_id)
        )
    envelope = payload.encrypted_envelope or {}
    sender = envelope.get("from")
    if (
        not isinstance(sender, dict)
        or sender.get("did") not in auth_dids(auth)
        or envelope.get("conversation_id") != str(session_id)
    ):
        return False
    try:
        verify_e2ee_message_envelope_signature(envelope)
    except (E2EEEnvelopeError, ValueError, TypeError):
        return False
    return True


async def _stored_exact_chat_send(
    db,
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    auth: MessagingAuth,
    session_id: UUID | None,
    recipient_rows: Sequence[Mapping[str, Any]],
    actor_dids: list[str],
):
    """Acknowledge one accepted artifact after ordinary request validation.

    Receiver-Wide Replay And Contact Compatibility
    (docs/identity-messaging-contract.md:366-374) exempts exact plaintext retries
    from age only. The shared owner decides sameness; this adapter retains chat
    request binding, current sender key and encrypted expiry checks.
    """
    if payload.message_id is None:
        return None
    lookup = await read_stored_message(
        db,
        claim=StoredMessageClaim(
            kind=MessageKind.CHAT,
            message_id=UUID(payload.message_id),
            sender_did=actor_dids[0],
            conversation_id=session_id,
            chat_participant_dids=frozenset(actor_dids)
            | frozenset(row.get("did") or _target_did(row) for row in recipient_rows),
            # Admitted current keys can identify an original local-key party
            # after that same key is registered globally. No row is rewritten.
            chat_participant_current_keys={
                actor_dids[0]: auth.did_key,
                **{
                    row.get("did") or _target_did(row): str(
                        row.get("did_key") or row.get("current_did_key") or ""
                    )
                    for row in recipient_rows
                },
            },
            chat_controls=ChatReplayControls(
                sender_leaving=payload.leaving,
                hang_on=payload.hang_on,
                reply_to=UUID(payload.reply_to) if payload.reply_to else None,
                timestamp=payload.timestamp,
                signing_did=payload.from_did,
            ),
            artifact=replay_artifact(
                content_mode=payload.content_mode,
                encrypted_envelope=payload.encrypted_envelope,
                signature=payload.signature,
                signed_payload=payload.signed_payload,
            ),
        ),
    )
    if lookup.state is StoredMessageState.MISSING:
        return None
    if lookup.message is None:
        if (
            lookup.state is StoredMessageState.CONFLICT
            and payload.signature is not None
            and not _payload_is_encrypted(payload)
        ):
            if isinstance(payload, SendMessageRequest) and session_id is not None:
                # Continued plaintext replay runs before new-message attestation
                # so retained departed parties can acknowledge their artifact.
                # A different artifact must still verify before the age-only
                # carrier tells its sender that re-signing is appropriate.
                await _validate_continued_chat_attestation(
                    db,
                    auth,
                    payload=payload,
                    actor_did=actor_dids[0],
                    sender_address=_sender_address(auth),
                    session_uuid=session_id,
                    recipient_rows=recipient_rows,
                )
            _parse_signed_timestamp(str(payload.timestamp))
        lookup.refuse_conflicting_message_id()
    row = lookup.message
    if row is None:
        raise RuntimeError("An exact chat replay state must retain its stored message")
    if _payload_is_encrypted(payload):
        validate_encrypted_chat_payload(
            payload,
            auth=auth,
            actor_did=str(row["from_did"]),
            session_id=str(row["session_id"]),
            recipient_rows=recipient_rows,
        )
        _parse_signed_timestamp(str(payload.timestamp))
    else:
        if payload.signature is None or payload.timestamp is None:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="message_id and timestamp are required when signature is provided",
            )
        if payload.from_did not in auth_dids(auth):
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did must match the authenticated sender. Use the authenticated sender identity and sign the message again.",
            )
        _validate_signed_chat_payload(
            signer_did_key=auth.did_key,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient_rows=recipient_rows,
            requested_to_aliases=getattr(payload, "to_aliases", None),
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, _sender_address(auth)),
            from_stable_id=auth.did_aw,
            body=_chat_payload_body(payload),
            from_did=payload.from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            conversation_id=(
                str(row["session_id"])
                if session_id is not None or _signed_payload_conversation_id(payload.signed_payload)
                else None
            ),
            sender_leaving=payload.leaving,
            hang_on=payload.hang_on,
        )
    # Only an admitted, integrity-checked exact retry may consume its bound refs.
    await confirm_accepted_attachment_refs(db, kind=MessageKind.CHAT, message_id=row["message_id"])
    return row


def _actor_did(auth: MessagingAuth) -> str:
    return (auth.did_aw or auth.did_key or "").strip()


def _actor_alias(auth: MessagingAuth, actor_agent: Mapping[str, Any] | None) -> str:
    require_address_evidence(auth)
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or ((actor_agent or {}).get("alias") or "").strip()
        or ((actor_agent or {}).get("address") or "").strip()
        or _actor_did(auth)
    )


async def _resolve_remote_chat_route(
    db,
    *,
    runtime: MessagingRuntime,
    source: str,
    registry_client,
    recipient: Mapping[str, Any],
    requester_did_key: str | None = None,
) -> dict[str, Any]:
    address = str(recipient.get("address") or "").strip()
    if recipient.get("_authority_route_current"):
        route = {
            "address": address,
            "did_aw": str(recipient.get("did_aw") or "").strip(),
            "current_did_key": str(
                recipient.get("current_did_key") or recipient.get("did_key") or ""
            ).strip(),
            "delivery_origin": _target_delivery_origin(recipient),
        }
        if all(route.values()):
            return route
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Remote chat recipient has an incomplete authority route",
        )
    if registry_client is None:
        raise RegistryClientUnavailable()
    try:
        if "/" in address:
            domain, name = address.split("/", 1)
            strict_authority = runtime.federation_authority
            if strict_authority is not None:
                resolution = await strict_authority.resolve_contact(
                    address,
                    source_ip=source,
                )
            elif requester_did_key:
                resolution = await registry_client.resolve_address(
                    domain,
                    name,
                    did_key=requester_did_key,
                )
            else:
                resolution = await registry_client.resolve_address(domain, name)
        else:
            raise DeliveryRefusal(
                status_code=HTTPStatus.FAILED_DEPENDENCY,
                detail="Remote chat recipient has no address route for refresh",
            )
    except (DeliveryRefusal, FederationAuthorityError):
        raise
    except Exception as exc:
        # This SDK boundary preserves known dependency statuses and maps unknown
        # faults to 500. The shared refusal logs only type/status, never input.
        raise registry_dependency_refusal(
            exc, operation="AWID remote chat route resolution"
        ) from exc
    if resolution is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Recipient route not found: {address}",
        )
    target_stable_id = (resolution.did_aw or "").strip()
    target_current_did = (resolution.current_did_key or "").strip()
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_did = str(recipient.get("did") or "").strip()
    if target_stable_id not in {recipient_stable_id, recipient_did}:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Remote chat recipient identity changed",
        )
    resolved_origin = resolved_recipient_delivery_origin(resolution)
    delivery_origin = resolved_origin or _target_delivery_origin(recipient)
    if not delivery_origin:
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Recipient address has no federated delivery origin",
        )
    local = await local_recipient_for_own_route(
        db,
        {
            "did_aw": target_stable_id,
            "current_did_key": target_current_did,
            "address": address,
            "delivery_origin": delivery_origin,
        },
        runtime,
    )
    if local is not None:
        # Do not persist an own-origin remote route. The shared delivery helper
        # applies local chat/policy checks and the caller stores the message.
        return {
            "address": address,
            "did_aw": target_stable_id,
            "current_did_key": target_current_did,
            "delivery_origin": delivery_origin,
        }
    if resolved_origin and (
        resolved_origin != _target_delivery_origin(recipient)
        or target_current_did
        != str(recipient.get("current_did_key") or recipient.get("did_key") or "").strip()
    ):
        await _update_chat_participant_route(
            db,
            conversation_id=str(
                recipient.get("session_id") or recipient.get("conversation_id") or ""
            ),
            did=recipient_did or target_stable_id,
            delivery_origin=delivery_origin,
            current_did_key=target_current_did,
        )
    return {
        "address": address,
        "did_aw": target_stable_id,
        "current_did_key": target_current_did,
        "delivery_origin": delivery_origin,
    }


def _raise_bare_did_chat_first_contact_unsupported() -> NoReturn:
    raise DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail="Bare did:aw first-contact is unsupported; use to_addresses=domain/name or continue an existing session",
    )


async def _update_chat_participant_route(
    db,
    *,
    conversation_id: str,
    did: str,
    delivery_origin: str,
    current_did_key: str,
) -> None:
    if not conversation_id or not did or not delivery_origin or not current_did_key:
        return
    aweb_db = db.get_manager("aweb")
    try:
        conversation_uuid = UUID(conversation_id)
    except (ValueError, TypeError):
        return
    async with aweb_db.transaction() as tx:
        await tx.execute(
            """
            UPDATE {{tables.chat_participants}}
            SET delivery_origin = $3,
                current_did_key = $4
            WHERE session_id = $1 AND did = $2
            """,
            conversation_uuid,
            did,
            delivery_origin,
            current_did_key,
        )
        await tx.execute(
            """
            UPDATE {{tables.conversation_participants}}
            SET delivery_origin = $3,
                current_did_key = $4,
                transport_hint = 'federation:' || $3
            WHERE conversation_id = $1 AND did = $2
            """,
            conversation_uuid,
            did,
            delivery_origin,
            current_did_key,
        )


def _apply_remote_chat_route(
    participant_rows: list[dict[str, Any]],
    recipient: Recipient,
    route: Mapping[str, Any],
) -> Recipient:
    recipient = replace(
        recipient,
        did_aw=route["did_aw"],
        did_key=route["current_did_key"],
        current_did_key=route["current_did_key"],
        delivery_origin=route["delivery_origin"],
    )
    target_refs = _target_did_refs(recipient)
    for participant in participant_rows:
        if str(participant.get("did") or "").strip() not in target_refs:
            continue
        participant.update(
            {
                "did_key": route["current_did_key"],
                "current_did_key": route["current_did_key"],
                "delivery_origin": route["delivery_origin"],
                "transport_hint": "federation:" + route["delivery_origin"],
            }
        )
        break
    return recipient


def _is_stale_delivery_origin_status(status_code: int) -> bool:
    return status_code in {404, 410, 421}


async def resolve_actor_agent(
    db, actor_dids: list[str], *, team_id: str | None = None
) -> Mapping[str, Any] | None:
    """Find a local sender projection for the adapter's authenticated DIDs."""
    for did in actor_dids:
        if not did:
            continue
        actor_agent = await resolve_agent_by_did(db, did, team_id=team_id)
        if actor_agent is not None and actor_agent.get("agent_id") is not None:
            return actor_agent
    return None


def _address_from_alias(value: str | None) -> str:
    text = (value or "").strip()
    return text if "/" in text else ""


def _target_did_refs(row: Mapping[str, Any]) -> set[str]:
    return {
        value
        for value in (
            str(row.get("did_aw") or "").strip(),
            str(row.get("did_key") or "").strip(),
            str(row.get("did") or "").strip(),
        )
        if value
    }


async def _resolve_named_recipients(
    db,
    *,
    runtime: MessagingRuntime,
    source: str,
    auth: MessagingAuth,
    to_aliases: list[str],
    to_dids: list[str],
    to_addresses: list[str],
    signed_payload: str | None = None,
    signature: str | None = None,
    recipient_binding: RecipientIdentityBinding | None = None,
) -> list[Mapping[str, Any]]:
    actor_dids = participant_dids(auth)
    resolved: dict[str, Mapping[str, Any]] = {}
    row: Mapping[str, Any] | None

    if to_aliases:
        if auth.team_id is None:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="to_aliases requires team context",
            )
        target_rows: list[Mapping[str, Any]] = []
        local_aliases: list[str] = []
        for alias in to_aliases:
            if "~" not in alias:
                local_aliases.append(alias)
                continue
            target = resolve_alias_target(auth.team_id, alias, field="to_aliases")
            if not await team_exists(db, target.team_id):
                raise DeliveryRefusal(
                    status_code=HTTPStatus.NOT_FOUND,
                    detail=f"Unknown team: {target.team_id}",
                )
            row = await messaging_participant_by_alias(
                db,
                team_id=target.team_id,
                alias=target.alias,
                selected_team_id=auth.team_id,
                registry_client=runtime.registry_client,
            )
            if row is None:
                raise recipient_not_found(label=alias)
            target_rows.append(row)
        if local_aliases:
            local_rows = await messaging_participants_by_aliases(
                db,
                team_id=auth.team_id,
                aliases=local_aliases,
                selected_team_id=auth.team_id,
                registry_client=runtime.registry_client,
            )
            resolved_aliases = {row["alias"] for row in local_rows}
            missing = [alias for alias in local_aliases if alias not in resolved_aliases]
            if missing:
                raise recipient_not_found(label=", ".join(missing))
            target_rows.extend(local_rows)
        for row in target_rows:
            target_did = (row.get("did_aw") or row.get("did_key") or "").strip()
            if target_did:
                resolved[target_did] = row

    for did in to_dids:
        row = await resolve_recipient_by_did(db, did, sender_team_id=auth.team_id)
        if row is None and did.startswith("did:aw:"):
            _raise_bare_did_chat_first_contact_unsupported()
        if row is None:
            raise recipient_not_found(label=did)
        resolved[did] = identity_recipient(row)

    for address in to_addresses:
        row = await resolve_address_recipient(
            db,
            auth,
            runtime,
            address=address,
            source=source,
            kind=MessageKind.CHAT,
            binding=recipient_binding,
            signed_payload=signed_payload,
            signature=signature,
        )
        resolved[str(row.get("did_aw") or row.get("did_key") or "").strip()] = row

    if not resolved:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Must provide to_aliases, to_dids, or to_addresses. Choose a recipient and retry.",
        )
    if any(_target_did_refs(row) & set(actor_dids) for row in resolved.values()):
        raise DeliveryRefusal(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Self-chat is not supported. Choose another recipient and retry.",
        )

    return list(resolved.values())


async def _preflight_named_chat(
    db,
    *,
    auth: MessagingAuth,
    runtime: MessagingRuntime,
    recipients: list[Mapping[str, Any]],
) -> None:
    await require_agent_chat(db, recipients)
    actor_did = participant_dids(auth)[0]
    sender_address = _sender_address(auth)
    for row in recipients:
        if row.get("external"):
            continue
        try:
            await authorize_message_delivery(
                db,
                registry_client=runtime.registry_client,
                recipient_agent=row,
                sender_did=actor_did,
                sender_address=sender_address,
                sender_verified_dids=auth_dids(auth),
            )
        except DeliveryPolicyRefused:
            raise
        except (ValidationError, NotFoundError, ForbiddenError) as exc:
            raise DeliveryRefusal(status_code=exc.status_code, detail=exc.detail) from exc


async def _resolve_session_recipient_rows(
    db,
    *,
    session_id: UUID,
    actor_dids: list[str],
) -> list[Recipient]:
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT did, agent_id, alias, address, delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
          AND NOT (did = ANY($2::text[]))
        ORDER BY alias, did
        """,
        session_id,
        actor_dids,
    )
    recipient_rows: list[dict[str, Any]] = []
    for row in rows:
        participant = dict(row)
        projection = await read_participant_identity_projection(
            db, participant_did=participant.get("did") or ""
        )
        resolved = (
            identity_recipient(projection, str(participant.get("address") or ""))
            if projection is not None
            else None
        )
        policy_rows = await policy_rows_for_participant(db, participant)
        policy: Mapping[str, Any] = resolved or (policy_rows[0] if policy_rows else {})
        resolved_projection: Mapping[str, Any] = resolved or {}
        participant_did = (participant.get("did") or "").strip()
        participant_alias = (participant.get("alias") or "").strip()
        participant_address = (participant.get("address") or "").strip()
        recipient_rows.append(
            {
                "session_id": str(session_id),
                "did": participant_did,
                "alias": participant_alias,
                "address": (resolved_projection.get("address") or "").strip()
                or participant_address
                or _address_from_alias(participant_alias),
                "delivery_origin": (participant.get("delivery_origin") or "").strip() or None,
                "current_did_key": (participant.get("current_did_key") or "").strip() or None,
                "did_aw": (resolved_projection.get("did_aw") or "").strip()
                or (participant_did if participant_did.startswith("did:aw:") else ""),
                "did_key": (resolved_projection.get("did_key") or "").strip()
                or (participant.get("current_did_key") or "").strip()
                or (participant_did if participant_did.startswith("did:key:") else ""),
                "agent_id": (resolved_projection.get("agent_id") if resolved else None),
                "team_id": (resolved_projection.get("team_id") if resolved else None),
                "inbound_mode": (resolved_projection.get("inbound_mode") if resolved else None),
                "local_resolved": resolved is not None,
                "identity_scope": policy.get("identity_scope"),
                "has_global_claim": policy.get("has_global_claim"),
                "policy_did_aw": policy.get("policy_did_aw"),
                "_policy_recipients": policy_rows,
            }
        )
    return [
        Recipient.from_remote_projection(row)
        if row.get("delivery_origin")
        else Recipient.from_local_projection(row)
        for row in recipient_rows
    ]


class ChatSessionSelection(Enum):
    REQUEST_DEFAULT = auto()
    REUSE_PAIR = auto()


def _require_chat_session_selection(value: ChatSessionSelection) -> None:
    """Keep the internal session branch named before resolution performs reads."""
    if not isinstance(value, ChatSessionSelection):
        raise TypeError("Pass a named ChatSessionSelection value.")


@dataclass(frozen=True, init=False)
class ChatTarget:
    """Whom a chat send reaches: the recipients a new send names, or the session it continues.

    ``session_id`` and ``actor_did``, the sender's participant DID in that
    session, are set for a continuation. ``source`` keys the federation
    authority's rate bucket for the route lookups the send makes.

    ``REUSE_PAIR`` marks a send to one recipient that goes to the session
    the two share, or to one the send creates when they share none;
    ``shared_session_id`` is the session they shared when the target was
    resolved. Such a send never closes a session.
    """

    recipients: tuple[Recipient, ...]
    source: str
    session_id: UUID | None = None
    actor_did: str = ""
    session_selection: ChatSessionSelection = ChatSessionSelection.REQUEST_DEFAULT
    shared_session_id: UUID | None = None

    def __init__(
        self,
        *,
        recipients: Sequence[Mapping[str, Any]],
        source: str,
        session_id: UUID | None = None,
        actor_did: str = "",
        session_selection: ChatSessionSelection = ChatSessionSelection.REQUEST_DEFAULT,
        shared_session_id: UUID | None = None,
    ) -> None:
        _require_chat_session_selection(session_selection)
        object.__setattr__(
            self,
            "recipients",
            tuple(Recipient.from_delivery_projection(row) for row in recipients),
        )
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "actor_did", actor_did)
        object.__setattr__(self, "session_selection", session_selection)
        object.__setattr__(self, "shared_session_id", shared_session_id)


@dataclass(frozen=True)
class SentChat:
    """A chat send as stored: its session and its message row.

    ``message`` is ``send_in_session``'s row, or the stored row of the request
    this one repeats. ``participants`` are the session's participants after a
    send to named recipients stored its message: the stored ``did``, ``alias``
    and ``address`` of each in alias order, or, when ``federated``, the rows as
    the send to another server stored them. They are ``None`` for a send that
    continues a session and for a native request replay. A federated create
    replay retains its response participants, as the original create does.
    """

    session_id: UUID
    message: dict[str, Any]
    participants: list[dict[str, Any]] | None = None
    federated: bool = False


async def resolve_chat_targets(
    db,
    auth: MessagingAuth,
    selector: CreateSessionRequest | str,
    runtime: MessagingRuntime,
    source: str,
    *,
    session_selection: ChatSessionSelection = ChatSessionSelection.REQUEST_DEFAULT,
    recipient_binding: RecipientIdentityBinding | None = None,
) -> ChatTarget:
    """Resolve whom a send reaches, before any of it is stored.

    A ``CreateSessionRequest`` supplies the recipient fields, the session id it
    proposes and any signature the sender made over the recipient binding. A
    session id selects the other participants of that session. ``source`` keys
    the federation authority's rate bucket for this caller.

    With ``REUSE_PAIR`` the request names one recipient and no session:
    the target carries the session the two share, which the sender signs, or
    none, for which the sender proposes an id.
    """
    _require_chat_session_selection(session_selection)
    actor_dids = participant_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Authenticated identity is missing a routing DID",
        )
    if isinstance(selector, str):
        return await _resolve_session_target(
            db, auth, selector, runtime, source, actor_dids=actor_dids
        )

    requested_session_id = UUID(selector.session_id) if selector.session_id is not None else None
    if requested_session_id is not None:
        await validate_session_id(
            db,
            session_id=requested_session_id,
            actor_dids=actor_dids,
        )

    target_rows = await _resolve_named_recipients(
        db,
        runtime=runtime,
        source=source,
        auth=auth,
        to_aliases=selector.to_aliases,
        to_dids=selector.to_dids,
        to_addresses=selector.to_addresses,
        signed_payload=selector.signed_payload,
        signature=selector.signature,
        recipient_binding=recipient_binding,
    )
    new_local_plaintext_send = (
        session_selection is ChatSessionSelection.REQUEST_DEFAULT
        and not selector.to_addresses
        and not any(row.get("external") or _target_delivery_origin(row) for row in target_rows)
        and selector.session_id is None
        and selector.message_id is None
        and selector.signature is None
        and not _payload_is_encrypted(selector)
    )
    if not new_local_plaintext_send:
        await _preflight_named_chat(db, auth=auth, runtime=runtime, recipients=target_rows)
    if session_selection is ChatSessionSelection.REQUEST_DEFAULT:
        return ChatTarget(recipients=target_rows, source=source)
    if len(target_rows) != 1:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="A send that reuses the pair's session names one recipient",
        )
    shared_session_id = await find_session_between(
        db, did_a=actor_did, did_b=_target_did(target_rows[0])
    )
    return ChatTarget(
        recipients=target_rows,
        source=source,
        session_selection=ChatSessionSelection.REUSE_PAIR,
        shared_session_id=shared_session_id,
    )


async def _resolve_session_target(
    db,
    auth: MessagingAuth,
    session_id: str,
    runtime: MessagingRuntime,
    source: str,
    *,
    actor_dids: list[str],
) -> ChatTarget:
    sender_address = _sender_address(auth)

    try:
        session_uuid = UUID(session_id.strip())
    except (ValueError, TypeError):
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="Invalid id format"
        )

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one(
        "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid
    )
    if not sess:
        raise DeliveryRefusal(status_code=HTTPStatus.NOT_FOUND, detail="Session not found")

    actor_did = await resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise DeliveryRefusal(status_code=HTTPStatus.NOT_FOUND, detail="Session not found")
    recipient_rows = await _resolve_session_recipient_rows(
        db, session_id=session_uuid, actor_dids=actor_dids
    )
    # Succession is mail-only. Retired humans get a mail-directed refusal;
    # retired agents retain the existing chat behavior for live group members.
    for row in recipient_rows:
        if not _target_delivery_origin(row):
            await _require_live_mail_participant(db, row, {}, human_only=True)
    for index, row in enumerate(recipient_rows):
        local = await local_recipient_for_own_route(db, row, runtime)
        if local is not None:
            recipient_rows[index] = Recipient.from_delivery_projection(row).with_local_identity(
                local
            )
    await require_agent_chat(db, recipient_rows)
    for row in recipient_rows:
        if (
            str(row.get("did") or "").startswith("did:key:")
            and not _target_delivery_origin(row)
            and not row.get("local_resolved")
        ):
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail=LOCAL_DID_KEY_RECIPIENT_UNREACHABLE,
            )
    for index, row in enumerate(recipient_rows):
        if not _target_delivery_origin(row):
            continue
        route = await resolve_stored_remote_chat_route(
            registry_client=runtime.registry_client,
            recipient=row,
        )
        recipient_rows[index] = replace(
            row,
            did_aw=route["did_aw"],
            did_key=route["current_did_key"],
            current_did_key=route["current_did_key"],
            delivery_origin=route["delivery_origin"],
        )
    await require_conversation_not_legacy_bound(
        db,
        conversation_id=str(session_uuid),
        conversation_type="chat",
    )
    for row in recipient_rows:
        if _target_delivery_origin(row):
            continue
        policy_rows = row.get("_policy_recipients") or []
        if not policy_rows:
            # No live local recipient: keep stored signature context, but
            # there is no local delivery or policy to authorize.
            continue
        for policy_recipient in policy_rows:
            await authorize_message_delivery(
                db,
                registry_client=runtime.registry_client,
                recipient_agent=policy_recipient,
                sender_did=actor_did,
                sender_address=sender_address,
                sender_verified_dids=auth_dids(auth),
                stored_route_continuation=True,
            )
    return ChatTarget(
        recipients=recipient_rows,
        source=source,
        session_id=session_uuid,
        actor_did=actor_did,
    )


async def send_chat(
    db,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: CreateSessionRequest | SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    """Store and deliver the signed or encrypted ``payload`` to a resolved target.

    A target that names recipients takes a ``CreateSessionRequest``; a target
    that continues a session takes a ``SendMessageRequest``.
    """
    observe_message_vocabulary(
        source=MessageInputSource.CHAT_SEND,
        content_mode=payload.content_mode,
    )
    sender = DeliverySender(
        did=(participant_dids(auth) or [""])[0],
        address=_sender_address(auth),
        verified_dids=tuple(auth_dids(auth)),
        first_contact_restriction=await first_contact_sender_restriction(
            db, auth, runtime.first_contact_sender_policy
        )
        if target.session_id is None
        else None,
    )
    if any(row.get("external") or _target_delivery_origin(row) for row in target.recipients):
        refuse_restricted_first_contact_to_route(sender)
        return await _dispatch_chat(db, auth=auth, target=target, payload=payload, runtime=runtime)
    return await _send_local_chat(
        db, auth=auth, sender=sender, target=target, payload=payload, runtime=runtime
    )


async def _dispatch_chat(
    db,
    *,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: CreateSessionRequest | SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    if target.session_id is not None:
        if not isinstance(payload, SendMessageRequest):
            raise TypeError("A continued chat target requires SendMessageRequest")
        return await _send_in_continued_session(db, auth, target, payload, runtime)
    if not isinstance(payload, CreateSessionRequest):
        raise TypeError("A named chat target requires CreateSessionRequest")
    return await _send_to_named_recipients(db, auth, target, payload, runtime)


async def _authorize_local_chat_commit(
    db, *, sender: DeliverySender, target: ChatTarget, runtime: MessagingRuntime
) -> None:
    """Hold native policy rows through the write, using the one delivery rule.

    Global And Local Identities (docs/identity-messaging-contract.md:68-99) applies current
    policy even to a
    stored participant. Raw claim matches provide locks/policy only; a new
    send retains its independently admitted recipient identity and route.
    """
    attempt = (
        DeliveryAttempt.STORED_ROUTE
        if target.session_id is not None
        else DeliveryAttempt.FIRST_CONTACT
    )
    policy_dids = [row.did or row.did_aw or row.did_key or "" for row in target.recipients]
    locked_policy_rows = {}
    for did in dict.fromkeys(policy_dids):
        locked_policy_rows[did] = await policy_rows_for_participant(
            db,
            {"did": did},
            read_lock=MemberReadLock.SHARE,
        )
    if attempt is DeliveryAttempt.FIRST_CONTACT:
        await require_agent_chat(db, target.recipients, locked_policy_rows=locked_policy_rows)
    for recipient, did in zip(target.recipients, policy_dids, strict=True):
        policies = locked_policy_rows[did]
        selected = policies if attempt is DeliveryAttempt.STORED_ROUTE else (recipient,)
        for policy in selected:
            await authorize_delivery(
                db,
                recipient=policy,
                sender=sender,
                attempt=attempt,
                registry_client=runtime.registry_client,
            )
    if attempt is DeliveryAttempt.STORED_ROUTE:
        await require_agent_chat(db, target.recipients, locked_policy_rows=locked_policy_rows)


async def _send_local_chat(
    db,
    *,
    auth: MessagingAuth,
    sender: DeliverySender,
    target: ChatTarget,
    payload: CreateSessionRequest | SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    """Commit native chat under admission locks, then perform external effects."""
    events = HeldMutationEvents()
    held_runtime = replace(runtime, on_mutation=events.record)
    try:
        with agent_wake_scope(runtime.agent_wake_publisher):
            async with db.get_manager("aweb").transaction() as tx:
                send_db = TransactionInfra(db, tx)
                await _authorize_local_chat_commit(
                    send_db, sender=sender, target=target, runtime=runtime
                )
                sent = await _dispatch_chat(
                    send_db,
                    auth=auth,
                    target=target,
                    payload=payload,
                    runtime=held_runtime,
                )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if not is_unique_write_conflict(exc):
            raise
        async with db.get_manager("aweb").transaction() as tx:
            send_db = TransactionInfra(db, tx)
            await _authorize_local_chat_commit(
                send_db, sender=sender, target=target, runtime=runtime
            )
            stored = await _stored_exact_chat_send(
                send_db,
                payload,
                auth=auth,
                session_id=target.session_id,
                recipient_rows=target.recipients,
                actor_dids=participant_dids(auth),
            )
            if stored is None:
                raise
            sent = SentChat(session_id=stored["session_id"], message=dict(stored))
        events = HeldMutationEvents()
    # New named sends alone learn contacts; replay receipts have no participants.
    # Namespace/controller resolution belongs outside the message transaction.
    if target.session_id is None and sent.participants is not None:
        await _record_successful_chat_contacts(
            db,
            owner_did=(auth.did_aw or _actor_did(auth)).strip(),
            sender_team_id=auth.team_id,
            recipients=target.recipients,
            registry_client=runtime.registry_client,
        )
    await events.fire(runtime.on_mutation)
    return sent


@dataclass(frozen=True, kw_only=True)
class _ChatAuthor:
    did: str
    agent_id: str | None
    alias: str
    address: str | None


@dataclass(frozen=True, kw_only=True)
class _ChatSessionPlan:
    requested_session_id: UUID | None
    validation_conversation_id: str | None


async def _send_to_named_recipients(
    db,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: CreateSessionRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    actor_dids = participant_dids(auth)
    actor_did = actor_dids[0]
    actor_agent = None
    if not auth.agent_id or not ((auth.alias or "").strip() or (auth.address or "").strip()):
        actor_agent = await resolve_actor_agent(db, actor_dids, team_id=auth.team_id)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(auth, actor_agent)
    sender_address = _sender_address(auth)

    requested_session_id = UUID(payload.session_id) if payload.session_id is not None else None
    target_rows = list(target.recipients)
    if _payload_is_encrypted(payload):
        await require_non_custodial_recipients(
            db, payload.encrypted_envelope or {}, target_rows, sender=auth
        )

    participant_rows = [
        {
            "did": actor_did,
            "did_key": auth.did_key,
            "agent_id": actor_agent_id,
            "alias": actor_alias,
            "address": sender_address,
        }
    ] + [
        {
            "did": _target_did(row),
            "did_key": (row.get("did_key") or "").strip() or None,
            "current_did_key": (row.get("did_key") or row.get("current_did_key") or "").strip()
            or None,
            "agent_id": str(row["agent_id"]) if row.get("agent_id") else None,
            "alias": (row.get("alias") or "").strip() or _target_did(row),
            "address": (row.get("address") or "").strip() or None,
            "delivery_origin": _target_delivery_origin(row) or None,
        }
        for row in target_rows
    ]

    existing_message = await _stored_exact_chat_send(
        db,
        payload,
        auth=auth,
        session_id=requested_session_id,
        recipient_rows=target_rows,
        actor_dids=actor_dids,
    )
    if existing_message is not None:
        transport = (
            MessageTransport.FEDERATED
            if any(row.get("external") or _target_delivery_origin(row) for row in target_rows)
            else MessageTransport.LOCAL
        )
        return SentChat(
            session_id=existing_message["session_id"],
            message=dict(existing_message),
            participants=participant_rows if transport is MessageTransport.FEDERATED else None,
            federated=transport is MessageTransport.FEDERATED,
        )
    validation_conversation_id = (
        str(requested_session_id) if requested_session_id is not None else None
    )
    signed_requested_session_id = _sender_bound_fresh_session(payload, auth, requested_session_id)
    if target.session_selection is ChatSessionSelection.REUSE_PAIR:
        requested_session_id = await _reuse_or_create_session(
            db,
            team_id=auth.team_id,
            participant_rows=participant_rows,
            created_by=actor_alias,
            shared_session_id=target.shared_session_id,
            proposed_session_id=requested_session_id,
        )
        validation_conversation_id = str(requested_session_id)
    elif len(participant_rows) == 2:
        existing_session_id = await find_session_between(
            db,
            did_a=participant_rows[0]["did"],
            did_b=participant_rows[1]["did"],
        )
        if existing_session_id is not None:
            if (
                signed_requested_session_id
                and requested_session_id is not None
                and requested_session_id != existing_session_id
            ):
                try:
                    await close_conversation(
                        db,
                        conversation_id=existing_session_id,
                        system_close=True,
                    )
                except NotFoundError:
                    logger.debug("chat_session_already_closed")
            elif requested_session_id is not None and requested_session_id != existing_session_id:
                raise DeliveryRefusal(
                    status_code=HTTPStatus.CONFLICT,
                    detail="Existing active chat session found; continue that session instead",
                )
            else:
                requested_session_id = existing_session_id
                validation_conversation_id = str(existing_session_id)
                if payload.signature is not None and _signed_payload_conversation_id(
                    payload.signed_payload
                ) != str(existing_session_id):
                    raise DeliveryRefusal(
                        status_code=HTTPStatus.CONFLICT,
                        detail="Signed chat message must bind the existing session_id",
                    )
    external_targets = [
        row for row in target_rows if row.get("external") or _target_delivery_origin(row)
    ]
    if external_targets:
        return await _send_to_remote_named_chat(
            db,
            auth=auth,
            target=target,
            payload=payload,
            runtime=runtime,
            author=_ChatAuthor(
                did=actor_did,
                agent_id=actor_agent_id,
                alias=actor_alias,
                address=sender_address,
            ),
            participant_rows=participant_rows,
            plan=_ChatSessionPlan(
                requested_session_id=requested_session_id,
                validation_conversation_id=validation_conversation_id,
            ),
            external_targets=external_targets,
        )
    return await _send_to_local_named_chat(
        db,
        auth=auth,
        target=target,
        payload=payload,
        runtime=runtime,
        author=_ChatAuthor(
            did=actor_did,
            agent_id=actor_agent_id,
            alias=actor_alias,
            address=sender_address,
        ),
        participant_rows=participant_rows,
        plan=_ChatSessionPlan(
            requested_session_id=requested_session_id,
            validation_conversation_id=validation_conversation_id,
        ),
    )


async def _send_to_remote_named_chat(
    db,
    *,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: CreateSessionRequest,
    runtime: MessagingRuntime,
    author: _ChatAuthor,
    participant_rows: list[dict[str, Any]],
    plan: _ChatSessionPlan,
    external_targets: list[Recipient],
) -> SentChat:
    """Deliver one resolved remote target and retain the accepted chat locally."""
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    actor_did = author.did
    actor_agent_id = author.agent_id
    sender_address = author.address
    requested_session_id = plan.requested_session_id
    target_rows = list(target.recipients)
    if len(target_rows) != 1 or len(external_targets) != 1:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated chat currently requires exactly one remote address recipient",
        )
    if not _target_delivery_origin(external_targets[0]):
        raise DeliveryRefusal(
            status_code=HTTPStatus.FAILED_DEPENDENCY,
            detail="Recipient address has no federated delivery origin",
        )
    if requested_session_id is None:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Federated chat delivery requires session_id",
        )
    encrypted_metadata = validate_encrypted_chat_payload(
        payload,
        auth=auth,
        actor_did=actor_did,
        session_id=str(requested_session_id),
        recipient_rows=target_rows,
    )
    if encrypted_metadata is None:
        _require_remote_chat_signature(payload, session_id=str(requested_session_id))
        from_did = str(payload.from_did or "").strip()
        if from_did not in set(auth_dids(auth)):
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="from_did must match the authenticated sender",
            )
        _validate_signed_chat_payload(
            signer_did_key=auth.did_key,
            signature=str(payload.signature),
            signed_payload=payload.signed_payload,
            recipient_rows=target_rows,
            requested_to_aliases=payload.to_aliases,
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, sender_address),
            from_stable_id=auth.did_aw,
            body=payload.message,
            from_did=from_did,
            message_id=str(payload.message_id),
            timestamp=str(payload.timestamp),
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            conversation_id=str(requested_session_id),
            sender_leaving=payload.leaving,
            hang_on=payload.hang_on,
        )
    # payload.timestamp is sender attestation retained in signed_payload or
    # encrypted_envelope; send_in_session assigns independent server receipt
    # time for ordering, so the two values may disagree.
    _parse_signed_timestamp(str(payload.timestamp))
    pre_message_id = uuid_mod.UUID(str(payload.message_id))
    route = await _resolve_remote_chat_route(
        db,
        runtime=runtime,
        source=target.source,
        registry_client=registry_client,
        recipient=external_targets[0],
        requester_did_key=auth.did_key,
    )
    original = external_targets[0]
    routed = _apply_remote_chat_route(participant_rows, original, route)
    target_rows = [routed if row is original else row for row in target_rows]
    external_targets[0] = routed

    remote = await deliver_federated_chat(
        runtime,
        payload,
        db=db,
        auth=auth,
        sender_address=sender_address,
        id_chain=id_chain,
        route=route,
        session_id=str(requested_session_id),
    )
    remote_session_id = str(remote.get("session_id") or remote.get("conversation_id") or "").strip()
    remote_message_id = str(remote.get("message_id") or "").strip()
    if remote_session_id != str(requested_session_id):
        raise DeliveryRefusal(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Federated chat response session_id mismatch",
        )
    if remote_message_id != str(pre_message_id):
        raise DeliveryRefusal(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Federated chat response message_id mismatch",
        )

    try:
        session_id, msg_row = await _store_remote_chat_create(
            db,
            auth=auth,
            runtime=runtime,
            payload=payload,
            author=author,
            participant_rows=participant_rows,
            session_id=requested_session_id,
            encrypted_metadata=encrypted_metadata,
            message_id=pre_message_id,
        )
    except (ConflictError, QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if not isinstance(exc, ConflictError) and not is_unique_write_conflict(exc):
            raise
        # Session/message projection commits as one unit. A unique loser sees
        # the winner's committed artifact before returning its stored answer.
        stored = await _stored_exact_chat_send(
            db,
            payload,
            auth=auth,
            session_id=requested_session_id,
            recipient_rows=target_rows,
            actor_dids=participant_dids(auth),
        )
        if stored is None:
            raise
        return SentChat(
            session_id=stored["session_id"],
            message=dict(stored),
            participants=participant_rows,
            federated=True,
        )
    if msg_row is None:
        raise DeliveryRefusal(status_code=HTTPStatus.NOT_FOUND, detail=SENDER_NOT_IN_SESSION)
    await _record_successful_chat_contacts(
        db,
        owner_did=(auth.did_aw or actor_did).strip(),
        sender_team_id=auth.team_id,
        recipients=[{**external_targets[0], **route}],
        registry_client=registry_client,
    )
    await _fire_chat_message_sent(
        runtime,
        auth,
        session_id=session_id,
        message_id=msg_row["message_id"],
        from_agent_id=actor_agent_id,
        from_did=actor_did,
        to_aliases=[row["alias"] for row in target_rows],
        preview="" if encrypted_metadata is not None else payload.message[:80],
        content_mode=payload.content_mode,
        federated=True,
    )
    return SentChat(
        session_id=session_id,
        message=msg_row,
        participants=participant_rows,
        federated=True,
    )


async def _store_remote_chat_create(
    db,
    *,
    auth: MessagingAuth,
    runtime: MessagingRuntime,
    payload: CreateSessionRequest,
    author: _ChatAuthor,
    participant_rows: list[dict[str, Any]],
    session_id: UUID,
    encrypted_metadata: dict | None,
    message_id: UUID,
) -> tuple[UUID, dict | None]:
    """Persist the accepted remote create's local session/message projection."""
    requested_session_id = session_id
    pre_message_id = message_id
    id_chain = auth.id_chain
    actor_did = author.did
    actor_agent_id = author.agent_id
    actor_alias = author.alias
    sender_address = author.address
    with agent_wake_scope(runtime.agent_wake_publisher):
        async with db.get_manager("aweb").transaction() as tx:
            send_db = TransactionInfra(db, tx)
            session_id = await ensure_session(
                send_db,
                team_id=auth.team_id,
                participant_rows=participant_rows,
                created_by=actor_alias,
                session_id=requested_session_id,
            )
            msg_row = await send_in_session(
                send_db,
                id_chain=id_chain,
                session_id=session_id,
                sender_did=actor_did,
                sender_agent_id=actor_agent_id,
                sender_address=sender_address,
                body=payload.message,
                reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
                leaving=payload.leaving,
                hang_on=payload.hang_on,
                signature=payload.signature,
                signed_payload=payload.signed_payload,
                content_mode=payload.content_mode,
                message_version=payload.message_version,
                encrypted_envelope=payload.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                message_id=pre_message_id,
            )
    return session_id, msg_row


async def _send_to_local_named_chat(
    db,
    *,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: CreateSessionRequest,
    runtime: MessagingRuntime,
    author: _ChatAuthor,
    participant_rows: list[dict[str, Any]],
    plan: _ChatSessionPlan,
) -> SentChat:
    """Persist and complete a named native chat after remote routing is excluded."""
    id_chain = auth.id_chain
    actor_did = author.did
    actor_agent_id = author.agent_id
    actor_alias = author.alias
    sender_address = author.address
    target_rows = list(target.recipients)
    requested_session_id = plan.requested_session_id
    validation_conversation_id = plan.validation_conversation_id
    session_id = await ensure_session(
        db,
        team_id=auth.team_id,
        participant_rows=participant_rows,
        created_by=actor_alias,
        session_id=requested_session_id,
    )
    await require_conversation_not_legacy_bound(
        db,
        conversation_id=str(session_id),
        conversation_type="chat",
    )

    aweb_db = db.get_manager("aweb")
    pre_message_id = uuid_mod.uuid4()

    encrypted_metadata = validate_encrypted_chat_payload(
        payload,
        auth=auth,
        actor_did=actor_did,
        session_id=str(session_id),
        recipient_rows=target_rows,
    )

    if encrypted_metadata is not None:
        # payload.timestamp is sender attestation retained in encrypted_envelope;
        # send_in_session assigns independent server receipt time for ordering,
        # so the two values may disagree.
        _parse_signed_timestamp(str(payload.timestamp))
        pre_message_id = uuid_mod.UUID(str(payload.message_id))
    elif payload.signature is not None:
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
        _validate_signed_chat_payload(
            signer_did_key=auth.did_key,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient_rows=target_rows,
            requested_to_aliases=payload.to_aliases,
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, sender_address),
            from_stable_id=auth.did_aw,
            body=payload.message,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            conversation_id=validation_conversation_id,
            sender_leaving=payload.leaving,
            hang_on=payload.hang_on,
        )
        # payload.timestamp is sender attestation retained in signed_payload;
        # send_in_session assigns independent server receipt time for ordering,
        # so the two values may disagree.
        _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    if payload.reply_to is not None:
        reply_target = await aweb_db.fetch_one(
            """
            SELECT 1 FROM {{tables.chat_messages}}
            WHERE session_id = $1 AND message_id = $2
            """,
            session_id,
            uuid_mod.UUID(payload.reply_to),
        )
        if reply_target is None:
            raise DeliveryRefusal(
                status_code=HTTPStatus.NOT_FOUND, detail="Replied-to message not found"
            )

    with agent_wake_scope(runtime.agent_wake_publisher):
        msg_row = await send_in_session(
            db,
            id_chain=id_chain,
            session_id=session_id,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            sender_address=sender_address,
            body=payload.message,
            reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
            leaving=payload.leaving,
            hang_on=payload.hang_on,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            content_mode=payload.content_mode,
            message_version=payload.message_version,
            encrypted_envelope=payload.encrypted_envelope,
            encrypted_metadata=encrypted_metadata,
            message_id=pre_message_id,
        )
    if msg_row is None:
        raise DeliveryRefusal(status_code=HTTPStatus.NOT_FOUND, detail=SENDER_NOT_IN_SESSION)

    await _record_wait(
        db,
        payload,
        session_id=session_id,
        message=msg_row,
        actor_agent_id=actor_agent_id,
    )

    participants = await aweb_db.fetch_all(
        """
        SELECT did, alias, address
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        ORDER BY alias ASC
        """,
        session_id,
    )
    await _fire_chat_message_sent(
        runtime,
        auth,
        session_id=session_id,
        message_id=msg_row["message_id"],
        from_agent_id=actor_agent_id,
        from_did=actor_did,
        to_aliases=[row["alias"] for row in participants if row["did"] != actor_did],
        preview="" if encrypted_metadata is not None else payload.message[:80],
        content_mode=payload.content_mode,
    )

    return SentChat(session_id=session_id, message=msg_row, participants=participants)


async def _validate_continued_chat_attestation(
    db,
    auth: MessagingAuth,
    *,
    payload: SendMessageRequest,
    actor_did: str,
    sender_address: str | None,
    session_uuid: UUID,
    recipient_rows: Sequence[Mapping[str, Any]],
) -> tuple[UUID, dict | None]:
    """Validate the continued message's signature or encrypted sender artifact."""
    pre_message_id = uuid_mod.uuid4()
    if _payload_is_encrypted(payload):
        await require_non_custodial_recipients(
            db, payload.encrypted_envelope or {}, recipient_rows, sender=auth
        )
    encrypted_metadata = validate_encrypted_chat_payload(
        payload,
        auth=auth,
        actor_did=actor_did,
        session_id=str(session_uuid),
        recipient_rows=recipient_rows,
    )
    if encrypted_metadata is not None:
        # payload.timestamp is sender attestation retained in encrypted_envelope;
        # send_in_session assigns independent server receipt time for ordering,
        # so the two values may disagree.
        _parse_signed_timestamp(str(payload.timestamp))
        pre_message_id = uuid_mod.UUID(str(payload.message_id))
    elif payload.signature is not None:
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
        _validate_signed_chat_payload(
            signer_did_key=auth.did_key,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient_rows=recipient_rows,
            from_alias=auth.alias,
            from_address=sender_signature_address(auth, sender_address),
            from_stable_id=auth.did_aw,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            conversation_id=str(session_uuid),
            sender_leaving=payload.leaving,
            hang_on=payload.hang_on,
        )
        # payload.timestamp is sender attestation retained in signed_payload;
        # send_in_session assigns independent server receipt time for ordering,
        # so the two values may disagree.
        pre_message_id = uuid_mod.UUID(payload.message_id)

    return pre_message_id, encrypted_metadata


async def _send_in_continued_session(
    db,
    auth: MessagingAuth,
    target: ChatTarget,
    payload: SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    actor_dids = participant_dids(auth)
    actor_agent = await resolve_actor_agent(db, actor_dids, team_id=auth.team_id)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    sender_address = _sender_address(auth)
    session_uuid = target.session_id
    if session_uuid is None:
        raise ValueError("A continued chat target requires a session ID")
    actor_did = target.actor_did
    recipient_rows = target.recipients

    encrypted = _payload_is_encrypted(payload)
    if encrypted:
        pre_message_id, encrypted_metadata = await _validate_continued_chat_attestation(
            db,
            auth,
            payload=payload,
            actor_did=actor_did,
            sender_address=sender_address,
            session_uuid=session_uuid,
            recipient_rows=recipient_rows,
        )

    existing_message = await _stored_exact_chat_send(
        db,
        payload,
        auth=auth,
        session_id=session_uuid,
        recipient_rows=recipient_rows,
        actor_dids=actor_dids,
    )
    if existing_message is not None:
        return SentChat(session_id=session_uuid, message=dict(existing_message))
    if not encrypted:
        pre_message_id, encrypted_metadata = await _validate_continued_chat_attestation(
            db,
            auth,
            payload=payload,
            actor_did=actor_did,
            sender_address=sender_address,
            session_uuid=session_uuid,
            recipient_rows=recipient_rows,
        )

    remote_recipients: list[Mapping[str, Any]] = [
        row for row in recipient_rows if _target_delivery_origin(row)
    ]
    if (
        not remote_recipients
        and payload.signature is not None
        and not _payload_is_encrypted(payload)
    ):
        _parse_signed_timestamp(str(payload.timestamp))
    if remote_recipients:
        if len(recipient_rows) != 1 or len(remote_recipients) != 1:
            raise DeliveryRefusal(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="Federated chat continuation requires exactly one remote recipient",
            )
        route = remote_recipients[0]
        try:
            remote = await deliver_federated_chat(
                runtime,
                payload,
                db=db,
                auth=auth,
                sender_address=sender_address,
                id_chain=id_chain,
                route=route,
                session_id=str(session_uuid),
            )
        except DeliveryRefusal as exc:
            if not _is_stale_delivery_origin_status(exc.status_code):
                raise
            refreshed_route = await _resolve_remote_chat_route(
                db,
                runtime=runtime,
                source=target.source,
                registry_client=registry_client,
                recipient=route,
                requester_did_key=auth.did_key,
            )
            if refreshed_route["delivery_origin"] == _target_delivery_origin(route):
                raise exc
            remote_recipients[0] = {
                **route,
                "did_aw": refreshed_route["did_aw"],
                "did_key": refreshed_route["current_did_key"],
                "current_did_key": refreshed_route["current_did_key"],
                "delivery_origin": refreshed_route["delivery_origin"],
            }
            remote = await deliver_federated_chat(
                runtime,
                payload,
                db=db,
                auth=auth,
                sender_address=sender_address,
                id_chain=id_chain,
                route=remote_recipients[0],
                session_id=str(session_uuid),
            )
        remote_session_id = str(
            remote.get("session_id") or remote.get("conversation_id") or ""
        ).strip()
        remote_message_id = str(remote.get("message_id") or "").strip()
        if remote_session_id != str(session_uuid):
            raise DeliveryRefusal(
                status_code=HTTPStatus.BAD_GATEWAY,
                detail="Federated chat response session_id mismatch",
            )
        if remote_message_id != str(pre_message_id):
            raise DeliveryRefusal(
                status_code=HTTPStatus.BAD_GATEWAY,
                detail="Federated chat response message_id mismatch",
            )

    try:
        with agent_wake_scope(runtime.agent_wake_publisher):
            msg_row = await send_in_session(
                db,
                id_chain=id_chain,
                session_id=session_uuid,
                sender_did=actor_did,
                sender_agent_id=actor_agent_id,
                sender_address=sender_address,
                body=payload.body,
                reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
                leaving=payload.leaving,
                hang_on=payload.hang_on,
                signature=payload.signature,
                signed_payload=payload.signed_payload,
                content_mode=payload.content_mode,
                message_version=payload.message_version,
                encrypted_envelope=payload.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                message_id=pre_message_id,
            )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if not remote_recipients or not is_unique_write_conflict(exc):
            raise
        stored = await _stored_exact_chat_send(
            db,
            payload,
            auth=auth,
            session_id=session_uuid,
            recipient_rows=recipient_rows,
            actor_dids=actor_dids,
        )
        if stored is None:
            raise
        return SentChat(session_id=session_uuid, message=dict(stored))
    if msg_row is None:
        raise DeliveryRefusal(status_code=HTTPStatus.NOT_FOUND, detail=SENDER_NOT_IN_SESSION)
    if remote_recipients:
        await _record_successful_chat_contacts(
            db,
            owner_did=(auth.did_aw or actor_did).strip(),
            sender_team_id=auth.team_id,
            recipients=remote_recipients,
            registry_client=registry_client,
        )
    else:
        await _record_wait(
            db,
            payload,
            session_id=session_uuid,
            message=msg_row,
            actor_agent_id=actor_agent_id,
        )
    await _fire_chat_message_sent(
        runtime,
        auth,
        session_id=session_uuid,
        message_id=msg_row["message_id"],
        from_agent_id=actor_agent_id,
        from_did=actor_did,
        to_aliases=[row["alias"] for row in recipient_rows],
        preview="" if encrypted_metadata is not None else payload.body[:80],
        content_mode=payload.content_mode,
        federated=bool(remote_recipients),
    )

    return SentChat(session_id=session_uuid, message=msg_row)


async def _reuse_or_create_session(
    db,
    *,
    team_id: str | None,
    participant_rows: list[dict[str, Any]],
    created_by: str,
    shared_session_id: UUID | None,
    proposed_session_id: UUID | None,
) -> UUID:
    """The session a reuse-or-create send goes to, chosen under the pair's lock.

    The pair's session is looked up again under a lock that every such send
    for the pair takes, and a session is created only inside it: two sends
    that both found none create one session between them. The send that finds
    the pair's session to be another than the one its target was resolved
    with, or than the one its message names, raises ``ChatSessionChanged``.
    """
    did_a, did_b = participant_rows[0]["did"], participant_rows[1]["did"]
    async with db.get_manager("aweb").transaction() as tx:
        await tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            "chat-pair:" + "\n".join(sorted((did_a, did_b))),
        )
        locked_db = TransactionInfra(db, tx)
        current = await find_session_between(locked_db, did_a=did_a, did_b=did_b)
        if (
            current != shared_session_id
            or proposed_session_id is None
            or (current is not None and current != proposed_session_id)
        ):
            raise ChatSessionChanged()
        if current is not None:
            return current
        return await ensure_session(
            locked_db,
            team_id=team_id,
            participant_rows=participant_rows,
            created_by=created_by,
            session_id=proposed_session_id,
        )


async def _record_wait(
    db,
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    session_id: UUID,
    message: dict[str, Any],
    actor_agent_id: str | None,
) -> None:
    """Record on the session the wait its sender starts with this message."""
    if payload.wait_seconds is None:
        return
    await db.get_manager("aweb").execute(
        """
        UPDATE {{tables.chat_sessions}}
        SET wait_seconds = $2,
            wait_started_at = $3,
            wait_started_by = $4
        WHERE session_id = $1
        """,
        session_id,
        int(payload.wait_seconds),
        message["created_at"],
        UUID(actor_agent_id) if actor_agent_id else None,
    )


async def _fire_chat_message_sent(
    runtime: MessagingRuntime,
    auth: MessagingAuth,
    *,
    session_id: UUID,
    message_id: UUID,
    from_agent_id: str | None,
    from_did: str,
    to_aliases: list[str],
    preview: str,
    content_mode: ContentModeValue | None,
    federated: bool = False,
) -> None:
    context = ChatMessageSentContext(
        team_id=auth.team_id,
        session_id=str(session_id),
        message_id=str(message_id),
        from_agent_id=from_agent_id,
        from_alias=auth.alias or "",
        from_did=from_did,
        from_did_aw=(auth.did_aw or "").strip() or None,
        to_aliases=tuple(to_aliases),
        preview=preview,
        content_mode=content_mode,
        transport=MessageTransport.FEDERATED if federated else MessageTransport.LOCAL,
    )
    await fire_mutation_callback(
        runtime.on_mutation,
        MutationEventType.CHAT_MESSAGE_SENT.value,
        context.to_context(),
    )
