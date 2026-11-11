"""Chat recipient resolution and sends, for every adapter."""

from __future__ import annotations

import json
import logging
import uuid as uuid_mod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

import asyncpg.exceptions
from fastapi import HTTPException

from awid.federation_errors import FederationAuthorityError
from aweb.agent_wake import agent_wake_scope
from aweb.attachment_service import attachment_retry, refuse_remote_attachments
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)
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
    verify_federation_envelope,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.hooks import fire_mutation_callback
from aweb.identity_auth_deps import MessagingAuth, auth_dids, participant_dids
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    local_recipient_for_own_route,
    local_recipient_visible_to_auth,
    namespace_uses_home_registry,
    refuse_same_origin_nonresident,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    get_agent_by_namespace_alias,
    namespace_exists,
    resolve_alias_target,
    team_exists,
)
from aweb.messaging.chat import (
    ensure_session,
    find_session_between,
    resolve_agent_by_did,
    resolve_session_actor_did,
    send_in_session,
    validate_session_id,
)
from aweb.messaging.chat_policy import require_agent_chat
from aweb.messaging.contacts import (
    resolve_local_namespace_controller_did,
    upsert_successful_identity_contact,
)
from aweb.messaging.conversations import close_conversation
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.messaging.mail_routing import _require_live_mail_participant
from aweb.messaging.messages import authorize_message_delivery, policy_rows_for_participant
from aweb.messaging.participants import messaging_participant_by_alias, messaging_participants_by_aliases
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.sender_address import sender_address as _sender_address
from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
)
from aweb.messaging.verification import require_conversation_not_legacy_bound
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError

if TYPE_CHECKING:
    from aweb.routes.chat import CreateSessionRequest, SendMessageRequest

logger = logging.getLogger(__name__)

# What a send answers when the sender is not a participant of the session it wrote to.
SENDER_NOT_IN_SESSION = "Failed to send message"
LOCAL_DID_KEY_RECIPIENT_UNREACHABLE = "Local did:key recipient requires local resolution or learned return route"


def _target_delivery_origin(row: dict[str, Any] | None) -> str:
    return str((row or {}).get("delivery_origin") or "").strip()


def _require_remote_chat_signature(payload: CreateSessionRequest | SendMessageRequest, *, session_id: str | None) -> None:
    if not payload.signature or not payload.signed_payload:
        raise HTTPException(
            status_code=422,
            detail="Federated chat delivery requires a sender-signed payload",
        )
    if not payload.from_did or not payload.from_did.strip():
        raise HTTPException(
            status_code=422,
            detail="from_did is required for federated chat delivery",
        )
    if not payload.message_id or not payload.timestamp or not session_id:
        raise HTTPException(
            status_code=422,
            detail="message_id, timestamp, and session_id are required for federated chat delivery",
        )


def _payload_is_encrypted(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return (
        getattr(payload, "content_mode", "legacy_plaintext_v1") == "encrypted_v2"
        or getattr(payload, "message_version", 1) == 2
        or getattr(payload, "encrypted_envelope", None) is not None
    )


def _chat_envelope_recipients(rows: list[dict[str, Any]]) -> list[dict[str, str | None]]:
    recipients: list[dict[str, str | None]] = []
    for row in rows:
        recipient_did = str(row.get("did_key") or row.get("current_did_key") or row.get("did") or "").strip()
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
    recipient_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not _payload_is_encrypted(payload):
        return None
    if payload.content_mode != "encrypted_v2":
        raise HTTPException(status_code=422, detail="content_mode must be encrypted_v2 for encrypted chat")
    if payload.message_version != 2:
        raise HTTPException(status_code=422, detail="message_version must be 2 for encrypted chat")
    if not isinstance(payload.encrypted_envelope, dict):
        raise HTTPException(status_code=422, detail="encrypted_envelope is required for encrypted chat")
    if _chat_payload_body(payload):
        raise HTTPException(status_code=422, detail="Encrypted chat payload body must be empty")
    if payload.signature or payload.signed_payload:
        raise HTTPException(status_code=422, detail="Encrypted chat must not include legacy signature fields")
    if payload.message_id is None or payload.timestamp is None:
        raise HTTPException(status_code=422, detail="message_id and timestamp are required for encrypted chat")
    envelope = payload.encrypted_envelope or {}
    try:
        validate_e2ee_message_envelope(
            envelope,
            kind="chat",
            message_id=payload.message_id,
            conversation_id=session_id,
            sender_did=(auth.did_key or actor_did).strip(),
            sender_stable_id=(auth.did_aw or "").strip() or None,
            recipients=_chat_envelope_recipients(recipient_rows),
        )
    except E2EEEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if str(envelope.get("signature") or "").strip() == "":
        raise HTTPException(status_code=422, detail="encrypted envelope signature is required")
    return encrypted_message_storage_metadata(envelope)


def _chat_federation_signature(payload: CreateSessionRequest | SendMessageRequest) -> str:
    if _payload_is_encrypted(payload):
        return str(((payload.encrypted_envelope or {}).get("signature")) or "").strip()
    return str(payload.signature or "").strip()


async def resolve_stored_remote_chat_route(
    *,
    registry_client,
    recipient: dict[str, Any],
) -> dict[str, str | bool]:
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
        raise HTTPException(status_code=424, detail="Remote chat recipient has no stored routable identity")
    current_did = str(recipient.get("current_did_key") or recipient.get("did_key") or "").strip()
    if not current_did:
        raise HTTPException(status_code=424, detail="Remote chat recipient stored route is missing current did:key")
    if not current_did.startswith("did:key:"):
        raise HTTPException(status_code=422, detail="Remote chat recipient stored route current did:key is invalid")
    if not delivery_origin:
        raise HTTPException(status_code=424, detail="Remote chat recipient has no delivery origin")
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
    # Only a message in a session can ask its recipients to hang on.
    return getattr(payload, "hang_on", False)


async def deliver_federated_chat(
    runtime: MessagingRuntime,
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    db,
    auth: MessagingAuth,
    sender_address: str | None,
    id_chain: dict | None,
    route: dict[str, Any],
    session_id: str,
) -> dict[str, Any]:
    refuse_remote_attachments()
    if not _payload_is_encrypted(payload):
        _require_remote_chat_signature(payload, session_id=session_id)
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise HTTPException(status_code=422, detail="Federated chat delivery requires a sender identity")
    sender_current_did = (
        ((payload.encrypted_envelope or {}).get("from") or {}).get("did")
        if _payload_is_encrypted(payload)
        else payload.from_did
    )
    sender_current_did = str(sender_current_did or "").strip()
    if sender_current_did not in set(auth_dids(auth)):
        raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
    federation_signature = _chat_federation_signature(payload)

    try:
        envelope = FederationEnvelope(
            type="chat",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address,
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
            content_mode=getattr(payload, "content_mode", None),
            message_version=getattr(payload, "message_version", None),
            encrypted_envelope=getattr(payload, "encrypted_envelope", None),
            wait_seconds=getattr(payload, "wait_seconds", None),
            reply_to=payload.reply_to,
            sender_leaving=_chat_payload_leaving(payload),
            hang_on=_chat_payload_hang_on(payload),
        )
        verify_federation_envelope(
            envelope,
            federation_signature,
            expected={
                "type": "chat",
                "target_address": route["address"],
                "target_did_aw": route["did_aw"],
                "target_current_did_key": route["current_did_key"],
                "target_delivery_origin": envelope.target_delivery_origin,
                "message_id": payload.message_id,
                "conversation_id": session_id,
            },
        )
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    local = await local_recipient_for_own_route(db, route, runtime)
    if local is not None:
        if envelope.target_current_did_key != local.get("did_key"):
            raise HTTPException(status_code=403, detail="identity_binding_mismatch")
        await require_agent_chat(db, [local], registry_client=runtime.registry_client)
        try:
            await authorize_message_delivery(
                db, recipient_agent=local, sender_did=sender_routing_did,
                sender_address=sender_address, sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id, sender_verified_dids=auth_dids(auth),
                stored_route_continuation=True,
            )
        except (ValidationError, NotFoundError, ForbiddenError) as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
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
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def _target_did(row: dict[str, Any]) -> str:
    return (row.get("did_aw") or row.get("did_key") or row.get("did") or "").strip()


def _parse_timestamp(value: str, label: str = "timestamp") -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid {label} format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail=f"{label} must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _parse_signed_timestamp(value: str) -> datetime:
    dt = _parse_timestamp(value, "timestamp")
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    try:
        enforce_message_timestamp_skew(dt)
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return dt


def _validate_signed_chat_payload(
    *,
    signature: str,
    signed_payload: str | None,
    recipient_rows: list[dict[str, Any]] | None = None,
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
) -> None:
    if signed_payload is None:
        raise HTTPException(status_code=422, detail="signed_payload is required when signature is provided")
    try:
        payload = json.loads(signed_payload)
    except Exception:
        raise HTTPException(status_code=422, detail="signed_payload must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="signed_payload must be a JSON object")
    if payload.get("type") != "chat":
        raise HTTPException(status_code=422, detail="signed_payload type must be chat")
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
        raise HTTPException(status_code=422, detail="signed_payload from must match the authenticated sender")
    recipient_rows = recipient_rows or []
    allowed_to_values: set[str] = set()
    requested_aliases = sorted(value.strip() for value in requested_to_aliases or [] if value.strip())
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
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to not in allowed_to_values:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the chat target")
    allowed_to_dids = {
        value
        for row in recipient_rows
        for value in (
            str(row.get("did") or "").strip(),
            str(row.get("did_aw") or "").strip(),
            str(row.get("did_key") or "").strip(),
        )
        if value
    }
    signed_to_did = str(payload.get("to_did") or "").strip()
    if signed_to_did and (len(recipient_rows) != 1 or signed_to_did not in allowed_to_dids):
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the chat target")
    allowed_to_stable_ids = {
        value for row in recipient_rows for value in (str(row.get("did_aw") or "").strip(),) if value
    }
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if signed_to_stable_id and (len(recipient_rows) != 1 or signed_to_stable_id not in allowed_to_stable_ids):
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the chat target")
    if payload.get("body") != body:
        raise HTTPException(status_code=422, detail="signed_payload body must match the chat message")
    if payload.get("from_did") != from_did:
        raise HTTPException(status_code=422, detail="signed_payload from_did must match the authenticated sender")
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise HTTPException(
            status_code=422,
            detail="signed_payload from_stable_id must match the authenticated sender",
        )
    if payload.get("message_id") != message_id:
        raise HTTPException(status_code=422, detail="signed_payload message_id must match the chat message")
    if payload.get("timestamp") != timestamp:
        raise HTTPException(status_code=422, detail="signed_payload timestamp must match the chat message")
    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if conversation_id is not None:
        if not signed_conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id is required")
        if signed_conversation_id != conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")
    elif signed_conversation_id:
        raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")
    if payload.get("wait_seconds") != wait_seconds:
        raise HTTPException(status_code=422, detail="signed_payload wait_seconds must match the chat message")
    if (payload.get("reply_to") or None) != ((reply_to or "").strip() or None):
        raise HTTPException(status_code=422, detail="signed_payload reply_to must match the chat message")
    if bool(payload.get("sender_leaving")) != sender_leaving:
        raise HTTPException(status_code=422, detail="signed_payload sender_leaving must match the chat message")
    if bool(payload.get("hang_on")) != hang_on:
        raise HTTPException(status_code=422, detail="signed_payload hang_on must match the chat message")
    try:
        validate_ed25519_message_signature(signature)
    except MessageSignatureShapeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _record_successful_chat_contacts(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipients: list[dict[str, Any]],
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
        controller_did = str(
            recipient.get("authority_controller_did") or ""
        ).strip()
        if not controller_did and recipient.get(
            "requires_local_address_authority"
        ):
            controller_did = (
                await resolve_local_namespace_controller_did(
                    registry_client,
                    contact_address=address,
                    contact_did_aw=str(recipient.get("did_aw") or ""),
                    contact_current_did_key=str(
                        recipient.get("did_key") or ""
                    ),
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
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("conversation_id") or "").strip()


def _sender_bound_fresh_session(payload: CreateSessionRequest, auth: MessagingAuth, session_id: UUID | None) -> bool:
    """Authorize replacement before any close; ciphertext needs verified binding."""
    if session_id is None:
        return False
    if not _payload_is_encrypted(payload):
        return (payload.signature is not None
                and payload.from_did in auth_dids(auth)
                and _signed_payload_conversation_id(payload.signed_payload) == str(session_id))
    envelope = payload.encrypted_envelope or {}
    sender = envelope.get("from")
    if (not isinstance(sender, dict) or sender.get("did") not in auth_dids(auth)
            or envelope.get("conversation_id") != str(session_id)):
        return False
    try:
        verify_e2ee_message_envelope_signature(envelope)
    except (E2EEEnvelopeError, ValueError, TypeError):
        return False
    return True


async def _chat_create_retry(db, payload: CreateSessionRequest, *, actor_dids: list[str], target_dids: list[str]):
    """Acknowledge an exact accepted message without replacing a later session."""
    if payload.message_id is None:
        return None
    manager = db.get_manager("aweb")
    row = await manager.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(payload.message_id),
    )
    if row is None:
        return None
    envelope = row.get("encrypted_envelope")
    if isinstance(envelope, str):
        envelope = json.loads(envelope)
    matches = (
        row["from_did"] in actor_dids
        and (payload.session_id is None or str(row["session_id"]) == payload.session_id)
        and row["body"] == payload.message
        and row.get("signature") == payload.signature
        and row.get("signed_payload") == payload.signed_payload
        and envelope == payload.encrypted_envelope
        and row["content_mode"] == payload.content_mode
        and row["message_version"] == payload.message_version
        and bool(row["sender_leaving"]) == payload.leaving
        and (str(row["reply_to"]) if row.get("reply_to") else None) == payload.reply_to
    )
    signed = envelope if envelope is not None else json.loads(row.get("signed_payload") or "{}")
    timestamp = signed.get("created_at" if envelope is not None else "timestamp")
    signer = (signed.get("from") or {}).get("did") if envelope is not None else signed.get("from_did")
    matches = (matches and payload.timestamp == timestamp
               and (payload.from_did == signer or (envelope is not None and payload.from_did is None))
               and (envelope is not None or payload.wait_seconds == signed.get("wait_seconds")))
    # Encrypted wait_seconds is an outer request option, not stored message
    # evidence. Acknowledge the matching envelope without applying a wait again;
    # the session's current wait may belong to a later accepted request.
    participants = await manager.fetch_all(
        "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1", row["session_id"],
    )
    matches = matches and {p["did"] for p in participants} == set(actor_dids) | set(target_dids)
    if not matches:
        raise HTTPException(status_code=409, detail=(
            "This message ID has already been used for a different chat request. "
            "Retry the original request unchanged. Use a new message ID only if you intend to send a new message."
        ))
    return row


def _actor_did(auth: MessagingAuth) -> str:
    return (auth.did_aw or auth.did_key or "").strip()


def _actor_alias(auth: MessagingAuth, actor_agent: dict[str, Any] | None) -> str:
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
    recipient: dict[str, Any],
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
        raise HTTPException(status_code=424, detail="Remote chat recipient has an incomplete authority route")
    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID remote chat route resolution")
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
            raise HTTPException(
                status_code=424,
                detail="Remote chat recipient has no address route for refresh",
            )
    except (HTTPException, FederationAuthorityError):
        raise
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning("AWID registry dependency failed for remote chat route resolution: %s", address, exc_info=True)
        raise awid_dependency_http_exception(exc, operation="AWID remote chat route resolution") from exc
    except Exception as exc:
        logger.exception("Unexpected AWID registry dependency error for remote chat route resolution: %s", address)
        raise awid_dependency_http_exception(exc, operation="AWID remote chat route resolution") from exc
    if resolution is None:
        raise HTTPException(status_code=404, detail=f"Recipient route not found: {address}")
    target_stable_id = str(getattr(resolution, "did_aw", "") or "").strip()
    target_current_did = str(getattr(resolution, "current_did_key", "") or "").strip()
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_did = str(recipient.get("did") or "").strip()
    if target_stable_id not in {recipient_stable_id, recipient_did}:
        raise HTTPException(status_code=422, detail="Remote chat recipient identity changed")
    delivery = getattr(resolution, "delivery", None)
    resolved_origin = str(
        getattr(resolution, "delivery_origin", None)
        or getattr(delivery, "origin", "")
        or ""
    ).strip()
    delivery_origin = resolved_origin or _target_delivery_origin(recipient)
    if not delivery_origin:
        raise HTTPException(status_code=424, detail="Recipient address has no federated delivery origin")
    local = await local_recipient_for_own_route(
        db, {"did_aw": target_stable_id, "current_did_key": target_current_did,
             "address": address, "delivery_origin": delivery_origin},
        runtime,
    )
    if local is not None:
        # Do not persist an own-origin remote route. The shared delivery helper
        # applies local chat/policy checks and the caller stores the message.
        return {"address": address, "did_aw": target_stable_id,
                "current_did_key": target_current_did, "delivery_origin": delivery_origin}
    if resolved_origin and (
        resolved_origin != _target_delivery_origin(recipient)
        or target_current_did
        != str(recipient.get("current_did_key") or recipient.get("did_key") or "").strip()
    ):
        await _update_chat_participant_route(
            db,
            conversation_id=str(recipient.get("session_id") or recipient.get("conversation_id") or ""),
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


def _raise_bare_did_chat_first_contact_unsupported() -> None:
    raise HTTPException(
        status_code=422,
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
    except Exception:
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
    recipient: dict[str, Any],
    route: dict[str, Any],
) -> None:
    recipient.update(
        {
            "did_aw": route["did_aw"],
            "did_key": route["current_did_key"],
            "current_did_key": route["current_did_key"],
            "delivery_origin": route["delivery_origin"],
        }
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
        return


def _is_stale_delivery_origin_status(status_code: int) -> bool:
    return status_code in {404, 410, 421}


async def _local_agent_by_address(db, *, domain: str, name: str) -> dict[str, Any] | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _signed_payload_address_binding(
    payload: dict[str, Any] | None,
    *,
    address: str,
) -> dict[str, str] | None:
    if not isinstance(payload, dict) or payload.get("type") != "chat":
        return None
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to != address:
        return None
    signed_to_did = str(payload.get("to_did") or "").strip()
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if not signed_to_did and not signed_to_stable_id:
        return None
    return {"did_key": signed_to_did, "did_aw": signed_to_stable_id}


def _row_matches_signed_address_binding(row: dict[str, Any], binding: dict[str, str] | None) -> bool:
    if binding is None:
        return False
    row_stable_id = str(row.get("did_aw") or "").strip()
    row_current_did = str(row.get("did_key") or row.get("did") or "").strip()
    bound_stable_id = str(binding.get("did_aw") or "").strip()
    bound_current_did = str(binding.get("did_key") or "").strip()
    if bound_stable_id and bound_stable_id != row_stable_id:
        return False
    if bound_current_did and bound_current_did not in {row_stable_id, row_current_did}:
        return False
    return bool(bound_stable_id or bound_current_did)


async def _resolve_actor_agent(db, actor_dids: list[str]) -> dict[str, Any] | None:
    for did in actor_dids:
        if not did:
            continue
        actor_agent = await resolve_agent_by_did(db, did)
        if actor_agent is not None:
            return actor_agent
    return None


def _address_from_alias(value: str | None) -> str:
    text = (value or "").strip()
    return text if "/" in text else ""


def _target_did_refs(row: dict[str, Any]) -> set[str]:
    return {
        value
        for value in (
            str(row.get("did_aw") or "").strip(),
            str(row.get("did_key") or "").strip(),
            str(row.get("did") or "").strip(),
        )
        if value
    }


async def _left_dids_by_session(db, session_ids: list[UUID]) -> dict[str, set[str]]:
    if not session_ids:
        return {}
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT session_id, did
        FROM {{tables.chat_participants}}
        WHERE session_id = ANY($1::uuid[])
          AND left_at IS NOT NULL
        """,
        session_ids,
    )
    left: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        left[str(row["session_id"])].add(str(row["did"]))
    return left


async def _resolve_named_recipients(
    db,
    *,
    runtime: MessagingRuntime,
    source: str,
    registry_client,
    auth: MessagingAuth,
    to_aliases: list[str],
    to_dids: list[str],
    to_addresses: list[str],
    signed_payload: str | None = None,
    signature: str | None = None,
) -> list[dict[str, Any]]:
    actor_dids = participant_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    actor_did_set = set(actor_dids)
    sender_address = _sender_address(auth)
    resolved: dict[str, dict[str, Any]] = {}

    if to_aliases:
        if auth.team_id is None:
            raise HTTPException(status_code=422, detail="to_aliases requires team context")
        target_rows: list[dict[str, Any]] = []
        local_aliases: list[str] = []
        for alias in to_aliases:
            if "~" not in alias:
                local_aliases.append(alias)
                continue
            target = resolve_alias_target(auth.team_id, alias, field="to_aliases")
            if not await team_exists(db, target.team_id):
                raise HTTPException(status_code=404, detail=f"Unknown team: {target.team_id}")
            row = await messaging_participant_by_alias(db, team_id=target.team_id, alias=target.alias, selected_team_id=auth.team_id, registry_client=runtime.registry_client)
            if row is None:
                raise HTTPException(status_code=404, detail=f"Unknown aliases: {alias}")
            target_rows.append(row)
        if local_aliases:
            local_rows = await messaging_participants_by_aliases(db, team_id=auth.team_id, aliases=local_aliases, selected_team_id=auth.team_id, registry_client=runtime.registry_client)
            resolved_aliases = {row["alias"] for row in local_rows}
            missing = [alias for alias in local_aliases if alias not in resolved_aliases]
            if missing:
                raise HTTPException(status_code=404, detail=f"Unknown aliases: {', '.join(missing)}")
            target_rows.extend(local_rows)
        for row in target_rows:
            target_did = (row.get("did_aw") or row.get("did_key") or "").strip()
            if target_did:
                resolved[target_did] = row

    for did in to_dids:
        row = await resolve_agent_by_did(db, did)
        if row is None and did.startswith("did:aw:"):
            _raise_bare_did_chat_first_contact_unsupported()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Recipient agent not found: {did}")
        resolved[did] = identity_recipient(row)

    for address in to_addresses:
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_addresses entries must be domain/name")
        domain, name = address.split("/", 1)
        local_candidate = await _local_agent_by_address(db, domain=domain, name=name)
        if local_candidate is not None:
            binding = _signed_payload_address_binding(
                verified_signed_payload_json(
                    signed_payload=signed_payload,
                    signature=signature,
                    did_key=auth.did_key,
                ),
                address=address,
            )
            signed_binding = _row_matches_signed_address_binding(local_candidate, binding)
            needs_current_binding = requires_registry_address_binding(local_candidate) and binding is not None and not signed_binding
            if signed_binding or (local_recipient_visible_to_auth(local_candidate, auth) and not needs_current_binding):
                target_did = str(
                    local_candidate.get("did_aw") or local_candidate.get("did_key") or ""
                ).strip()
                if target_did:
                    local_recipient = identity_recipient(local_candidate, address)
                    local_recipient["requires_local_address_authority"] = True
                    resolved[target_did] = local_recipient
                    continue

        resolution = None
        strict_authority = runtime.federation_authority
        home_namespace = await namespace_uses_home_registry(db, registry_client, domain)
        if home_namespace:
            try:
                resolution = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            except AWID_DEPENDENCY_ERRORS as exc:
                logger.warning("Chat home address lookup unavailable for %s", address, exc_info=True)
                raise FederationAuthorityError("sender_registry_unavailable") from exc
        elif strict_authority is not None:
            try:
                resolution = await strict_authority.resolve_contact(
                    address,
                    source_ip=source,
                )
            except FederationAuthorityError as exc:
                if exc.reason != "recipient_identity_not_found":
                    raise
        elif registry_client is not None:
            resolution = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolution is not None and resolution.did_aw:
            row = await local_recipient_for_address_binding(db, resolution, address)
            if row is None:
                delivery = getattr(resolution, "delivery", None)
                delivery_origin = (
                    getattr(resolution, "delivery_origin", None)
                    or getattr(delivery, "origin", "")
                    or ""
                )
                refuse_same_origin_nonresident(
                    str(delivery_origin), origins=runtime.public_origins,
                )
                row = {
                    "agent_id": None,
                    "team_id": None,
                    "alias": name,
                    "address": address,
                    "did_aw": resolution.did_aw.strip(),
                    "did_key": (getattr(resolution, "current_did_key", "") or "").strip(),
                    "delivery_origin": str(delivery_origin).strip(),
                    "authority_controller_did": str(
                        getattr(resolution, "controller_did", "") or ""
                    ).strip(),
                    "external": True,
                    "_authority_route_current": home_namespace or strict_authority is not None,
                }
            else:
                row["authority_controller_did"] = str(
                    getattr(resolution, "controller_did", "") or ""
                ).strip()
            resolved[resolution.did_aw] = row
            continue

        row = await _local_agent_by_address(db, domain=domain, name=name)
        if row is None:
            if await namespace_exists(db, domain):
                raise FederationAuthorityError("recipient_identity_not_found")
            if registry_client is None:
                raise awid_registry_not_configured_exception(operation="AWID chat address target lookup")
            raise HTTPException(status_code=404, detail=f"Recipient address not found: {address}")
        if registry_client is not None and requires_registry_address_binding(row):
            binding = _signed_payload_address_binding(
                verified_signed_payload_json(
                    signed_payload=signed_payload,
                    signature=signature,
                    did_key=auth.did_key,
                ),
                address=address,
            )
            if not (
                local_recipient_visible_to_auth(row, auth)
                or _row_matches_signed_address_binding(row, binding)
            ):
                raise HTTPException(status_code=404, detail=f"Recipient address not found: {address}")
        row = identity_recipient(row, address)
        target_did = (row.get("did_aw") or row.get("did_key") or "").strip()
        if not target_did:
            raise HTTPException(status_code=404, detail=f"Recipient agent not found: {address}")
        resolved[target_did] = row

    if not resolved:
        raise HTTPException(status_code=422, detail="Must provide to_aliases, to_dids, or to_addresses")

    if any(_target_did_refs(row) & actor_did_set for row in resolved.values()):
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

    await require_agent_chat(db, list(resolved.values()), registry_client=registry_client)
    for row in resolved.values():
        if row.get("external"):
            continue
        try:
            await authorize_message_delivery(
                db,
                recipient_agent=row,
                sender_did=actor_did,
                sender_address=sender_address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
                sender_verified_dids=auth_dids(auth),
            )
        except (ValidationError, NotFoundError, ForbiddenError) as exc:
            if (isinstance(exc, ForbiddenError) and row.get("address") in to_addresses
                    and row.get("identity_scope") == "local"
                    and not row.get("has_global_claim") and not row.get("did_aw")):
                raise FederationAuthorityError("local_recipient_route_missing") from exc
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return list(resolved.values())


async def _resolve_session_recipient_rows(
    db,
    *,
    session_id: UUID,
    actor_dids: list[str],
) -> list[dict[str, Any]]:
    aweb_db = db.get_manager("aweb")
    left_dids = (await _left_dids_by_session(db, [session_id])).get(str(session_id), set())
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
        resolved = await resolve_agent_by_did(db, participant.get("did") or "")
        if resolved is not None:
            resolved = identity_recipient(resolved, str(participant.get("address") or ""))
        policy_rows = await policy_rows_for_participant(db, participant)
        policy = resolved or (policy_rows[0] if policy_rows else {})
        participant_did = (participant.get("did") or "").strip()
        if participant_did in left_dids:
            continue
        participant_alias = (participant.get("alias") or "").strip()
        participant_address = (participant.get("address") or "").strip()
        recipient_rows.append(
            {
                "session_id": str(session_id),
                "did": participant_did,
                "alias": participant_alias,
                "address": ((resolved or {}).get("address") or "").strip()
                or participant_address
                or _address_from_alias(participant_alias),
                "delivery_origin": (participant.get("delivery_origin") or "").strip() or None,
                "current_did_key": (participant.get("current_did_key") or "").strip() or None,
                "did_aw": ((resolved or {}).get("did_aw") or "").strip()
                or (participant_did if participant_did.startswith("did:aw:") else ""),
                "did_key": ((resolved or {}).get("did_key") or "").strip()
                or (participant.get("current_did_key") or "").strip()
                or (participant_did if participant_did.startswith("did:key:") else ""),
                "agent_id": ((resolved or {}).get("agent_id") if resolved else None),
                "team_id": ((resolved or {}).get("team_id") if resolved else None),
                "inbound_mode": ((resolved or {}).get("inbound_mode") if resolved else None),
                "local_resolved": resolved is not None,
                "identity_scope": policy.get("identity_scope"),
                "has_global_claim": policy.get("has_global_claim"),
                "policy_did_aw": policy.get("policy_did_aw"),
                "_policy_recipients": policy_rows,
            }
        )
    return recipient_rows


@dataclass(frozen=True)
class ChatTarget:
    """Whom a chat send reaches: the recipients a new send names, or the session it continues.

    ``session_id`` and ``actor_did``, the sender's participant DID in that
    session, are set for a continuation. ``source`` keys the federation
    authority's rate bucket for the route lookups the send makes.
    """

    recipients: list[dict[str, Any]]
    source: str
    session_id: UUID | None = None
    actor_did: str = ""


@dataclass(frozen=True)
class SentChat:
    """A chat send as stored: its session and its message row.

    ``message`` is ``send_in_session``'s row, or the stored row of the request
    this one repeats. ``participants`` are the session's participants as a new
    send to another server stored them, and ``None`` for every other send.
    """

    session_id: UUID
    message: dict[str, Any]
    participants: list[dict[str, Any]] | None = None


async def resolve_chat_targets(
    db, auth: MessagingAuth, selector: CreateSessionRequest | str, runtime: MessagingRuntime, source: str,
) -> ChatTarget:
    """Resolve whom a send reaches, before any of it is stored.

    A ``CreateSessionRequest`` supplies the recipient fields, the session id it
    proposes and any signature the sender made over the recipient binding. A
    session id selects the other participants of that session. ``source`` keys
    the federation authority's rate bucket for this caller.
    """
    actor_dids = participant_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    if isinstance(selector, str):
        return await _resolve_session_target(db, auth, selector, runtime, source, actor_dids=actor_dids)

    requested_session_id = UUID(selector.session_id) if selector.session_id is not None else None
    if requested_session_id is not None:
        await validate_session_id(
            db, session_id=requested_session_id, actor_dids=actor_dids,
        )

    target_rows = await _resolve_named_recipients(
        db,
        runtime=runtime,
        source=source,
        registry_client=runtime.registry_client,
        auth=auth,
        to_aliases=selector.to_aliases,
        to_dids=selector.to_dids,
        to_addresses=selector.to_addresses,
        signed_payload=selector.signed_payload,
        signature=selector.signature,
    )
    return ChatTarget(recipients=target_rows, source=source)


async def _resolve_session_target(
    db, auth: MessagingAuth, session_id: str, runtime: MessagingRuntime, source: str, *, actor_dids: list[str],
) -> ChatTarget:
    sender_address = _sender_address(auth)

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")
    recipient_rows = await _resolve_session_recipient_rows(db, session_id=session_uuid, actor_dids=actor_dids)
    # Succession is mail-only. Retired humans get a mail-directed refusal;
    # retired agents retain the existing chat behavior for live group members.
    try:
        for row in recipient_rows:
            if not _target_delivery_origin(row):
                await _require_live_mail_participant(db, row, {}, human_only=True)
    except ValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    for row in recipient_rows:
        local = await local_recipient_for_own_route(db, row, runtime)
        if local is not None:
            row.update(local, delivery_origin=None, current_did_key=local.get("did_key"))
    await require_agent_chat(db, recipient_rows, registry_client=runtime.registry_client)
    for row in recipient_rows:
        if (
            str(row.get("did") or "").startswith("did:key:")
            and not _target_delivery_origin(row)
            and not row.get("local_resolved")
        ):
            raise HTTPException(status_code=422, detail=LOCAL_DID_KEY_RECIPIENT_UNREACHABLE)
    for index, row in enumerate(recipient_rows):
        if not _target_delivery_origin(row):
            continue
        route = await resolve_stored_remote_chat_route(
            registry_client=runtime.registry_client,
            recipient=row,
        )
        recipient_rows[index] = {
            **row,
            "did_aw": route["did_aw"],
            "did_key": route["current_did_key"],
            "current_did_key": route["current_did_key"],
            "delivery_origin": route["delivery_origin"],
        }
    try:
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
                    recipient_agent=policy_recipient,
                    sender_did=actor_did,
                    sender_address=sender_address,
                    sender_team_id=auth.team_id,
                    sender_verified_team_id=auth.verified_team_id,
                    sender_verified_dids=auth_dids(auth),
                    stored_route_continuation=True,
                )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return ChatTarget(recipients=recipient_rows, source=source, session_id=session_uuid, actor_did=actor_did)


async def send_chat(
    db, auth: MessagingAuth, target: ChatTarget, payload: CreateSessionRequest | SendMessageRequest,
    runtime: MessagingRuntime,
) -> SentChat:
    """Store and deliver the signed or encrypted ``payload`` to a resolved target.

    A target that names recipients takes a ``CreateSessionRequest``; a target
    that continues a session takes a ``SendMessageRequest``.
    """
    if target.session_id is not None:
        return await _send_in_continued_session(db, auth, target, payload, runtime)
    return await _send_to_named_recipients(db, auth, target, payload, runtime)


async def _send_to_named_recipients(
    db, auth: MessagingAuth, target: ChatTarget, payload: CreateSessionRequest, runtime: MessagingRuntime,
) -> SentChat:
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    actor_dids = participant_dids(auth)
    actor_did = actor_dids[0]
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(auth, actor_agent)
    sender_address = _sender_address(auth)

    requested_session_id = UUID(payload.session_id) if payload.session_id is not None else None
    target_rows = target.recipients
    target_dids = sorted({_target_did(row) for row in target_rows if _target_did(row)})
    if _payload_is_encrypted(payload):
        await require_non_custodial_recipients(db, payload.encrypted_envelope or {}, target_rows, sender=auth)

    existing_attachment = await attachment_retry(db, payload, "chat")
    if existing_attachment:
        binding, row = existing_attachment
        expected_targets = set(binding.participant_dids) - set(actor_dids)
        if (set(target_dids) != expected_targets
                or (payload.session_id and payload.session_id != binding.conversation_id)
                or payload.message or payload.signature or payload.signed_payload
                or bool(payload.leaving) != bool(row.get("sender_leaving"))
                or (payload.reply_to or "") != str(row.get("reply_to") or "")):
            raise HTTPException(409, detail={"code": "attachment_conflict"})
        return SentChat(session_id=UUID(binding.conversation_id), message=dict(row))

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
            "current_did_key": (row.get("did_key") or row.get("current_did_key") or "").strip() or None,
            "agent_id": str(row["agent_id"]) if row.get("agent_id") else None,
            "alias": (row.get("alias") or "").strip() or _target_did(row),
            "address": (row.get("address") or "").strip() or None,
            "delivery_origin": _target_delivery_origin(row) or None,
        }
        for row in target_rows
    ]

    existing_message = await _chat_create_retry(
        db, payload, actor_dids=actor_dids, target_dids=target_dids,
    )
    if existing_message is not None:
        return SentChat(session_id=existing_message["session_id"], message=dict(existing_message))
    validation_conversation_id = str(requested_session_id) if requested_session_id is not None else None
    signed_requested_session_id = _sender_bound_fresh_session(payload, auth, requested_session_id)
    if len(participant_rows) == 2:
        try:
            existing_session_id = await find_session_between(
                db,
                did_a=participant_rows[0]["did"],
                did_b=participant_rows[1]["did"],
            )
        except ConflictError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
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
                    pass
            elif requested_session_id is not None and requested_session_id != existing_session_id:
                raise HTTPException(
                    status_code=409,
                    detail="Existing active chat session found; continue that session instead",
                )
            else:
                requested_session_id = existing_session_id
                validation_conversation_id = str(existing_session_id)
                if (
                    payload.signature is not None
                    and _signed_payload_conversation_id(payload.signed_payload) != str(existing_session_id)
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Signed chat message must bind the existing session_id",
                    )
    external_targets = [row for row in target_rows if row.get("external") or _target_delivery_origin(row)]
    if external_targets:
        if len(target_rows) != 1 or len(external_targets) != 1:
            raise HTTPException(status_code=422, detail="Federated chat currently requires exactly one remote address recipient")
        if not _target_delivery_origin(external_targets[0]):
            raise HTTPException(status_code=424, detail="Recipient address has no federated delivery origin")
        if requested_session_id is None:
            raise HTTPException(status_code=422, detail="Federated chat delivery requires session_id")
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
                raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
            _validate_signed_chat_payload(
                signature=str(payload.signature),
                signed_payload=payload.signed_payload,
                recipient_rows=target_rows,
                requested_to_aliases=payload.to_aliases,
                from_alias=auth.alias,
                from_address=sender_address,
                from_stable_id=auth.did_aw,
                body=payload.message,
                from_did=from_did,
                message_id=str(payload.message_id),
                timestamp=str(payload.timestamp),
                wait_seconds=payload.wait_seconds,
                reply_to=payload.reply_to,
                conversation_id=str(requested_session_id),
                sender_leaving=payload.leaving,
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
        _apply_remote_chat_route(participant_rows, external_targets[0], route)

        remote = await deliver_federated_chat(
            runtime,
            payload,
            db=db, auth=auth,
            sender_address=sender_address,
            id_chain=id_chain,
            route=route,
            session_id=str(requested_session_id),
        )
        remote_session_id = str(remote.get("session_id") or remote.get("conversation_id") or "").strip()
        remote_message_id = str(remote.get("message_id") or "").strip()
        if remote_session_id != str(requested_session_id):
            raise HTTPException(status_code=502, detail="Federated chat response session_id mismatch")
        if remote_message_id != str(pre_message_id):
            raise HTTPException(status_code=502, detail="Federated chat response message_id mismatch")

        session_id = await ensure_session(
            db,
            team_id=auth.team_id,
            participant_rows=participant_rows,
            created_by=actor_alias,
            session_id=requested_session_id,
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
                signature=payload.signature,
                signed_payload=payload.signed_payload,
                content_mode=payload.content_mode,
                message_version=payload.message_version,
                encrypted_envelope=payload.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                message_id=pre_message_id,
            )
        if msg_row is None:
            raise HTTPException(status_code=500, detail=SENDER_NOT_IN_SESSION)
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
        return SentChat(session_id=session_id, message=msg_row, participants=participant_rows)
    session_id = await ensure_session(
        db,
        team_id=auth.team_id,
        participant_rows=participant_rows,
        created_by=actor_alias,
        session_id=requested_session_id,
    )
    try:
        await require_conversation_not_legacy_bound(
            db,
            conversation_id=str(session_id),
            conversation_type="chat",
        )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

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
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        from_did = payload.from_did.strip()
        if from_did not in set(auth_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_chat_payload(
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient_rows=target_rows,
            requested_to_aliases=payload.to_aliases,
            from_alias=auth.alias,
            from_address=sender_address,
            from_stable_id=auth.did_aw,
            body=payload.message,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            wait_seconds=payload.wait_seconds,
            reply_to=payload.reply_to,
            conversation_id=validation_conversation_id,
            sender_leaving=payload.leaving,
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
            raise HTTPException(status_code=404, detail="Replied-to message not found")

    try:
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
                signature=payload.signature,
                signed_payload=payload.signed_payload,
                content_mode=payload.content_mode,
                message_version=payload.message_version,
                encrypted_envelope=payload.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                message_id=pre_message_id,
            )
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail=SENDER_NOT_IN_SESSION)

    await _record_successful_chat_contacts(
        db,
        owner_did=(auth.did_aw or actor_did).strip(),
        sender_team_id=auth.team_id,
        recipients=target_rows,
        registry_client=registry_client,
    )

    if payload.wait_seconds is not None:
        await aweb_db.execute(
            """
            UPDATE {{tables.chat_sessions}}
            SET wait_seconds = $2,
                wait_started_at = $3,
                wait_started_by = $4
            WHERE session_id = $1
            """,
            session_id,
            int(payload.wait_seconds),
            msg_row["created_at"],
            UUID(actor_agent_id) if actor_agent_id else None,
        )

    other_participants = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did <> $2
        ORDER BY alias ASC
        """,
        session_id,
        actor_did,
    )
    await _fire_chat_message_sent(
        runtime,
        auth,
        session_id=session_id,
        message_id=msg_row["message_id"],
        from_agent_id=actor_agent_id,
        from_did=actor_did,
        to_aliases=[row["alias"] for row in other_participants],
        preview="" if encrypted_metadata is not None else payload.message[:80],
        content_mode=payload.content_mode,
    )

    return SentChat(session_id=session_id, message=msg_row)


async def _send_in_continued_session(
    db, auth: MessagingAuth, target: ChatTarget, payload: SendMessageRequest, runtime: MessagingRuntime,
) -> SentChat:
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    actor_dids = participant_dids(auth)
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    sender_address = _sender_address(auth)
    session_uuid = target.session_id
    actor_did = target.actor_did
    recipient_rows = target.recipients

    pre_message_id = uuid_mod.uuid4()
    if _payload_is_encrypted(payload):
        await require_non_custodial_recipients(db, payload.encrypted_envelope or {}, recipient_rows, sender=auth)
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
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        from_did = payload.from_did.strip()
        if from_did not in set(auth_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_chat_payload(
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient_rows=recipient_rows,
            from_alias=auth.alias,
            from_address=sender_address,
            from_stable_id=auth.did_aw,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            reply_to=payload.reply_to,
            conversation_id=str(session_uuid),
            sender_leaving=payload.leaving,
            hang_on=payload.hang_on,
        )
        # payload.timestamp is sender attestation retained in signed_payload;
        # send_in_session assigns independent server receipt time for ordering,
        # so the two values may disagree.
        _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    remote_recipients = [row for row in recipient_rows if _target_delivery_origin(row)]
    if remote_recipients:
        if len(recipient_rows) != 1 or len(remote_recipients) != 1:
            raise HTTPException(status_code=422, detail="Federated chat continuation requires exactly one remote recipient")
        route = remote_recipients[0]
        try:
            remote = await deliver_federated_chat(
                runtime,
                payload,
                db=db, auth=auth,
                sender_address=sender_address,
                id_chain=id_chain,
                route=route,
                session_id=str(session_uuid),
            )
        except HTTPException as exc:
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
                db=db, auth=auth,
                sender_address=sender_address,
                id_chain=id_chain,
                route=remote_recipients[0],
                session_id=str(session_uuid),
            )
        remote_session_id = str(remote.get("session_id") or remote.get("conversation_id") or "").strip()
        remote_message_id = str(remote.get("message_id") or "").strip()
        if remote_session_id != str(session_uuid):
            raise HTTPException(status_code=502, detail="Federated chat response session_id mismatch")
        if remote_message_id != str(pre_message_id):
            raise HTTPException(status_code=502, detail="Federated chat response message_id mismatch")

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
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail=SENDER_NOT_IN_SESSION)
    if remote_recipients:
        await _record_successful_chat_contacts(
            db,
            owner_did=(auth.did_aw or actor_did).strip(),
            sender_team_id=auth.team_id,
            recipients=remote_recipients,
            registry_client=registry_client,
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
    content_mode: str,
    federated: bool = False,
) -> None:
    context = {
        "team_id": auth.team_id,
        "session_id": str(session_id),
        "conversation_id": str(session_id),
        "message_id": str(message_id),
        "from_agent_id": from_agent_id,
        "from_alias": auth.alias or "",
        "from_did": from_did,
        "from_did_aw": (auth.did_aw or "").strip() or None,
        "to_aliases": to_aliases,
        "preview": preview,
        "content_mode": content_mode,
    }
    if federated:
        context["federated"] = True
    await fire_mutation_callback(runtime.on_mutation, "chat.message_sent", context)
