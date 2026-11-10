"""Chat sends to a participant on another server, for every adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from aweb.attachment_service import refuse_remote_attachments
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    encrypted_message_storage_metadata,
    validate_e2ee_message_envelope,
)
from aweb.federation.envelope import (
    FederationEnvelope,
    FederationEnvelopeError,
    verify_federation_envelope,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.identity_auth_deps import MessagingAuth, auth_dids
from aweb.messaging.address_auth import local_recipient_for_own_route
from aweb.messaging.chat_policy import require_agent_chat
from aweb.messaging.messages import authorize_message_delivery
from aweb.messaging.runtime import MessagingRuntime
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError

if TYPE_CHECKING:
    from aweb.routes.chat import CreateSessionRequest, SendMessageRequest


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
