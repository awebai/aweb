from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid as uuid_mod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator
from uuid import UUID

import asyncpg.exceptions
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.config import get_settings
from aweb.deps import get_db, get_redis
from aweb.events import chat_session_channel_name, publish_chat_session_signal
from aweb.federation.envelope import FederationEnvelope, FederationEnvelopeError, verify_federation_envelope
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.hooks import fire_mutation_hook
from aweb.identity_metadata import lookup_identity_metadata_by_did, routable_chat_address
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
    namespace_exists,
    resolve_alias_target,
    team_exists,
    validate_alias_selector,
)
from aweb.messaging.address_auth import (
    local_recipient_visible_to_auth,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    find_session_between,
    get_agent_by_alias,
    get_agents_by_aliases,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    resolve_agent_by_did,
    send_in_session,
)
from aweb.messaging.conversations import close_conversation
from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts, upsert_successful_identity_contact
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.messages import authorize_message_delivery, utc_iso as _utc_iso
from aweb.messaging.verification import require_conversation_not_legacy_bound
from aweb.messaging.waiting import (
    get_waiting_agents,
    get_waiting_agents_by_session,
    register_waiting,
    unregister_waiting,
)
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/chat", tags=["aweb-chat"])

MAX_CHAT_STREAM_DURATION = 300
CHAT_STREAM_FALLBACK_POLL_SECONDS = 2.0
CHAT_STREAM_KEEPALIVE_SECONDS = 30.0


def _parse_uuid(value: str, *, field: str) -> str:
    try:
        return str(UUID(str(value).strip()))
    except Exception:
        raise ValueError(f"Invalid {field} format")


def _parse_timestamp(value: str, label: str = "timestamp") -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid {label} format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail=f"{label} must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _parse_deadline(value: str) -> datetime:
    return _parse_timestamp(value, "deadline")


def _parse_signed_timestamp(value: str) -> datetime:
    dt = _parse_timestamp(value, "timestamp")
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    return dt


def _validate_signed_chat_payload(
    *,
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
        return
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


async def _record_successful_chat_contacts(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipients: list[dict[str, Any]],
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
        await upsert_successful_identity_contact(
            db,
            owner_did=owner,
            contact_address=address,
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


def _actor_did(auth: MessagingAuth) -> str:
    return (auth.did_aw or auth.did_key or "").strip()


def _actor_dids(auth: MessagingAuth) -> list[str]:
    dids: list[str] = []
    for value in ((auth.did_aw or "").strip(), (auth.did_key or "").strip()):
        if value and value not in dids:
            dids.append(value)
    return dids


def _actor_alias(auth: MessagingAuth, actor_agent: dict[str, Any] | None) -> str:
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or ((actor_agent or {}).get("alias") or "").strip()
        or ((actor_agent or {}).get("address") or "").strip()
        or _actor_did(auth)
    )


def _sender_address(auth: MessagingAuth) -> str | None:
    return (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias) or None


def _local_public_origin(request: Request) -> str:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    if configured:
        return configured
    return get_settings().public_origin


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


def _federation_transport(request: Request):
    return (
        getattr(request.app.state, "federation_chat_transport", None)
        or getattr(request.app.state, "federation_message_transport", None)
        or getattr(request.app.state, "federation_mail_transport", None)
    )


async def _resolve_remote_chat_route(
    db,
    *,
    registry_client,
    recipient: dict[str, Any],
    requester_did_key: str | None = None,
) -> dict[str, Any]:
    address = str(recipient.get("address") or "").strip()
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry unavailable")
    try:
        if "/" in address:
            domain, name = address.split("/", 1)
            if requester_did_key:
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
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc
    if resolution is None:
        raise HTTPException(status_code=404, detail=f"Recipient route not found: {address}")
    target_stable_id = str(getattr(resolution, "did_aw", "") or "").strip()
    target_current_did = str(getattr(resolution, "current_did_key", "") or "").strip()
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_did = str(recipient.get("did") or "").strip()
    if target_stable_id not in {recipient_stable_id, recipient_did}:
        raise HTTPException(status_code=422, detail="Remote chat recipient identity changed")
    delivery = getattr(resolution, "delivery", None)
    resolved_origin = str(getattr(delivery, "origin", "") or "").strip()
    delivery_origin = resolved_origin or _target_delivery_origin(recipient)
    if not delivery_origin:
        raise HTTPException(status_code=424, detail="Recipient address has no federated delivery origin")
    if resolved_origin and resolved_origin != _target_delivery_origin(recipient):
        await _update_chat_participant_delivery_origin(
            db,
            conversation_id=str(recipient.get("session_id") or recipient.get("conversation_id") or ""),
            did=recipient_did or target_stable_id,
            delivery_origin=delivery_origin,
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


async def _resolve_stored_remote_chat_route(
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


async def _update_chat_participant_delivery_origin(
    db,
    *,
    conversation_id: str,
    did: str,
    delivery_origin: str,
) -> None:
    if not conversation_id or not did or not delivery_origin:
        return
    aweb_db = db.get_manager("aweb")
    try:
        conversation_uuid = UUID(conversation_id)
    except Exception:
        return
    await aweb_db.execute(
        """
        UPDATE {{tables.chat_participants}}
        SET delivery_origin = $3
        WHERE session_id = $1 AND did = $2
        """,
        conversation_uuid,
        did,
        delivery_origin,
    )
    await aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET delivery_origin = $3
        WHERE conversation_id = $1 AND did = $2
        """,
        conversation_uuid,
        did,
        delivery_origin,
    )


def _chat_payload_body(payload: CreateSessionRequest | SendMessageRequest) -> str:
    return payload.message if isinstance(payload, CreateSessionRequest) else payload.body


def _chat_payload_leaving(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return payload.leaving


def _chat_payload_hang_on(payload: CreateSessionRequest | SendMessageRequest) -> bool:
    return payload.hang_on if isinstance(payload, SendMessageRequest) else False


def _is_stale_delivery_origin_status(status_code: int) -> bool:
    return status_code in {404, 410, 421}


async def _deliver_federated_chat(
    request: Request,
    payload: CreateSessionRequest | SendMessageRequest,
    *,
    auth: MessagingAuth,
    sender_address: str | None,
    route: dict[str, Any],
    session_id: str,
) -> dict[str, Any]:
    _require_remote_chat_signature(payload, session_id=session_id)
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise HTTPException(status_code=422, detail="Federated chat delivery requires a sender identity")
    sender_current_did = str(payload.from_did or "").strip()
    if sender_current_did not in set(_actor_dids(auth)):
        raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")

    try:
        envelope = FederationEnvelope(
            type="chat",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address,
            sender_delivery_origin=_local_public_origin(request),
            target_address=route["address"],
            target_did_aw=route["did_aw"],
            target_current_did_key=route["current_did_key"],
            target_delivery_origin=route["delivery_origin"],
            body=_chat_payload_body(payload),
            message_id=str(payload.message_id),
            timestamp=str(payload.timestamp),
            signed_payload=str(payload.signed_payload),
            conversation_id=session_id,
            wait_seconds=getattr(payload, "wait_seconds", None),
            reply_to=payload.reply_to,
            sender_leaving=_chat_payload_leaving(payload),
            hang_on=_chat_payload_hang_on(payload),
        )
        verify_federation_envelope(
            envelope,
            str(payload.signature),
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

    try:
        return await deliver_federated_message(
            delivery_origin=route["delivery_origin"],
            envelope=envelope,
            signature=str(payload.signature),
            transport=_federation_transport(request),
        )
    except FederatedMailDeliveryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


async def _local_agent_by_address(db, *, domain: str, name: str) -> dict[str, Any] | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _with_requested_address(row: dict[str, Any], address: str) -> dict[str, Any]:
    copied = dict(row)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


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
    if bound_stable_id and row_stable_id and bound_stable_id == row_stable_id:
        return True
    if bound_current_did and row_current_did and bound_current_did == row_current_did:
        return True
    return False


async def _resolve_actor_agent(db, actor_dids: list[str]) -> dict[str, Any] | None:
    for did in actor_dids:
        if not did:
            continue
        actor_agent = await resolve_agent_by_did(db, did)
        if actor_agent is not None:
            return actor_agent
    return None


async def _resolve_session_actor_did(db, *, session_id: UUID, actor_dids: list[str]) -> str:
    if not actor_dids:
        return ""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT did
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
          AND did = ANY($2::text[])
        ORDER BY CASE WHEN did = $3 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        session_id,
        actor_dids,
        actor_dids[0],
    )
    return (row.get("did") or "").strip() if row else ""


def _chat_to_address(participant_rows: list[dict[str, Any]], *, from_did: str) -> str:
    refs = [
        (row.get("address") or row["alias"])
        for row in participant_rows
        if (row.get("did") or "").strip() != from_did
    ]
    refs.sort()
    return ",".join(refs)


def _address_from_alias(value: str | None) -> str:
    text = (value or "").strip()
    return text if "/" in text else ""


def _target_did(row: dict[str, Any]) -> str:
    return (row.get("did_aw") or row.get("did_key") or row.get("did") or "").strip()


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


def _group_participants_by_session(
    participant_rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in participant_rows:
        grouped[str(row["session_id"])].append(dict(row))
    return grouped


async def _lookup_addresses_by_did(db, dids: list[str]) -> dict[str, str]:
    metadata = await lookup_identity_metadata_by_did(db, dids)
    result: dict[str, str] = {}
    for did, meta in metadata.items():
        address = (meta.get("address") or "").strip()
        if address:
            result[did] = address
    return result


async def _targets_left(db, *, session_id: UUID, target_dids: list[str]) -> list[str]:
    if not target_dids:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT ON (from_did) from_did, sender_leaving
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND from_did = ANY($2::text[])
        ORDER BY from_did, created_at DESC
        """,
        session_id,
        target_dids,
    )
    left_dids = {str(row["from_did"]) for row in rows if row.get("sender_leaving")}
    if not left_dids:
        return []
    part_rows = await aweb_db.fetch_all(
        """
        SELECT did, alias
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = ANY($2::text[])
        """,
        session_id,
        list(left_dids),
    )
    return [row["alias"] for row in part_rows]


async def _resolve_chat_targets(
    db,
    *,
    request: Request,
    registry_client,
    auth: MessagingAuth,
    to_aliases: list[str],
    to_dids: list[str],
    to_addresses: list[str],
    signed_payload: str | None = None,
    signature: str | None = None,
) -> list[dict[str, Any]]:
    actor_dids = _actor_dids(auth)
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
            row = await get_agent_by_alias(db, team_id=target.team_id, alias=target.alias)
            if row is None:
                raise HTTPException(status_code=404, detail=f"Unknown aliases: {alias}")
            target_rows.append(row)
        if local_aliases:
            local_rows = await get_agents_by_aliases(db, team_id=auth.team_id, aliases=local_aliases)
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
        resolved[did] = row

    for address in to_addresses:
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_addresses entries must be domain/name")
        domain, name = address.split("/", 1)
        resolution = None
        if registry_client is not None:
            resolution = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolution is not None and resolution.did_aw:
            row = await resolve_agent_by_did(db, resolution.did_aw)
            if row is None:
                delivery = getattr(resolution, "delivery", None)
                row = {
                    "agent_id": None,
                    "team_id": None,
                    "alias": name,
                    "address": address,
                    "did_aw": resolution.did_aw.strip(),
                    "did_key": (getattr(resolution, "current_did_key", "") or "").strip(),
                    "delivery_origin": (getattr(delivery, "origin", "") or "").strip(),
                    "external": True,
                }
            resolved[resolution.did_aw] = row
            continue

        row = await _local_agent_by_address(db, domain=domain, name=name)
        if row is None:
            if await namespace_exists(db, domain):
                raise HTTPException(status_code=404, detail=f"Recipient agent not found: {address}")
            if registry_client is None:
                raise HTTPException(status_code=503, detail="AWID registry unavailable")
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
        row = _with_requested_address(row, address)
        target_did = (row.get("did_aw") or row.get("did_key") or "").strip()
        if not target_did:
            raise HTTPException(status_code=404, detail=f"Recipient agent not found: {address}")
        resolved[target_did] = row

    if not resolved:
        raise HTTPException(status_code=422, detail="Must provide to_aliases, to_dids, or to_addresses")

    if any(_target_did_refs(row) & actor_did_set for row in resolved.values()):
        raise HTTPException(status_code=400, detail="Self-chat is not supported")

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
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return list(resolved.values())


async def _resolve_session_recipient_rows(
    db,
    *,
    session_id: UUID,
    actor_dids: list[str],
) -> list[dict[str, Any]]:
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT did, alias, address, delivery_origin, current_did_key
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
        participant_did = (participant.get("did") or "").strip()
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
            }
        )
    return recipient_rows


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None = None
    to_aliases: list[str] = Field(default_factory=list)
    to_dids: list[str] = Field(default_factory=list)
    to_addresses: list[str] = Field(default_factory=list)
    message: str
    leaving: bool = False
    wait_seconds: int | None = None
    message_id: str | None = None
    reply_to: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_hosted_handle_targets(cls, data):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        aliases: list[str] = []
        promoted_addresses: list[str] = []
        for value in normalized.get("to_aliases") or []:
            text = str(value or "").strip()
            address = normalize_hosted_handle_reference(text, require_agent=True)
            if text.startswith("@") and address != text and "/" in address:
                promoted_addresses.append(address)
            else:
                aliases.append(text)
        if promoted_addresses:
            normalized["to_aliases"] = aliases
            normalized["to_addresses"] = list(normalized.get("to_addresses") or []) + promoted_addresses
        if normalized.get("to_addresses"):
            normalized["to_addresses"] = [
                normalize_hosted_handle_reference(str(value), require_agent=True)
                for value in normalized.get("to_addresses") or []
            ]
        return normalized

    @field_validator("to_aliases", "to_dids", "to_addresses")
    @classmethod
    def _clean_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if value:
                cleaned.append(value)
        return cleaned

    @field_validator("to_aliases")
    @classmethod
    def _validate_aliases(cls, values: list[str]) -> list[str]:
        return [validate_alias_selector(value, field="to_aliases") for value in values]

    @field_validator("to_addresses")
    @classmethod
    def _validate_addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            if value.startswith("@"):
                raise ValueError("Invalid to_addresses format")
        return values

    @model_validator(mode="after")
    def _validate_targets(self) -> "CreateSessionRequest":
        if not self.to_aliases and not self.to_dids and not self.to_addresses:
            raise ValueError("Must provide to_aliases, to_dids, or to_addresses")
        if len(self.to_aliases) != len(set(self.to_aliases)):
            raise ValueError("to_aliases contains duplicates")
        if len(self.to_dids) != len(set(self.to_dids)):
            raise ValueError("to_dids contains duplicates")
        if len(self.to_addresses) != len(set(self.to_addresses)):
            raise ValueError("to_addresses contains duplicates")
        return self

    @field_validator("session_id", "message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None, info: ValidationInfo) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field=str(info.field_name or "message_id"))


class CreateSessionParticipant(BaseModel):
    did: str
    alias: str
    agent_id: str | None = None
    address: str | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    conversation_id: str
    message_id: str
    participants: list[CreateSessionParticipant]
    sse_url: str
    targets_connected: list[str]
    targets_left: list[str]


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_or_send(
    request: Request,
    payload: CreateSessionRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(auth, actor_agent)
    sender_address = _sender_address(auth)
    registry_client = getattr(request.app.state, "awid_registry_client", None)

    target_rows = await _resolve_chat_targets(
        db,
        request=request,
        registry_client=registry_client,
        auth=auth,
        to_aliases=payload.to_aliases,
        to_dids=payload.to_dids,
        to_addresses=payload.to_addresses,
        signed_payload=payload.signed_payload,
        signature=payload.signature,
    )
    target_dids = sorted({_target_did(row) for row in target_rows if _target_did(row)})

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

    requested_session_id = UUID(payload.session_id) if payload.session_id is not None else None
    validation_conversation_id = str(requested_session_id) if requested_session_id is not None else None
    signed_requested_session_id = (
        requested_session_id is not None
        and payload.signature is not None
        and _signed_payload_conversation_id(payload.signed_payload) == str(requested_session_id)
    )
    if len(participant_rows) == 2:
        try:
            existing_session_id = await find_session_between(
                db,
                did_a=participant_rows[0]["did"],
                did_b=participant_rows[1]["did"],
                did_key_a=participant_rows[0].get("did_key"),
                did_key_b=participant_rows[1].get("did_key"),
                agent_id_a=participant_rows[0].get("agent_id"),
                agent_id_b=participant_rows[1].get("agent_id"),
                address_a=participant_rows[0].get("address"),
                address_b=participant_rows[1].get("address"),
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
        _require_remote_chat_signature(payload, session_id=str(requested_session_id))
        from_did = str(payload.from_did or "").strip()
        if from_did not in set(_actor_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        _validate_signed_chat_payload(
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
        msg_created_at = _parse_signed_timestamp(str(payload.timestamp))
        pre_message_id = uuid_mod.UUID(str(payload.message_id))
        route = await _resolve_remote_chat_route(
            db,
            registry_client=registry_client,
            recipient=external_targets[0],
            requester_did_key=auth.did_key,
        )

        remote = await _deliver_federated_chat(
            request,
            payload,
            auth=auth,
            sender_address=sender_address,
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
        msg_row = await send_in_session(
            db,
            session_id=session_id,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            sender_address=sender_address,
            body=payload.message,
            reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
            leaving=payload.leaving,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
        if msg_row is None:
            raise HTTPException(status_code=500, detail="Failed to send message")
        await _record_successful_chat_contacts(
            db,
            owner_did=(auth.did_aw or actor_did).strip(),
            sender_team_id=auth.team_id,
            recipients=[{**external_targets[0], **route}],
        )
        await fire_mutation_hook(
            request,
            "chat.message_sent",
            {
                "team_id": auth.team_id,
                "session_id": str(session_id),
                "conversation_id": str(session_id),
                "message_id": str(msg_row["message_id"]),
                "from_agent_id": actor_agent_id,
                "from_alias": auth.alias or "",
                "from_did": actor_did,
                "from_did_aw": (auth.did_aw or "").strip() or None,
                "to_aliases": [row["alias"] for row in target_rows],
                "preview": payload.message[:80],
                "federated": True,
            },
        )
        return CreateSessionResponse(
            session_id=str(session_id),
            conversation_id=str(session_id),
            message_id=str(msg_row["message_id"]),
            participants=[
                CreateSessionParticipant(
                    did=str(row["did"]),
                    alias=row["alias"],
                    agent_id=str(row["agent_id"]) if row.get("agent_id") else None,
                    address=row.get("address"),
                )
                for row in participant_rows
            ],
            sse_url=f"/v1/chat/sessions/{session_id}/stream",
            targets_connected=[],
            targets_left=[],
        )
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
    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        from_did = payload.from_did.strip()
        if from_did not in set(_actor_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_chat_payload(
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
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
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
        msg_row = await send_in_session(
            db,
            session_id=session_id,
            sender_did=actor_did,
            sender_agent_id=actor_agent_id,
            sender_address=sender_address,
            body=payload.message,
            reply_to=uuid_mod.UUID(payload.reply_to) if payload.reply_to is not None else None,
            leaving=payload.leaving,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail="Failed to send message")

    await _record_successful_chat_contacts(
        db,
        owner_did=(auth.did_aw or actor_did).strip(),
        sender_team_id=auth.team_id,
        recipients=target_rows,
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

    participants_rows = await aweb_db.fetch_all(
        """
        SELECT did, alias, address
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
        ORDER BY alias ASC
        """,
        session_id,
    )
    participant_address_map = await _lookup_addresses_by_did(
        db,
        [(row.get("did") or "").strip() for row in participants_rows],
    )

    targets_left = await _targets_left(db, session_id=session_id, target_dids=target_dids)
    waiting_dids = await get_waiting_agents(redis, str(session_id), target_dids)
    waiting_set = set(waiting_dids)
    targets_connected = [
        row["alias"]
        for row in participants_rows
        if (row.get("did") or "").strip() in waiting_set and (row.get("did") or "").strip() in set(target_dids)
    ]

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "team_id": auth.team_id,
            "session_id": str(session_id),
            "conversation_id": str(session_id),
            "message_id": str(msg_row["message_id"]),
            "from_agent_id": actor_agent_id,
            "from_alias": auth.alias or "",
            "from_did": actor_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_aliases": [
                row["alias"]
                for row in participants_rows
                if (row.get("did") or "").strip() != actor_did
            ],
            "preview": payload.message[:80],
        },
    )

    return CreateSessionResponse(
        session_id=str(session_id),
        conversation_id=str(session_id),
        message_id=str(msg_row["message_id"]),
        participants=[
            {
                "did": str(row["did"]),
                "alias": row["alias"],
                "address": participant_address_map.get((row.get("did") or "").strip())
                or (row.get("address") or "").strip()
                or _address_from_alias(row.get("alias"))
                or None,
            }
            for row in participants_rows
        ],
        sse_url=f"/v1/chat/sessions/{session_id}/stream",
        targets_connected=targets_connected,
        targets_left=targets_left,
    )


class PendingResponse(BaseModel):
    pending: list[dict[str, Any]]
    messages_waiting: int = 0


@router.get("/pending", response_model=PendingResponse)
async def pending(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> PendingResponse:
    del request
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    conversations_by_session: dict[str, dict[str, Any]] = {}
    for participant_did in actor_dids:
        rows = await get_pending_conversations(
            db,
            participant_did=participant_did,
            participant_agent_id=actor_agent_id,
        )
        for row in rows:
            conversations_by_session.setdefault(row["session_id"], row)
    conversations = list(conversations_by_session.values())

    aweb_db = db.get_manager("aweb")
    mail_unread = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.messages}}
        WHERE to_did = ANY($1::text[]) AND read_at IS NULL
        """,
        actor_dids,
    )

    session_ids = [UUID(item["session_id"]) for item in conversations]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.did, p.alias, p.address
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [
            (row.get("did") or "").strip()
            for row in participant_rows
            if (row.get("did") or "").strip()
        ]
        + [
            (item.get("last_from_did") or "").strip()
            for item in conversations
            if (item.get("last_from_did") or "").strip()
        ],
    )
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            item["session_id"]: [did for did in item.get("participant_dids", []) if did not in set(actor_dids)]
            for item in conversations
        },
    )

    pending_items = []
    for item in conversations:
        session_participants = participants_by_session.get(item["session_id"], [])
        waiting = waiting_by_session.get(item["session_id"], [])
        participants = [
            row["alias"]
            for row in session_participants
            if (row.get("did") or "").strip() not in set(actor_dids)
        ]
        participant_addresses = [
            (row.get("address") or "").strip() or routable_chat_address(
                identity_map.get((row.get("did") or "").strip(), {}),
                auth.team_id,
                row["alias"],
            )
            for row in session_participants
            if (row.get("did") or "").strip() not in set(actor_dids)
        ]
        time_remaining_seconds = (
            max(
                0,
                int(item["wait_seconds"] or 0)
                + int(item["extended_wait_seconds"] or 0)
                - int((datetime.now(timezone.utc) - item["wait_started_at"]).total_seconds()),
            )
            if item.get("wait_seconds") is not None and item.get("wait_started_at") is not None and waiting
            else 0
        )
        if int(item["unread_count"] or 0) <= 0 and time_remaining_seconds <= 0:
            continue
        pending_items.append(
            {
                "session_id": item["session_id"],
                "conversation_id": item["session_id"],
                "team_id": item.get("team_id") or "",
                "participants": participants,
                "participant_dids": [
                    (row.get("did") or "").strip()
                    for row in session_participants
                    if (row.get("did") or "").strip() not in set(actor_dids)
                ],
                "participant_addresses": participant_addresses,
                "last_message": item["last_message"],
                "last_from": item["last_from"],
                "last_from_stable_id": identity_map.get(
                    (item.get("last_from_did") or "").strip(), {}
                ).get("stable_id", ""),
                "last_from_did": (item.get("last_from_did") or "").strip(),
                "last_from_address": item.get("last_from_address") or routable_chat_address(
                    identity_map.get((item.get("last_from_did") or "").strip(), {}),
                    auth.team_id,
                    item["last_from"],
                ),
                "unread_count": item["unread_count"],
                "last_activity": _utc_iso(item["last_activity"]) if item["last_activity"] else "",
                "sender_waiting": len(waiting) > 0,
                "time_remaining_seconds": time_remaining_seconds,
            }
        )

    return PendingResponse(pending=pending_items, messages_waiting=int(mail_unread or 0))


class HistoryResponse(BaseModel):
    messages: list[dict[str, Any]]


@router.get("/sessions/{session_id}/messages", response_model=HistoryResponse)
async def history(
    request: Request,
    session_id: str = Path(..., min_length=1),
    unread_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
    message_id: str | None = Query(default=None),
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> HistoryResponse:
    del request
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")

    participant_rows = await aweb_db.fetch_all(
        """
        SELECT p.did, p.alias, p.address
        FROM {{tables.chat_participants}} p
        WHERE session_id = $1
        ORDER BY p.alias ASC
        """,
        session_uuid,
    )

    messages = await get_message_history(
        db,
        session_id=session_uuid,
        participant_did=actor_did,
        unread_only=unread_only,
        limit=limit,
        message_id=message_id,
    )
    contact_addrs = await get_contact_addresses(db, owner_dids=owner_dids)
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [m["from_did"] for m in messages if m.get("from_did")],
    )

    history_items: list[dict[str, Any]] = []
    for msg in messages:
        from_did = (msg.get("from_did") or "").strip()
        from_address = msg.get("from_address") or routable_chat_address(
            identity_map.get(from_did, {}),
            auth.team_id,
            msg["from_alias"],
        )
        history_items.append(
            {
                "conversation_id": str(session_uuid),
                "message_id": msg["message_id"],
                "from_agent": msg["from_alias"],
                "from_address": from_address,
                "body": msg["body"],
                "timestamp": _utc_iso(msg["created_at"]),
                "sender_leaving": msg["sender_leaving"],
                "reply_to": msg.get("reply_to"),
                "to_address": _chat_to_address(participant_rows, from_did=from_did),
                "from_did": from_did or None,
                "from_stable_id": identity_map.get(from_did, {}).get("stable_id") or None,
                "signature": msg.get("signature"),
                "signed_payload": msg.get("signed_payload"),
                "is_contact": is_address_in_contacts(from_address, contact_addrs),
            }
        )

    return HistoryResponse(messages=history_items)


class MarkReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    up_to_message_id: str = Field(..., min_length=1)

    @field_validator("up_to_message_id")
    @classmethod
    def _validate_message_id(cls, v: str) -> str:
        return _parse_uuid(v, field="up_to_message_id")


@router.post("/sessions/{session_id}/read")
async def mark_read(
    request: Request,
    session_id: str,
    payload: MarkReadRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> dict[str, Any]:
    del request
    actor_dids = _actor_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    session_uuid = UUID(session_id.strip())

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")

    result = await mark_messages_read(
        db,
        session_id=session_uuid,
        participant_did=actor_did,
        participant_agent_id=actor_agent_id,
        up_to_message_id=payload.up_to_message_id,
    )
    if int(result["messages_marked"] or 0) > 0:
        await publish_chat_session_signal(
            redis,
            session_id=str(session_uuid),
            signal_type="read_receipt",
            agent_id=actor_did,
            message_id=payload.up_to_message_id,
        )

    return {"success": True, "messages_marked": result["messages_marked"]}


async def _close_session_pubsub(pubsub: PubSub | None, channel: str) -> None:
    if pubsub is None:
        return
    try:
        await pubsub.unsubscribe(channel)
    except Exception:
        pass
    try:
        await pubsub.aclose()
    except Exception:
        pass


async def _sse_events(
    *,
    db,
    redis,
    session_id: UUID,
    viewer_did: str,
    viewer_team_id: str | None,
    contact_owner_dids: list[str],
    deadline: datetime,
    after: datetime | None = None,
) -> AsyncIterator[str]:
    aweb_db = db.get_manager("aweb")
    session_id_str = str(session_id)

    await register_waiting(redis, session_id_str, viewer_did)
    last_refresh = time.monotonic()
    last_keepalive = last_refresh
    last_pubsub_ping = last_refresh
    last_db_poll = last_refresh
    channel = chat_session_channel_name(session_id_str)
    pubsub: PubSub | None = None
    reconnect_delay_seconds = 0.1
    max_reconnect_delay_seconds = 5.0
    next_reconnect_at: float | None = None

    try:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.did, p.alias, p.address
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = $1
            ORDER BY p.alias ASC
            """,
            session_id,
        )
        if not participant_rows:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        viewer_row = next((row for row in participant_rows if (row.get("did") or "").strip() == viewer_did), None)
        if viewer_row is None:
            yield f"event: error\ndata: {json.dumps({'error': 'Session not found'})}\n\n"
            return

        contact_addrs = await get_contact_addresses(db, owner_dids=contact_owner_dids)

        async def _connect_pubsub() -> PubSub:
            ps: PubSub = redis.pubsub()
            await ps.subscribe(channel)
            return ps

        try:
            pubsub = await _connect_pubsub()
            last_pubsub_ping = time.monotonic()
        except RedisError:
            logger.info("Chat session pubsub subscribe failed; using DB fallback polling", exc_info=True)
            next_reconnect_at = time.monotonic() + reconnect_delay_seconds
            reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)

        yield ": keepalive\n\n"
        last_keepalive = time.monotonic()

        if after is not None:
            recent = await aweb_db.fetch_all(
                """
                SELECT message_id, from_agent_id, from_alias, from_address, body, created_at,
                       sender_leaving, hang_on, reply_to, from_did, signature, signed_payload
                FROM {{tables.chat_messages}}
                WHERE session_id = $1 AND created_at > $2
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                after,
            )
            last_message_at = recent[-1]["created_at"] if recent else after
            sender_dids = [str(r["from_did"]) for r in recent if r.get("from_did")]
            waiting = set(await get_waiting_agents(redis, session_id_str, list(set(sender_dids))))
            identity_map = await lookup_identity_metadata_by_did(db, sender_dids)
            for row in recent:
                is_hang_on = bool(row["hang_on"])
                from_did = (row.get("from_did") or "").strip()
                from_address = row.get("from_address") or routable_chat_address(
                    identity_map.get(from_did, {}),
                    viewer_team_id,
                    row["from_alias"],
                )
                payload = {
                    "type": "message",
                    "session_id": session_id_str,
                    "conversation_id": session_id_str,
                    "message_id": str(row["message_id"]),
                    "from_agent": row["from_alias"],
                    "from_address": from_address,
                    "from_stable_id": identity_map.get(from_did, {}).get("stable_id") or None,
                    "body": row["body"],
                    "sender_leaving": bool(row["sender_leaving"]),
                    "sender_waiting": from_did in waiting,
                    "hang_on": is_hang_on,
                    "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                    "reply_to": str(row["reply_to"]) if row.get("reply_to") is not None else None,
                    "timestamp": _utc_iso(row["created_at"]),
                    "to_address": _chat_to_address(participant_rows, from_did=from_did),
                    "from_did": row.get("from_did"),
                    "signature": row.get("signature"),
                    "signed_payload": row.get("signed_payload"),
                    "is_contact": is_address_in_contacts(from_address, contact_addrs),
                }
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
        else:
            last_message_at = datetime.now(timezone.utc)

        last_receipt_at = datetime.now(timezone.utc)
        last_db_poll = time.monotonic()

        while datetime.now(timezone.utc) < deadline:
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, viewer_did)
                last_refresh = now_mono

            if pubsub is None and (next_reconnect_at is None or now_mono >= next_reconnect_at):
                try:
                    pubsub = await _connect_pubsub()
                    reconnect_delay_seconds = 0.1
                    next_reconnect_at = None
                    last_pubsub_ping = time.monotonic()
                except RedisError:
                    logger.info("Chat session pubsub reconnect failed; using DB fallback polling", exc_info=True)
                    next_reconnect_at = now_mono + reconnect_delay_seconds
                    reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)

            should_poll = now_mono - last_db_poll >= CHAT_STREAM_FALLBACK_POLL_SECONDS
            if not should_poll:
                wait_timeout = min(1.0, max(0.0, CHAT_STREAM_FALLBACK_POLL_SECONDS - (now_mono - last_db_poll)))
                if pubsub is not None:
                    try:
                        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=wait_timeout)
                    except RedisConnectionError:
                        logger.info("Chat session pubsub connection dropped; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                        message = None
                    except RedisError:
                        logger.warning("Chat session pubsub error; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = time.monotonic() + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                        message = None
                    if message is not None and message["type"] == "message":
                        should_poll = True
                else:
                    await asyncio.sleep(wait_timeout)

            if should_poll:
                new_msgs = await aweb_db.fetch_all(
                    """
                    SELECT message_id, from_agent_id, from_alias, from_address, body, created_at,
                           sender_leaving, hang_on, reply_to, from_did, signature, signed_payload
                    FROM {{tables.chat_messages}}
                    WHERE session_id = $1 AND created_at > $2
                    ORDER BY created_at ASC
                    LIMIT 200
                    """,
                    session_id,
                    last_message_at,
                )
                sender_dids = list({str(row["from_did"]) for row in new_msgs if row.get("from_did")})
                sender_waiting = set(await get_waiting_agents(redis, session_id_str, sender_dids)) if sender_dids else set()
                identity_map = await lookup_identity_metadata_by_did(db, sender_dids)
                for row in new_msgs:
                    last_message_at = max(last_message_at, row["created_at"])
                    is_hang_on = bool(row["hang_on"])
                    from_did = (row.get("from_did") or "").strip()
                    from_address = row.get("from_address") or routable_chat_address(
                        identity_map.get(from_did, {}),
                        viewer_team_id,
                        row["from_alias"],
                    )
                    payload = {
                        "type": "message",
                        "session_id": session_id_str,
                        "conversation_id": session_id_str,
                        "message_id": str(row["message_id"]),
                        "from_agent": row["from_alias"],
                        "from_address": from_address,
                        "from_stable_id": identity_map.get(from_did, {}).get("stable_id") or None,
                        "body": row["body"],
                        "sender_leaving": bool(row["sender_leaving"]),
                        "sender_waiting": from_did in sender_waiting,
                        "hang_on": is_hang_on,
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS if is_hang_on else 0,
                        "reply_to": str(row["reply_to"]) if row.get("reply_to") is not None else None,
                        "timestamp": _utc_iso(row["created_at"]),
                        "to_address": _chat_to_address(participant_rows, from_did=from_did),
                        "from_did": row.get("from_did"),
                        "signature": row.get("signature"),
                        "signed_payload": row.get("signed_payload"),
                        "is_contact": is_address_in_contacts(from_address, contact_addrs),
                    }
                    yield f"event: message\ndata: {json.dumps(payload)}\n\n"

                receipts = await aweb_db.fetch_all(
                    """
                    SELECT rr.did, rr.last_read_message_id, rr.last_read_at, p.alias
                    FROM {{tables.chat_read_receipts}} rr
                    JOIN {{tables.chat_participants}} p
                      ON p.session_id = rr.session_id AND p.did = rr.did
                    WHERE rr.session_id = $1
                      AND rr.did <> $2
                      AND rr.last_read_at IS NOT NULL
                      AND rr.last_read_at > $3
                    ORDER BY rr.last_read_at ASC
                    """,
                    session_id,
                    viewer_did,
                    last_receipt_at,
                )
                for row in receipts:
                    last_receipt_at = max(last_receipt_at, row["last_read_at"])
                    payload = {
                        "type": "read_receipt",
                        "session_id": session_id_str,
                        "conversation_id": session_id_str,
                        "reader_alias": row["alias"],
                        "up_to_message_id": str(row["last_read_message_id"]) if row["last_read_message_id"] else "",
                        "extends_wait_seconds": HANG_ON_EXTENSION_SECONDS,
                        "timestamp": _utc_iso(row["last_read_at"]),
                    }
                    yield f"event: read_receipt\ndata: {json.dumps(payload)}\n\n"

                last_db_poll = time.monotonic()

            current_time = time.monotonic()
            if current_time - last_keepalive >= CHAT_STREAM_KEEPALIVE_SECONDS:
                if pubsub is not None and current_time - last_pubsub_ping >= CHAT_STREAM_KEEPALIVE_SECONDS:
                    try:
                        await pubsub.ping()
                        last_pubsub_ping = current_time
                    except RedisError:
                        logger.info("Chat session pubsub ping failed; using DB fallback polling", exc_info=True)
                        await _close_session_pubsub(pubsub, channel)
                        pubsub = None
                        next_reconnect_at = current_time + reconnect_delay_seconds
                        reconnect_delay_seconds = min(max_reconnect_delay_seconds, reconnect_delay_seconds * 2)
                yield ": keepalive\n\n"
                last_keepalive = current_time
    finally:
        await _close_session_pubsub(pubsub, channel)
        await unregister_waiting(redis, session_id_str, viewer_did)


@router.get("/sessions/{session_id}/stream")
async def stream(
    request: Request,
    session_id: str,
    deadline: str = Query(..., min_length=1),
    after: str | None = Query(None),
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    del request
    actor_dids = _actor_dids(auth)
    owner_dids = _actor_dids(auth)
    if not owner_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=403, detail="Not a participant in this session")

    deadline_dt = _parse_deadline(deadline)
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_CHAT_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline

    after_dt = _parse_timestamp(after, "after") if after is not None else None
    await register_waiting(redis, str(session_uuid), actor_did)

    return StreamingResponse(
        _sse_events(
            db=db,
            redis=redis,
            session_id=session_uuid,
            viewer_did=actor_did,
            viewer_team_id=auth.team_id,
            contact_owner_dids=owner_dids,
            deadline=deadline_dt,
            after=after_dt,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1)
    leaving: bool = False
    hang_on: bool = False
    wait_seconds: int | None = Field(default=None, ge=0, le=600)
    reply_to: str | None = None
    message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None

    @field_validator("message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="message_id")


class SendMessageResponse(BaseModel):
    message_id: str
    conversation_id: str
    delivered: bool
    extends_wait_seconds: int = 0


@router.post("/sessions/{session_id}/messages", response_model=SendMessageResponse)
async def send_message(
    request: Request,
    session_id: str = Path(..., min_length=1),
    payload: SendMessageRequest = ...,
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    sender_address = _sender_address(auth)

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid id format")

    aweb_db = db.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    actor_did = await _resolve_session_actor_did(db, session_id=session_uuid, actor_dids=actor_dids)
    if not actor_did:
        raise HTTPException(status_code=404, detail="Session not found")
    recipient_rows = await _resolve_session_recipient_rows(db, session_id=session_uuid, actor_dids=actor_dids)
    for row in recipient_rows:
        if (
            str(row.get("did") or "").startswith("did:key:")
            and not _target_delivery_origin(row)
            and not row.get("local_resolved")
        ):
            raise HTTPException(status_code=422, detail="Local did:key recipient requires local resolution or learned return route")
    for index, row in enumerate(recipient_rows):
        if not _target_delivery_origin(row):
            continue
        route = await _resolve_stored_remote_chat_route(
            registry_client=getattr(request.app.state, "awid_registry_client", None),
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
            if _target_delivery_origin(row) or not row.get("local_resolved"):
                continue
            await authorize_message_delivery(
                db,
                recipient_agent=row,
                sender_did=actor_did,
                sender_address=sender_address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
                sender_verified_dids=auth_dids(auth),
                stored_route_continuation=True,
            )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    msg_created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()
    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        from_did = payload.from_did.strip()
        if from_did not in set(_actor_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_chat_payload(
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
        msg_created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    remote_recipients = [row for row in recipient_rows if _target_delivery_origin(row)]
    if remote_recipients:
        if len(recipient_rows) != 1 or len(remote_recipients) != 1:
            raise HTTPException(status_code=422, detail="Federated chat continuation requires exactly one remote recipient")
        route = remote_recipients[0]
        try:
            remote = await _deliver_federated_chat(
                request,
                payload,
                auth=auth,
                sender_address=sender_address,
                route=route,
                session_id=str(session_uuid),
            )
        except HTTPException as exc:
            if not _is_stale_delivery_origin_status(exc.status_code):
                raise
            refreshed_route = await _resolve_remote_chat_route(
                db,
                registry_client=getattr(request.app.state, "awid_registry_client", None),
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
            remote = await _deliver_federated_chat(
                request,
                payload,
                auth=auth,
                sender_address=sender_address,
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
            msg_row = await send_in_session(
                db,
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
                created_at=msg_created_at,
                message_id=pre_message_id,
            )
        except Exception as exc:
            if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
                raise HTTPException(status_code=409, detail="message_id already exists")
            raise
        if msg_row is None:
            raise HTTPException(status_code=500, detail="Failed to send message")
        await _record_successful_chat_contacts(
            db,
            owner_did=(auth.did_aw or actor_did).strip(),
            sender_team_id=auth.team_id,
            recipients=remote_recipients,
        )
        await fire_mutation_hook(
            request,
            "chat.message_sent",
            {
                "team_id": auth.team_id,
                "session_id": str(session_uuid),
                "conversation_id": str(session_uuid),
                "message_id": str(msg_row["message_id"]),
                "from_agent_id": actor_agent_id,
                "from_alias": auth.alias or "",
                "from_did": actor_did,
                "from_did_aw": (auth.did_aw or "").strip() or None,
                "to_aliases": [row["alias"] for row in recipient_rows],
                "preview": payload.body[:80],
                "federated": True,
            },
        )
        return SendMessageResponse(
            message_id=str(msg_row["message_id"]),
            conversation_id=str(session_uuid),
            delivered=True,
            extends_wait_seconds=HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0,
        )

    try:
        msg_row = await send_in_session(
            db,
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
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
    except Exception as exc:
        if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise
    if msg_row is None:
        raise HTTPException(status_code=500, detail="Failed to send message")

    await fire_mutation_hook(
        request,
        "chat.message_sent",
        {
            "team_id": auth.team_id,
            "session_id": str(session_uuid),
            "conversation_id": str(session_uuid),
            "message_id": str(msg_row["message_id"]),
            "from_agent_id": actor_agent_id,
            "from_alias": auth.alias or "",
            "from_did": actor_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_aliases": [row["alias"] for row in recipient_rows],
            "preview": payload.body[:80],
        },
    )

    return SendMessageResponse(
        message_id=str(msg_row["message_id"]),
        conversation_id=str(session_uuid),
        delivered=True,
        extends_wait_seconds=HANG_ON_EXTENSION_SECONDS if payload.hang_on else 0,
    )


class SessionListItem(BaseModel):
    session_id: str
    conversation_id: str
    team_id: str = ""
    participants: list[str]
    participant_dids: list[str] = Field(default_factory=list)
    participant_addresses: list[str] = Field(default_factory=list)
    created_at: str
    last_activity: str
    sender_waiting: bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionListItem]


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SessionListResponse:
    del request
    actor_dids = _actor_dids(auth)
    actor_did = actor_dids[0] if actor_dids else ""
    if not actor_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    aweb_db = db.get_manager("aweb")
    rows_by_session: dict[str, Any] = {}
    for participant_did in actor_dids:
        rows = await aweb_db.fetch_all(
            """
            SELECT s.session_id, s.created_at,
                   s.team_id,
                   COALESCE(MAX(m.created_at), s.created_at) AS last_activity,
                   array_agg(DISTINCT p2.alias ORDER BY p2.alias) AS participants,
                   array_agg(DISTINCT p2.did ORDER BY p2.did) AS participant_dids
            FROM {{tables.chat_sessions}} s
            JOIN {{tables.chat_participants}} p
              ON p.session_id = s.session_id AND p.did = $1
            JOIN {{tables.chat_participants}} p2
              ON p2.session_id = s.session_id
            LEFT JOIN {{tables.chat_messages}} m
              ON m.session_id = s.session_id
            GROUP BY s.session_id, s.team_id, s.created_at
            ORDER BY last_activity DESC, s.created_at DESC
            """,
            participant_did,
        )
        for row in rows:
            rows_by_session.setdefault(str(row["session_id"]), row)
    rows = list(rows_by_session.values())
    rows.sort(key=lambda row: (row["last_activity"], row["created_at"]), reverse=True)

    session_ids = [row["session_id"] for row in rows]
    participant_rows: list[dict[str, Any]] = []
    if session_ids:
        participant_rows = await aweb_db.fetch_all(
            """
            SELECT p.session_id, p.did, p.alias, p.address
            FROM {{tables.chat_participants}} p
            WHERE p.session_id = ANY($1::uuid[])
            ORDER BY p.session_id, p.alias
            """,
            session_ids,
        )
    participants_by_session = _group_participants_by_session(participant_rows)
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [(row.get("did") or "").strip() for row in participant_rows if (row.get("did") or "").strip()],
    )
    waiting_by_session = await get_waiting_agents_by_session(
        redis,
        {
            str(row["session_id"]): [did for did in (row["participant_dids"] or []) if did not in set(actor_dids)]
            for row in rows
        },
    )

    sessions = []
    for row in rows:
        session_participants = participants_by_session.get(str(row["session_id"]), [])
        waiting = waiting_by_session.get(str(row["session_id"]), [])
        sessions.append(
            SessionListItem(
                session_id=str(row["session_id"]),
                conversation_id=str(row["session_id"]),
                team_id=row["team_id"] or "",
                participants=[
                    participant["alias"]
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in set(actor_dids)
                ],
                participant_dids=[
                    (participant.get("did") or "").strip()
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in set(actor_dids)
                ],
                participant_addresses=[
                    (participant.get("address") or "").strip() or routable_chat_address(
                        identity_map.get((participant.get("did") or "").strip(), {}),
                        auth.team_id,
                        participant["alias"],
                    )
                    for participant in session_participants
                    if (participant.get("did") or "").strip() not in set(actor_dids)
                ],
                created_at=_utc_iso(row["created_at"]),
                last_activity=_utc_iso(row["last_activity"]),
                sender_waiting=len(waiting) > 0,
            )
        )

    return SessionListResponse(sessions=sessions)
