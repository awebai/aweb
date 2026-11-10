from __future__ import annotations

from aweb.agent_wake import agent_wake_publisher, agent_wake_scope, record_did_wakes
from aweb.federation.origins import public_origins
from aweb.messaging.mail_attribution import incoming_mail_sql, readable_mail_sql

from aweb.identity_auth_deps import participant_dids
from aweb.attachment_service import prepare_attachment_send, attachment_retry, attachment_references_by_message

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from awid.federation_errors import FederationAuthorityError
from awid.pagination import decode_cursor, encode_cursor, validate_pagination_params
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS, awid_registry_not_configured_exception
from aweb.deps import get_db
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.hooks import fire_mutation_hook
from aweb.id_chain_auth import stored_id_chain
from aweb.identity_metadata import lookup_identity_metadata_by_did
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth
from aweb.messaging.sender_address import sender_address as _sender_address
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
    identity_recipient,
    local_recipient_for_address_binding,
    local_recipient_visible_to_auth,
    namespace_uses_home_registry,
    refuse_same_origin_nonresident,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.conversations import (
    get_conversation,
)
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.participant_succession import predecessor_target_for_mail
from aweb.messaging.mail_send import (
    SentMail,
    _create_mail_conversation,
    _lost_send_race,
    _parse_signed_timestamp,
    _stored_exact_send,
    _validate_encrypted_payload,
    _validate_signed_mail_payload,
    deliver_remote_mail_and_project_locally,
    record_successful_contact_side_effect,
    send_federated_mail_conversation_continuation,
    send_mail_conversation_continuation,
)
from aweb.messaging.runtime import messaging_runtime
from aweb.messaging.mail_routing import (
    explicit_mail_target_matches_participant,
    mail_continuation_context,
    participant_is_remote,
)
from aweb.messaging.messages import (
    MessagePriority,
    authorize_message_delivery,
    deliver_message,
    get_agent_by_id,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)
from aweb.messaging.verification import (
    message_verification_status,
)
from aweb.db import TransactionInfra
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL, ConflictError, ForbiddenError, NotFoundError, ValidationError

from aweb.messaging.participants import messaging_participant_by_alias
from aweb.messaging.sender_membership import SenderMembership, sender_memberships

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


async def _resolve_message_alias(db, auth: MessagingAuth, raw_alias: str, registry_client=None) -> dict | None:
    target = resolve_alias_target(auth.team_id, raw_alias, field="to_alias")
    if "~" in str(raw_alias or "") and not await team_exists(db, target.team_id):
        raise HTTPException(status_code=404, detail=f"Unknown team: {target.team_id}")
    return await messaging_participant_by_alias(db, team_id=target.team_id, alias=target.alias,
                                              selected_team_id=auth.team_id, registry_client=registry_client)


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1)
    to_did: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_stable_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_address: Optional[str] = Field(default=None, min_length=1, max_length=256)
    conversation_id: Optional[str] = None
    new_conversation: bool = False  # Accepted no-op; conversation_id alone selects continuation.
    subject: str = ""
    body: str = ""
    content_mode: Optional[str] = None
    message_version: Optional[int] = None
    encrypted_envelope: Optional[dict] = None
    priority: MessagePriority = "normal"
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
    signed_payload: Optional[str] = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="after")
    def _validate_content_mode(self):
        is_encrypted = (
            self.content_mode == "encrypted_v2"
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if is_encrypted:
            if self.content_mode != "encrypted_v2":
                raise ValueError("content_mode must be encrypted_v2 for encrypted messages")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted messages")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted messages")
            if self.subject or self.body:
                raise ValueError("encrypted messages must not include plaintext subject or body")
        elif self.body == "":
            raise ValueError("body is required for legacy plaintext mail")
        return self

    @model_validator(mode="before")
    @classmethod
    def _normalize_hosted_handle_targets(cls, data):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        to_alias = str(normalized.get("to_alias") or "").strip()
        if to_alias.startswith("@"):
            address = normalize_hosted_handle_reference(to_alias, require_agent=True)
            if address != to_alias and "/" in address and not normalized.get("to_address"):
                normalized["to_address"] = address
                normalized.pop("to_alias", None)
        if normalized.get("to_address") is not None:
            normalized["to_address"] = normalize_hosted_handle_reference(
                str(normalized["to_address"]),
                require_agent=True,
            )
        return normalized

    @field_validator("to_agent_id")
    @classmethod
    def _validate_agent_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid agent_id format")

    @field_validator("to_alias")
    @classmethod
    def _validate_to_alias(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_alias_selector(v, field="to_alias")

    @field_validator("to_address")
    @classmethod
    def _validate_to_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip()
        if value.startswith("@"):
            raise ValueError("Invalid to_address format")
        return value

    @field_validator("message_id")
    @classmethod
    def _validate_message_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid message_id format")

    @field_validator("conversation_id")
    @classmethod
    def _validate_conversation_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid conversation_id format")


class SendMessageResponse(BaseModel):
    message_id: str
    conversation_id: Optional[str] = None
    status: str
    delivered_at: str


class InboxMessage(BaseModel):
    id_chain: dict | None = None
    attachment_refs: list[dict] = Field(default_factory=list)
    sender_membership: SenderMembership | None = None
    message_id: str
    conversation_id: Optional[str] = None
    from_agent_id: Optional[str] = None
    from_alias: str
    to_alias: str
    subject: Optional[str] = None
    body: Optional[str] = None
    content_mode: str = "legacy_plaintext_v1"
    message_version: int = 1
    encrypted_envelope: Optional[dict] = None
    priority: MessagePriority
    read_at: Optional[str]
    created_at: str
    from_did: Optional[str] = None
    to_did: Optional[str] = None
    from_stable_id: Optional[str] = None
    to_stable_id: Optional[str] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    signature: Optional[str] = None
    signed_payload: Optional[str] = None
    verification_status: Optional[str] = None

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        data = handler(self)
        if self.content_mode != "legacy_plaintext_v1":
            data.pop("subject", None)
            data.pop("body", None)
        return data


class InboxResponse(BaseModel):
    messages: list[InboxMessage]
    has_more: bool = False
    next_cursor: Optional[str] = None


class MailConversationResponse(InboxResponse):
    after_cursor: str | None = None


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


async def _inbox_response_from_rows(
    request,
    db,
    rows,
    *,
    has_more: bool = False,
    next_cursor: str | None = None,
    sender_member_rows: list[dict] | None = None,
) -> InboxResponse:
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [
            str(value).strip()
            for row in rows
            for value in (row.get("from_did"), row.get("to_did"))
            if value
        ],
    )

    memberships = await sender_memberships(request, db, rows, member_rows=sender_member_rows)
    attachment_refs = await attachment_references_by_message(
        db, "mail",
        [r["message_id"] for r in rows if str(r.get("content_mode") or "") == "encrypted_v2"],
    )
    messages = []
    for r in rows:
        from_did = (r.get("from_did") or "").strip()
        to_did = (r.get("to_did") or "").strip()
        content_mode = str(r.get("content_mode") or "legacy_plaintext_v1")
        encrypted_envelope = r.get("encrypted_envelope")
        if isinstance(encrypted_envelope, str):
            encrypted_envelope = json.loads(encrypted_envelope)
        messages.append(
            InboxMessage(
                attachment_refs=attachment_refs.get(str(r["message_id"]), []),
                sender_membership=memberships[(str(r.get("team_id") or ""), str(r.get("from_agent_id") or ""))],
                message_id=str(r["message_id"]),
                conversation_id=(str(r["conversation_id"]) if r.get("conversation_id") else None),
                from_agent_id=(str(r["from_agent_id"]) if r.get("from_agent_id") else None),
                from_alias=r["from_alias"],
                to_alias=r["to_alias"],
                subject=(r["subject"] if content_mode == "legacy_plaintext_v1" else ""),
                body=(r["body"] if content_mode == "legacy_plaintext_v1" else ""),
                content_mode=content_mode,
                message_version=int(r.get("message_version") or 1),
                encrypted_envelope=(dict(encrypted_envelope) if encrypted_envelope is not None else None),
                priority=r["priority"],
                read_at=r["read_at"].isoformat() if r.get("read_at") else None,
                created_at=r["created_at"].isoformat(),
                from_did=from_did or None,
                to_did=to_did or None,
                from_stable_id=(identity_map.get(from_did, {}).get("stable_id") or None),
                to_stable_id=(identity_map.get(to_did, {}).get("stable_id") or None),
                from_address=(r.get("from_address") or identity_map.get(from_did, {}).get("address") or None),
                to_address=(identity_map.get(to_did, {}).get("address") or None),
                signature=r.get("signature"),
                signed_payload=r.get("signed_payload"),
                id_chain=stored_id_chain(r.get("id_chain")),
                verification_status=message_verification_status(dict(r)),
            )
        )

    return InboxResponse(messages=messages, has_more=has_more, next_cursor=next_cursor)


def _mail_conversation_cursor(conversation_id: UUID, order: str, row) -> str:
    return encode_cursor({
        "kind": "mail_conversation",
        "conversation_id": str(conversation_id),
        "order": order,
        "created_at": row["created_at"].isoformat(),
        "message_id": str(row["message_id"]),
    })


def _mail_conversation_boundary(
    cursor: str | None, conversation_id: UUID, order: str,
) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    try:
        data = decode_cursor(cursor)
        if (not data or data.get("kind") != "mail_conversation"
                or data.get("conversation_id") != str(conversation_id)
                or data.get("order") != order):
            raise ValueError("Cursor scope or order mismatch")
        created_at = datetime.fromisoformat(data["created_at"])
        message_id = UUID(data["message_id"])
        if created_at.tzinfo is None:
            raise ValueError("Cursor timestamp must be timezone-aware")
        # Normalize before passing to asyncpg, including range validation for
        # timezone offsets at datetime's minimum/maximum supported year.
        return created_at.astimezone(timezone.utc), message_id
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        raise HTTPException(status_code=422, detail="Invalid mail conversation cursor") from exc


@router.get("/conversations/{conversation_id}", response_model=MailConversationResponse)
async def get_mail_conversation(
    request: Request,
    conversation_id: str,
    db=Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    order: Annotated[Literal["asc", "desc"], Query()] = "asc",
    cursor: Annotated[str | None, Query()] = None,
    after: Annotated[str | None, Query()] = None,
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> MailConversationResponse:
    aweb_db = db.get_manager("aweb")
    actor_dids = participant_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        conv_uuid = UUID(conversation_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid conversation_id format")

    conversation = await aweb_db.fetch_one(
        """
        SELECT conversation_id, conversation_type
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        conv_uuid,
    )
    if conversation:
        participant = await aweb_db.fetch_one(
            """
            SELECT 1
            FROM {{tables.conversation_participants}}
            WHERE conversation_id = $1
              AND did = ANY($2::text[])
            LIMIT 1
            """,
            conv_uuid,
            actor_dids,
        )
        if not participant:
            raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        if conversation["conversation_type"] != "mail":
            raise HTTPException(status_code=422, detail="Conversation is not a mail conversation")
        # A cursor selects a position, never an identity or authorization scope.
        # Keep the participant check above on every page, even for forged cursors.
        if after is not None and (cursor is not None or order != "asc"):
            raise HTTPException(status_code=422, detail="after requires order=asc and cannot be combined with cursor")
        boundary = _mail_conversation_boundary(after if after is not None else cursor, conv_uuid, order)
        params: list = [conv_uuid]
        where = "WHERE m.conversation_id = $1"
        if boundary is not None:
            params.extend(boundary)
            comparison = "<" if order == "desc" else ">"
            where += f" AND (m.created_at, m.message_id) {comparison} ($2, $3)"
        direction = "DESC" if order == "desc" else "ASC"
        rows = await aweb_db.fetch_all(
            f"""
            SELECT m.team_id, m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
                   m.subject, m.body, m.priority, m.read_at, m.created_at,
                   m.from_did, m.to_did, m.signature, m.signed_payload, m.id_chain, m.conversation_id,
                   m.content_mode, m.message_version, m.encrypted_envelope
            FROM {{{{tables.messages}}}} m
            {where}
            ORDER BY m.created_at {direction}, m.message_id {direction}
            LIMIT ${len(params) + 1}
            """,
            *params,
            limit + 1,
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = _mail_conversation_cursor(conv_uuid, order, rows[-1]) if has_more else None
        # The polling watermark never advances beyond a returned row. Empty
        # polls preserve it so the client can keep waiting at the same boundary.
        after_cursor = after
        if rows:
            newest = rows[0] if order == "desc" else rows[-1]
            after_cursor = _mail_conversation_cursor(conv_uuid, "asc", newest)
        response = await _inbox_response_from_rows(request, db, rows, has_more=has_more, next_cursor=next_cursor)
        return MailConversationResponse(
            messages=response.messages, has_more=response.has_more,
            next_cursor=response.next_cursor, after_cursor=after_cursor,
        )

    legacy_rows = await aweb_db.fetch_all(
        """
        SELECT m.team_id, m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload, m.id_chain, m.conversation_id,
               m.content_mode, m.message_version, m.encrypted_envelope
        FROM {{tables.messages}} m
        WHERE m.message_id = $1
          AND (m.from_did = ANY($2::text[]) OR m.to_did = ANY($2::text[]))
        ORDER BY m.created_at ASC, m.message_id ASC
        LIMIT $3
        """,
        conv_uuid,
        actor_dids,
        limit,
    )
    if legacy_rows:
        raise HTTPException(
            status_code=404,
            detail="This is a legacy mail without a conversation; use --message-id",
        )
    raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)


def _external_recipient_from_address(address: str, resolution) -> dict:
    _, name = address.split("/", 1)
    delivery = getattr(resolution, "delivery", None)
    delivery_origin = (
        getattr(resolution, "delivery_origin", None)
        or getattr(delivery, "origin", "")
        or ""
    )
    return {
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
    }


def _raise_bare_did_first_contact_unsupported() -> None:
    raise HTTPException(
        status_code=422,
        detail="Bare did:aw first-contact is unsupported; use to_address=domain/name or continue an existing conversation",
    )


def _recipient_transport_hint(payload: SendMessageRequest) -> str:
    if payload.to_address is not None:
        return "to_address"
    if payload.to_stable_id is not None:
        return "to_stable_id"
    if payload.to_did is not None:
        return "to_did"
    if payload.to_agent_id is not None:
        return "to_agent_id"
    if payload.to_alias is not None:
        return "to_alias"
    return "mail"


def _recipient_conversation_address(recipient: dict | None, payload: SendMessageRequest) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    if requested_address:
        return requested_address
    return derive_team_address(
        str((recipient or {}).get("team_id") or ""),
        str((recipient or {}).get("alias") or ""),
    ) or None


async def _local_recipient_from_address(db, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _recipient_identity_matches(left: dict | None, right: dict | None) -> bool:
    if left is None or right is None:
        return False
    left_did = str(left.get("did_aw") or left.get("did_key") or "").strip()
    right_did = str(right.get("did_aw") or right.get("did_key") or "").strip()
    return bool(left_did and right_did and left_did == right_did)


def _signed_payload_matches_address_binding(
    payload: dict | None,
    *,
    address: str,
    recipient: dict,
) -> bool:
    if not isinstance(payload, dict) or payload.get("type") != "mail":
        return False
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to != address:
        return False
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_current_did = str(recipient.get("did_key") or "").strip()
    signed_to_did = str(payload.get("to_did") or "").strip()
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if not signed_to_did and not signed_to_stable_id:
        return False
    if signed_to_did and signed_to_did not in {recipient_stable_id, recipient_current_did}:
        return False
    if signed_to_stable_id and signed_to_stable_id != recipient_stable_id:
        return False
    return bool(recipient_stable_id or recipient_current_did)


async def _bound_recipient_from_address(
    db,
    *,
    registry_client,
    auth: MessagingAuth,
    address: str,
    expected_recipient: dict | None = None,
    signed_payload: str | None = None,
    signature: str | None = None,
) -> dict | None:
    if "/" not in address:
        raise HTTPException(status_code=422, detail="to_address must be domain/name")
    domain, name = address.split("/", 1)
    if registry_client is not None:
        resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolved is not None and resolved.did_aw:
            bound_recipient = await resolve_agent_by_did(db, resolved.did_aw)
            if bound_recipient is not None:
                return bound_recipient
    local_recipient = await _local_recipient_from_address(db, domain=domain, name=name)
    if requires_registry_address_binding(local_recipient):
        if local_recipient_visible_to_auth(local_recipient, auth):
            return local_recipient
        if registry_client is None:
            return local_recipient
        if (
            expected_recipient is not None
            and _recipient_identity_matches(local_recipient, expected_recipient)
            and _signed_payload_matches_address_binding(
                verified_signed_payload_json(
                    signed_payload=signed_payload,
                    signature=signature,
                    did_key=auth.did_key,
                ),
                address=address,
                recipient=local_recipient,
            )
        ):
            return local_recipient
        raise HTTPException(status_code=404, detail="Recipient address not found")
    return local_recipient


def _send_response(sent: SentMail) -> SendMessageResponse:
    return SendMessageResponse(**asdict(sent))


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    from aweb.human_channels.http import ingress_requested, accept_native_http

    if ingress_requested(request):
        accepted = await accept_native_http(
            request, payload, auth=auth, db=db, kind="mail"
        )
        row = await db.get_manager("aweb").fetch_one(
            "SELECT created_at FROM {{tables.messages}} WHERE message_id=$1",
            UUID(accepted["message_id"]),
        )
        return SendMessageResponse(
            message_id=accepted["message_id"],
            conversation_id=accepted["conversation_id"],
            status="delivered",
            delivered_at=row["created_at"].isoformat(),
        )
    attachment_context = prepare_attachment_send(request, payload, auth)
    if attachment_context is not None:
        with attachment_context:
            existing = await attachment_retry(db, payload, "mail")
            if existing:
                binding, row = existing
                return SendMessageResponse(message_id=binding.message_id, conversation_id=binding.conversation_id,
                                           status="delivered", delivered_at=row["created_at"].isoformat())
            return await send_message(request, payload, db=db, auth=auth)
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    id_chain = getattr(getattr(request, "state", None), "id_chain", None)
    sender_address = _sender_address(auth)
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

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
        return _send_response(await send_mail_conversation_continuation(
            messaging_runtime(request.app.state),
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            conversation_id=payload.conversation_id,
        ))

    if has_explicit_recipient and payload.conversation_id is not None:
        requested_conversation = await get_conversation(db, conversation_id=payload.conversation_id)
        if requested_conversation is not None:
            try:
                requested_continuation = await mail_continuation_context(
                    db,
                    conversation_id=payload.conversation_id,
                    sender_did=sender_did,
                    equivalent_dids=participant_dids(auth),
                )
            except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
            target_matches = await explicit_mail_target_matches_participant(
                db, requested_continuation.recipient_participant,
                to_agent_id=payload.to_agent_id,
                to_alias=payload.to_alias,
                to_did=payload.to_did,
                to_stable_id=payload.to_stable_id,
                to_address=payload.to_address,
            )
            if (not target_matches and payload.encrypted_envelope is None
                    and payload.to_agent_id is None and payload.to_alias is None
                    and payload.to_address is None):
                signed = verified_signed_payload_json(
                    signed_payload=payload.signed_payload, signature=payload.signature,
                    did_key=auth.did_key,
                )
                historical = await predecessor_target_for_mail(
                    db, conversation_id=payload.conversation_id,
                    successor_did=requested_continuation.recipient_participant["did"],
                    signed=signed,
                ) if signed is not None else None
                if historical is not None:
                    identities = {historical["did_key"], historical["did_aw"]} - {None}
                    target_matches = all(
                        value is None or value in identities
                        for value in (payload.to_did, payload.to_stable_id)
                    )
            if not target_matches:
                raise HTTPException(
                    status_code=409,
                    detail="conversation_id recipient does not match the requested recipient",
                )
            if not participant_is_remote(requested_continuation.recipient_participant):
                return _send_response(await send_mail_conversation_continuation(
                    messaging_runtime(request.app.state),
                    payload,
                    db,
                    auth=auth,
                    registry_client=registry_client,
                    sender_address=sender_address,
                    sender_did=sender_did,
                    id_chain=id_chain,
                    conversation_id=payload.conversation_id,
                ))
            return _send_response(await send_federated_mail_conversation_continuation(
                messaging_runtime(request.app.state),
                payload,
                db,
                auth=auth,
                registry_client=registry_client,
                sender_address=sender_address,
                sender_did=sender_did,
                id_chain=id_chain,
                continuation=requested_continuation,
            ))

    recipient = None
    recipient_did: str | None = None
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if payload.to_address is None and payload.to_stable_id is not None:
        recipient_did = payload.to_stable_id.strip()
        recipient = await resolve_agent_by_did(db, recipient_did)
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_did is not None and payload.to_did.strip():
            bound_recipient = await resolve_agent_by_did(db, payload.to_did.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_did must match the to_stable_id recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_stable_id recipient")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_stable_id recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_stable_id recipient")
            recipient = identity_recipient(recipient, address)
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is None and payload.to_did is not None:
        requested_recipient_did = payload.to_did.strip()
        recipient = await resolve_agent_by_did(db, requested_recipient_did)
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if requested_recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_did recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_did recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_did recipient")
            recipient = identity_recipient(recipient, address)
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or requested_recipient_did).strip()
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is not None:
        address = payload.to_address.strip()
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_address must be domain/name")
        domain, name = address.split("/", 1)
        local_candidate = await _local_recipient_from_address(db, domain=domain, name=name)
        if local_candidate is not None:
            signed = verified_signed_payload_json(
                signed_payload=payload.signed_payload, signature=payload.signature, did_key=auth.did_key,
            )
            signed_binding = _signed_payload_matches_address_binding(
                signed, address=address, recipient=local_candidate,
            )
            # Preserve already admitted local sends. A signed current-key claim
            # that contradicts the projection must instead use registry evidence.
            needs_current_binding = (
                requires_registry_address_binding(local_candidate) and signed is not None
                and bool(signed.get("to_did") or signed.get("to_stable_id")) and not signed_binding
            )
            if signed_binding or (local_recipient_visible_to_auth(local_candidate, auth) and not needs_current_binding):
                recipient_did = str(
                    local_candidate.get("did_aw") or local_candidate.get("did_key") or ""
                ).strip()
                recipient = identity_recipient(local_candidate, address)
                recipient["requires_local_address_authority"] = True

        strict_authority = getattr(request.app.state, "federation_authority", None)
        home_namespace = recipient is None and await namespace_uses_home_registry(db, registry_client, domain)
        if home_namespace:
            try:
                resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            except AWID_DEPENDENCY_ERRORS as exc:
                logging.getLogger(__name__).warning("Mail home address lookup unavailable for %s", address, exc_info=True)
                raise FederationAuthorityError("sender_registry_unavailable") from exc
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)
        elif recipient is None and strict_authority is not None:
            try:
                resolved = await strict_authority.resolve_contact(
                    address,
                    source_ip=str(request.client.host if request.client else "unknown"),
                )
            except FederationAuthorityError as exc:
                if exc.reason != "recipient_identity_not_found":
                    raise
                resolved = None
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)
                else:
                    recipient["authority_controller_did"] = str(
                        getattr(resolved, "controller_did", "") or ""
                    ).strip()
        elif recipient is None and registry_client is not None:
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)

        if recipient is not None and recipient.get("external"):
            refuse_same_origin_nonresident(
                recipient["delivery_origin"], origins=public_origins(request),
            )

        if recipient is None:
            recipient = await _local_recipient_from_address(db, domain=domain, name=name)
            if recipient is None:
                if await namespace_exists(db, domain):
                    raise FederationAuthorityError("recipient_identity_not_found")
                if registry_client is None:
                    raise awid_registry_not_configured_exception(operation="AWID mail recipient address lookup")
                raise HTTPException(status_code=404, detail="Recipient address not found")
            if registry_client is not None and requires_registry_address_binding(recipient):
                if not (
                    local_recipient_visible_to_auth(recipient, auth)
                    or _signed_payload_matches_address_binding(
                        verified_signed_payload_json(
                            signed_payload=payload.signed_payload,
                            signature=payload.signature,
                            did_key=auth.did_key,
                        ),
                        address=address,
                        recipient=recipient,
                    )
                ):
                    raise HTTPException(status_code=404, detail="Recipient address not found")
            recipient = identity_recipient(recipient, address)
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            if not recipient_did:
                raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            if recipient.get("external"):
                if payload.to_alias.strip() != recipient["alias"]:
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
            else:
                bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
                if not _recipient_identity_matches(bound_recipient, recipient):
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if recipient.get("external") or payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_address recipient")
        if payload.to_stable_id is not None and payload.to_stable_id.strip():
            if payload.to_stable_id.strip() != str(recipient.get("did_aw") or "").strip():
                raise HTTPException(status_code=422, detail="to_stable_id must match the to_address recipient")
        if payload.to_did is not None and payload.to_did.strip():
            candidate_dids = {
                str(recipient.get("did_aw") or "").strip(),
                str(recipient.get("did_key") or "").strip(),
            }
            if payload.to_did.strip() not in candidate_dids:
                raise HTTPException(status_code=422, detail="to_did must match the to_address recipient")
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias") or address
    elif to_agent_id is not None:
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=to_agent_id,
        ) if auth.team_id else await get_agent_by_id(db, agent_id=to_agent_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_agent_id recipient")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_alias = recipient.get("alias")
    elif payload.to_alias is not None:
        recipient = await _resolve_message_alias(db, auth, payload.to_alias, registry_client=registry_client)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]
    else:
        raise HTTPException(status_code=422, detail="Must provide to_did, to_address, to_agent_id, or to_alias")

    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    if payload.signature is not None:
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
        _validate_signed_mail_payload(
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient=recipient,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            requested_to_alias=payload.to_alias,
            from_alias=auth.alias,
            from_address=sender_address,
            from_stable_id=auth.did_aw,
            priority=payload.priority,
            subject=payload.subject,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            conversation_id=payload.conversation_id,
        )
        # payload.timestamp is the sender's attestation retained in
        # signed_payload; deliver_message separately assigns server receipt
        # time for ordering, so the two values may disagree.
        _parse_signed_timestamp(payload.timestamp)

    if (recipient or {}).get("external"):
        return _send_response(await deliver_remote_mail_and_project_locally(
            messaging_runtime(request.app.state),
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
        ))

    try:
        if not (recipient or {}).get("external"):
            await authorize_message_delivery(
                db,
                recipient_agent=recipient,
                sender_did=sender_did,
                sender_address=sender_address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
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
                db, payload.encrypted_envelope or {}, [recipient] if recipient else [], sender=auth,
            )
        stored, message_is_new = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
        if stored is not None:
            return _send_response(stored)
        try:
            with agent_wake_scope(agent_wake_publisher(request.app.state)):
                # The conversation and its first message commit together: a refused
                # delivery leaves no conversation behind.
                async with db.get_manager("aweb").transaction() as tx:
                    send_db = TransactionInfra(db, tx)
                    # If an explicit recipient is present, conversation_id is a caller-chosen
                    # initial id. Continuations use conversation_id without recipient fields.
                    conversation = await _create_mail_conversation(
                        send_db,
                        conversation_type="mail",
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
                                "alias": to_alias or (recipient or {}).get("alias") or recipient_did or "",
                                "address": _recipient_conversation_address(recipient, payload),
                                "current_did_key": (recipient or {}).get("did_key"),
                                "transport_hint": "local",
                            }
                        ],
                        team_id=auth.team_id,
                    )
                    message_id, server_received_at = await deliver_message(
                        send_db,
                        id_chain=id_chain,
                        registry_client=registry_client,
                        recipient_agent=recipient,
                        team_id=auth.team_id,
                        from_agent_id=auth.agent_id,
                        from_alias=auth.alias,
                        to_agent_id=to_agent_id,
                        to_alias=to_alias,
                        from_did=sender_did,
                        to_did=recipient_did or "",
                        sender_address=sender_address,
                        subject=payload.subject,
                        body=payload.body,
                        priority=payload.priority,
                        signature=payload.signature,
                        signed_payload=payload.signed_payload,
                        content_mode=payload.content_mode or "legacy_plaintext_v1",
                        message_version=payload.message_version or 1,
                        encrypted_envelope=payload.encrypted_envelope,
                        encrypted_metadata=encrypted_metadata,
                        message_id=msg_uuid,
                        conversation_id=conversation["conversation_id"],
                        skip_policy_check=True,
                        known_new=message_is_new,
                    )
        except Exception as exc:
            # An identical send that ran concurrently committed first; its
            # rollback here leaves nothing of this attempt behind.
            if not _lost_send_race(exc):
                raise
            stored, _ = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
            if stored is None:
                raise
            return _send_response(stored)
    except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
        if (isinstance(exc, ForbiddenError) and payload.to_address
                and recipient.get("identity_scope") == "local"
                and not recipient.get("has_global_claim") and not recipient.get("did_aw")):
            raise FederationAuthorityError("local_recipient_route_missing") from exc
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=(auth.did_aw or sender_did).strip(),
        sender_team_id=auth.team_id,
        recipient=recipient,
        registry_client=registry_client,
    )

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_agent_id": to_agent_id,
            "from_alias": auth.alias or sender_did,
            "message_id": str(message_id),
            "conversation_id": conversation["conversation_id"],
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
            "content_mode": payload.content_mode or "legacy_plaintext_v1",
        },
    )

    return SendMessageResponse(
        message_id=str(message_id),
        conversation_id=conversation["conversation_id"],
        status="delivered",
        delivered_at=_utc_iso(server_received_at),
    )


class UnreadMailCount(BaseModel):
    unread_count: int


@router.get("/unread-count", response_model=UnreadMailCount)
async def unread_mail_count(
    db=Depends(get_db), auth: MessagingAuth = Depends(get_messaging_auth),
) -> UnreadMailCount:
    """Distinct incoming unread mail for this participant; never acknowledges."""
    dids = participant_dids(auth)
    if not dids:
        raise HTTPException(401, "Authenticated identity is missing a routing DID")
    count = await db.get_manager("aweb").fetch_val(
        f"""SELECT COUNT(*) FROM {{{{tables.messages}}}} m
            WHERE {incoming_mail_sql('$1')} AND m.read_at IS NULL""", dids,
    )
    return UnreadMailCount(unread_count=count)


@router.get("/inbox", response_model=InboxResponse, name="get_inbox")
async def _get_inbox_http(
    request: Request,
    db=Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    unread_only: bool = Query(default=False),
    message_id: str | None = Query(default=None),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> InboxResponse:
    # FastAPI injects Request only for the concrete type, not Request | None.
    return await get_inbox(
        request, db=db, limit=limit, cursor=cursor, unread_only=unread_only,
        message_id=message_id, auth=auth,
    )


async def get_inbox(
    request: Request | None,
    db=Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    unread_only: bool = Query(default=False),
    message_id: str | None = Query(default=None),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> InboxResponse:
    aweb_db = db.get_manager("aweb")
    inbox_dids = participant_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    exact_message_id: UUID | None = None
    if message_id is not None and message_id.strip():
        if cursor:
            raise HTTPException(status_code=422, detail="cursor cannot be combined with message_id")
        try:
            exact_message_id = UUID(message_id.strip())
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid message_id format")

    try:
        page_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    where_clause = f"WHERE {incoming_mail_sql('$1')}"
    params: list = [inbox_dids]
    if exact_message_id is not None:
        params.append(exact_message_id)
        where_clause += f" AND m.message_id = ${len(params)}"
    else:
        if unread_only:
            where_clause += " AND m.read_at IS NULL"
        if cursor_data is not None:
            try:
                cursor_created_at = datetime.fromisoformat(str(cursor_data["created_at"]))
                cursor_message_id = UUID(str(cursor_data["message_id"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="Invalid inbox cursor") from exc
            if cursor_created_at.tzinfo is None:
                cursor_created_at = cursor_created_at.replace(tzinfo=timezone.utc)
            params.extend([cursor_created_at, cursor_message_id])
            where_clause += (
                f" AND (m.created_at, m.message_id) < "
                f"(${len(params) - 1}, ${len(params)})"
            )

    query_limit = 1 if exact_message_id is not None else page_limit + 1
    rows = await aweb_db.fetch_all(
        f"""
        SELECT m.team_id, m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload, m.id_chain, m.conversation_id,
               m.content_mode, m.message_version, m.encrypted_envelope,
               sender.agent_id AS sender_agent_id, sender.team_id AS sender_team_id,
               CASE WHEN sender.did_aw_verified_key = sender.did_key THEN sender.did_aw END AS sender_did_aw,
               sender.status AS sender_status, sender.deleted_at AS sender_deleted_at,
               sender.certificate_id AS sender_certificate_id
        FROM {{{{tables.messages}}}} m
        LEFT JOIN {{{{tables.agents}}}} sender ON sender.agent_id = m.from_agent_id
        {where_clause}
        ORDER BY m.created_at DESC, m.message_id DESC
        LIMIT ${len(params) + 1}
        """,
        *params,
        query_limit,
    )
    # The senders' agent rows, read with the page for their membership state.
    sender_columns = ("agent_id", "team_id", "did_aw", "status", "deleted_at", "certificate_id")
    sender_member_rows = list({
        str(row["sender_agent_id"]): {column: row[f"sender_{column}"] for column in sender_columns}
        for row in rows
        if row["sender_agent_id"] is not None
    }.values())
    rows = [
        {key: value for key, value in row.items() if not key.startswith("sender_")}
        for row in rows
    ]

    has_more = exact_message_id is None and len(rows) > page_limit
    rows = rows[:page_limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = encode_cursor(
            {
                "created_at": last["created_at"].isoformat(),
                "message_id": str(last["message_id"]),
            }
        )
    return await _inbox_response_from_rows(
        request, db,
        rows,
        has_more=has_more,
        next_cursor=next_cursor,
        sender_member_rows=sender_member_rows,
    )


@router.get("/{message_id}", response_model=InboxMessage)
async def get_message(
    message_id: str,
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
    request: Request = None,
) -> InboxMessage:
    try:
        msg_uuid = UUID(message_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    actor_dids = participant_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")
    row = await db.get_manager("aweb").fetch_one(
        f"""
        SELECT m.team_id, m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload, m.id_chain, m.conversation_id,
               m.content_mode, m.message_version, m.encrypted_envelope
        FROM {{{{tables.messages}}}} m
        WHERE m.message_id = $1
          AND {readable_mail_sql('$2')}
        """,
        msg_uuid,
        actor_dids,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Message not found")
    response = await _inbox_response_from_rows(request, db, [row])
    return response.messages[0]


@router.post("/{message_id}/ack", response_model=AckResponse)
async def ack_message(
    request: Request, message_id: str, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> AckResponse:

    try:
        msg_uuid = UUID(message_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    inbox_dids = participant_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    with agent_wake_scope(agent_wake_publisher(request.app.state)):
        result = await aweb_db.fetch_one(
            f"""
            UPDATE {{{{tables.messages}}}} m
            SET read_at = $1
            WHERE m.message_id = $2 AND {incoming_mail_sql('$3')}
              AND read_at IS NULL
            RETURNING message_id, from_alias, subject, content_mode
            """,
            now,
            msg_uuid,
            inbox_dids,
        )
        if result:
            record_did_wakes(inbox_dids, "mail")

    if not result:
        # Either already read or not found — check existence
        existing = await aweb_db.fetch_one(
            f"""
            SELECT message_id, read_at, from_alias, subject FROM {{{{tables.messages}}}} m
            WHERE m.message_id = $1 AND {incoming_mail_sql('$2')}
            """,
            msg_uuid,
            inbox_dids,
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Message not found")

    if result:
        await fire_mutation_hook(
            request,
            "message.acknowledged",
            {
                "team_id": auth.team_id,
                "agent_id": auth.agent_id,
                "alias": auth.alias,
                "message_id": str(msg_uuid),
                "from_alias": result["from_alias"],
                "subject": result["subject"] or "",
                "content_mode": result["content_mode"] or "legacy_plaintext_v1",
            },
        )

    return AckResponse(
        message_id=str(msg_uuid),
        acknowledged_at=now.isoformat(),
    )
