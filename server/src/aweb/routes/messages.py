from __future__ import annotations

from aweb.agent_wake import agent_wake_publisher
from aweb.messaging.mail_attribution import incoming_mail_sql, readable_mail_sql

from aweb.identity_auth_deps import participant_dids
from aweb.attachment_service import prepare_attachment_send, attachment_retry, attachment_references_by_message

import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from awid.pagination import decode_cursor, encode_cursor, validate_pagination_params
from aweb.deps import get_db
from aweb.hooks import mutation_callback
from aweb.id_chain_auth import stored_id_chain
from aweb.identity_metadata import lookup_identity_metadata_by_did
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.messaging.alias_targets import validate_alias_selector
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.mail_ack import acknowledge_mail
from aweb.messaging.mail_send import SentMail, resolve_mail_target, send_mail
from aweb.messaging.runtime import messaging_runtime
from aweb.messaging.messages import MessagePriority
from aweb.messaging.verification import (
    message_verification_status,
)
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL

from aweb.messaging.sender_membership import SenderMembership, sender_memberships

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


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


def _send_response(sent: SentMail) -> SendMessageResponse:
    return SendMessageResponse(**asdict(sent))


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    attachment_context = prepare_attachment_send(
        getattr(request.app.state, "attachment_backend", None), payload, auth,
    )
    if attachment_context is not None:
        with attachment_context:
            existing = await attachment_retry(db, payload, "mail")
            if existing:
                binding, row = existing
                return SendMessageResponse(message_id=binding.message_id, conversation_id=binding.conversation_id,
                                           status="delivered", delivered_at=row["created_at"].isoformat())
            return await send_message(request, payload, db=db, auth=auth)
    runtime = messaging_runtime(request.app.state)
    sender = replace(auth, id_chain=getattr(getattr(request, "state", None), "id_chain", None))
    target = await resolve_mail_target(
        db, sender, payload, runtime,
        source=str(request.client.host if request.client else "unknown"),
    )
    return _send_response(await send_mail(db, sender, target, payload, runtime))


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
               sender.did_key AS sender_did_key, sender.alias AS sender_alias,
               sender.identity_scope AS sender_identity_scope, sender.address AS sender_address,
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
    sender_columns = ("agent_id", "team_id", "did_aw", "did_key", "alias", "identity_scope", "address", "status", "deleted_at", "certificate_id")
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

    acknowledged = await acknowledge_mail(
        db, auth, [msg_uuid], read_at=now,
        agent_wake_publisher=agent_wake_publisher(request.app.state),
        on_mutation=mutation_callback(request),
    )

    if not acknowledged:
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

    return AckResponse(
        message_id=str(msg_uuid),
        acknowledged_at=now.isoformat(),
    )
