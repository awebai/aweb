from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.identity_metadata import lookup_identity_metadata_by_did
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
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


async def _resolve_message_alias(db, auth: MessagingAuth, raw_alias: str) -> dict | None:
    target = resolve_alias_target(auth.team_id, raw_alias, field="to_alias")
    if "~" in str(raw_alias or "") and not await team_exists(db, target.team_id):
        raise HTTPException(status_code=404, detail=f"Unknown team: {target.team_id}")
    return await get_agent_by_alias(db, team_id=target.team_id, alias=target.alias)


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1)
    to_did: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_stable_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_address: Optional[str] = Field(default=None, min_length=1, max_length=256)
    subject: str = ""
    body: str
    priority: MessagePriority = "normal"
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
    signed_payload: Optional[str] = None

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

    @field_validator("message_id")
    @classmethod
    def _validate_message_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid message_id format")


class SendMessageResponse(BaseModel):
    message_id: str
    status: str
    delivered_at: str


class InboxMessage(BaseModel):
    message_id: str
    from_agent_id: Optional[str] = None
    from_alias: str
    to_alias: str
    subject: str
    body: str
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


class InboxResponse(BaseModel):
    messages: list[InboxMessage]


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


def _parse_signed_timestamp(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid timestamp format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail="timestamp must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    return dt


def _validate_signed_mail_payload(
    *,
    signed_payload: str | None,
    recipient: dict | None,
    to_agent_id: str | None,
    to_alias: str | None,
    requested_to_alias: str | None,
    from_alias: str | None,
    from_address: str | None,
    from_stable_id: str | None,
    priority: MessagePriority,
    subject: str,
    body: str,
    from_did: str,
    message_id: str,
    timestamp: str,
) -> None:
    if signed_payload is None:
        return
    try:
        payload = json.loads(signed_payload)
    except Exception:
        raise HTTPException(status_code=422, detail="signed_payload must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="signed_payload must be a JSON object")
    if payload.get("type") != "mail":
        raise HTTPException(status_code=422, detail="signed_payload type must be mail")
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
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to not in allowed_to_values:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_did = str(payload.get("to_did") or "").strip()
    if signed_to_did and signed_to_did not in {
        str(recipient_stable_id).strip(),
        str(recipient_current_did).strip(),
    }:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if signed_to_stable_id and signed_to_stable_id != str(recipient_stable_id).strip():
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    if (payload.get("priority") or "normal") != priority:
        raise HTTPException(status_code=422, detail="signed_payload priority must match the mail message")
    if payload.get("subject", "") != subject:
        raise HTTPException(status_code=422, detail="signed_payload subject must match the mail subject")
    if payload.get("body") != body:
        raise HTTPException(status_code=422, detail="signed_payload body must match the mail body")
    if payload.get("from_did") != from_did:
        raise HTTPException(status_code=422, detail="signed_payload from_did must match the authenticated sender")
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise HTTPException(
            status_code=422,
            detail="signed_payload from_stable_id must match the authenticated sender",
        )
    if payload.get("message_id") != message_id:
        raise HTTPException(status_code=422, detail="signed_payload message_id must match the mail message")
    if payload.get("timestamp") != timestamp:
        raise HTTPException(status_code=422, detail="signed_payload timestamp must match the mail message")


def _external_recipient_from_address(address: str, resolution) -> dict:
    _, name = address.split("/", 1)
    return {
        "agent_id": None,
        "team_id": None,
        "alias": name,
        "address": address,
        "did_aw": resolution.did_aw.strip(),
        "did_key": (getattr(resolution, "current_did_key", "") or "").strip(),
        "messaging_policy": None,
        "external": True,
    }


def _sender_address(auth: MessagingAuth) -> str | None:
    return (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias) or None


async def _local_recipient_from_address(db, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _with_requested_address(row: dict, address: str) -> dict:
    copied = dict(row)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


def _recipient_identity_matches(left: dict | None, right: dict | None) -> bool:
    if left is None or right is None:
        return False
    left_agent_id = str(left.get("agent_id") or "").strip()
    right_agent_id = str(right.get("agent_id") or "").strip()
    if left_agent_id and left_agent_id == right_agent_id:
        return True
    for field in ("did_aw", "did_key"):
        left_value = str(left.get(field) or "").strip()
        right_value = str(right.get(field) or "").strip()
        if left_value and right_value and left_value == right_value:
            return True
    return False


async def _bound_recipient_from_address(
    db,
    *,
    registry_client,
    auth: MessagingAuth,
    address: str,
) -> dict | None:
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry unavailable")
    if "/" not in address:
        raise HTTPException(status_code=422, detail="to_address must be domain/name")
    domain, name = address.split("/", 1)
    resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
    if resolved is not None and resolved.did_aw:
        bound_recipient = await resolve_agent_by_did(db, resolved.did_aw)
        if bound_recipient is not None:
            return bound_recipient
    return await _local_recipient_from_address(db, domain=domain, name=name)


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    sender_address = _sender_address(auth)

    recipient = None
    recipient_did: str | None = None
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if payload.to_stable_id is not None:
        recipient_did = payload.to_stable_id.strip()
        recipient = await resolve_agent_by_did(db, recipient_did)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_did is not None and payload.to_did.strip():
            bound_recipient = await resolve_agent_by_did(db, payload.to_did.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_did must match the to_stable_id recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_stable_id recipient")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_stable_id recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_stable_id recipient")
            recipient = _with_requested_address(recipient, address)
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient.get("alias")
    elif payload.to_did is not None:
        requested_recipient_did = payload.to_did.strip()
        recipient = await resolve_agent_by_did(db, requested_recipient_did)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
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
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_did recipient")
            recipient = _with_requested_address(recipient, address)
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or requested_recipient_did).strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient.get("alias")
    elif payload.to_address is not None:
        address = payload.to_address.strip()
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_address must be domain/name")
        domain, name = address.split("/", 1)
        if registry_client is not None:
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await resolve_agent_by_did(db, recipient_did)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)

        if recipient is None:
            recipient = await _local_recipient_from_address(db, domain=domain, name=name)
            if recipient is None:
                if await namespace_exists(db, domain):
                    raise HTTPException(status_code=404, detail="Recipient agent not found")
                if registry_client is None:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")
                raise HTTPException(status_code=404, detail="Recipient address not found")
            recipient = _with_requested_address(recipient, address)
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            if not recipient_did:
                raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            if recipient.get("external"):
                if payload.to_alias.strip() != recipient["alias"]:
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
            else:
                bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
                if not _recipient_identity_matches(bound_recipient, recipient):
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if recipient.get("external") or payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_address recipient")
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias") or address
    elif to_agent_id is not None:
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=to_agent_id,
        ) if auth.team_id else await get_agent_by_id(db, agent_id=to_agent_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_agent_id recipient")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_alias = recipient.get("alias")
    elif payload.to_alias is not None:
        recipient = await _resolve_message_alias(db, auth, payload.to_alias)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]
    else:
        raise HTTPException(status_code=422, detail="Must provide to_did, to_address, to_agent_id, or to_alias")

    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    created_at = None
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
        )
        created_at = _parse_signed_timestamp(payload.timestamp)

    try:
        message_id, created_at = await deliver_message(
            db,
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
            created_at=created_at,
            message_id=msg_uuid,
        )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

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
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
        },
    )

    return SendMessageResponse(
        message_id=str(message_id),
        status="delivered",
        delivered_at=_utc_iso(created_at),
    )


@router.get("/inbox", response_model=InboxResponse)
async def get_inbox(
    request: Request,
    db=Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    unread_only: bool = Query(default=False),
    message_id: str | None = Query(default=None),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> InboxResponse:
    aweb_db = db.get_manager("aweb")
    inbox_dids = auth_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    where_clause = "WHERE m.to_did = ANY($1::text[])"
    params: list = [inbox_dids]

    if message_id is not None and message_id.strip():
        try:
            params.append(UUID(message_id.strip()))
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid message_id format")
        where_clause += f" AND m.message_id = ${len(params)}"
    elif unread_only:
        where_clause += " AND m.read_at IS NULL"

    rows = await aweb_db.fetch_all(
        f"""
        SELECT m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload
        FROM {{{{tables.messages}}}} m
        {where_clause}
        ORDER BY m.created_at DESC
        LIMIT ${len(params) + 1}
        """,
        *params,
        limit,
    )

    identity_map = await lookup_identity_metadata_by_did(
        db,
        [
            str(value).strip()
            for row in rows
            for value in (row.get("from_did"), row.get("to_did"))
            if value
        ],
    )

    messages = []
    for r in rows:
        from_did = (r.get("from_did") or "").strip()
        to_did = (r.get("to_did") or "").strip()
        messages.append(InboxMessage(
            message_id=str(r["message_id"]),
            from_agent_id=(str(r["from_agent_id"]) if r.get("from_agent_id") else None),
            from_alias=r["from_alias"],
            to_alias=r["to_alias"],
            subject=r["subject"],
            body=r["body"],
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
        ))

    return InboxResponse(messages=messages)


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
    inbox_dids = auth_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    result = await aweb_db.fetch_one(
        """
        UPDATE {{tables.messages}}
        SET read_at = $1
        WHERE message_id = $2 AND to_did = ANY($3::text[])
          AND read_at IS NULL
        RETURNING message_id, from_alias, subject
        """,
        now,
        msg_uuid,
        inbox_dids,
    )

    if not result:
        # Either already read or not found — check existence
        existing = await aweb_db.fetch_one(
            """
            SELECT message_id, read_at, from_alias, subject FROM {{tables.messages}}
            WHERE message_id = $1 AND to_did = ANY($2::text[])
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
            },
        )

    return AckResponse(
        message_id=str(msg_uuid),
        acknowledged_at=now.isoformat(),
    )
