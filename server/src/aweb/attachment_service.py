"""Transactional managed attachment binding and participant-scoped downloads."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from hashlib import sha256
import json
import logging
from uuid import UUID
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import Response
from awid.signing import canonical_json_bytes
from aweb.attachments import (AttachmentBinding, AttachmentParticipant, AttachmentRef,
                              AttachmentDescriptor, AttachmentError, MAX_FILE_BYTES, refs)
from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth

logger = logging.getLogger(__name__)
router = APIRouter(tags=["aweb-attachments"])


@dataclass
class _Send:
    backend: object
    references: list[AttachmentRef]
    message: dict
    auth: MessagingAuth
    inside: bool = False
    bound: bool = False


_current: ContextVar[_Send | None] = ContextVar("attachment_send", default=None)


@contextmanager
def _send_context(context):
    token = _current.set(context)
    try:
        yield
        if not context.bound:
            raise AttachmentError("attachment_conflict").http()
    finally:
        _current.reset(token)


def prepare_attachment_send(request, payload, auth):
    """Enter once per new request. Only encrypted-v2 attachments are supported."""
    if _current.get() is not None:
        return None
    raw_descriptors = getattr(payload, "attachments", None)
    if raw_descriptors is not None and raw_descriptors != []:
        raise AttachmentError("request_invalid").http()
    raw = getattr(payload, "attachment_refs", None)
    if raw is None or raw == []:
        return None
    if payload.content_mode != "encrypted_v2" or payload.message_version != 2:
        raise AttachmentError("request_invalid").http()
    try:
        references = refs(raw)
    except AttachmentError as exc:
        raise exc.http() from None
    backend = getattr(request.app.state, "attachment_backend", None)
    if backend is None:
        raise AttachmentError("attachment_unavailable").http()
    return _send_context(_Send(backend, references, payload.model_dump(), auth))


def refuse_remote_attachments():
    if _current.get() is not None:
        raise AttachmentError("request_invalid").http()


class _TxInfra:
    def __init__(self, original, tx):
        self.original, self.tx = original, tx

    def get_manager(self, name="aweb"):
        return self.tx if name == "aweb" else self.original.get_manager(name)

    def __getattr__(self, name):
        return getattr(self.original, name)


def attachment_transaction(kind):
    """Wrap the existing DB-only message persistence operation, not routing I/O."""
    def decorate(function):
        @wraps(function)
        async def persist(db, *args, **kwargs):
            context = _current.get()
            if context is None or context.inside:
                return await function(db, *args, **kwargs)
            try:
                async with db.get_manager("aweb").transaction() as tx:
                    for reference in sorted(context.references, key=lambda item: item.id):
                        await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", reference.id)
                    context.inside = True
                    try:
                        result = await function(_TxInfra(db, tx), *args, **kwargs)
                    finally:
                        context.inside = False
                    message_id = str(result[0] if kind == "mail" else result["message_id"])
                    await _bind(tx, kind, message_id, context)
                    context.bound = True
                    return result
            except AttachmentError as exc:
                raise exc.http() from None
        return persist
    return decorate


async def _binding(db, kind, message_id):
    table = "messages" if kind == "mail" else "chat_messages"
    row = await db.fetch_one(
        f"SELECT * FROM {{{{tables.{table}}}}} WHERE message_id=$1", UUID(message_id))
    if not row:
        raise AttachmentError("not_found")
    cid = str(row["conversation_id"] if kind == "mail" else row["session_id"])
    if kind == "mail":
        participants = tuple(str(row[key]) for key in ("from_did", "to_did"))
    else:
        people = await db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1", UUID(cid))
        participants = tuple(str(person["did"]) for person in people)
    return AttachmentBinding(kind, message_id, cid, str(row["from_did"]), participants,
                             str(row["from_agent_id"]) if row.get("from_agent_id") else None,
                             str(row["team_id"]) if row.get("team_id") else None), row


async def _bind(tx, kind, message_id, context):
    binding, row = await _binding(tx, kind, message_id)
    envelope = row.get("encrypted_envelope")
    if isinstance(envelope, str):
        envelope = json.loads(envelope)
    supplied = context.message.get("encrypted_envelope")
    if row.get("content_mode") != "encrypted_v2" or envelope != supplied:
        raise AttachmentError("attachment_conflict")
    if binding.sender_did not in auth_dids(context.auth):
        raise AttachmentError("attachment_conflict")
    digest = sha256(canonical_json_bytes(envelope)).hexdigest()
    previous = await tx.fetch_all(
        "SELECT * FROM {{tables.message_attachments}} WHERE message_kind=$1 AND message_id=$2 ORDER BY ordinal",
        kind, UUID(message_id))
    if previous:
        old = [(str(item["attachment_id"]), item["size"], item["descriptor_sha256"], item["envelope_sha256"])
               for item in previous]
        new = [(item.id, item.size, item.descriptor_sha256, digest) for item in context.references]
        if old != new:
            raise AttachmentError("attachment_conflict")
        return
    occupied = await tx.fetch_one(
        "SELECT attachment_id FROM {{tables.message_attachments}} WHERE attachment_id=ANY($1::uuid[])",
        [UUID(item.id) for item in context.references])
    if occupied:
        raise AttachmentError("attachment_conflict")
    # The backend must decrypt and check inner descriptors against EVERY ref
    # and staged row. Nothing in the transport refs grants authority.
    try:
        await context.backend.bind(tx, binding=binding, refs=context.references, message=context.message)
    except AttachmentError:
        raise
    except Exception as exc:
        logger.error("Attachment bind backend failed message_id=%s error_type=%s", message_id, type(exc).__name__)
        raise AttachmentError("attachment_unavailable") from None
    for index, item in enumerate(context.references):
        await tx.execute(
            "INSERT INTO {{tables.message_attachments}} "
            "(attachment_id,message_kind,message_id,conversation_id,size,descriptor_sha256,envelope_sha256,ordinal) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            UUID(item.id), kind, UUID(message_id), UUID(binding.conversation_id), item.size,
            item.descriptor_sha256, digest, index)


async def attachment_references(db, kind, message_id):
    rows = await db.get_manager("aweb").fetch_all(
        "SELECT attachment_id,size,descriptor_sha256 FROM {{tables.message_attachments}} "
        "WHERE message_kind=$1 AND message_id=$2 ORDER BY ordinal", kind, UUID(str(message_id)))
    return [{"id": str(row["attachment_id"]), "size": row["size"],
             "descriptor_sha256": row["descriptor_sha256"]} for row in rows]


async def read_attachment(request, kind, message_id, attachment_id, db, auth):
    manager = db.get_manager("aweb")
    try:
        binding, row = await _binding(manager, kind, str(message_id))
        if kind == "mail":
            if not set(auth_dids(auth)).intersection(binding.participant_dids):
                raise AttachmentError("not_found")
        else:
            from aweb.messaging.chat import resolve_session_actor_did
            if not await resolve_session_actor_did(db, session_id=UUID(binding.conversation_id), actor_dids=auth_dids(auth)):
                raise AttachmentError("not_found")
        bound = await manager.fetch_one(
            "SELECT size,descriptor_sha256 FROM {{tables.message_attachments}} "
            "WHERE attachment_id=$1 AND message_kind=$2 AND message_id=$3",
            attachment_id, kind, message_id)
        if not bound:
            raise AttachmentError("not_found")
        reference = AttachmentRef(id=str(attachment_id), size=bound["size"],
                                  descriptor_sha256=bound["descriptor_sha256"])
        backend = getattr(request.app.state, "attachment_backend", None)
        if backend is None:
            raise AttachmentError("attachment_unavailable")
        participant = AttachmentParticipant(tuple(auth_dids(auth)), auth.agent_id, auth.team_id)
        try:
            descriptor, data = await backend.read(db, binding=binding, participant=participant, ref=reference)
        except AttachmentError:
            raise
        except Exception as exc:
            logger.error("Attachment read backend failed attachment_id=%s error_type=%s", attachment_id, type(exc).__name__)
            raise AttachmentError("attachment_unavailable") from None
        try:
            descriptor = AttachmentDescriptor.model_validate(descriptor)
        except (ValueError, TypeError):
            raise AttachmentError("attachment_unavailable") from None
        if (not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES or descriptor.ref() != reference
                or len(data) != descriptor.size or sha256(data).hexdigest() != descriptor.sha256):
            raise AttachmentError("attachment_unavailable")
        if datetime.fromisoformat(descriptor.expires_at.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            raise AttachmentError("attachment_expired")
        return Response(data, media_type=descriptor.media_type, headers={
            "Content-Disposition": "attachment; filename*=UTF-8''" + quote(descriptor.filename, safe=""),
            "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store",
            "X-AWEB-Attachment-SHA256": descriptor.sha256,
        })
    except AttachmentError as exc:
        raise exc.http() from None


@router.get("/v1/messages/{message_id}/attachments/{attachment_id}")
async def fetch_mail_attachment(request: Request, message_id: UUID, attachment_id: UUID,
                                db=Depends(get_db), auth: MessagingAuth = Depends(get_messaging_auth)):
    return await read_attachment(request, "mail", message_id, attachment_id, db, auth)


@router.get("/v1/chat/messages/{message_id}/attachments/{attachment_id}")
async def fetch_chat_attachment(request: Request, message_id: UUID, attachment_id: UUID,
                                db=Depends(get_db), auth: MessagingAuth = Depends(get_messaging_auth)):
    return await read_attachment(request, "chat", message_id, attachment_id, db, auth)


async def attachment_retry(db, payload, kind):
    """Reuse only an already-verified identical envelope and stored ref set."""
    context = _current.get()
    if context is None:
        return None
    envelope = payload.encrypted_envelope or {}
    message_id = envelope.get("message_id")
    if not message_id:
        return None
    table = "messages" if kind == "mail" else "chat_messages"
    try:
        message_uuid = UUID(message_id)
    except (ValueError, TypeError, AttributeError):
        raise AttachmentError("request_invalid").http() from None
    exists = await db.get_manager("aweb").fetch_one(
        f"SELECT message_id FROM {{{{tables.{table}}}}} WHERE message_id=$1", message_uuid)
    if not exists:
        return None
    # This verifies stored sender, content, ordered refs and commitment. It
    # cannot call provider.bind on this path: stored binding rows must exist.
    previous = await attachment_references(db, kind, message_id)
    if previous != [item.model_dump() for item in context.references]:
        raise AttachmentError("attachment_conflict").http()
    binding, row = await _binding(db.get_manager("aweb"), kind, message_id)
    stored = row["encrypted_envelope"]
    if isinstance(stored, str):
        stored = json.loads(stored)
    if (stored != envelope or binding.sender_did not in auth_dids(context.auth)
            or payload.message_id != message_id or payload.timestamp != envelope.get("created_at")
            or (payload.from_did and payload.from_did != envelope.get("from", {}).get("did"))
            or (getattr(payload, "conversation_id", None) and payload.conversation_id != binding.conversation_id)):
        raise AttachmentError("attachment_conflict").http()
    for name, allowed in {
        "to_did": {row.get("to_did"), envelope.get("routing", {}).get("to_did")},
        "to_stable_id": {envelope.get("routing", {}).get("to_stable_id")},
        "to_address": {envelope.get("routing", {}).get("to")},
        "to_alias": {row.get("to_alias"), envelope.get("routing", {}).get("to")},
    }.items():
        if getattr(payload, name, None) and getattr(payload, name) not in allowed:
            raise AttachmentError("attachment_conflict").http()
    context.bound = True
    return binding, row
