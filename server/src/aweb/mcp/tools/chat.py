"""MCP tools for real-time chat messaging."""

from __future__ import annotations

from aweb.messaging.chat_policy import HumanChatRefused
from aweb.identity_auth_deps import participant_dids

from aweb.attachments import readable_attachments

import asyncio
import json
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from awid.federation_errors import FederationAuthorityError
from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    get_message_history,
    get_pending_conversations,
    resolve_session_actor_did,
    wake_chat_session_participants,
)
from aweb.messaging.sender_address import sender_address as _sender_address
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.verification import (
    message_verification_status,
    verified_signed_recipient_fields,
)
from aweb.messaging.waiting import register_waiting, unregister_waiting
from aweb.messaging.chat_read import mark_chat_read
from aweb.mcp.auth import current_agent_wake_publisher, get_auth
from aweb.mcp.signing import (
    HostedMessageDecryptor,
    HostedMessageDecryptionError,
    HostedMessageEncryptionError,
    HostedMessageEncryptor,
    HostedMessageSigner,
    HostedMessageSigningError,
    decrypt_hosted_message_row,
    encrypt_hosted_message,
    sign_hosted_message,
)
from aweb.mcp.tools.federation import (
    mcp_messaging_auth,
    mcp_messaging_runtime,
)
from aweb.mcp.tools.refusals import CONVERSATION_CHANGED_DURING_SEND, send_refusal
from aweb.messaging.chat_send import (
    SENDER_NOT_IN_SESSION,
    ChatSessionChanged,
    _resolve_actor_agent,
    resolve_chat_targets,
    send_chat,
)
from aweb.routes.chat import (
    CreateSessionRequest,
    SendMessageRequest as ChatSendMessageRequest,
)
from aweb.service_errors import ServiceError

MAX_TOTAL_WAIT_SECONDS = 600
# How many times a send signs for the pair's session before it gives up.
SESSION_ATTEMPTS = 3


def _actor_dids() -> list[str]:
    return participant_dids(get_auth())


def _signed_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _signed_from(auth) -> str:
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or (auth.did_aw or "").strip()
        or (auth.did_key or "").strip()
    )


def _recipient_signed_fields(rows: list[dict], *, named_alias: str = "") -> tuple[str, str, str]:
    """What a hosted identity signs about its recipients: ``to``, and for a
    single recipient its current key and its stable identity.

    ``to`` is the alias the caller named, a recipient on another server's
    address, or else the recipients' aliases.
    """
    if named_alias:
        to_value = named_alias
    elif len(rows) == 1 and (rows[0].get("external") or rows[0].get("delivery_origin")) and rows[0].get("address"):
        to_value = rows[0]["address"]
    else:
        to_value = ",".join(sorted(
            value
            for value in (
                (
                    row.get("alias")
                    or row.get("address")
                    or row.get("did_aw")
                    or row.get("did_key")
                    or row.get("did")
                    or ""
                ).strip()
                for row in rows
            )
            if value
        ))
    if len(rows) != 1:
        return to_value, "", ""
    row = rows[0]
    did = str(row.get("did") or "")
    return (
        to_value,
        row.get("did_key") or (did if did.startswith("did:key:") else ""),
        row.get("did_aw") or (did if did.startswith("did:aw:") else ""),
    )


def _signed_chat_fields(
    auth,
    *,
    signed_from: str,
    recipient_rows: list[dict],
    named_alias: str,
    message: str,
    message_id: str,
    conversation_id: str,
    timestamp: str,
    wait_seconds: int | None,
    hang_on: bool,
    leaving: bool,
) -> dict:
    """The fields a hosted identity signs, or encrypts, for one chat message."""
    to_value, to_current_did, to_stable_id = _recipient_signed_fields(recipient_rows, named_alias=named_alias)
    signed_fields = {
        "body": message,
        "conversation_id": conversation_id,
        "from": signed_from,
        "from_did": (auth.did_key or "").strip(),
        "message_id": message_id,
        "subject": "",
        "timestamp": timestamp,
        "to": to_value,
        "to_did": to_current_did,
        "type": "chat",
    }
    if to_stable_id:
        signed_fields["to_stable_id"] = to_stable_id
    if auth.did_aw:
        signed_fields["from_stable_id"] = auth.did_aw
    if hang_on:
        signed_fields["hang_on"] = True
    if wait_seconds is not None:
        signed_fields["wait_seconds"] = wait_seconds
    if leaving:
        signed_fields["sender_leaving"] = True
    return signed_fields


def _send_refusal(exc: Exception, *, address: str = "", hosted_envelope: bool = False) -> str:
    """A chat send the service refused, in this tool's error shape."""
    if isinstance(exc, HumanChatRefused):
        return json.dumps({"error": exc.detail, **exc.body()})
    return send_refusal(exc, address=address, hosted_envelope=hosted_envelope)


def _chat_recipient_for_encryptor(row: dict) -> dict:
    recipient = dict(row)
    agent_id = str(recipient.get("agent_id") or "").strip()
    if agent_id:
        recipient["agent_id"] = agent_id
    return recipient


async def _decrypt_chat_row_for_hosted(
    *,
    auth,
    hosted_decryptor: HostedMessageDecryptor | None,
    row: dict,
) -> dict[str, object]:
    body = str(row.get("body") or "")
    if str(row.get("content_mode") or "legacy_plaintext_v1") != "encrypted_v2":
        return {"body": body, "decryptable": True, "content_notice": None}
    try:
        decrypted = await decrypt_hosted_message_row(
            auth=auth,
            decryptor=hosted_decryptor,
            message_type="chat",
            row=row,
        )
    except HostedMessageDecryptionError as exc:
        return {"body": "", "decryptable": False, "content_notice": str(exc)}
    if decrypted is None:
        return {
            "body": "",
            "decryptable": False,
            "content_notice": (
                "Encrypted chat content is not available in this server context. "
                "Use a local client that holds the identity encryption key."
            ),
        }
    return {
        **(readable_attachments(decrypted.attachments) if decrypted.attachments_available else {"attachments": [], "attachments_available": False}),
        "body": decrypted.body,
        "decryptable": bool(decrypted.decryptable),
        "content_notice": decrypted.content_notice,
    }


async def _wait_for_replies(
    aweb_db,
    redis,
    *,
    auth,
    hosted_decryptor: HostedMessageDecryptor | None,
    session_id: UUID,
    participant_did: str,
    after_seq: int,
    wait_seconds: int,
) -> tuple[list[dict], bool]:
    session_id_str = str(session_id)
    start = time.monotonic()
    absolute_deadline = start + MAX_TOTAL_WAIT_SECONDS
    deadline = start + wait_seconds

    await register_waiting(redis, session_id_str, participant_did)
    await wake_chat_session_participants(aweb_db, current_agent_wake_publisher(), session_id=session_id)
    last_refresh = time.monotonic()
    last_seen_seq = after_seq

    try:
        while time.monotonic() < deadline:
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, participant_did)
                last_refresh = now_mono

            new_msgs = await aweb_db.fetch_all(
                """
                SELECT message_id, seq, from_did, from_alias, from_address,
                       CASE WHEN content_mode = 'encrypted_v2' THEN '' ELSE body END AS body,
                       signature, signed_payload,
                       content_mode, message_version, encrypted_envelope, created_at,
                       sender_leaving, hang_on
                FROM {{tables.chat_messages}} m
                WHERE session_id = $1
                  AND NOT EXISTS (
                        SELECT 1 FROM {{tables.chat_participants}} own
                        WHERE own.session_id = m.session_id AND own.did = $2
                          AND (m.from_did = own.did OR m.from_did = NULLIF(own.current_did_key, ''))
                    )
                  AND seq > $3
                ORDER BY seq ASC
                LIMIT 50
                """,
                session_id,
                participant_did,
                last_seen_seq,
            )

            if new_msgs:
                replies = []
                for row in new_msgs:
                    content = await _decrypt_chat_row_for_hosted(
                        auth=auth,
                        hosted_decryptor=hosted_decryptor,
                        row=dict(row),
                    )
                    last_seen_seq = row["seq"]
                    is_hang_on = bool(row["hang_on"])
                    if is_hang_on:
                        extended = time.monotonic() + HANG_ON_EXTENSION_SECONDS
                        deadline = min(max(deadline, extended), absolute_deadline)
                    replies.append(
                        {
                            "message_id": str(row["message_id"]),
                            "from_alias": row["from_alias"],
                            "from_address": row["from_address"],
                            "from_did": row["from_did"],
                            "signature": row.get("signature"),
                            "signed_payload": row.get("signed_payload"),
                            **verified_signed_recipient_fields({**row, "conversation_id": session_id_str}),
                            "body": content["body"],
                            "attachments": content.get("attachments", []),
                            "attachments_available": content.get("attachments_available", False),
                            "decryptable": content["decryptable"],
                            "content_notice": content["content_notice"],
                            "hang_on": is_hang_on,
                            "sender_leaving": bool(row["sender_leaving"]),
                            "timestamp": row["created_at"].isoformat(),
                            "verification_status": message_verification_status(
                                {**row, "conversation_id": session_id_str}
                            ),
                        }
                    )
                if any(not reply["hang_on"] for reply in replies):
                    return replies, False

            await asyncio.sleep(0.5)

        return [], True
    finally:
        await unregister_waiting(redis, session_id_str, participant_did)
        await wake_chat_session_participants(aweb_db, current_agent_wake_publisher(), session_id=session_id)


async def chat_send(
    db_infra,
    redis,
    *,
    registry_client,
    federation_authority=None,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    message: str,
    to_alias: str = "",
    to_did: str = "",
    to_address: str = "",
    session_id: str = "",
    wait: bool = False,
    wait_seconds: int = 120,
    leaving: bool = False,
    hang_on: bool = False,
    plaintext: bool = False,
    federation_transport=None,
    public_origin: str | None = None,
) -> str:
    auth = get_auth()
    from aweb.human_channels.http import ingress_requested

    if auth.request is not None and ingress_requested(auth.request):
        from aweb.human_channels.mcp import send_mcp_native
        from aweb.human_channels.contract import ContractError

        try:
            result = await send_mcp_native(
                db_infra,
                auth,
                kind="chat",
                arguments=dict(
                    to_alias=to_alias,
                    to_did=to_did,
                    to_address=to_address,
                    session_id=session_id,
                    message=message,
                    wait=wait,
                    wait_seconds=wait_seconds,
                    leaving=leaving,
                    hang_on=hang_on,
                    plaintext=plaintext,
                ),
                hosted_signer=hosted_signer,
                hosted_encryptor=hosted_encryptor,
            )
        except HumanChatRefused as exc:
            return json.dumps({"error": exc.detail, **exc.body(), "effects": "none"})
        except ContractError as error:
            return json.dumps({"error": error.code, "effects": "none"})
        if wait:
            row = await db_infra.get_manager("aweb").fetch_one(
                "SELECT seq,from_did FROM {{tables.chat_messages}} WHERE message_id=$1",
                UUID(result["message_id"]),
            )
            replies, timed_out = await _wait_for_replies(
                db_infra.get_manager("aweb"),
                redis,
                auth=auth,
                hosted_decryptor=hosted_decryptor,
                session_id=UUID(result["session_id"]),
                participant_did=row["from_did"],
                after_seq=row["seq"],
                wait_seconds=wait_seconds,
            )
            result.update(replies=replies, timed_out=timed_out)
        return json.dumps(result)
    sender = mcp_messaging_auth(auth)
    actor_dids = participant_dids(sender)
    actor_did = actor_dids[0] if actor_dids else ""
    sender_address = _sender_address(auth)
    aweb_db = db_infra.get_manager("aweb")
    hosted_handle_address = to_alias.strip().startswith("@")
    normalized_alias = normalize_hosted_handle_reference(to_alias, require_agent=True)
    if hosted_handle_address and normalized_alias != to_alias.strip() and "/" in normalized_alias:
        to_address = normalized_alias
        to_alias = ""
    else:
        to_address = normalize_hosted_handle_reference(to_address, require_agent=True)

    recipient_modes = int(bool(to_alias.strip())) + int(bool(to_did.strip())) + int(bool(to_address.strip()))
    if not session_id and recipient_modes != 1:
        return json.dumps({"error": "Provide exactly one of to_alias, to_did, or to_address"})
    if session_id and recipient_modes != 0:
        return json.dumps({"error": "Provide session_id or a recipient, not both"})

    if not actor_did:
        return json.dumps({"error": "Authenticated identity is missing a routing DID"})

    runtime = mcp_messaging_runtime(
        auth, public_origin=public_origin, registry_client=registry_client,
        federation_authority=federation_authority, chat_transport=federation_transport,
    )
    source = "mcp:" + str(auth.did_key or auth.did_aw or "unknown")
    address_ref = to_address.strip()
    named_alias = ""
    selector = None
    if not session_id:
        # The tool's arguments are not an HTTP request body: they select the
        # recipient as given, without the request model's field validators.
        if to_alias:
            if auth.team_id is None:
                return json.dumps({"error": "to_alias requires team context"})
            named_alias = to_alias.strip()
            selector = CreateSessionRequest.model_construct(to_aliases=[named_alias])
        elif to_did:
            selector = CreateSessionRequest.model_construct(to_dids=[to_did.strip()])
        else:
            if "/" not in address_ref:
                return json.dumps({"error": "to_address must be domain/name"})
            selector = CreateSessionRequest.model_construct(to_addresses=[address_ref])
    else:
        try:
            UUID(session_id.strip())
        except Exception:
            return json.dumps({"error": "Invalid session_id format"})

    # A send that names its recipient goes to the session the two share, or
    # creates one. The send chooses under the pair's lock; when the session
    # the fields were signed for is not the one it finds, nothing is stored
    # and the fields are resolved and signed again.
    for _ in range(SESSION_ATTEMPTS):
        try:
            if selector is not None:
                target = await resolve_chat_targets(
                    db_infra, sender, selector, runtime, source, reuse_or_create=True,
                )
            else:
                target = await resolve_chat_targets(db_infra, sender, session_id, runtime, source)
        except (HTTPException, FederationAuthorityError, ServiceError) as exc:
            return _send_refusal(exc, address=address_ref)

        recipient_rows = target.recipients
        continues_session = target.session_id is not None
        federated = any(row.get("external") or row.get("delivery_origin") for row in recipient_rows)
        sid = target.session_id or target.shared_session_id or uuid_mod.uuid4()
        # sender_attested_at is signed sender intent; send_in_session assigns
        # independent server receipt time for ordering, so they may disagree.
        sender_attested_at = datetime.now(timezone.utc).replace(microsecond=0)
        pre_message_id = uuid_mod.uuid4()
        signed_fields = _signed_chat_fields(
            auth,
            signed_from=sender_address if federated and sender_address else _signed_from(auth),
            recipient_rows=recipient_rows,
            named_alias=named_alias,
            message=message,
            message_id=str(pre_message_id),
            conversation_id=str(sid),
            timestamp=_signed_timestamp(sender_attested_at),
            wait_seconds=wait_seconds if wait else None,
            hang_on=hang_on,
            leaving=leaving,
        )
        signed = None
        encrypted = None
        if auth.trusted_proxy and not plaintext:
            try:
                encrypted = await encrypt_hosted_message(
                    auth=auth,
                    encryptor=hosted_encryptor,
                    message_type="chat",
                    payload=signed_fields,
                    recipients=[_chat_recipient_for_encryptor(row) for row in recipient_rows],
                )
            except HostedMessageEncryptionError as exc:
                return json.dumps({"error": str(exc)})
        else:
            try:
                signed = await sign_hosted_message(
                    auth=auth,
                    signer=hosted_signer,
                    message_type="chat",
                    payload=signed_fields,
                )
            except HostedMessageSigningError as exc:
                return json.dumps({"error": str(exc)})

        sent_fields = dict(
            hang_on=hang_on,
            wait_seconds=wait_seconds if wait else None,
            content_mode=encrypted.content_mode if encrypted is not None else "legacy_plaintext_v1",
            message_version=encrypted.message_version if encrypted is not None else 1,
            encrypted_envelope=encrypted.encrypted_envelope if encrypted is not None else None,
            leaving=leaving,
            message_id=str(pre_message_id),
            timestamp=_signed_timestamp(sender_attested_at),
            from_did=signed.from_did if signed else (auth.did_key or "").strip() or None,
            signature=signed.signature if signed else None,
            signed_payload=signed.signed_payload if signed else None,
        )
        if continues_session:
            payload = ChatSendMessageRequest.model_construct(
                body="" if encrypted is not None else message, **sent_fields,
            )
        else:
            payload = selector.model_copy(update=dict(
                session_id=str(sid),
                message="" if encrypted is not None else message,
                **sent_fields,
            ))
        try:
            sent = await send_chat(db_infra, sender, target, payload, runtime)
        except ChatSessionChanged:
            continue
        except Exception as exc:
            if continues_session and getattr(exc, "detail", None) == SENDER_NOT_IN_SESSION:
                # A caller who is not in the session is answered as for a session that does not exist.
                return json.dumps({"error": "Session not found"})
            return _send_refusal(exc, address=address_ref, hosted_envelope=encrypted is not None)
        break
    else:
        return json.dumps({"error": CONVERSATION_CHANGED_DURING_SEND})
    msg = sent.message

    result: dict = {
        "session_id": str(sent.session_id),
        "conversation_id": str(sent.session_id),
        "message_id": str(msg["message_id"]),
        "delivered": True,
    }
    if wait:
        replies, timed_out = await _wait_for_replies(
            aweb_db,
            redis,
            auth=auth,
            hosted_decryptor=hosted_decryptor,
            session_id=sent.session_id,
            participant_did=target.actor_did or actor_did,
            after_seq=msg["seq"],
            wait_seconds=wait_seconds,
        )
        result["replies"] = replies
        result["timed_out"] = timed_out
    return json.dumps(result)


async def chat_pending(
    db_infra,
    redis,
    *,
    hosted_decryptor: HostedMessageDecryptor | None = None,
) -> str:
    auth = get_auth()
    actor_dids = _actor_dids()
    actor_agent = await _resolve_actor_agent(db_infra, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    conversations_by_session: dict[str, dict] = {}
    for actor_did in actor_dids:
        rows = await get_pending_conversations(
            db_infra,
            participant_did=actor_did,
            participant_agent_id=actor_agent_id,
        )
        for row in rows:
            conversations_by_session.setdefault(row["session_id"], row)
    conversations = list(conversations_by_session.values())
    for row in conversations:
        content = await _decrypt_chat_row_for_hosted(
            auth=auth,
            hosted_decryptor=hosted_decryptor,
            row={
                "content_mode": row.get("last_message_content_mode") or "legacy_plaintext_v1",
                "message_version": row.get("last_message_version") or 1,
                "encrypted_envelope": row.get("last_encrypted_envelope"),
                "body": row.get("last_message") or "",
            },
        )
        row["last_message"] = content["body"]
        row["last_message_decryptable"] = content["decryptable"]
        row["last_message_content_notice"] = content["content_notice"]
    pending = [
        {
            "session_id": row["session_id"],
            "conversation_id": row["session_id"],
            "participants": row["participants"],
            "participant_addresses": row.get("participant_addresses") or [],
            "last_message": row["last_message"],
            "last_message_decryptable": row.get("last_message_decryptable", True),
            "last_message_content_notice": row.get("last_message_content_notice"),
            "last_from": row["last_from"],
            "unread_count": row["unread_count"],
            "last_activity": row["last_activity"].isoformat() if row["last_activity"] else "",
        }
        for row in conversations
    ]
    return json.dumps({"pending": pending})


async def chat_history(
    db_infra,
    *,
    session_id: str,
    unread_only: bool = False,
    limit: int = 50,
    hosted_decryptor: HostedMessageDecryptor | None = None,
) -> str:
    auth = get_auth()
    actor_dids = _actor_dids()
    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    aweb_db = db_infra.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        return json.dumps({"error": "Session not found"})

    actor_did = await resolve_session_actor_did(
        db_infra,
        session_id=session_uuid,
        actor_dids=actor_dids,
    )
    if not actor_did:
        return json.dumps({"error": "Session not found"})

    try:
        messages = await get_message_history(
            db_infra,
            session_id=session_uuid,
            participant_did=actor_did,
            unread_only=unread_only,
            limit=min(limit, 200),
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    output_messages = []
    for msg in messages:
        content = await _decrypt_chat_row_for_hosted(
            auth=auth,
            hosted_decryptor=hosted_decryptor,
            row=msg,
        )
        output_messages.append(
            {
                "message_id": msg["message_id"],
                "conversation_id": str(session_uuid),
                "from_alias": msg["from_alias"],
                "from_address": msg.get("from_address"),
                "from_did": msg.get("from_did"),
                "signature": msg.get("signature"),
                "signed_payload": msg.get("signed_payload"),
                **verified_signed_recipient_fields({**msg, "conversation_id": str(session_uuid)}),
                "body": content["body"],
                "attachments": content.get("attachments", []),
                "attachments_available": content.get("attachments_available", False),
                "decryptable": content["decryptable"],
                "content_notice": content["content_notice"],
                "sender_leaving": msg["sender_leaving"],
                "timestamp": msg["created_at"].isoformat(),
                "verification_status": message_verification_status(
                    {**msg, "conversation_id": str(session_uuid)}
                ),
            }
        )

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "conversation_id": str(session_uuid),
            "messages": output_messages,
        }
    )


async def chat_read(
    db_infra,
    *,
    session_id: str,
    up_to_message_id: str | None = None,
    message_ids: list[str] | None = None,
    redis=None,
) -> str:
    auth = get_auth()

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    normalized_message_ids: list[str] | None = None
    normalized_watermark: str | None = None
    if up_to_message_id is not None:
        try:
            normalized_watermark = str(UUID(up_to_message_id.strip()))
        except Exception:
            return json.dumps({"error": "Invalid message_id format"})
    if message_ids is not None:
        if not message_ids:
            return json.dumps({"error": "message_ids is required"})
        try:
            normalized_message_ids = [str(UUID(message_id.strip())) for message_id in message_ids]
        except Exception:
            return json.dumps({"error": "Invalid message_id format"})
    elif normalized_watermark is None:
        return json.dumps({"error": "up_to_message_id or message_ids is required"})

    try:
        result = await mark_chat_read(
            db_infra,
            redis,
            mcp_messaging_auth(auth),
            mcp_messaging_runtime(auth),
            session_id=session_uuid,
            message_ids=normalized_message_ids,
            up_to_message_id=normalized_watermark,
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})
    if result is None:
        return json.dumps({"error": "Session not found"})

    return json.dumps(
        {
            "session_id": result["session_id"],
            "messages_marked": result["messages_marked"],
            "status": "read",
        }
    )
