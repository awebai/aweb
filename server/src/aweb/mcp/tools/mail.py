"""MCP tools for async mail messaging."""

from __future__ import annotations
from aweb.messaging.mail_attribution import incoming_mail_sql

from aweb.identity_auth_deps import participant_dids

from aweb.attachments import readable_attachments

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import cast

from fastapi import HTTPException

from awid.federation_errors import FederationAuthorityError
from aweb.e2ee_messages import E2EERecipientKeyMismatch
from aweb.federation.errors import RecipientNotResidentError
from aweb.agent_wake import agent_wake_scope, record_did_wakes
from aweb.mcp.auth import current_agent_wake_publisher, get_auth
from aweb.mcp.mutations import fire_mcp_mutation_hook
from aweb.mcp.signing import (
    HostedMessageDecryptor,
    HostedMessageDecryptionError,
    HostedMessageDecryptionResult,
    HostedMessageEncryptor,
    HostedMessageEncryptionError,
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
from aweb.messaging import mail_send
from aweb.messaging.sender_address import sender_address as _sender_address
from aweb.messaging.address_auth import (
    local_recipient_for_own_route,
    unreachable_address_refusal,
)
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.messages import (
    MessagePriority,
    utc_iso as _utc_iso,
)
from aweb.messaging.verification import (
    message_verification_status,
)
from aweb.messaging.mail_routing import (
    ParticipantRetiredError,
    participant_is_remote,
    recipient_for_conversation_participant,
    remote_recipient_from_participant,
)
from aweb.routes.messages import SendMessageRequest
from aweb.service_errors import ServiceError

async def list_threads(
    db, *, limit: int = 50, cursor: str = "", participant_did: str = "",
    participant_address: str = "",
) -> str:
    from aweb.routes.conversations import list_conversations_for_auth

    try:
        response = await list_conversations_for_auth(
            db, mcp_messaging_auth(get_auth()), conversation_type="mail", limit=limit,
            cursor=cursor or None, participant_did=participant_did or None,
            participant_address=participant_address or None,
        )
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})
    return response.model_dump_json()


VALID_PRIORITIES: set[str] = set(MessagePriority.__args__)  # type: ignore[attr-defined]


def mcp_mail_message_from_row(
    row: dict,
    *,
    include_bodies: bool = True,
    hosted_plaintext=None,
) -> dict:
    content_mode = str(row.get("content_mode") or "legacy_plaintext_v1")
    encrypted = content_mode == "encrypted_v2"
    decryptable = bool(getattr(hosted_plaintext, "decryptable", False)) if encrypted else True
    read_at = _utc_iso(row["read_at"]) if row.get("read_at") is not None else None
    msg: dict = {
        "message_id": str(row["message_id"]),
        "conversation_id": str(row["conversation_id"]) if row.get("conversation_id") else None,
        "from_agent_id": (str(row["from_agent_id"]) if row.get("from_agent_id") else None),
        "from_alias": row["from_alias"],
        "from_address": row["from_address"] or "",
        "to_alias": row["to_alias"],
        "subject": (
            getattr(hosted_plaintext, "subject", "")
            if encrypted and decryptable
            else ("" if encrypted else row["subject"])
        ),
        "priority": row["priority"],
        "read": read_at is not None,
        "read_at": read_at,
        "created_at": _utc_iso(row["created_at"]),
        "to_did": row.get("to_did"),
        "content_mode": content_mode,
        "message_version": int(row.get("message_version") or (2 if encrypted else 1)),
        "encrypted": encrypted,
        "decryptable": decryptable,
    }
    if encrypted and decryptable and include_bodies:
        msg.update(readable_attachments(getattr(hosted_plaintext, "attachments", None)))
        if not getattr(hosted_plaintext, "attachments_available", True):
            msg.update({"attachments": [], "attachments_available": False})
    else:
        msg.update({"attachments": [], "attachments_available": not encrypted})
    if include_bodies:
        msg["body"] = (
            getattr(hosted_plaintext, "body", "")
            if encrypted and decryptable
            else ("" if encrypted else row["body"])
        )
    if encrypted:
        notice = getattr(hosted_plaintext, "content_notice", None)
        msg["content_notice"] = notice or (
            None
            if decryptable
            else (
                "Encrypted message content is not available through hosted MCP; "
                "read it in a local client that holds the identity encryption key."
            )
        )
    if row.get("from_did"):
        msg["from_did"] = row["from_did"]
    if not encrypted and row.get("signature"):
        msg["signature"] = row["signature"]
    if not encrypted and row.get("signed_payload"):
        msg["signed_payload"] = row["signed_payload"]
    msg["verification_status"] = message_verification_status(dict(row))
    return msg


def _signed_recipient(recipient_ref: str, recipient_alias: str) -> str:
    """The recipient a first mail signs: the DID, address or team~alias the
    caller named, otherwise the alias it resolved to."""
    if recipient_ref.startswith("did:") or "/" in recipient_ref or "~" in recipient_ref:
        return recipient_ref
    return recipient_alias


def _signed_mail_fields(
    auth,
    *,
    signed_from: str,
    to: str,
    to_did: str,
    to_stable_id: str,
    subject: str,
    body: str,
    priority: str,
    message_id: str,
    conversation_id: str,
    timestamp: str,
) -> dict:
    """The fields a hosted identity signs, or encrypts, for one mail."""
    signed_fields = {
        "body": body,
        "conversation_id": conversation_id,
        "from": signed_from,
        "from_did": (auth.did_key or "").strip(),
        "message_id": message_id,
        "subject": subject,
        "timestamp": timestamp,
        "to": to,
        "to_did": to_did,
        "type": "mail",
    }
    if to_stable_id:
        signed_fields["to_stable_id"] = to_stable_id
    if auth.did_aw:
        signed_fields["from_stable_id"] = auth.did_aw
    if priority != "normal":
        signed_fields["priority"] = priority
    return signed_fields


REGISTRY_CANNOT_CONFIRM_ADDRESS = "the registry can't confirm {address} right now; try again, or check the address"
SENDER_KEY_NOT_PUBLISHED = (
    "your encryption key isn't published yet; try again shortly, and if it persists contact support"
)
SENDER_KEY_NOT_VERIFIABLE = (
    "your published encryption key can't be verified right now; try again shortly, "
    "and if it persists contact support"
)
RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE = (
    "this recipient's published encryption key can't be verified right now; try again later, "
    "and if it persists contact support"
)
RECIPIENT_KEY_CHANGED = "this recipient's key changed; resend the message"
RECIPIENT_NOT_AS_REGISTERED = (
    "this recipient's identity or key no longer matches the registry; check the address and resend"
)
REGISTRY_CANNOT_CONFIRM_RECIPIENT_KEY = (
    "the registry can't confirm this recipient's key right now; try again shortly"
)

# What a hosted sender does next when the custody check refuses its envelope.
# The sender of a hosted envelope holds a hosted key, so the check refused
# because that key, or the recipient's, is not verifiably published here.
_HOSTED_ENVELOPE_NEXT_ACTIONS = {
    "recipient_custodial_no_e2ee": SENDER_KEY_NOT_PUBLISHED,
    "federation_envelope_invalid": SENDER_KEY_NOT_VERIFIABLE,
    "recipient_encryption_assertion_invalid_or_stale": RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE,
}
_IDENTITY_BINDING_NEXT_ACTIONS = {
    "identity_binding_mismatch": RECIPIENT_NOT_AS_REGISTERED,
    "identity_binding_unavailable": REGISTRY_CANNOT_CONFIRM_RECIPIENT_KEY,
}


def _send_refusal(exc: Exception, *, address: str = "", hosted_envelope: bool = False) -> str:
    """A send the service refused, in this tool's error shape.

    The reader is a language model: a refusal it can act on is a sentence
    naming the next action, with the service's code beside it as ``reason``.
    ``address`` is the full address the send named, ``hosted_envelope`` whether
    hosted custody encrypted it. A full address that reaches no one is refused
    in one set of words, which do not say whether a local identity holds that
    name.
    """
    if isinstance(exc, RecipientNotResidentError):
        return json.dumps({"error": exc.detail, "reason": exc.reason, "retryable": exc.retryable})
    if isinstance(exc, FederationAuthorityError):
        if address and exc.reason in ("recipient_identity_not_found", "local_recipient_route_missing"):
            return json.dumps({"error": unreachable_address_refusal(address)})
        next_action = None
        if address and exc.reason == "sender_registry_unavailable":
            next_action = REGISTRY_CANNOT_CONFIRM_ADDRESS.format(address=address)
        elif hosted_envelope:
            next_action = _HOSTED_ENVELOPE_NEXT_ACTIONS.get(exc.reason)
        if next_action is not None:
            return json.dumps({"error": next_action, "reason": exc.reason})
        return json.dumps({"error": exc.reason})
    detail = getattr(exc, "detail", None)
    if address and detail == "Recipient address not found":
        return json.dumps({"error": unreachable_address_refusal(address)})
    if isinstance(exc.__cause__, E2EERecipientKeyMismatch):
        return json.dumps({"error": RECIPIENT_KEY_CHANGED})
    if isinstance(exc, HTTPException) and detail in _IDENTITY_BINDING_NEXT_ACTIONS:
        return json.dumps({"error": _IDENTITY_BINDING_NEXT_ACTIONS[detail], "reason": detail})
    return json.dumps({"error": detail or str(exc)})


async def send_mail(
    db_infra,
    *,
    registry_client,
    federation_authority=None,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    to: str = "",
    conversation_id: str = "",
    subject: str = "",
    body: str = "",
    priority: str = "normal",
    plaintext: bool = False,
    federation_transport=None,
    public_origin: str | None = None,
) -> str:
    """Send an async message by alias, did:aw, or address."""
    auth = get_auth()
    from aweb.human_channels.http import ingress_requested

    if auth.request is not None and ingress_requested(auth.request):
        from aweb.human_channels.mcp import send_mcp_native
        from aweb.human_channels.contract import ContractError

        try:
            return json.dumps(
                await send_mcp_native(
                    db_infra,
                    auth,
                    kind="mail",
                    arguments=dict(
                        to=to,
                        conversation_id=conversation_id,
                        subject=subject,
                        body=body,
                        priority=priority,
                        plaintext=plaintext,
                    ),
                    hosted_signer=hosted_signer,
                    hosted_encryptor=hosted_encryptor,
                )
            )
        except ParticipantRetiredError as error:
            return json.dumps({"error": error.detail, "effects": "none"})
        except ContractError as error:
            return json.dumps({"error": error.code, "effects": "none"})
    sender_address = _sender_address(auth)
    if priority not in VALID_PRIORITIES:
        return json.dumps(
            {"error": f"Invalid priority. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"}
        )
    if not body.strip():
        return json.dumps({"error": "body is required"})

    recipient_ref = normalize_hosted_handle_reference(to, require_agent=True)
    conversation_ref = (conversation_id or "").strip()
    if conversation_ref and recipient_ref:
        return json.dumps({"error": "Provide to or conversation_id, not both"})
    if not recipient_ref and not conversation_ref:
        return json.dumps({"error": "Recipient or conversation_id is required"})

    if recipient_ref and not recipient_ref.startswith("did:") and "/" not in recipient_ref and not auth.team_id:
        return json.dumps({"error": "Alias delivery requires team context"})

    runtime = mcp_messaging_runtime(
        auth, public_origin=public_origin, registry_client=registry_client,
        federation_authority=federation_authority, mail_transport=federation_transport,
    )
    sender = mcp_messaging_auth(auth)
    address_ref = recipient_ref if "/" in recipient_ref and not recipient_ref.startswith("did:") else ""
    # The tool's arguments are not an HTTP request body: they select the
    # recipient as given, without the request model's field validators.
    if conversation_ref:
        selector = SendMessageRequest.model_construct(conversation_id=conversation_ref)
    elif recipient_ref.startswith("did:"):
        selector = SendMessageRequest.model_construct(to_did=recipient_ref)
    elif address_ref:
        selector = SendMessageRequest.model_construct(to_address=recipient_ref)
    else:
        selector = SendMessageRequest.model_construct(to_alias=recipient_ref)

    message_id = uuid_mod.uuid4()
    # sender_attested_at is signed sender intent; deliver_message returns
    # independent server receipt time for ordering, so they may disagree.
    sender_attested_at = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        target = await mail_send.resolve_mail_target(
            db_infra, sender, selector, runtime,
            source="mcp:" + str(auth.did_key or auth.did_aw or "unknown"),
        )
        if target.continuation is not None:
            recipient_participant = target.continuation.recipient_participant
            signed_conversation_id = conversation_ref
            sent_to = recipient_participant.get("alias") or recipient_participant["did"]
            if participant_is_remote(recipient_participant):
                recipient = await remote_recipient_from_participant(
                    registry_client,
                    recipient_participant,
                )
                local = await local_recipient_for_own_route(db_infra, recipient, runtime)
                if local is not None:
                    recipient["did_key"] = local["did_key"]
                signed_from = sender_address or ""
                signed_to = (recipient.get("address") or "").strip()
                signed_to_did = (recipient.get("did_key") or "").strip()
                signed_to_stable_id = (recipient.get("did_aw") or "").strip()
            else:
                recipient = await recipient_for_conversation_participant(
                    db_infra,
                    recipient_participant,
                )
                signed_from = ""
                # A reply on a stored local route signs the participant's
                # stable identity and no current key.
                signed_to = ""
                signed_to_did = ""
                signed_to_stable_id = (
                    recipient_participant["did"]
                    if str(recipient_participant["did"]).startswith("did:aw:")
                    else ""
                )
        else:
            recipient = target.recipient
            signed_conversation_id = str(uuid_mod.uuid4())
            sent_to = target.to_alias or recipient_ref
            signed_from = sender_address if recipient.get("external") and sender_address else ""
            signed_to = _signed_recipient(recipient_ref, target.to_alias or recipient_ref)
            signed_to_did = (recipient.get("did_key") or "").strip()
            signed_to_stable_id = (recipient.get("did_aw") or "").strip()
    except (HTTPException, FederationAuthorityError, ServiceError) as exc:
        return _send_refusal(exc, address=address_ref)

    signed_fields = _signed_mail_fields(
        auth,
        signed_from=signed_from or (auth.alias or auth.address or auth.did_aw or auth.did_key or "").strip(),
        to=signed_to,
        to_did=signed_to_did,
        to_stable_id=signed_to_stable_id,
        subject=subject,
        body=body,
        priority=priority,
        message_id=str(message_id),
        conversation_id=signed_conversation_id,
        timestamp=_utc_iso(sender_attested_at),
    )
    signature: str | None = None
    signed_payload: str | None = None
    encrypted = None
    if not plaintext:
        try:
            encrypted = await encrypt_hosted_message(
                auth=auth,
                encryptor=hosted_encryptor,
                message_type="mail",
                payload=signed_fields,
                recipient=recipient,
            )
        except HostedMessageEncryptionError as exc:
            return json.dumps({"error": str(exc)})
    if encrypted is None:
        try:
            signed = await sign_hosted_message(
                auth=auth,
                signer=hosted_signer,
                message_type="mail",
                payload=signed_fields,
            )
        except HostedMessageSigningError as exc:
            return json.dumps({"error": str(exc)})
        if signed is not None:
            signature = signed.signature
            signed_payload = signed.signed_payload

    message = selector.model_copy(update=dict(
        conversation_id=signed_conversation_id,
        subject="" if encrypted is not None else subject,
        body="" if encrypted is not None else body,
        content_mode=encrypted.content_mode if encrypted is not None else None,
        message_version=encrypted.message_version if encrypted is not None else None,
        encrypted_envelope=encrypted.encrypted_envelope if encrypted is not None else None,
        priority=cast(MessagePriority, priority),
        message_id=str(message_id),
        timestamp=_utc_iso(sender_attested_at),
        from_did=auth.did_key,
        signature=signature,
        signed_payload=signed_payload,
    ))
    try:
        sent = await mail_send.send_mail(db_infra, sender, target, message, runtime)
    except Exception as exc:
        return _send_refusal(exc, address=address_ref, hosted_envelope=encrypted is not None)

    return json.dumps(
        {
            "message_id": sent.message_id,
            "conversation_id": sent.conversation_id,
            "status": sent.status,
            "delivered_at": sent.delivered_at,
            "to": sent_to,
        }
    )


async def check_inbox(
    db_infra,
    *,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    unread_only: bool = True,
    limit: int = 50,
    include_bodies: bool = True,
) -> str:
    """List inbox messages for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    inbox_dids = participant_dids(auth)
    if not inbox_dids:
        return json.dumps({"error": "Authenticated identity is missing a routing DID"})

    try:
        limit_value = max(1, min(int(limit), 500))
    except Exception:
        return json.dumps({"error": "limit must be an integer"})

    rows = await aweb_db.fetch_all(
        f"""
        SELECT message_id, conversation_id, from_agent_id, from_alias, from_address, to_alias,
               subject, body, priority, read_at, created_at,
               from_did, to_did, signature, signed_payload, content_mode, message_version,
               encrypted_envelope
        FROM {{{{tables.messages}}}} m
        WHERE {incoming_mail_sql('$1')}
          AND ($2::bool IS FALSE OR read_at IS NULL)
        ORDER BY created_at DESC
        LIMIT $3
        """,
        inbox_dids,
        bool(unread_only),
        limit_value,
    )

    # Auto-acknowledge unread messages
    unread_message_ids = [r["message_id"] for r in rows if r["read_at"] is None]
    if unread_message_ids:
        with agent_wake_scope(current_agent_wake_publisher()):
            acknowledged = await aweb_db.fetch_all(
                f"""
                UPDATE {{{{tables.messages}}}} m
                SET read_at = NOW()
                WHERE {incoming_mail_sql('$1')}
                  AND message_id = ANY($2::uuid[])
                  AND read_at IS NULL
                RETURNING message_id, from_alias, subject, content_mode
                """,
                inbox_dids,
                unread_message_ids,
            )
            if acknowledged:
                record_did_wakes(inbox_dids, "mail")
        for row in acknowledged:
            await fire_mcp_mutation_hook(
                "message.acknowledged",
                {
                    "team_id": auth.team_id,
                    "agent_id": auth.agent_id,
                    "alias": auth.alias,
                    "message_id": str(row["message_id"]),
                    "from_alias": row["from_alias"],
                    "subject": row["subject"] or "",
                    "content_mode": row["content_mode"] or "legacy_plaintext_v1",
                },
            )

    messages = []
    for r in rows:
        hosted_plaintext = None
        try:
            hosted_plaintext = await decrypt_hosted_message_row(
                auth=auth,
                decryptor=hosted_decryptor,
                message_type="mail",
                row=dict(r),
            )
        except HostedMessageDecryptionError as exc:
            hosted_plaintext = HostedMessageDecryptionResult(
                decryptable=False,
                content_notice=str(exc),
            )
        msg = mcp_mail_message_from_row(
            dict(r),
            include_bodies=include_bodies,
            hosted_plaintext=hosted_plaintext,
        )
        if r["message_id"] in unread_message_ids:
            msg["read"] = True
        messages.append(msg)

    return json.dumps({"messages": messages})
