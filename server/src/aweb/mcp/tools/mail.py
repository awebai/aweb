"""MCP tools for async mail messaging."""

from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import cast

from aweb.mcp.auth import auth_dids, get_auth, primary_auth_did
from aweb.mcp.signing import (
    HostedMessageSigner,
    HostedMessageSigningError,
    sign_hosted_message,
)
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
    namespace_exists,
)
from aweb.messaging.address_auth import local_recipient_visible_to_auth, requires_registry_address_binding
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    evaluate_messaging_policy,
    get_agent_by_alias,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)
from aweb.messaging.conversations import (
    create_conversation,
    list_conversation_participants,
    require_active_conversation_participant,
    touch_conversation_activity,
)
from aweb.messaging.verification import (
    message_verification_status,
    require_conversation_not_legacy_bound,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError, ValidationError

VALID_PRIORITIES: set[str] = set(MessagePriority.__args__)  # type: ignore[attr-defined]


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


def _sender_address(auth) -> str | None:
    return (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias) or None


async def _local_recipient_from_address(db_infra, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db_infra, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise ServiceError(str(exc)) from exc


def _with_requested_address(row: dict, address: str) -> dict:
    copied = dict(row)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


async def send_mail(
    db_infra,
    *,
    registry_client,
    hosted_signer: HostedMessageSigner | None = None,
    to: str = "",
    conversation_id: str = "",
    subject: str = "",
    body: str = "",
    priority: str = "normal",
) -> str:
    """Send an async message by alias, did:aw, or address."""
    auth = get_auth()
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

    if conversation_ref:
        message_id = uuid_mod.uuid4()
        created_at = datetime.now(timezone.utc).replace(microsecond=0)
        sender_did = primary_auth_did(auth)
        signature: str | None = None
        signed_payload: str | None = None
        try:
            auth_context = await require_active_conversation_participant(
                db_infra,
                conversation_id=conversation_ref,
                authenticated_did=sender_did,
                equivalent_dids=auth_dids(auth),
            )
            await require_conversation_not_legacy_bound(
                db_infra,
                conversation_id=conversation_ref,
                conversation_type="mail",
            )
            participants = await list_conversation_participants(
                db_infra,
                conversation_id=conversation_ref,
            )
            sender_participant_did = auth_context["participant"]["did"]
            recipients = [
                participant for participant in participants
                if participant["did"] != sender_participant_did
            ]
            if len(recipients) == 0 and len(participants) == 1:
                # Defensive self-loopback for a conversation that only has its creator.
                recipient_participant = auth_context["participant"]
            elif len(recipients) == 1:
                recipient_participant = recipients[0]
            else:
                raise ValidationError("Mail conversation continuation requires exactly one recipient")
        except (ValidationError, NotFoundError, ForbiddenError) as exc:
            return json.dumps({"error": exc.detail})

        signed_fields = {
            "body": body,
            "conversation_id": conversation_ref,
            "from": (auth.alias or auth.address or auth.did_aw or auth.did_key or "").strip(),
            "from_did": (auth.did_key or "").strip(),
            "message_id": str(message_id),
            "subject": subject,
            "timestamp": _utc_iso(created_at),
            "to": "",
            "to_did": "",
            "type": "mail",
        }
        if auth.did_aw:
            signed_fields["from_stable_id"] = auth.did_aw
        if priority != "normal":
            signed_fields["priority"] = priority
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
            sender_did = signed.from_did
            signature = signed.signature
            signed_payload = signed.signed_payload

        recipient_did = recipient_participant["did"]
        recipient = {
            "agent_id": recipient_participant.get("agent_id"),
            "alias": recipient_participant.get("alias") or recipient_did,
            "address": recipient_participant.get("address"),
            "did_aw": recipient_did if str(recipient_did).startswith("did:aw:") else "",
            "did_key": recipient_did if str(recipient_did).startswith("did:key:") else "",
            "messaging_policy": None,
        }
        try:
            message_id, created_at = await deliver_message(
                db_infra,
                registry_client=registry_client,
                recipient_agent=recipient,
                from_did=sender_did,
                to_did=recipient_did,
                team_id=auth_context["conversation"].get("team_id") or auth.team_id,
                from_agent_id=auth.agent_id,
                from_alias=auth.alias,
                sender_address=sender_address,
                to_agent_id=recipient_participant.get("agent_id"),
                to_alias=recipient_participant.get("alias"),
                subject=subject,
                body=body,
                priority=cast(MessagePriority, priority),
                signature=signature,
                signed_payload=signed_payload,
                created_at=created_at,
                message_id=message_id,
                conversation_id=conversation_ref,
                skip_policy_check=True,
            )
            await touch_conversation_activity(db_infra, conversation_id=conversation_ref)
        except Exception as exc:
            detail = getattr(exc, "detail", None)
            return json.dumps({"error": detail or str(exc)})

        return json.dumps(
            {
                "message_id": str(message_id),
                "conversation_id": conversation_ref,
                "status": "delivered",
                "delivered_at": _utc_iso(created_at),
                "to": recipient_participant.get("alias") or recipient_did,
            }
        )

    recipient = None
    recipient_did = ""
    recipient_alias = ""
    if recipient_ref.startswith("did:aw:") or recipient_ref.startswith("did:key:"):
        recipient_did = recipient_ref
        recipient = await resolve_agent_by_did(db_infra, recipient_did)
    elif "/" in recipient_ref:
        domain, name = recipient_ref.split("/", 1)
        if registry_client is not None:
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await resolve_agent_by_did(db_infra, recipient_did)
                if recipient is None:
                    recipient = _external_recipient_from_address(recipient_ref, resolved)
        if recipient is None:
            try:
                recipient = await _local_recipient_from_address(db_infra, domain=domain, name=name)
            except ServiceError as exc:
                return json.dumps({"error": exc.detail})
            if recipient is None:
                if await namespace_exists(db_infra, domain):
                    return json.dumps({"error": f"Agent '{recipient_ref}' not found"})
                if registry_client is None:
                    return json.dumps({"error": "AWID registry unavailable"})
                return json.dumps({"error": f"Address '{recipient_ref}' not found"})
            if (
                registry_client is not None
                and requires_registry_address_binding(recipient)
                and not local_recipient_visible_to_auth(recipient, auth)
            ):
                return json.dumps({"error": f"Address '{recipient_ref}' not found"})
            recipient = _with_requested_address(recipient, recipient_ref)
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            if not recipient_did:
                return json.dumps({"error": f"Agent '{recipient_ref}' not found"})
    else:
        if not auth.team_id:
            return json.dumps({"error": "Alias delivery requires team context"})
        recipient = await get_agent_by_alias(
            db_infra, team_id=auth.team_id, alias=recipient_ref,
        )
        if recipient is not None:
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            recipient_alias = recipient["alias"]

    if recipient is None:
        return json.dumps({"error": f"Agent '{recipient_ref}' not found"})
    if not recipient_alias:
        recipient_alias = recipient.get("alias") or recipient_ref

    message_id = uuid_mod.uuid4()
    initial_conversation_id = uuid_mod.uuid4()
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    sender_did = primary_auth_did(auth)
    signature: str | None = None
    signed_payload: str | None = None
    to_stable_id = (recipient.get("did_aw") or "").strip()
    to_current_did = (recipient.get("did_key") or "").strip()
    signed_to = recipient_ref if recipient_ref.startswith("did:") or "/" in recipient_ref else recipient_alias
    signed_fields = {
        "body": body,
        "conversation_id": str(initial_conversation_id),
        "from": (auth.alias or auth.address or auth.did_aw or auth.did_key or "").strip(),
        "from_did": (auth.did_key or "").strip(),
        "message_id": str(message_id),
        "subject": subject,
        "timestamp": _utc_iso(created_at),
        "to": signed_to,
        "to_did": to_current_did,
        "type": "mail",
    }
    if to_stable_id:
        signed_fields["to_stable_id"] = to_stable_id
    if auth.did_aw:
        signed_fields["from_stable_id"] = auth.did_aw
    if priority != "normal":
        signed_fields["priority"] = priority

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
        sender_did = signed.from_did
        signature = signed.signature
        signed_payload = signed.signed_payload

    try:
        if not (recipient or {}).get("external"):
            await evaluate_messaging_policy(
                db_infra,
                registry_client=registry_client,
                recipient_agent=recipient,
                sender_did=sender_did,
                sender_address=sender_address,
            )
        conversation = await create_conversation(
            db_infra,
            conversation_type="mail",
            created_by_did=sender_did,
            conversation_id=initial_conversation_id,
            initiator={
                "did": sender_did,
                "agent_id": auth.agent_id,
                "alias": auth.alias or sender_address or sender_did,
                "address": sender_address,
                "transport_hint": "sender",
            },
            recipients=[
                {
                    "did": recipient_did,
                    "agent_id": str(recipient["agent_id"]) if recipient.get("agent_id") else None,
                    "alias": recipient_alias,
                    "address": recipient.get("address") or (recipient_ref if "/" in recipient_ref else None),
                    "transport_hint": "to_address" if "/" in recipient_ref else "to_alias",
                }
            ],
            team_id=auth.team_id,
        )
        message_id, created_at = await deliver_message(
            db_infra,
            registry_client=registry_client,
            recipient_agent=recipient,
            from_did=sender_did,
            to_did=recipient_did,
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            sender_address=sender_address,
            to_agent_id=str(recipient["agent_id"]) if recipient.get("agent_id") else None,
            to_alias=recipient_alias,
            subject=subject,
            body=body,
            priority=cast(MessagePriority, priority),
            signature=signature,
            signed_payload=signed_payload,
            created_at=created_at,
            message_id=message_id,
            conversation_id=conversation["conversation_id"],
            skip_policy_check=True,
        )
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return json.dumps({"error": detail or str(exc)})

    return json.dumps(
        {
            "message_id": str(message_id),
            "conversation_id": conversation["conversation_id"],
            "status": "delivered",
            "delivered_at": _utc_iso(created_at),
            "to": recipient_alias,
        }
    )


async def check_inbox(
    db_infra,
    *,
    unread_only: bool = True,
    limit: int = 50,
    include_bodies: bool = True,
) -> str:
    """List inbox messages for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    inbox_dids = auth_dids(auth)
    if not inbox_dids:
        return json.dumps({"error": "Authenticated identity is missing a routing DID"})

    try:
        limit_value = max(1, min(int(limit), 500))
    except Exception:
        return json.dumps({"error": "limit must be an integer"})

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, conversation_id, from_agent_id, from_alias, from_address, to_alias,
               subject, body, priority, read_at, created_at,
               from_did, to_did, signature, signed_payload
        FROM {{tables.messages}}
        WHERE to_did = ANY($1::text[])
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
        await aweb_db.execute(
            """
            UPDATE {{tables.messages}}
            SET read_at = COALESCE(read_at, NOW())
            WHERE to_did = ANY($1::text[])
              AND message_id = ANY($2::uuid[])
            """,
            inbox_dids,
            unread_message_ids,
        )

    messages = []
    for r in rows:
        read_at = _utc_iso(r["read_at"]) if r["read_at"] is not None else None
        msg: dict = {
            "message_id": str(r["message_id"]),
            "conversation_id": str(r["conversation_id"]) if r.get("conversation_id") else None,
            "from_agent_id": (str(r["from_agent_id"]) if r.get("from_agent_id") else None),
            "from_alias": r["from_alias"],
            "from_address": r["from_address"] or "",
            "to_alias": r["to_alias"],
            "subject": r["subject"],
            "priority": r["priority"],
            "read": read_at is not None or r["message_id"] in unread_message_ids,
            "read_at": read_at,
            "created_at": _utc_iso(r["created_at"]),
            "to_did": r.get("to_did"),
        }
        if include_bodies:
            msg["body"] = r["body"]
        if r["from_did"]:
            msg["from_did"] = r["from_did"]
        if r["signature"]:
            msg["signature"] = r["signature"]
        if r["signed_payload"]:
            msg["signed_payload"] = r["signed_payload"]
        msg["verification_status"] = message_verification_status(dict(r))
        messages.append(msg)

    return json.dumps({"messages": messages})
