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
from aweb.messaging.alias_targets import namespace_exists
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    get_agent_by_alias,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)

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


async def send_mail(
    db_infra,
    *,
    registry_client,
    hosted_signer: HostedMessageSigner | None = None,
    to: str,
    subject: str = "",
    body: str,
    priority: str = "normal",
) -> str:
    """Send an async message by alias, did:aw, or address."""
    auth = get_auth()
    if priority not in VALID_PRIORITIES:
        return json.dumps(
            {"error": f"Invalid priority. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"}
        )

    recipient_ref = (to or "").strip()
    if not recipient_ref:
        return json.dumps({"error": "Recipient is required"})

    recipient = None
    recipient_did = ""
    recipient_alias = ""
    if recipient_ref.startswith("did:aw:") or recipient_ref.startswith("did:key:"):
        recipient_did = recipient_ref
        recipient = await resolve_agent_by_did(db_infra, recipient_did)
    elif "/" in recipient_ref:
        if registry_client is None:
            return json.dumps({"error": "AWID registry unavailable"})
        domain, name = recipient_ref.split("/", 1)
        resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolved is None or not resolved.did_aw:
            return json.dumps({"error": f"Address '{recipient_ref}' not found"})
        recipient_did = resolved.did_aw
        recipient = await resolve_agent_by_did(db_infra, recipient_did)
        if recipient is None:
            if await namespace_exists(db_infra, domain):
                return json.dumps({"error": f"Agent '{recipient_ref}' not found"})
            recipient = _external_recipient_from_address(recipient_ref, resolved)
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
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    sender_did = primary_auth_did(auth)
    signature: str | None = None
    signed_payload: str | None = None
    to_stable_id = (recipient.get("did_aw") or "").strip()
    to_current_did = (recipient.get("did_key") or "").strip()
    signed_to = recipient_ref if recipient_ref.startswith("did:") or "/" in recipient_ref else recipient_alias
    signed_fields = {
        "body": body,
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
        message_id, created_at = await deliver_message(
            db_infra,
            registry_client=registry_client,
            recipient_agent=recipient,
            from_did=sender_did,
            to_did=recipient_did,
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            sender_address=auth.address,
            to_agent_id=str(recipient["agent_id"]) if recipient.get("agent_id") else None,
            to_alias=recipient_alias,
            subject=subject,
            body=body,
            priority=cast(MessagePriority, priority),
            signature=signature,
            signed_payload=signed_payload,
            created_at=created_at,
            message_id=message_id,
        )
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return json.dumps({"error": detail or str(exc)})

    return json.dumps(
        {
            "message_id": str(message_id),
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
        SELECT message_id, from_agent_id, from_alias, from_address, to_alias,
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
        messages.append(msg)

    return json.dumps({"messages": messages})
