"""MCP tools for contact management."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.mcp.auth import auth_dids, get_auth, primary_auth_did
from aweb.mcp.signing import HostedMessageSigner
from aweb.mcp.tools.chat import chat_send
from aweb.mcp.tools.mail import send_mail
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
)
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.chat import find_session_between
from aweb.messaging.contacts import (
    add_contact,
    add_handle_contact,
    list_contacts,
    normalize_owner_dids,
    remove_contact,
    resolve_handle_contact_agent,
)
from aweb.messaging.conversations import find_active_one_to_one_conversation_between
from aweb.service_errors import ServiceError, ValidationError


async def contacts_list(db_infra) -> str:
    """List all contacts for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    try:
        contacts = await list_contacts(db_infra, owner_dids=owner_dids)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"contacts": contacts})


async def list_contacts_tool(db_infra) -> str:
    """Consumer-friendly alias for contacts_list."""
    return await contacts_list(db_infra)


async def contacts_add(db_infra, *, contact_address: str, label: str = "") -> str:
    """Add a contact for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    owner_did = owner_dids[0] if owner_dids else ""
    try:
        result = await add_contact(
            db_infra,
            owner_did=owner_did,
            contact_address=contact_address,
            label=label or None,
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    result["status"] = "added"
    return json.dumps(result)


async def add_contact_by_handle(db_infra, *, handle: str, label: str = "") -> str:
    """Add a pending contact by @namespace or @namespace/agent."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    owner_did = owner_dids[0] if owner_dids else ""
    try:
        namespace, agent_name = _parse_handle(handle)
        result = await add_handle_contact(
            db_infra,
            owner_did=owner_did,
            handle_namespace=namespace,
            target_agent_name=agent_name,
            label=label or "",
            status="pending",
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    result["status"] = "pending"
    return json.dumps(result)


async def add_contact_by_email(db_infra, *, email: str, label: str = "") -> str:
    """Reserve a pending email contact request.

    Email contact storage needs an explicit product contract; unlike address and
    handle contacts, the current aweb schema has no email reference column.
    """
    try:
        _normalize_email(email)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"error": "Email contact requests are not available on this server"})


async def send_message_to_contact(
    db_infra,
    redis=None,
    *,
    registry_client,
    hosted_signer: HostedMessageSigner | None = None,
    contact_id: str,
    message: str,
    subject: str = "",
    channel: str = "mail",
    priority: str = "normal",
    wait: bool = False,
    wait_seconds: int = 120,
) -> str:
    """Send mail or chat to a saved contact, reusing existing 1:1 conversations."""
    if not message.strip():
        return json.dumps({"error": "message is required"})
    try:
        normalized_channel = _normalize_channel(channel)
        contact = await _get_owned_contact(db_infra, contact_id=contact_id)
        target = await _target_from_contact_reference(db_infra, contact=contact)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    # Pending is receiver-side policy state, not sender-side send authority:
    # sending to a pending contact is the bilateral invite/first-contact flow.
    existing = await _find_existing_conversation(
        db_infra,
        conversation_type=normalized_channel,
        target=target,
    )
    if existing is None:
        try:
            target = await _resolve_contact_target(db_infra, registry_client=registry_client, contact=contact)
        except ServiceError as exc:
            return json.dumps({"error": exc.detail})
    if normalized_channel == "mail":
        if existing is not None:
            return await send_mail(
                db_infra,
                registry_client=registry_client,
                hosted_signer=hosted_signer,
                conversation_id=existing["conversation_id"],
                subject=subject,
                body=message,
                priority=priority,
            )
        return await send_mail(
            db_infra,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            to=target["address"],
            subject=subject,
            body=message,
            priority=priority,
        )

    if existing is not None:
        return await chat_send(
            db_infra,
            redis,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            session_id=existing["conversation_id"],
            message=message,
            wait=wait,
            wait_seconds=wait_seconds,
        )
    return await chat_send(
        db_infra,
        redis,
        registry_client=registry_client,
        hosted_signer=hosted_signer,
        to_address=target["address"],
        message=message,
        wait=wait,
        wait_seconds=wait_seconds,
    )


async def read_messages_from_contact(
    db_infra,
    *,
    registry_client,
    contact_id: str,
    channel: str = "mail",
    limit: int = 50,
) -> str:
    """Read messages exchanged with a contact using server-side conversation filters."""
    try:
        normalized_channel = _normalize_channel(channel)
        limit_value = max(1, min(int(limit), 200))
        contact = await _get_owned_contact(db_infra, contact_id=contact_id)
        target = await _target_from_contact_reference(db_infra, contact=contact)
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return json.dumps({"error": detail or str(exc)})

    if normalized_channel == "mail":
        messages = await _read_mail_messages_from_target(db_infra, target=target, limit=limit_value)
    else:
        messages = await _read_chat_messages_from_target(db_infra, target=target, limit=limit_value)
    return json.dumps({"messages": messages})


async def contacts_remove(db_infra, *, contact_id: str) -> str:
    """Remove a contact for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    try:
        await remove_contact(db_infra, owner_dids=owner_dids, contact_id=contact_id)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    # remove_contact already validated the UUID; normalize for the response.
    try:
        normalized_id = str(UUID(contact_id.strip()))
    except Exception:
        normalized_id = contact_id.strip()
    return json.dumps({"contact_id": normalized_id, "status": "removed"})


def _owner_dids() -> list[str]:
    auth = get_auth()
    return normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])


def _parse_handle(handle: str) -> tuple[str, str | None]:
    ref = normalize_hosted_handle_reference(handle)
    if ref.startswith("@"):
        raise ValidationError("Invalid handle format")
    if not ref:
        raise ValidationError("handle is required")
    if "/" in ref:
        namespace, agent_name = ref.split("/", 1)
        if not agent_name.strip():
            raise ValidationError("Invalid handle format")
    else:
        namespace, agent_name = ref, None
    return namespace, agent_name


def _normalize_email(email: str) -> str:
    value = (email or "").strip()
    if value.count("@") != 1 or value.startswith("@") or value.endswith("@"):
        raise ValidationError("Invalid email format")
    return value


def _normalize_channel(channel: str) -> str:
    value = (channel or "mail").strip().lower()
    if value not in {"mail", "chat"}:
        raise ValidationError("channel must be mail or chat")
    return value


async def _get_owned_contact(db_infra, *, contact_id: str) -> dict:
    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        raise ValidationError("Invalid contact_id format")
    owner_dids = _owner_dids()
    if not owner_dids:
        raise ValidationError("Authenticated identity is missing a routing DID")
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT contact_id, owner_did, contact_address, label, created_at,
               reference_type, status, handle_namespace, target_agent_name
        FROM {{tables.contacts}}
        WHERE contact_id = $1
          AND owner_did = ANY($2::text[])
        """,
        contact_uuid,
        owner_dids,
    )
    if row is None:
        raise ValidationError("Contact not found")
    return dict(row)


async def _target_from_contact_reference(db_infra, *, contact: dict) -> dict:
    if contact["reference_type"] == "handle":
        target = await resolve_handle_contact_agent(
            db_infra,
            handle_namespace=contact["handle_namespace"],
            target_agent_name=contact["target_agent_name"],
        )
        if target is None:
            raise ValidationError("No active agent found for handle contact")
        return target

    address = (contact.get("contact_address") or "").strip()
    if "/" not in address:
        raise ValidationError("Contact address must be domain/name")
    _, name = address.split("/", 1)
    return {
        "agent_id": None,
        "team_id": None,
        "alias": name,
        "address": address,
        "did_aw": "",
        "did_key": "",
        "external": True,
    }


async def _resolve_contact_target(db_infra, *, registry_client, contact: dict) -> dict:
    if contact["reference_type"] == "handle":
        target = await resolve_handle_contact_agent(
            db_infra,
            handle_namespace=contact["handle_namespace"],
            target_agent_name=contact["target_agent_name"],
        )
        if target is None:
            raise ValidationError("No active agent found for handle contact")
        return target

    address = (contact.get("contact_address") or "").strip()
    if "/" not in address:
        raise ValidationError("Contact address must be domain/name")
    domain, name = address.split("/", 1)
    target: dict | None = None
    if registry_client is not None:
        resolved = await registry_client.resolve_address(domain, name, did_key=(get_auth().did_key or None))
        if resolved is not None and resolved.did_aw:
            target = {
                "agent_id": None,
                "team_id": None,
                "alias": name,
                "address": address,
                "did_aw": resolved.did_aw.strip(),
                "did_key": (getattr(resolved, "current_did_key", "") or "").strip(),
                        "external": True,
            }
    if target is None:
        try:
            target = await get_agent_by_namespace_alias(db_infra, namespace=domain, alias=name)
        except AmbiguousLocalAddressError as exc:
            raise ServiceError(str(exc)) from exc
    if target is None:
        return {
            "agent_id": None,
            "team_id": None,
            "alias": name,
            "address": address,
            "did_aw": "",
            "did_key": "",
                "external": True,
        }
    copied = dict(target)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


async def _find_existing_conversation(db_infra, *, conversation_type: str, target: dict) -> dict | None:
    auth = get_auth()
    if conversation_type == "chat":
        session_id = await find_session_between(
            db_infra,
            did_a=primary_auth_did(auth),
            did_key_a=auth.did_key,
            agent_id_a=auth.agent_id,
            address_a=(auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias),
            did_b=(target.get("did_aw") or target.get("did_key") or "").strip(),
            did_key_b=(target.get("did_key") or "").strip() or None,
            agent_id_b=target.get("agent_id"),
            address_b=(target.get("address") or "").strip() or None,
        )
        if session_id is not None:
            return {"conversation_id": str(session_id)}
    return await find_active_one_to_one_conversation_between(
        db_infra,
        conversation_type=conversation_type,  # type: ignore[arg-type]
        did_a=primary_auth_did(auth),
        did_key_a=auth.did_key,
        agent_id_a=auth.agent_id,
        address_a=(auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias),
        did_b=(target.get("did_aw") or target.get("did_key") or "").strip(),
        did_key_b=(target.get("did_key") or "").strip() or None,
        agent_id_b=target.get("agent_id"),
        address_b=(target.get("address") or "").strip() or None,
    )


def _target_refs(target: dict) -> tuple[list[str], list[str]]:
    dids = [
        value
        for value in (
            (target.get("did_aw") or "").strip(),
            (target.get("did_key") or "").strip(),
        )
        if value
    ]
    addresses = [value for value in [(target.get("address") or "").strip()] if value]
    return dids, addresses


async def _read_mail_messages_from_target(db_infra, *, target: dict, limit: int) -> list[dict]:
    auth = get_auth()
    actor_dids = auth_dids(auth)
    if not actor_dids:
        return []
    target_dids, target_addresses = _target_refs(target)
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        WITH matching_conversations AS (
            SELECT DISTINCT ca.conversation_id
            FROM {{tables.conversations}} c
            JOIN {{tables.conversation_participants}} ca
              ON ca.conversation_id = c.conversation_id
            JOIN {{tables.conversation_participants}} cb
              ON cb.conversation_id = c.conversation_id
            WHERE c.conversation_type = 'mail'
              AND (
                    ca.did = ANY($1::text[])
                 OR ($2::text IS NOT NULL AND ca.address = $2)
              )
              AND (
                    ($3::text[] <> '{}'::text[] AND cb.did = ANY($3::text[]))
                 OR ($4::text[] <> '{}'::text[] AND cb.address = ANY($4::text[]))
              )
              AND ca.did <> cb.did
        )
        SELECT m.message_id, m.conversation_id, m.from_did, m.to_did, m.from_alias,
               m.from_address, m.to_alias, m.subject, m.body, m.priority,
               m.read_at, m.created_at
        FROM {{tables.messages}} m
        WHERE m.conversation_id IN (SELECT conversation_id FROM matching_conversations)
        ORDER BY m.created_at DESC, m.message_id DESC
        LIMIT $5
        """,
        actor_dids,
        (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias),
        target_dids,
        target_addresses,
        limit,
    )
    return [
        {
            "message_id": str(row["message_id"]),
            "conversation_id": str(row["conversation_id"]) if row.get("conversation_id") else None,
            "from_did": row["from_did"],
            "to_did": row["to_did"],
            "from_alias": row["from_alias"],
            "from_address": row["from_address"],
            "to_alias": row["to_alias"],
            "subject": row["subject"],
            "body": row["body"],
            "priority": row["priority"],
            "read": row["read_at"] is not None,
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


async def _read_chat_messages_from_target(db_infra, *, target: dict, limit: int) -> list[dict]:
    auth = get_auth()
    actor_dids = auth_dids(auth)
    if not actor_dids:
        return []
    target_dids, target_addresses = _target_refs(target)
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        WITH matching_sessions AS (
            SELECT DISTINCT ca.session_id
            FROM {{tables.chat_participants}} ca
            JOIN {{tables.chat_participants}} cb
              ON cb.session_id = ca.session_id
            WHERE (
                    ca.did = ANY($1::text[])
                 OR ($2::text IS NOT NULL AND ca.address = $2)
              )
              AND (
                    ($3::text[] <> '{}'::text[] AND cb.did = ANY($3::text[]))
                 OR ($4::text[] <> '{}'::text[] AND cb.address = ANY($4::text[]))
              )
              AND ca.did <> cb.did
        )
        SELECT m.message_id, m.session_id, m.from_did, m.from_alias, m.from_address,
               m.body, m.sender_leaving, m.hang_on, m.created_at
        FROM {{tables.chat_messages}} m
        WHERE m.session_id IN (SELECT session_id FROM matching_sessions)
        ORDER BY m.created_at DESC, m.message_id DESC
        LIMIT $5
        """,
        actor_dids,
        (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias),
        target_dids,
        target_addresses,
        limit,
    )
    return [
        {
            "message_id": str(row["message_id"]),
            "session_id": str(row["session_id"]),
            "conversation_id": str(row["session_id"]),
            "from_did": row["from_did"],
            "from_alias": row["from_alias"],
            "from_address": row["from_address"],
            "body": row["body"],
            "sender_leaving": bool(row["sender_leaving"]),
            "hang_on": bool(row["hang_on"]),
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]
