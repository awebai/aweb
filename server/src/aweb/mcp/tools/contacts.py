"""MCP tools for contact management."""

from __future__ import annotations

from aweb.mcp.tools.federation import mcp_sender_budget_key

import json
from uuid import UUID

from awid.federation_errors import FederationAuthorityError
from aweb.mcp.tools.errors import messaging_tool
from aweb.messaging.sender_membership import sender_memberships
from aweb.messaging.kinds import MessageKind
from aweb.mcp.tools.refusals import send_refusal
from fastapi import HTTPException
from aweb.identity_auth_deps import participant_dids
from aweb.mcp.auth import get_auth
from aweb.mcp.tools.mail import mcp_mail_message_from_row
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.contacts import (
    add_contact as add_contact_record,
    add_handle_contact,
    list_contacts as list_contact_records,
    normalize_owner_dids,
    remove_contact as remove_contact_record,
    resolve_handle_contact_agent,
)
from aweb.messaging.verification import verified_signed_recipient_fields
from aweb.service_errors import ServiceError, ValidationError


@messaging_tool
async def list_contacts(db_infra) -> str:
    """List all contacts for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    try:
        contacts = await list_contact_records(db_infra, owner_dids=owner_dids)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"contacts": contacts})


@messaging_tool
async def add_contact(
    db_infra,
    *,
    contact_address: str,
    label: str = "",
    federation_authority=None,
) -> str:
    """Add a contact for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    owner_did = owner_dids[0] if owner_dids else ""
    try:
        if federation_authority is None:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            )
        resolved = await federation_authority.resolve_contact(
            normalize_hosted_handle_reference(contact_address),
            source_ip=mcp_sender_budget_key(auth),
        )
        result = await add_contact_record(
            db_infra,
            owner_did=owner_did,
            contact_address=resolved.canonical_address,
            contact_did_aw=resolved.did_aw,
            binding_controller_did=resolved.controller_did,
            label=label or None,
        )
    except FederationAuthorityError as exc:
        return json.dumps({"error": exc.reason})
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    result["status"] = "added"
    return json.dumps(result)


@messaging_tool
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


@messaging_tool
async def read_contact_messages(
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
    except (ServiceError, HTTPException, FederationAuthorityError) as exc:
        return send_refusal(exc)

    if normalized_channel is MessageKind.MAIL:
        messages = await _read_mail_messages_from_target(
            db_infra, target=target, limit=limit_value
        )
    else:
        messages = await _read_chat_messages_from_target(
            db_infra, target=target, limit=limit_value
        )
    return json.dumps({"messages": messages})


@messaging_tool
async def remove_contact(db_infra, *, contact_id: str) -> str:
    """Remove a contact for the authenticated identity."""
    auth = get_auth()
    owner_dids = normalize_owner_dids(owner_dids=[auth.did_aw, auth.did_key])
    try:
        await remove_contact_record(
            db_infra, owner_dids=owner_dids, contact_id=contact_id
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    # remove_contact_record already validated the UUID; normalize for the response.
    try:
        normalized_id = str(UUID(contact_id.strip()))
    except (ValueError, TypeError, AttributeError):
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


def _normalize_channel(channel: str) -> MessageKind:
    value = (channel or "mail").strip().lower()
    if value == MessageKind.MAIL:
        return MessageKind.MAIL
    if value == MessageKind.CHAT:
        return MessageKind.CHAT
    raise ValidationError(
        "channel must be mail or chat. Choose mail or chat and try again."
    )


async def _get_owned_contact(db_infra, *, contact_id: str) -> dict:
    try:
        contact_uuid = UUID(contact_id.strip())
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Invalid contact_id format")
    owner_dids = _owner_dids()
    if not owner_dids:
        raise ValidationError("Authenticated identity is missing a routing DID")
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT contact_id, owner_did, contact_address, label, created_at,
               reference_type, status, handle_namespace, target_agent_name,
               contact_did_aw, binding_controller_did, binding_accepted_at
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
        "did_aw": str(contact.get("contact_did_aw") or "").strip(),
        "did_key": "",
        "external": True,
    }


def _target_refs(target: dict) -> tuple[list[str], list[str]]:
    dids = [
        value
        for value in (
            (target.get("did_aw") or "").strip(),
            (target.get("did_key") or "").strip(),
        )
        if value
    ]
    addresses = (
        []
        if dids
        else [value for value in [(target.get("address") or "").strip()] if value]
    )
    return dids, addresses


async def _read_mail_messages_from_target(
    db_infra, *, target: dict, limit: int
) -> list[dict]:
    auth = get_auth()
    actor_dids = participant_dids(auth)
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
              AND ca.did = ANY($1::text[])
              AND (
                    ($2::text[] <> '{}'::text[] AND cb.did = ANY($2::text[]))
                 OR ($3::text[] <> '{}'::text[] AND cb.address = ANY($3::text[]))
              )
              AND ca.did <> cb.did
        )
        SELECT m.team_id, m.message_id, m.conversation_id, m.from_agent_id, m.from_did, m.to_did,
               m.from_alias, m.from_address, m.to_alias, m.subject, m.body, m.priority,
               m.read_at, m.created_at, m.signature, m.signed_payload, m.content_mode,
               m.message_version, m.encrypted_envelope
        FROM {{tables.messages}} m
        WHERE m.conversation_id IN (SELECT conversation_id FROM matching_conversations)
        ORDER BY m.created_at DESC, m.message_id DESC
        LIMIT $4
        """,
        actor_dids,
        target_dids,
        target_addresses,
        limit,
    )
    memberships = await sender_memberships(auth.request, db_infra, rows)
    return [
        mcp_mail_message_from_row(
            dict(row),
            include_bodies=True,
            sender_membership=memberships[
                (str(row.get("team_id") or ""), str(row.get("from_agent_id") or ""))
            ],
        )
        for row in rows
    ]


async def _read_chat_messages_from_target(
    db_infra, *, target: dict, limit: int
) -> list[dict]:
    auth = get_auth()
    actor_dids = participant_dids(auth)
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
            WHERE ca.did = ANY($1::text[])
              AND (
                    ($2::text[] <> '{}'::text[] AND cb.did = ANY($2::text[]))
                 OR ($3::text[] <> '{}'::text[] AND cb.address = ANY($3::text[]))
              )
              AND ca.did <> cb.did
        )
        SELECT m.message_id, m.session_id, m.from_did, m.from_alias, m.from_address,
               m.body, m.sender_leaving, m.hang_on, m.created_at,
               m.signature, m.signed_payload, m.content_mode
        FROM {{tables.chat_messages}} m
        WHERE m.session_id IN (SELECT session_id FROM matching_sessions)
        ORDER BY m.created_at DESC, m.message_id DESC
        LIMIT $4
        """,
        actor_dids,
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
            "signature": row.get("signature"),
            "signed_payload": row.get("signed_payload"),
            **verified_signed_recipient_fields(
                {**row, "conversation_id": str(row["session_id"])}
            ),
            "from_alias": row["from_alias"],
            "from_address": row["from_address"],
            "body": row["body"],
            "sender_leaving": bool(row["sender_leaving"]),
            "hang_on": bool(row["hang_on"]),
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]
