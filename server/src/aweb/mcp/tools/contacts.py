"""MCP tools for contact management."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.messaging.contacts import add_contact, list_contacts, remove_contact
from aweb.mcp.auth import get_auth
from aweb.service_errors import ServiceError


async def contacts_list(db_infra) -> str:
    """List all contacts for the authenticated identity."""
    auth = get_auth()
    owner_did = (auth.did_aw or auth.did_key or "").strip()
    try:
        contacts = await list_contacts(db_infra, owner_did=owner_did)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"contacts": contacts})


async def contacts_add(db_infra, *, contact_address: str, label: str = "") -> str:
    """Add a contact for the authenticated identity."""
    auth = get_auth()
    owner_did = (auth.did_aw or auth.did_key or "").strip()
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


async def contacts_remove(db_infra, *, contact_id: str) -> str:
    """Remove a contact for the authenticated identity."""
    auth = get_auth()
    owner_did = (auth.did_aw or auth.did_key or "").strip()
    try:
        await remove_contact(db_infra, owner_did=owner_did, contact_id=contact_id)
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    # remove_contact already validated the UUID; normalize for the response.
    try:
        normalized_id = str(UUID(contact_id.strip()))
    except Exception:
        normalized_id = contact_id.strip()
    return json.dumps({"contact_id": normalized_id, "status": "removed"})
