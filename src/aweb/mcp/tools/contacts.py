"""MCP tools for contact management."""

from __future__ import annotations

import json
from uuid import UUID

from fastapi import HTTPException

from aweb.contacts_service import add_contact, list_contacts, remove_contact
from aweb.mcp.auth import get_auth


async def contacts_list(db_infra) -> str:
    """List all contacts in the project."""
    auth = get_auth()
    try:
        contacts = await list_contacts(db_infra, project_id=auth.project_id)
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"contacts": contacts})


async def contacts_add(db_infra, *, contact_address: str, label: str = "") -> str:
    """Add a contact to the project."""
    auth = get_auth()
    try:
        result = await add_contact(
            db_infra,
            project_id=auth.project_id,
            contact_address=contact_address,
            label=label or None,
        )
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})

    result["status"] = "added"
    return json.dumps(result)


async def contacts_remove(db_infra, *, contact_id: str) -> str:
    """Remove a contact from the project."""
    auth = get_auth()
    try:
        await remove_contact(db_infra, project_id=auth.project_id, contact_id=contact_id)
    except HTTPException as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps({"contact_id": str(UUID(contact_id.strip())), "status": "removed"})
