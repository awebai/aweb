"""MCP tools for contact management."""

from __future__ import annotations

import json
import re
from uuid import UUID

from aweb.mcp.auth import get_auth

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.\-]+$")


async def contacts_list(db_infra) -> str:
    """List all contacts in the project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at
        FROM {{tables.contacts}}
        WHERE project_id = $1
        ORDER BY contact_address
        """,
        UUID(auth.project_id),
    )

    return json.dumps(
        {
            "contacts": [
                {
                    "contact_id": str(r["contact_id"]),
                    "contact_address": r["contact_address"],
                    "label": r["label"],
                    "created_at": r["created_at"].isoformat(),
                }
                for r in rows
            ]
        }
    )


async def contacts_add(db_infra, *, contact_address: str, label: str = "") -> str:
    """Add a contact to the project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    addr = contact_address.strip()
    if not addr or not CONTACT_ADDRESS_PATTERN.match(addr):
        return json.dumps({"error": "Invalid contact_address format"})

    # Reject self-references.
    proj = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(auth.project_id),
    )
    if proj:
        slug = proj["slug"]
        if addr == slug or addr.startswith(slug + "/"):
            return json.dumps({"error": "Cannot add self as contact"})

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (project_id, contact_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (project_id, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at
        """,
        UUID(auth.project_id),
        addr,
        label or None,
    )
    if row is None:
        return json.dumps({"error": "Contact already exists"})

    return json.dumps(
        {
            "contact_id": str(row["contact_id"]),
            "contact_address": row["contact_address"],
            "label": row["label"],
            "created_at": row["created_at"].isoformat(),
            "status": "added",
        }
    )


async def contacts_remove(db_infra, *, contact_id: str) -> str:
    """Remove a contact from the project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid contact_id format"})

    await aweb_db.execute(
        "DELETE FROM {{tables.contacts}} WHERE contact_id = $1 AND project_id = $2",
        contact_uuid,
        UUID(auth.project_id),
    )

    return json.dumps({"contact_id": str(contact_uuid), "status": "removed"})
