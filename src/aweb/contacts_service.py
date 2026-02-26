from __future__ import annotations

import re
from uuid import UUID

from aweb.service_errors import BadRequestError, ConflictError, NotFoundError, ValidationError

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")


async def add_contact(
    db,
    *,
    project_id: str,
    contact_address: str,
    label: str | None,
) -> dict:
    """Add a contact to the project. Returns the created contact dict.

    Raises ServiceError subclasses on validation failure or conflict.
    """
    aweb_db = db.get_manager("aweb")

    addr = contact_address.strip()
    if not addr or not CONTACT_ADDRESS_PATTERN.match(addr):
        raise ValidationError("Invalid contact_address format")

    # Reject self-references.
    proj = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    if proj is None:
        raise NotFoundError("Project not found")

    slug = proj["slug"]
    if addr == slug or addr.startswith(slug + "/"):
        raise BadRequestError("Cannot add self as contact")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (project_id, contact_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (project_id, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at
        """,
        UUID(project_id),
        addr,
        label,
    )
    if row is None:
        raise ConflictError("Contact already exists")

    return {
        "contact_id": str(row["contact_id"]),
        "contact_address": row["contact_address"],
        "label": row["label"],
        "created_at": row["created_at"].isoformat(),
    }


async def list_contacts(db, *, project_id: str) -> list[dict]:
    """List all contacts for a project."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at
        FROM {{tables.contacts}}
        WHERE project_id = $1
        ORDER BY contact_address
        """,
        UUID(project_id),
    )

    return [
        {
            "contact_id": str(r["contact_id"]),
            "contact_address": r["contact_address"],
            "label": r["label"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def get_contact_addresses(db, *, project_id: str) -> set[str]:
    """Return all contact_address values for a project."""
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        "SELECT contact_address FROM {{tables.contacts}} WHERE project_id = $1",
        UUID(project_id),
    )
    return {r["contact_address"] for r in rows}


def is_address_in_contacts(address: str, contact_addresses: set[str]) -> bool:
    """Check if an address matches any contact (exact or org-level).

    Address format is ``namespace/alias`` where namespace may contain ``/``
    (e.g. ``test/myorg/alice``).  The org-level is everything before the
    last ``/`` (i.e. the project slug / namespace).
    """
    if address in contact_addresses:
        return True
    # Org-level match: "org/sub/alias" → check "org/sub"
    last_slash = address.rfind("/")
    if last_slash > 0:
        org = address[:last_slash]
        return org in contact_addresses
    return False


async def remove_contact(db, *, project_id: str, contact_id: str) -> None:
    """Remove a contact by ID. Idempotent (no error if not found).

    Raises ValidationError on invalid contact_id format.
    """
    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        raise ValidationError("Invalid contact_id format")

    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.contacts}} WHERE contact_id = $1 AND project_id = $2",
        contact_uuid,
        UUID(project_id),
    )
