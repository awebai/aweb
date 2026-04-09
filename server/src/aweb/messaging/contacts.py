from __future__ import annotations

import re
from uuid import UUID

from aweb.service_errors import ConflictError, ValidationError

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")


async def add_contact(
    db,
    *,
    team_id: str,
    contact_address: str,
    label: str,
) -> dict:
    """Add a contact to the team. Returns the created contact dict.

    Raises ServiceError subclasses on validation failure or conflict.
    """
    aweb_db = db.get_manager("aweb")

    addr = contact_address.strip()
    if not addr or not CONTACT_ADDRESS_PATTERN.match(addr):
        raise ValidationError("Invalid contact_address format")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (team_id, contact_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (team_id, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at
        """,
        team_id,
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


async def list_contacts(db, *, team_id: str) -> list[dict]:
    """List all contacts for a team."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at
        FROM {{tables.contacts}}
        WHERE team_id = $1
        ORDER BY contact_address
        """,
        team_id,
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


async def get_contact_addresses(db, *, team_id: str) -> set[str]:
    """Return all contact_address values for a team."""
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        "SELECT contact_address FROM {{tables.contacts}} WHERE team_id = $1",
        team_id,
    )
    return {r["contact_address"] for r in rows}


def is_address_in_contacts(address: str, contact_addresses: set[str]) -> bool:
    """Check if an address matches any contact (exact or domain-level).

    Supports DNS address format: ``domain/name`` (slash separator).
    Domain-level matching: adding ``example.com`` as a contact matches
    ``example.com/alice``.
    """
    if address in contact_addresses:
        return True
    # DNS address match: "domain.com/name" → check "domain.com"
    slash = address.rfind("/")
    if slash > 0:
        return address[:slash] in contact_addresses
    return False


async def check_access(db, **kwargs) -> bool:
    """Team membership is the sole access control. Always returns True.

    Callers that still import this function are being migrated to remove
    the access check entirely.
    """
    return True


async def remove_contact(db, *, team_id: str, contact_id: str) -> None:
    """Remove a contact by ID. Idempotent (no error if not found).

    Raises ValidationError on invalid contact_id format.
    """
    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        raise ValidationError("Invalid contact_id format")

    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.contacts}} WHERE contact_id = $1 AND team_id = $2",
        contact_uuid,
        team_id,
    )
