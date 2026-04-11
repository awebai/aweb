from __future__ import annotations

import re
from uuid import UUID

from aweb.service_errors import ConflictError, ValidationError

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")


def normalize_owner_dids(*, owner_did: str | None = None, owner_dids: list[str] | None = None) -> list[str]:
    values: list[str] = []
    if owner_did is not None:
        values.append(owner_did)
    if owner_dids:
        values.extend(owner_dids)
    normalized: list[str] = []
    for value in values:
        did = str(value or "").strip()
        if did and did not in normalized:
            normalized.append(did)
    return normalized


async def add_contact(
    db,
    *,
    owner_did: str,
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
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (owner_did, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at
        """,
        owner_did,
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


async def list_contacts(db, *, owner_did: str | None = None, owner_dids: list[str] | None = None) -> list[dict]:
    """List all contacts for an identity."""
    aweb_db = db.get_manager("aweb")
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    if not owner_keys:
        return []

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at
        FROM {{tables.contacts}}
        WHERE owner_did = ANY($1::text[])
        ORDER BY contact_address
        """,
        owner_keys,
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


async def get_contact_addresses(db, *, owner_did: str | None = None, owner_dids: list[str] | None = None) -> set[str]:
    """Return all contact_address values for an identity."""
    aweb_db = db.get_manager("aweb")
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    if not owner_keys:
        return set()
    rows = await aweb_db.fetch_all(
        "SELECT contact_address FROM {{tables.contacts}} WHERE owner_did = ANY($1::text[])",
        owner_keys,
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


async def remove_contact(db, *, owner_did: str | None = None, owner_dids: list[str] | None = None, contact_id: str) -> None:
    """Remove a contact by ID. Idempotent (no error if not found).

    Raises ValidationError on invalid contact_id format.
    """
    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        raise ValidationError("Invalid contact_id format")

    aweb_db = db.get_manager("aweb")
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    if not owner_keys:
        return
    await aweb_db.execute(
        "DELETE FROM {{tables.contacts}} WHERE contact_id = $1 AND owner_did = ANY($2::text[])",
        contact_uuid,
        owner_keys,
    )
