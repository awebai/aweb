from __future__ import annotations

import re
from uuid import UUID

from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.service_errors import ConflictError, ValidationError

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")
HANDLE_NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
TARGET_AGENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
CONTACT_REFERENCE_TYPES = {"identity", "handle"}
CONTACT_STATUSES = {"pending", "active"}


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
    status: str = "active",
) -> dict:
    """Add a contact to the team. Returns the created contact dict.

    Raises ServiceError subclasses on validation failure or conflict.
    """
    aweb_db = db.get_manager("aweb")

    addr = normalize_hosted_handle_reference(contact_address)
    if not addr or not CONTACT_ADDRESS_PATTERN.match(addr):
        raise ValidationError("Invalid contact_address format")
    contact_status = _normalize_status(status)

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label, status)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (owner_did, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at,
                  reference_type, status, handle_namespace, target_agent_name
        """,
        owner_did,
        addr,
        label or "",
        contact_status,
    )
    if row is None:
        raise ConflictError("Contact already exists")

    return _contact_row_to_dict(row)


async def add_handle_contact(
    db,
    *,
    owner_did: str,
    handle_namespace: str,
    target_agent_name: str | None = None,
    label: str = "",
    status: str = "pending",
) -> dict:
    """Add a handle contact for a namespace or a specific namespace agent."""
    aweb_db = db.get_manager("aweb")
    namespace = _normalize_handle_namespace(handle_namespace)
    agent_name = _normalize_target_agent_name(target_agent_name)
    contact_status = _normalize_status(status)

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, label, reference_type, status,
            handle_namespace, target_agent_name
        )
        VALUES ($1, NULL, $2, 'handle', $3, $4, $5)
        ON CONFLICT DO NOTHING
        RETURNING contact_id, contact_address, label, created_at,
                  reference_type, status, handle_namespace, target_agent_name
        """,
        owner_did,
        label or "",
        contact_status,
        namespace,
        agent_name,
    )
    if row is None:
        raise ConflictError("Contact already exists")

    return _contact_row_to_dict(row)


async def list_contacts(db, *, owner_did: str | None = None, owner_dids: list[str] | None = None) -> list[dict]:
    """List all contacts for an identity."""
    aweb_db = db.get_manager("aweb")
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    if not owner_keys:
        return []

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at,
               reference_type, status, handle_namespace, target_agent_name
        FROM {{tables.contacts}}
        WHERE owner_did = ANY($1::text[])
        ORDER BY reference_type,
                 COALESCE(contact_address, handle_namespace || COALESCE('/' || target_agent_name, '')),
                 created_at
        """,
        owner_keys,
    )

    return [_contact_row_to_dict(r) for r in rows]


async def get_contact_addresses(db, *, owner_did: str | None = None, owner_dids: list[str] | None = None) -> set[str]:
    """Return all contact_address values for an identity."""
    aweb_db = db.get_manager("aweb")
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    if not owner_keys:
        return set()
    rows = await aweb_db.fetch_all(
        """
        SELECT contact_address
        FROM {{tables.contacts}}
        WHERE owner_did = ANY($1::text[])
          AND reference_type = 'identity'
          AND status = 'active'
          AND contact_address IS NOT NULL
        """,
        owner_keys,
    )
    return {r["contact_address"] for r in rows}


async def resolve_handle_contact_agent(
    db,
    *,
    handle_namespace: str,
    target_agent_name: str | None = None,
) -> dict | None:
    """Resolve an active persistent agent for a handle contact.

    Bare handles intentionally choose the recently active persistent agent by
    database state; callers do not scan messages or conversations.
    """
    aweb_db = db.get_manager("aweb")
    namespace = _normalize_handle_namespace(handle_namespace)
    agent_name = _normalize_target_agent_name(target_agent_name)

    if agent_name is not None:
        address = f"{namespace}/{agent_name}"
        row = await aweb_db.fetch_one(
            """
            SELECT a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                   a.lifetime, a.status, a.created_at,
                   MAX(w.last_seen_at) AS last_seen_at
            FROM {{tables.agents}} a
            LEFT JOIN {{tables.workspaces}} w
              ON w.agent_id = a.agent_id
             AND w.deleted_at IS NULL
            WHERE a.deleted_at IS NULL
              AND a.status = 'active'
              AND a.lifetime = 'persistent'
              AND a.address = $1
            GROUP BY a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                     a.lifetime, a.status, a.created_at
            ORDER BY last_seen_at DESC NULLS LAST, a.created_at ASC
            LIMIT 1
            """,
            address,
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                   a.lifetime, a.status, a.created_at,
                   MAX(w.last_seen_at) AS last_seen_at
            FROM {{tables.agents}} a
            LEFT JOIN {{tables.workspaces}} w
              ON w.agent_id = a.agent_id
             AND w.deleted_at IS NULL
            WHERE a.deleted_at IS NULL
              AND a.status = 'active'
              AND a.lifetime = 'persistent'
              AND a.address LIKE $1
            GROUP BY a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                     a.lifetime, a.status, a.created_at
            ORDER BY last_seen_at DESC NULLS LAST, a.created_at ASC
            LIMIT 1
            """,
            f"{namespace}/%",
        )
    if row is None:
        return None
    return {
        "agent_id": str(row["agent_id"]),
        "team_id": row["team_id"],
        "did_key": row["did_key"],
        "did_aw": row["did_aw"],
        "address": row["address"],
        "alias": row["alias"],
        "lifetime": row["lifetime"],
        "status": row["status"],
        "created_at": row["created_at"].isoformat(),
        "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
    }


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


def _normalize_status(status: str) -> str:
    value = (status or "").strip()
    if value not in CONTACT_STATUSES:
        raise ValidationError("Invalid contact status")
    return value


def _normalize_handle_namespace(handle_namespace: str) -> str:
    namespace = normalize_hosted_handle_reference(handle_namespace)
    if namespace.startswith("@"):
        raise ValidationError("Invalid handle_namespace format")
    if not namespace or "/" in namespace or not HANDLE_NAMESPACE_PATTERN.match(namespace):
        raise ValidationError("Invalid handle_namespace format")
    return namespace


def _normalize_target_agent_name(target_agent_name: str | None) -> str | None:
    if target_agent_name is None:
        return None
    value = target_agent_name.strip()
    if not value:
        return None
    if "/" in value or not TARGET_AGENT_NAME_PATTERN.match(value):
        raise ValidationError("Invalid target_agent_name format")
    return value


def _contact_row_to_dict(row) -> dict:
    return {
        "contact_id": str(row["contact_id"]),
        "contact_address": row["contact_address"],
        "label": row["label"],
        "created_at": row["created_at"].isoformat(),
        "reference_type": row["reference_type"],
        "status": row["status"],
        "handle_namespace": row["handle_namespace"],
        "target_agent_name": row["target_agent_name"],
    }
