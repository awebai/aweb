from __future__ import annotations

import logging
import re
from uuid import UUID

from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.service_errors import ConflictError, ValidationError

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")
HANDLE_NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
TARGET_AGENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
CONTACT_REFERENCE_TYPES = {"identity", "handle"}
CONTACT_STATUSES = {"pending", "active"}

logger = logging.getLogger(__name__)


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
    contact_did_aw: str | None = None,
    binding_controller_did: str | None = None,
) -> dict:
    """Add a contact to the team. Returns the created contact dict.

    Raises ServiceError subclasses on validation failure or conflict.
    """
    aweb_db = db.get_manager("aweb")

    addr = normalize_hosted_handle_reference(contact_address)
    if not addr or not CONTACT_ADDRESS_PATTERN.match(addr):
        raise ValidationError("Invalid contact_address format")
    contact_status = _normalize_status(status)
    bound_did = str(contact_did_aw or "").strip() or None
    controller_did = str(binding_controller_did or "").strip() or None
    if bound_did is not None and not bound_did.startswith("did:aw:"):
        raise ValidationError("Invalid contact_did_aw format")
    if (bound_did is None) != (controller_did is None):
        raise ValidationError("Identity-bound contacts require DID and controller proof")
    if controller_did is not None and not controller_did.startswith("did:key:z"):
        raise ValidationError("Invalid binding_controller_did format")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, label, status, contact_did_aw,
            binding_controller_did, binding_accepted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6,
                CASE WHEN $5::text IS NULL THEN NULL ELSE clock_timestamp() END)
        ON CONFLICT (owner_did, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, contact_did_aw,
                  binding_controller_did, binding_accepted_at,
                  label, created_at, reference_type, status,
                  handle_namespace, target_agent_name
        """,
        owner_did,
        addr,
        label or "",
        contact_status,
        bound_did,
        controller_did,
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
        SELECT contact_id, contact_address, contact_did_aw,
               binding_controller_did, binding_accepted_at,
               label, created_at, reference_type, status,
               handle_namespace, target_agent_name
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


async def has_exact_active_identity_contact(
    db,
    *,
    owner_did: str | None = None,
    owner_dids: list[str] | None = None,
    contact_address: str | None,
    contact_did_aw: str | None = None,
) -> bool:
    """Return whether owner has an exact active identity contact.

    This helper is intentionally narrower than ``is_address_in_contacts``: it
    does not allow domain-level matching, pending rows, handle rows, labels, or
    display names to authorize delivery.
    """
    owner_keys = normalize_owner_dids(owner_did=owner_did, owner_dids=owner_dids)
    addr = normalize_hosted_handle_reference(contact_address or "")
    bound_did = str(contact_did_aw or "").strip()
    if not owner_keys or not addr or not bound_did:
        return False
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.contacts}}
        WHERE owner_did = ANY($1::text[])
          AND reference_type = 'identity'
          AND status = 'active'
          AND contact_address = $2
          AND contact_did_aw = $3
        LIMIT 1
        """,
        owner_keys,
        addr,
        bound_did,
    )
    return row is not None


async def resolve_local_namespace_controller_did(
    registry_client,
    *,
    contact_address: str,
    contact_did_aw: str,
    contact_current_did_key: str,
) -> str | None:
    """Verify a current local address binding and return its namespace controller."""
    address = normalize_hosted_handle_reference(contact_address)
    instance_api = getattr(registry_client, "__dict__", {})
    has_fresh_api = registry_client is not None and all(
        name in instance_api or callable(getattr(type(registry_client), name, None))
        for name in ("resolve_address_fresh", "get_namespace_fresh")
    )
    if not has_fresh_api or address.count("/") != 1:
        return None
    domain, name = address.split("/", 1)
    if not domain or not name:
        return None
    try:
        resolved = await registry_client.resolve_address_fresh(domain, name)
        namespace = await registry_client.get_namespace_fresh(domain)
    except Exception:
        logger.warning(
            "Local AWID namespace controller lookup failed",
            extra={"domain": domain},
            exc_info=True,
        )
        return None
    if (
        resolved is None
        or str(getattr(resolved, "did_aw", "") or "").strip()
        != str(contact_did_aw or "").strip()
        or str(getattr(resolved, "current_did_key", "") or "").strip()
        != str(contact_current_did_key or "").strip()
        or namespace is None
        or str(getattr(namespace, "domain", "") or "").strip() != domain
    ):
        return None
    controller_did = str(getattr(namespace, "controller_did", "") or "").strip()
    return controller_did if controller_did.startswith("did:key:z") else None


async def upsert_successful_identity_contact(
    db,
    *,
    owner_did: str,
    contact_address: str | None,
    contact_did_aw: str | None = None,
    binding_controller_did: str | None = None,
    label: str = "",
) -> bool:
    """Idempotently add an active identity contact after accepted delivery.

    Existing rows are left unchanged so repeat sends do not mutate label/status.
    Returns True only when a new contact row was inserted.
    """
    owner = str(owner_did or "").strip()
    addr = normalize_hosted_handle_reference(contact_address or "")
    bound_did = str(contact_did_aw or "").strip()
    controller_did = str(binding_controller_did or "").strip()
    if (
        not owner
        or not addr
        or not CONTACT_ADDRESS_PATTERN.match(addr)
        or not bound_did.startswith("did:aw:")
        or not controller_did.startswith("did:key:z")
    ):
        return False
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at,
            label, reference_type, status
        )
        VALUES ($1, $2, $3, $4, clock_timestamp(), $5, 'identity', 'active')
        ON CONFLICT DO NOTHING
        RETURNING contact_id
        """,
        owner,
        addr,
        bound_did,
        controller_did,
        label or "",
    )
    return row is not None


async def bind_contact_identity(
    db,
    *,
    owner_dids: list[str],
    contact_id: str,
    contact_address: str,
    expected_old_did_aw: str | None,
    contact_did_aw: str,
    controller_did: str,
    replacement_accepted: bool,
) -> dict:
    owner_keys = normalize_owner_dids(owner_dids=owner_dids)
    try:
        contact_uuid = UUID(str(contact_id).strip())
    except Exception as exc:
        raise ValidationError("Invalid contact_id format") from exc
    address = normalize_hosted_handle_reference(contact_address)
    bound_did = str(contact_did_aw or "").strip()
    controller = str(controller_did or "").strip()
    expected = str(expected_old_did_aw or "").strip() or None
    if not owner_keys or not bound_did.startswith("did:aw:"):
        raise ValidationError("Invalid contact identity binding")
    if not controller.startswith("did:key:z"):
        raise ValidationError("Invalid contact controller binding")

    manager = db.get_manager("aweb")
    async with manager.transaction() as tx:
        current = await tx.fetch_one(
            """
            SELECT contact_address, contact_did_aw
            FROM {{tables.contacts}}
            WHERE contact_id = $1 AND owner_did = ANY($2::text[])
              AND reference_type = 'identity'
            FOR UPDATE
            """,
            contact_uuid,
            owner_keys,
        )
        if current is None:
            raise ValidationError("Contact not found")
        if current.get("contact_address") != address:
            raise ConflictError("Contact address does not match identity binding")
        current_did = str(current.get("contact_did_aw") or "").strip() or None
        if current_did != expected:
            raise ConflictError("Contact identity binding changed")
        if current_did is not None and current_did != bound_did and not replacement_accepted:
            raise ConflictError("Contact identity replacement requires explicit acceptance")
        row = await tx.fetch_one(
            """
            UPDATE {{tables.contacts}}
            SET contact_did_aw = $3,
                binding_controller_did = $4,
                binding_accepted_at = clock_timestamp()
            WHERE contact_id = $1 AND owner_did = ANY($2::text[])
              AND contact_did_aw IS NOT DISTINCT FROM $5::text
            RETURNING contact_id, contact_address, contact_did_aw,
                      binding_controller_did, binding_accepted_at,
                      label, created_at, reference_type, status,
                      handle_namespace, target_agent_name
            """,
            contact_uuid,
            owner_keys,
            bound_did,
            controller,
            expected,
        )
        if row is None:
            raise ConflictError("Contact identity binding changed")
    return _contact_row_to_dict(row)


async def resolve_handle_contact_agent(
    db,
    *,
    handle_namespace: str,
    target_agent_name: str | None = None,
) -> dict | None:
    """Resolve an active global agent for a handle contact.

    Bare handles intentionally choose the recently active global agent by
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
                   a.identity_scope, a.status, a.created_at,
                   MAX(w.last_seen_at) AS last_seen_at
            FROM {{tables.agents}} a
            LEFT JOIN {{tables.workspaces}} w
              ON w.agent_id = a.agent_id
             AND w.deleted_at IS NULL
            WHERE a.deleted_at IS NULL
              AND a.status = 'active'
              AND a.identity_scope = 'global'
              AND a.address = $1
            GROUP BY a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                     a.identity_scope, a.status, a.created_at
            ORDER BY last_seen_at DESC NULLS LAST, a.created_at ASC
            LIMIT 1
            """,
            address,
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                   a.identity_scope, a.status, a.created_at,
                   MAX(w.last_seen_at) AS last_seen_at
            FROM {{tables.agents}} a
            LEFT JOIN {{tables.workspaces}} w
              ON w.agent_id = a.agent_id
             AND w.deleted_at IS NULL
            WHERE a.deleted_at IS NULL
              AND a.status = 'active'
              AND a.identity_scope = 'global'
              AND a.address LIKE $1
            GROUP BY a.agent_id, a.team_id, a.did_key, a.did_aw, a.address, a.alias,
                     a.identity_scope, a.status, a.created_at
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
        "identity_scope": row["identity_scope"],
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
        "contact_did_aw": row.get("contact_did_aw"),
        "binding_controller_did": row.get("binding_controller_did"),
        "binding_accepted_at": (
            row["binding_accepted_at"].isoformat()
            if row.get("binding_accepted_at")
            else None
        ),
        "label": row["label"],
        "created_at": row["created_at"].isoformat(),
        "reference_type": row["reference_type"],
        "status": row["status"],
        "handle_namespace": row["handle_namespace"],
        "target_agent_name": row["target_agent_name"],
    }
