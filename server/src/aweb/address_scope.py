from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from aweb.awid import RegistryClient
from aweb.awid.registry import Address
from aweb.awid.registry import RegistryError
from aweb.auth import validate_agent_alias, validate_project_slug
from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RecipientRef:
    raw: str
    project_slug: str | None
    alias: str
    domain: str | None = None


@dataclass(frozen=True)
class ProjectScope:
    project_id: str
    project_slug: str
    owner_type: str | None
    owner_ref: str | None


@dataclass(frozen=True)
class ResolvedRecipient:
    agent_id: str
    agent_alias: str
    project_id: str
    project_slug: str
    registry_address: Optional[Address] = None


def parse_recipient_ref(value: str) -> RecipientRef:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("recipient must not be empty")
    if "/" in raw:
        domain, name = raw.split("/", 1)
        domain = domain.strip()
        name = name.strip()
        if not domain or not name:
            raise ValueError("Invalid namespace address format")
        return RecipientRef(raw=raw, project_slug=None, alias=name, domain=domain)
    if raw.count("~") > 1:
        raise ValueError("recipient must not contain more than one '~'")
    if "~" not in raw:
        return RecipientRef(raw=raw, project_slug=None, alias=validate_agent_alias(raw))
    project_slug, alias = raw.split("~", 1)
    project_slug = validate_project_slug(project_slug.strip())
    alias = validate_agent_alias(alias.strip())
    return RecipientRef(raw=raw, project_slug=project_slug, alias=alias)


def format_local_address(*, base_project_slug: str, target_project_slug: str, alias: str) -> str:
    if target_project_slug == base_project_slug:
        return alias
    return f"{target_project_slug}~{alias}"


async def get_project_scope(db, *, project_id: str) -> ProjectScope:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT p.project_id,
               p.slug AS project_slug,
               p.owner_type,
               p.owner_ref
        FROM {{tables.projects}} p
        WHERE p.project_id = $1
          AND p.deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectScope(
        project_id=str(row["project_id"]),
        project_slug=row["project_slug"],
        owner_type=row.get("owner_type"),
        owner_ref=str(row["owner_ref"]) if row.get("owner_ref") is not None else None,
    )


async def resolve_local_recipient(
    db,
    *,
    sender_project_id: str,
    sender_agent_id: str | None = None,
    ref: str,
    registry_client: RegistryClient | None = None,
) -> ResolvedRecipient:
    parsed = parse_recipient_ref(ref)
    aweb_db = db.get_manager("aweb")

    if parsed.domain is not None:
        if registry_client is None:
            raise HTTPException(status_code=503, detail="AWID registry client not configured")
        try:
            address = await registry_client.resolve_address(parsed.domain, parsed.alias)
        except RegistryError as exc:
            raise HTTPException(status_code=503, detail=exc.detail or str(exc)) from exc

        row = None
        registry_address = None
        if address is not None:
            registry_address = address
            row = await aweb_db.fetch_one(
                """
                SELECT a.agent_id, a.alias, p.project_id, p.slug AS project_slug,
                       p.owner_type, p.owner_ref
                FROM {{tables.agents}} a
                JOIN {{tables.projects}} p ON a.project_id = p.project_id
                    AND p.deleted_at IS NULL
                WHERE a.stable_id = $1
                  AND a.deleted_at IS NULL
                """,
                address.did_aw,
            )
        if row:
            allowed = await _can_use_external_address(
                db,
                sender_project_id=sender_project_id,
                sender_agent_id=sender_agent_id,
                recipient_project_id=str(row["project_id"]),
                recipient_owner_type=str(row.get("owner_type") or "") or None,
                recipient_owner_ref=str(row["owner_ref"]) if row.get("owner_ref") is not None else None,
                reachability=address.reachability,
                registry_client=registry_client,
            )
            if not allowed:
                row = None
    elif parsed.project_slug is None:
        row = await aweb_db.fetch_one(
            """
            SELECT a.agent_id, a.alias, p.project_id, p.slug AS project_slug
            FROM {{tables.agents}} a
            JOIN {{tables.projects}} p ON p.project_id = a.project_id
            WHERE a.project_id = $1
              AND a.alias = $2
              AND a.deleted_at IS NULL
              AND p.deleted_at IS NULL
            """,
            UUID(sender_project_id),
            parsed.alias,
        )
    else:
        sender_scope = await get_project_scope(db, project_id=sender_project_id)
        if parsed.project_slug == sender_scope.project_slug:
            raise HTTPException(
                status_code=422,
                detail="Use plain alias for agents in the same project; project~alias is for cross-project addressing",
            )
        row = await aweb_db.fetch_one(
            """
            SELECT a.agent_id, a.alias, p.project_id, p.slug AS project_slug
            FROM {{tables.agents}} a
            JOIN {{tables.projects}} p ON p.project_id = a.project_id
            JOIN {{tables.projects}} sp ON sp.project_id = $1
            WHERE p.slug = $2
              AND a.alias = $3
              AND a.deleted_at IS NULL
              AND p.deleted_at IS NULL
              AND sp.deleted_at IS NULL
              AND sp.owner_ref IS NOT NULL
              AND p.owner_type = sp.owner_type
              AND p.owner_ref = sp.owner_ref
            """,
            UUID(sender_project_id),
            parsed.project_slug,
            parsed.alias,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    recipient = ResolvedRecipient(
        agent_id=str(row["agent_id"]),
        agent_alias=row["alias"],
        project_id=str(row["project_id"]),
        project_slug=row["project_slug"],
        registry_address=registry_address if parsed.domain is not None else None,
    )
    return recipient


async def _sender_contact_addresses(
    db,
    *,
    sender_project_id: str,
    sender_agent_id: str | None,
    registry_client: RegistryClient | None,
) -> set[str]:
    sender_scope = await get_project_scope(db, project_id=sender_project_id)
    addresses: set[str] = {sender_scope.project_slug}

    if sender_agent_id is None:
        return addresses

    aweb_db = db.get_manager("aweb")
    sender_row = await aweb_db.fetch_one(
        """
        SELECT alias, stable_id
        FROM {{tables.agents}}
        WHERE agent_id = $1
          AND project_id = $2
          AND deleted_at IS NULL
        """,
        UUID(sender_agent_id),
        UUID(sender_project_id),
    )
    if sender_row is None:
        return addresses

    alias = str(sender_row["alias"])
    addresses.add(format_local_address(
        base_project_slug=sender_scope.project_slug,
        target_project_slug=sender_scope.project_slug,
        alias=alias,
    ))
    addresses.add(f"{sender_scope.project_slug}~{alias}")

    stable_id = str(sender_row.get("stable_id") or "").strip()
    if stable_id and registry_client is not None:
        try:
            assigned_addresses = await registry_client.list_did_addresses(stable_id)
        except RegistryError:
            logger.warning(
                "Failed to list registry addresses for sender stable_id=%s",
                stable_id,
                exc_info=True,
            )
        else:
            for address in assigned_addresses:
                addresses.add(f"{address.domain}/{address.name}")

    return addresses


async def _can_use_external_address(
    db,
    *,
    sender_project_id: str,
    sender_agent_id: str | None,
    recipient_project_id: str,
    recipient_owner_type: str | None,
    recipient_owner_ref: str | None,
    reachability: str,
    registry_client: RegistryClient | None,
) -> bool:
    if sender_project_id == recipient_project_id:
        return True
    if reachability == "private":
        return False
    if reachability == "public":
        return True

    sender_scope = await get_project_scope(db, project_id=sender_project_id)
    if reachability == "org_visible":
        return bool(
            sender_scope.owner_type
            and sender_scope.owner_ref
            and recipient_owner_type
            and recipient_owner_ref
            and sender_scope.owner_type == recipient_owner_type
            and sender_scope.owner_ref == recipient_owner_ref
        )

    if reachability == "contacts_only":
        contacts = await get_contact_addresses(db, project_id=recipient_project_id)
        sender_addresses = await _sender_contact_addresses(
            db,
            sender_project_id=sender_project_id,
            sender_agent_id=sender_agent_id,
            registry_client=registry_client,
        )
        return any(is_address_in_contacts(candidate, contacts) for candidate in sender_addresses)

    return False
