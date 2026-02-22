from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from uuid import UUID

import asyncpg.exceptions

from aweb.alias_allocator import AliasExhaustedError, candidate_name_prefixes, used_name_prefixes
from aweb.auth import hash_api_key, validate_agent_alias, validate_project_slug
from aweb.custody import encrypt_signing_key, get_custody_key
from aweb.did import decode_public_key, did_from_public_key, encode_public_key, generate_keypair

logger = logging.getLogger(__name__)


def generate_api_key() -> tuple[str, str, str]:
    random_hex = secrets.token_hex(32)
    full_key = f"aw_sk_{random_hex}"
    key_prefix = full_key[:12]
    key_hash = hash_api_key(full_key)
    return full_key, key_prefix, key_hash


@dataclass(frozen=True)
class BootstrapIdentityResult:
    project_id: str
    project_slug: str
    project_name: str
    agent_id: str
    alias: str
    api_key: str
    created: bool
    did: str | None = None
    custody: str | None = None
    lifetime: str = "persistent"


@dataclass(frozen=True)
class EnsuredProject:
    project_id: str
    slug: str
    name: str


async def _resolve_project(
    tx,
    *,
    project_slug: str,
    project_name: str,
    project_id: str | None,
    tenant_id: str | None,
) -> dict:
    """Find or create a project row within an existing transaction.

    When project_id is provided (cloud path), lookup is by PK and slug is
    only used for the initial INSERT.  When omitted (OSS path), lookup is
    by slug and the ID is auto-generated.
    """
    if project_id is not None:
        project = await tx.fetch_one(
            """
            SELECT project_id, slug, name
            FROM {{tables.projects}}
            WHERE project_id = $1 AND deleted_at IS NULL
            """,
            UUID(project_id),
        )
        if not project:
            tenant_uuid = UUID(tenant_id) if tenant_id else None
            project = await tx.fetch_one(
                """
                INSERT INTO {{tables.projects}} (project_id, slug, name, tenant_id)
                VALUES ($1, $2, $3, $4)
                RETURNING project_id, slug, name
                """,
                UUID(project_id),
                project_slug,
                project_name or "",
                tenant_uuid,
            )
    else:
        project = await tx.fetch_one(
            """
            SELECT project_id, slug, name
            FROM {{tables.projects}}
            WHERE slug = $1 AND deleted_at IS NULL
            """,
            project_slug,
        )
        if not project:
            project = await tx.fetch_one(
                """
                INSERT INTO {{tables.projects}} (slug, name)
                VALUES ($1, $2)
                RETURNING project_id, slug, name
                """,
                project_slug,
                project_name or "",
            )
    return dict(project)


async def ensure_project(
    db,
    *,
    project_slug: str,
    project_name: str = "",
    project_id: str | None = None,
    tenant_id: str | None = None,
) -> EnsuredProject:
    aweb_db = db.get_manager("aweb")
    project_slug = validate_project_slug(project_slug.strip())

    async with aweb_db.transaction() as tx:
        project = await _resolve_project(
            tx,
            project_slug=project_slug,
            project_name=project_name,
            project_id=project_id,
            tenant_id=tenant_id,
        )

    return EnsuredProject(
        project_id=str(project["project_id"]),
        slug=project["slug"],
        name=project.get("name") or "",
    )


async def bootstrap_identity(
    db,
    *,
    project_slug: str,
    project_name: str = "",
    project_id: str | None = None,
    tenant_id: str | None = None,
    alias: str | None,
    human_name: str = "",
    agent_type: str = "agent",
    did: str | None = None,
    public_key: str | None = None,
    custody: str | None = None,
    lifetime: str = "persistent",
) -> BootstrapIdentityResult:
    aweb_db = db.get_manager("aweb")

    project_slug = validate_project_slug(project_slug.strip())
    alias = validate_agent_alias(alias.strip()) if alias is not None and alias.strip() else None
    human_name = (human_name or "").strip()
    agent_type = (agent_type or "agent").strip() or "agent"

    # Prepare identity columns.
    agent_did: str | None = None
    agent_public_key: str | None = None
    signing_key_enc: bytes | None = None

    if custody == "self":
        if not did or not public_key:
            raise ValueError("Self-custodial agents require both did and public_key")
        try:
            pub_bytes = decode_public_key(public_key)
        except Exception:
            raise ValueError("public_key must be a base64url-encoded 32-byte Ed25519 public key")
        expected_did = did_from_public_key(pub_bytes)
        if expected_did != did:
            raise ValueError("DID does not match public_key")
        agent_did = did
        agent_public_key = public_key
    elif custody == "custodial":
        seed, pub = generate_keypair()
        agent_did = did_from_public_key(pub)
        agent_public_key = encode_public_key(pub)
        master_key = get_custody_key()
        if master_key is not None:
            signing_key_enc = encrypt_signing_key(seed, master_key)
        else:
            logger.warning(
                "Custodial agent created without AWEB_CUSTODY_KEY — "
                "private key discarded, server-side signing unavailable"
            )

    async with aweb_db.transaction() as tx:
        project = await _resolve_project(
            tx,
            project_slug=project_slug,
            project_name=project_name,
            project_id=project_id,
            tenant_id=tenant_id,
        )

        resolved_project_id = str(project["project_id"])
        actual_project_slug = project["slug"]
        actual_project_name = project.get("name") or ""

        created = False
        agent_id: str
        if alias is not None and alias.strip():
            agent = await tx.fetch_one(
                """
                SELECT agent_id, alias, did, custody, lifetime
                FROM {{tables.agents}}
                WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
                """,
                UUID(resolved_project_id),
                alias,
            )
            if agent:
                created = False
                agent_id = str(agent["agent_id"])
                # On re-init, return existing identity fields.
                agent_did = agent["did"]
                custody = agent["custody"]
                lifetime = agent["lifetime"]
            else:
                agent = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.agents}}
                        (project_id, alias, human_name, agent_type,
                         did, public_key, custody, signing_key_enc, lifetime)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING agent_id, alias
                    """,
                    UUID(resolved_project_id),
                    alias,
                    human_name,
                    agent_type,
                    agent_did,
                    agent_public_key,
                    custody,
                    signing_key_enc,
                    lifetime,
                )
                created = True
                agent_id = str(agent["agent_id"])
        else:
            existing = await tx.fetch_all(
                """
                SELECT alias
                FROM {{tables.agents}}
                WHERE project_id = $1 AND deleted_at IS NULL
                ORDER BY alias
                """,
                UUID(resolved_project_id),
            )
            used_prefixes = used_name_prefixes([(row.get("alias") or "") for row in existing])

            allocated_alias: str | None = None
            for prefix in candidate_name_prefixes():
                if prefix in used_prefixes:
                    continue
                prefix = validate_agent_alias(prefix)
                try:
                    agent = await tx.fetch_one(
                        """
                        INSERT INTO {{tables.agents}}
                            (project_id, alias, human_name, agent_type,
                             did, public_key, custody, signing_key_enc, lifetime)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        RETURNING agent_id, alias
                        """,
                        UUID(resolved_project_id),
                        prefix,
                        human_name,
                        agent_type,
                        agent_did,
                        agent_public_key,
                        custody,
                        signing_key_enc,
                        lifetime,
                    )
                except asyncpg.exceptions.UniqueViolationError:
                    continue
                allocated_alias = prefix
                agent_id = str(agent["agent_id"])
                created = True
                break

            if allocated_alias is None:
                raise AliasExhaustedError("All name prefixes are taken.")
            alias = allocated_alias

        api_key, key_prefix, key_hash = generate_api_key()
        await tx.execute(
            """
            INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active)
            VALUES ($1, $2, $3, $4, TRUE)
            """,
            UUID(resolved_project_id),
            UUID(agent_id),
            key_prefix,
            key_hash,
        )

        # Write agent_log 'create' entry for new agents.
        if created:
            await tx.execute(
                """
                INSERT INTO {{tables.agent_log}}
                    (agent_id, project_id, operation, new_did)
                VALUES ($1, $2, $3, $4)
                """,
                UUID(agent_id),
                UUID(resolved_project_id),
                "create",
                agent_did,
            )

    return BootstrapIdentityResult(
        project_id=resolved_project_id,
        project_slug=actual_project_slug,
        project_name=actual_project_name,
        agent_id=agent_id,
        alias=alias or "",
        api_key=api_key,
        created=created,
        did=agent_did,
        custody=custody,
        lifetime=lifetime,
    )
