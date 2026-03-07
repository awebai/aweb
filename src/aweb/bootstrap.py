from __future__ import annotations

import json as json_module
import logging
import re
import secrets
from dataclasses import dataclass
from uuid import UUID

import asyncpg.exceptions

from aweb.alias_allocator import AliasExhaustedError, candidate_name_prefixes, used_name_prefixes
from aweb.auth import (
    NAMESPACE_SLUG_MAX_LENGTH,
    hash_api_key,
    validate_agent_alias,
    validate_namespace_slug,
    validate_project_slug,
)
from aweb.custody import encrypt_signing_key, get_custody_key
from aweb.did import decode_public_key, did_from_public_key, encode_public_key, generate_keypair
from aweb.stable_id import stable_id_from_did_key

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
    namespace_slug: str
    project_name: str
    agent_id: str
    alias: str
    api_key: str
    created: bool
    did: str | None = None
    stable_id: str | None = None
    custody: str | None = None
    lifetime: str = "persistent"


@dataclass(frozen=True)
class EnsuredProject:
    project_id: str
    slug: str
    name: str


def _namespace_slug_from_project_slug(project_slug: str) -> str:
    """Derive a valid namespace slug from a project slug.

    Lowercases, replaces disallowed characters (slashes, underscores, dots)
    with hyphens, collapses consecutive hyphens, and strips edge hyphens.
    """
    slug = project_slug.lower()
    slug = re.sub(r"[^a-z0-9-]", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")
    if not slug:
        slug = "default"
    if len(slug) > NAMESPACE_SLUG_MAX_LENGTH:
        slug = slug[:NAMESPACE_SLUG_MAX_LENGTH].rstrip("-")
    return slug


async def _resolve_namespace(
    tx,
    *,
    namespace_slug: str | None = None,
    namespace_id: str | None = None,
) -> dict:
    """Find or create a namespace row within an existing transaction.

    When namespace_id is provided (cloud path), lookup is by PK.
    When namespace_slug is provided (OSS path), find-or-create by slug.
    """
    if namespace_id is not None:
        ns = await tx.fetch_one(
            """
            SELECT namespace_id, slug
            FROM {{tables.namespaces}}
            WHERE namespace_id = $1 AND deleted_at IS NULL
            """,
            UUID(namespace_id),
        )
        if not ns:
            raise ValueError(f"Namespace not found: {namespace_id}")
        return dict(ns)

    if namespace_slug is not None:
        # Atomic find-or-create: INSERT with ON CONFLICT handles concurrent requests.
        ns = await tx.fetch_one(
            """
            INSERT INTO {{tables.namespaces}} (slug)
            VALUES ($1)
            ON CONFLICT (slug) WHERE deleted_at IS NULL DO NOTHING
            RETURNING namespace_id, slug
            """,
            namespace_slug,
        )
        if not ns:
            # Another transaction won the race — fetch the existing row.
            ns = await tx.fetch_one(
                """
                SELECT namespace_id, slug
                FROM {{tables.namespaces}}
                WHERE slug = $1 AND deleted_at IS NULL
                """,
                namespace_slug,
            )
        if not ns:
            raise ValueError(f"Failed to resolve namespace: {namespace_slug}")
        return dict(ns)

    raise ValueError("namespace_slug or namespace_id is required")


async def _resolve_project(
    tx,
    *,
    project_slug: str,
    project_name: str,
    project_id: str | None,
    tenant_id: str | None,
    namespace_id: UUID | None = None,
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
                INSERT INTO {{tables.projects}} (project_id, slug, name, tenant_id, namespace_id)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING project_id, slug, name
                """,
                UUID(project_id),
                project_slug,
                project_name or "",
                tenant_uuid,
                namespace_id,
            )
        elif namespace_id is not None:
            # Existing project — ensure namespace_id is set if not already.
            await tx.execute(
                """
                UPDATE {{tables.projects}}
                SET namespace_id = COALESCE(namespace_id, $2)
                WHERE project_id = $1
                """,
                UUID(project_id),
                namespace_id,
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
                INSERT INTO {{tables.projects}} (slug, name, namespace_id)
                VALUES ($1, $2, $3)
                RETURNING project_id, slug, name
                """,
                project_slug,
                project_name or "",
                namespace_id,
            )
        elif namespace_id is not None:
            # Existing project — ensure namespace_id is set if not already.
            await tx.execute(
                """
                UPDATE {{tables.projects}}
                SET namespace_id = COALESCE(namespace_id, $2)
                WHERE project_id = $1
                """,
                project["project_id"],
                namespace_id,
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
    namespace_slug: str | None = None,
    namespace_id: str | None = None,
    alias: str | None,
    human_name: str = "",
    agent_type: str = "agent",
    did: str | None = None,
    public_key: str | None = None,
    custody: str | None = None,
    lifetime: str = "persistent",
    role: str | None = None,
    program: str | None = None,
    context: dict | None = None,
) -> BootstrapIdentityResult:
    aweb_db = db.get_manager("aweb")

    project_slug = validate_project_slug(project_slug.strip())
    # OSS path: derive namespace from project slug when not explicitly provided.
    if namespace_slug is None and namespace_id is None:
        namespace_slug = _namespace_slug_from_project_slug(project_slug)
    if namespace_slug is not None:
        namespace_slug = validate_namespace_slug(namespace_slug.strip())
    alias = validate_agent_alias(alias.strip()) if alias is not None and alias.strip() else None
    human_name = (human_name or "").strip()
    agent_type = (agent_type or "agent").strip() or "agent"
    did = did.strip() if did is not None and did.strip() else None
    public_key = public_key.strip() if public_key is not None and public_key.strip() else None
    custody = custody.strip() if custody is not None and custody.strip() else None
    lifetime = (lifetime or "persistent").strip() or "persistent"

    if lifetime not in ("persistent", "ephemeral"):
        raise ValueError("lifetime must be 'persistent' or 'ephemeral'")

    # Default custody per identity SOT:
    # - If DID material is provided, treat as self-custodial.
    # - Otherwise default to custodial (server generates DID/public_key).
    if custody is None:
        custody = "self" if (did is not None or public_key is not None) else "custodial"

    if custody not in ("self", "custodial"):
        raise ValueError("custody must be 'self' or 'custodial'")

    if lifetime == "ephemeral" and custody != "custodial":
        raise ValueError("Ephemeral agents must be custodial")

    # Prepare identity columns.
    agent_did: str | None = None
    agent_public_key: str | None = None
    agent_stable_id: str | None = None
    signing_key_enc: bytes | None = None

    if custody == "self":
        if did is None and public_key is None:
            # Unclaimed self-custodial agent — identity will be bound later
            # via PUT /v1/agents/me/identity.
            pass
        elif did is None or public_key is None:
            raise ValueError("Self-custodial agents require both did and public_key")
        else:
            try:
                pub_bytes = decode_public_key(public_key)
            except Exception:
                raise ValueError(
                    "public_key must be a base64-encoded 32-byte Ed25519 public key (url-safe or standard)"
                )
            expected_did = did_from_public_key(pub_bytes)
            if expected_did != did:
                raise ValueError("DID does not match public_key")
            agent_did = did
            # Normalize storage to canonical base64url encoding.
            agent_public_key = encode_public_key(pub_bytes)
    elif custody == "custodial":
        if did is not None or public_key is not None:
            raise ValueError("Custodial agents must not provide did/public_key")
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

    if agent_did is not None:
        agent_stable_id = stable_id_from_did_key(agent_did)

    async with aweb_db.transaction() as tx:
        # Resolve or create namespace.
        ns = await _resolve_namespace(
            tx,
            namespace_slug=namespace_slug,
            namespace_id=namespace_id,
        )
        resolved_namespace_id = ns["namespace_id"]
        actual_namespace_slug = ns["slug"]

        project = await _resolve_project(
            tx,
            project_slug=project_slug,
            project_name=project_name,
            project_id=project_id,
            tenant_id=tenant_id,
            namespace_id=resolved_namespace_id,
        )

        resolved_project_id = str(project["project_id"])
        actual_project_slug = project["slug"]
        actual_project_name = project.get("name") or ""

        created = False
        agent_id: str
        if alias is not None and alias.strip():
            agent = await tx.fetch_one(
                """
                SELECT agent_id, alias, did, stable_id, custody, lifetime
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
                agent_stable_id = agent.get("stable_id")
                custody = agent["custody"]
                lifetime = agent["lifetime"]
            else:
                agent = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.agents}}
                        (project_id, alias, human_name, agent_type,
                         did, public_key, stable_id, custody, signing_key_enc, lifetime,
                         namespace_id, role, program, context)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    RETURNING agent_id, alias
                    """,
                    UUID(resolved_project_id),
                    alias,
                    human_name,
                    agent_type,
                    agent_did,
                    agent_public_key,
                    agent_stable_id,
                    custody,
                    signing_key_enc,
                    lifetime,
                    resolved_namespace_id,
                    role,
                    program,
                    json_module.dumps(context) if context else None,
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
                             did, public_key, stable_id, custody, signing_key_enc, lifetime,
                             namespace_id, role, program, context)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                        RETURNING agent_id, alias
                        """,
                        UUID(resolved_project_id),
                        prefix,
                        human_name,
                        agent_type,
                        agent_did,
                        agent_public_key,
                        agent_stable_id,
                        custody,
                        signing_key_enc,
                        lifetime,
                        resolved_namespace_id,
                        role,
                        program,
                        json_module.dumps(context) if context else None,
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
        namespace_slug=actual_namespace_slug,
        project_name=actual_project_name,
        agent_id=agent_id,
        alias=alias or "",
        api_key=api_key,
        created=created,
        did=agent_did,
        stable_id=agent_stable_id,
        custody=custody,
        lifetime=lifetime,
    )


async def soft_delete_agent(db_infra, *, agent_id: str, project_id: str) -> None:
    """Soft-delete an agent for workspace cleanup.

    Sets deleted_at, status='deregistered', and clears signing_key_enc.
    Deactivates API keys and writes a workspace_cleanup entry to agent_log.
    Unlike deregister, this works for any lifetime and does not fire
    mutation hooks.

    Idempotent: no-op if the agent is already deleted.
    """
    aweb_db = db_infra.get_manager("aweb")
    agent_uuid = UUID(agent_id)
    project_uuid = UUID(project_id)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            UPDATE {{tables.agents}}
            SET signing_key_enc = NULL,
                status = 'deregistered',
                deleted_at = NOW()
            WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
            RETURNING did
            """,
            agent_uuid,
            project_uuid,
        )

        if row is not None:
            await tx.execute(
                """
                UPDATE {{tables.api_keys}} SET is_active = FALSE
                WHERE agent_id = $1 AND project_id = $2
                """,
                agent_uuid,
                project_uuid,
            )

            await tx.execute(
                """
                INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did)
                VALUES ($1, $2, $3, $4)
                """,
                agent_uuid,
                project_uuid,
                "workspace_cleanup",
                row["did"],
            )
