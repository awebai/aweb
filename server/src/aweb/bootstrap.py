from __future__ import annotations

import json as json_module
import logging
import os
import secrets
import uuid as uuid_mod
from dataclasses import dataclass
from uuid import UUID

import asyncpg.exceptions

from aweb.access_modes import validate_access_mode
from aweb.address_reachability import normalize_address_reachability
from aweb.alias_allocator import AliasExhaustedError, candidate_name_prefixes, used_name_prefixes
from aweb.auth import (
    hash_api_key,
    validate_agent_alias,
    validate_project_slug,
)
from aweb.awid.contract import resolve_identity_contract
from aweb.awid.custody import (
    decrypt_signing_key,
    encrypt_signing_key,
    get_custody_key,
    get_namespace_controller_key,
)
from aweb.awid.did import (
    decode_public_key,
    did_from_public_key,
    encode_public_key,
    generate_keypair,
    stable_id_from_did_key,
)
from aweb.awid.registry import AlreadyRegisteredError, RegistryClient, RegistryError
from aweb.config import is_local_awid_registry_url
from aweb.namespace_registry import (
    ensure_dns_namespace_registered,
    get_namespace_address,
    managed_namespace_domain,
    register_namespace_address,
    set_namespace_address_reachability,
    validate_subdomain_label,
)

logger = logging.getLogger(__name__)


def _uses_embedded_namespace_tables(registry_client: RegistryClient | None) -> bool:
    if registry_client is None:
        return True
    return is_local_awid_registry_url(registry_client.registry_url)


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
    api_key: str | None
    created: bool
    agent_type: str = "agent"
    did: str | None = None
    stable_id: str | None = None
    custody: str | None = None
    lifetime: str = "ephemeral"
    namespace: str | None = None
    address: str | None = None
    address_reachability: str | None = None


async def _resolve_project(
    tx,
    *,
    project_slug: str,
    project_name: str,
    project_id: str | None,
    tenant_id: str | None,
    owner_type: str | None = None,
    owner_ref: str | None = None,
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
                INSERT INTO {{tables.projects}} (project_id, slug, name, tenant_id, owner_type, owner_ref)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING project_id, slug, name
                """,
                UUID(project_id),
                project_slug,
                project_name or "",
                tenant_uuid,
                owner_type,
                owner_ref,
            )
        if owner_type is not None and owner_ref is not None:
            await tx.execute(
                """
                UPDATE {{tables.projects}}
                SET owner_type = COALESCE(owner_type, $2),
                    owner_ref = COALESCE(owner_ref, $3)
                WHERE project_id = $1
                """,
                UUID(project_id),
                owner_type,
                owner_ref,
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
                INSERT INTO {{tables.projects}} (slug, name, owner_type, owner_ref)
                VALUES ($1, $2, $3, $4)
                RETURNING project_id, slug, name
                """,
                project_slug,
                project_name or "",
                owner_type,
                owner_ref,
            )
        if owner_type is not None and owner_ref is not None:
            await tx.execute(
                """
                UPDATE {{tables.projects}}
                SET owner_type = COALESCE(owner_type, $2),
                    owner_ref = COALESCE(owner_ref, $3)
                WHERE project_id = $1
                """,
                project["project_id"],
                owner_type,
                owner_ref,
            )
    return dict(project)


async def bootstrap_identity(
    db,
    *,
    project_slug: str,
    project_name: str = "",
    project_id: str | None = None,
    tenant_id: str | None = None,
    owner_type: str | None = None,
    owner_ref: str | None = None,
    alias: str | None,
    human_name: str = "",
    agent_type: str = "agent",
    did: str | None = None,
    public_key: str | None = None,
    custody: str | None = None,
    lifetime: str = "ephemeral",
    role: str | None = None,
    program: str | None = None,
    context: dict | None = None,
    namespace: str | None = None,
    address_reachability: str | None = None,
    access_mode: str = "open",
    mint_api_key: bool = True,
    registry_client: RegistryClient | None = None,
    registry_server_url: str | None = None,
    registry_signing_key: bytes | None = None,
) -> BootstrapIdentityResult:
    aweb_db = db.get_manager("aweb")

    project_slug = validate_project_slug(project_slug.strip())
    alias = validate_agent_alias(alias.strip()) if alias is not None and alias.strip() else None
    human_name = (human_name or "").strip()
    agent_type = (agent_type or "agent").strip() or "agent"
    did = did.strip() if did is not None and did.strip() else None
    public_key = public_key.strip() if public_key is not None and public_key.strip() else None
    custody = custody.strip() if custody is not None and custody.strip() else None
    access_mode = validate_access_mode(access_mode)

    ns_domain: str | None = None
    ns_reachability: str | None = None
    if namespace is not None:
        namespace = validate_subdomain_label(namespace)
        managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
        if not managed_domain:
            raise ValueError(
                "Managed namespaces require AWEB_MANAGED_DOMAIN to be configured"
            )
        if alias is None or not alias.strip():
            raise ValueError("alias is required when namespace is specified")
        ns_domain = managed_namespace_domain(namespace)
        ns_reachability = normalize_address_reachability(address_reachability)

    reinit_without_key_material = (
        alias is not None
        and did is None
        and public_key is None
        and custody == "self"
    )

    contract = None
    if not reinit_without_key_material:
        contract = resolve_identity_contract(
            did=did,
            public_key=public_key,
            custody=custody,
            lifetime=lifetime,
            namespace=namespace,
        )
        custody = contract.custody
        lifetime = contract.lifetime
    else:
        lifetime = (lifetime or "ephemeral").strip() or "ephemeral"

    # Prepare identity columns.
    agent_did: str | None = contract.did if contract is not None else None
    agent_public_key: str | None = None
    agent_stable_id: str | None = contract.stable_id if contract is not None else None
    signing_key_enc: bytes | None = None
    effective_registry_signing_key: bytes | None = registry_signing_key

    if contract is not None and custody == "self":
        if did is None or public_key is None:
            raise ValueError("Self-custodial agents require both did and public_key")
        try:
            pub_bytes = decode_public_key(public_key)
        except Exception:
            raise ValueError(
                "public_key must be a base64-encoded 32-byte Ed25519 public key (url-safe or standard)"
            )
        expected_did = did_from_public_key(pub_bytes)
        if expected_did != did:
            raise ValueError("DID does not match public_key")
        # Normalize storage to canonical base64url encoding.
        agent_public_key = encode_public_key(pub_bytes)
    elif contract is not None and custody == "custodial":
        if did is not None or public_key is not None:
            raise ValueError("Custodial agents must not provide did/public_key")
        seed, pub = generate_keypair()
        agent_did = did_from_public_key(pub)
        if lifetime == "persistent":
            agent_stable_id = stable_id_from_did_key(agent_did)
        agent_public_key = encode_public_key(pub)
        effective_registry_signing_key = seed
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
            owner_type=owner_type,
            owner_ref=owner_ref,
        )

        resolved_project_id = str(project["project_id"])
        actual_project_slug = project["slug"]
        actual_project_name = project.get("name") or ""

        created = False
        agent_id: str
        if alias is not None and alias.strip():
            agent = await tx.fetch_one(
                """
                SELECT agent_id, alias, did, stable_id, custody, lifetime, agent_type, signing_key_enc
                FROM {{tables.agents}}
                WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
                """,
                UUID(resolved_project_id),
                alias,
            )
            if agent:
                existing_did = (agent["did"] or "").strip()
                if did and existing_did and did != existing_did:
                    raise ValueError(
                        f"alias '{alias}' is already in use by a different identity"
                    )
                created = False
                agent_id = str(agent["agent_id"])
                # On re-init, return existing identity fields.
                agent_did = existing_did
                agent_stable_id = agent.get("stable_id")
                custody = agent["custody"]
                lifetime = agent["lifetime"]
                agent_type = agent.get("agent_type") or "agent"
                if (
                    effective_registry_signing_key is None
                    and custody == "custodial"
                    and agent.get("signing_key_enc") is not None
                ):
                    master_key = get_custody_key()
                    if master_key is not None:
                        try:
                            effective_registry_signing_key = decrypt_signing_key(
                                agent["signing_key_enc"], master_key
                            )
                        except Exception:
                            logger.error(
                                "Failed to decrypt signing key during bootstrap re-init for agent %s",
                                agent_id,
                                exc_info=True,
                            )
            else:
                if reinit_without_key_material:
                    raise ValueError("Self-custodial identities require both did and public_key")
                agent = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.agents}}
                        (project_id, alias, human_name, agent_type,
                         did, public_key, stable_id, custody, signing_key_enc, lifetime,
                         access_mode, role, program, context)
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
                    access_mode,
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
                             access_mode, role, program, context)
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
                        access_mode,
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

        ns_address: str | None = None
        if ns_domain is not None:
            if agent_stable_id is None or agent_did is None:
                raise ValueError(
                    "Only permanent identities may own or publish addresses"
                )
            if _uses_embedded_namespace_tables(registry_client):
                ns_row = await tx.fetch_one(
                    """
                    SELECT namespace_id FROM {{tables.dns_namespaces}}
                    WHERE domain = $1 AND deleted_at IS NULL
                    """,
                    ns_domain,
                )
                if ns_row is None:
                    ns_id = uuid_mod.uuid4()
                    await tx.execute(
                        """
                        INSERT INTO {{tables.dns_namespaces}}
                            (namespace_id, domain, namespace_type, scope_id,
                             verification_status, created_at)
                        VALUES ($1, $2, 'managed', $3, 'verified', NOW())
                        """,
                        ns_id,
                        ns_domain,
                        UUID(resolved_project_id),
                    )
                else:
                    ns_id = ns_row["namespace_id"]

                existing_addr = await tx.fetch_one(
                    """
                    SELECT address_id FROM {{tables.public_addresses}}
                    WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
                    """,
                    ns_id,
                    alias,
                )
                if existing_addr is None:
                    await tx.execute(
                        """
                        INSERT INTO {{tables.public_addresses}}
                            (namespace_id, name, did_aw, current_did_key, reachability, created_at)
                        VALUES ($1, $2, $3, $4, $5, NOW())
                        """,
                        ns_id,
                        alias,
                        agent_stable_id,
                        agent_did,
                        ns_reachability,
                    )
            else:
                controller_signing_key = get_namespace_controller_key()
                if controller_signing_key is None:
                    raise ValueError(
                        "AWEB_NAMESPACE_CONTROLLER_KEY not set — cannot register managed namespace with external awid registry"
                    )
                await ensure_dns_namespace_registered(
                    registry_client=registry_client,
                    domain=ns_domain,
                    controller_signing_key=controller_signing_key,
                )
                if effective_registry_signing_key is None and custody == "self":
                    logger.info(
                        "Skipping managed address registration for self-custodial permanent identity %s; "
                        "DID registration uses the local private key",
                        alias or agent_stable_id or "(unassigned)",
                    )
                else:
                    existing_addr = await get_namespace_address(
                        registry_client=registry_client,
                        domain=ns_domain,
                        name=alias,
                    )
                    if existing_addr is None:
                        await register_namespace_address(
                            registry_client=registry_client,
                            domain=ns_domain,
                            name=alias,
                            did_aw=agent_stable_id,
                            current_did_key=agent_did,
                            controller_signing_key=controller_signing_key,
                            reachability=ns_reachability or "private",
                        )
                    else:
                        existing_did_aw = str(existing_addr.get("did_aw") or "").strip()
                        if existing_did_aw != agent_stable_id:
                            raise ValueError(
                                f"address '{ns_domain}/{alias}' is already in use"
                            )
                        if (
                            ns_reachability is not None
                            and str(existing_addr.get("reachability") or "private")
                            != ns_reachability
                        ):
                            await set_namespace_address_reachability(
                                registry_client=registry_client,
                                domain=ns_domain,
                                name=alias,
                                controller_signing_key=controller_signing_key,
                                reachability=ns_reachability,
                            )

            ns_address = f"{ns_domain}/{alias}"

        if registry_client is not None and registry_server_url is not None and lifetime == "persistent":
            if agent_did is not None and effective_registry_signing_key is not None:
                await _sync_registry_identity(
                    registry_client=registry_client,
                    did_key=agent_did,
                    signing_key=effective_registry_signing_key,
                    server_url=registry_server_url,
                )
            elif custody == "self":
                logger.info(
                    "Skipping registry sync for self-custodial permanent identity %s; "
                    "client-side registration uses the local private key",
                    alias or agent_stable_id or "(unassigned)",
                )

        api_key: str | None = None
        if mint_api_key:
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
        agent_type=agent_type,
        did=agent_did,
        stable_id=agent_stable_id,
        custody=custody,
        lifetime=lifetime,
        namespace=ns_domain,
        address=ns_address,
        address_reachability=ns_reachability,
    )


async def _sync_registry_identity(
    *,
    registry_client: RegistryClient,
    did_key: str,
    signing_key: bytes,
    server_url: str,
) -> None:
    did_aw = stable_id_from_did_key(did_key)
    try:
        await registry_client.register_did(did_key, signing_key, server_url)
        return
    except AlreadyRegisteredError as exc:
        if exc.did_aw != did_aw:
            raise ValueError("Registry did_aw conflict") from exc
        if exc.existing_did_key != did_key:
            raise ValueError(
                "Registry already has this did:aw registered to a different current did:key"
            ) from exc
    except RegistryError as exc:
        raise ValueError(f"Registry DID registration failed: {exc.detail}") from exc

    current_mapping = await registry_client.resolve_key(did_aw)
    if current_mapping.current_did_key != did_key:
        raise ValueError("Registry current did:key does not match the local identity")

    existing_mapping = await registry_client.get_mapping(did_aw, signing_key)
    if existing_mapping.server == server_url:
        return

    try:
        await registry_client.update_server(did_aw, server_url, signing_key)
    except RegistryError as exc:
        raise ValueError(f"Registry DID server update failed: {exc.detail}") from exc


async def delete_agent_identity(db_infra, *, agent_id: str, project_id: str) -> None:
    """Mark an agent identity deleted and deactivate its credentials.

    This is an internal cleanup helper used after callers have already decided
    that deletion is the correct lifecycle operation.

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
                status = 'deleted',
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
                "delete",
                row["did"],
            )
