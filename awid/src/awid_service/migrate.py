from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pgdbm import AsyncDatabaseManager

from aweb.db_config import build_database_config

from .config import get_settings
from .db import AwidDatabaseInfra


@dataclass(frozen=True)
class MigrationResult:
    projects: int
    agents: int
    did_mappings: int
    did_log_entries: int
    namespaces: int
    addresses: int
    replacements: int


async def migrate_from_aweb(
    *,
    source_schema: str = "aweb",
    target_schema: str = "awid",
    include_managed: bool = False,
) -> MigrationResult:
    settings = get_settings()
    config = build_database_config(connection_string=settings.database_url)
    shared_pool = await AsyncDatabaseManager.create_shared_pool(config)

    target = AwidDatabaseInfra(schema=target_schema)
    source = AsyncDatabaseManager(pool=shared_pool, schema=source_schema)
    try:
        await target.initialize(shared_pool=shared_pool, run_migrations=True)
        target_db = target.get_manager("aweb")

        async with target_db.transaction() as tx:
            projects = await _copy_projects(source=source, target=tx)
            agents = await _copy_agents(source=source, target=tx)
            did_mappings = await _copy_did_mappings(source=source, target=tx)
            did_log_entries = await _copy_did_log(source=source, target=tx)
            namespaces = await _copy_namespaces(
                source=source,
                target=tx,
                include_managed=include_managed,
            )
            addresses = await _copy_addresses(source=source, target=tx, include_managed=include_managed)
            replacements = await _copy_replacements(
                source=source,
                target=tx,
                include_managed=include_managed,
            )
        return MigrationResult(
            projects=projects,
            agents=agents,
            did_mappings=did_mappings,
            did_log_entries=did_log_entries,
            namespaces=namespaces,
            addresses=addresses,
            replacements=replacements,
        )
    finally:
        await target.close()
        await shared_pool.close()


async def _copy_projects(*, source, target) -> int:
    rows = await source.fetch_all(
        """
        SELECT project_id, slug, name, tenant_id, owner_type, owner_ref, created_at, deleted_at
        FROM {{tables.projects}}
        """
    )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.projects}}
                (project_id, slug, name, tenant_id, owner_type, owner_ref, created_at, deleted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (project_id) DO NOTHING
            """,
            row["project_id"],
            row["slug"],
            row["name"],
            row["tenant_id"],
            row["owner_type"],
            row["owner_ref"],
            row["created_at"],
            row["deleted_at"],
        )
    return len(rows)


async def _copy_agents(*, source, target) -> int:
    rows = await source.fetch_all(
        """
        SELECT agent_id, project_id, alias, human_name, agent_type, access_mode, did,
               public_key, custody, stable_id, lifetime, status,
               successor_agent_id, role, program, context, created_at, deleted_at
        FROM {{tables.agents}}
        """
    )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, project_id, alias, human_name, agent_type, access_mode, did,
                 public_key, custody, signing_key_enc, stable_id, lifetime, status,
                 successor_agent_id, role, program, context, created_at, deleted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7,
                    $8, $9, NULL, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18)
            ON CONFLICT (agent_id) DO NOTHING
            """,
            row["agent_id"],
            row["project_id"],
            row["alias"],
            row["human_name"],
            row["agent_type"],
            row["access_mode"],
            row["did"],
            row["public_key"],
            row["custody"],
            row["stable_id"],
            row["lifetime"],
            row["status"],
            row["successor_agent_id"],
            row["role"],
            row["program"],
            row["context"],
            row["created_at"],
            row["deleted_at"],
        )
    return len(rows)


async def _copy_did_mappings(*, source, target) -> int:
    rows = await source.fetch_all(
        """
        SELECT did_aw, current_did_key, server_url, address, handle, created_at, updated_at
        FROM {{tables.did_aw_mappings}}
        """
    )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.did_aw_mappings}}
                (did_aw, current_did_key, server_url, address, handle, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (did_aw) DO NOTHING
            """,
            row["did_aw"],
            row["current_did_key"],
            row["server_url"],
            row["address"],
            row["handle"],
            row["created_at"],
            row["updated_at"],
        )
    return len(rows)


async def _copy_did_log(*, source, target) -> int:
    rows = await source.fetch_all(
        """
        SELECT did_aw, seq, operation, previous_did_key, new_did_key,
               prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
               timestamp, created_at
        FROM {{tables.did_aw_log}}
        ORDER BY did_aw, seq
        """
    )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.did_aw_log}}
                (did_aw, seq, operation, previous_did_key, new_did_key,
                 prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
                 timestamp, created_at)
            VALUES ($1, $2, $3, $4, $5,
                    $6, $7, $8, $9, $10,
                    $11, $12)
            ON CONFLICT (did_aw, seq) DO NOTHING
            """,
            row["did_aw"],
            row["seq"],
            row["operation"],
            row["previous_did_key"],
            row["new_did_key"],
            row["prev_entry_hash"],
            row["entry_hash"],
            row["state_hash"],
            row["authorized_by"],
            row["signature"],
            row["timestamp"],
            row["created_at"],
        )
    return len(rows)


async def _resolved_namespaces(*, source, include_managed: bool) -> list[Any]:
    rows = await source.fetch_all(
        """
        WITH latest_replacement AS (
            SELECT DISTINCT ON (namespace_id)
                   namespace_id,
                   controller_did
            FROM {{tables.replacement_announcements}}
            ORDER BY namespace_id, created_at DESC
        )
        SELECT ns.namespace_id, ns.domain,
               COALESCE(ns.controller_did, lr.controller_did) AS effective_controller_did,
               ns.verification_status, ns.last_verified_at, ns.created_at, ns.deleted_at,
               ns.namespace_type, ns.scope_id
        FROM {{tables.dns_namespaces}} ns
        LEFT JOIN latest_replacement lr ON lr.namespace_id = ns.namespace_id
        ORDER BY ns.created_at
        """
    )
    unresolved = [
        row["domain"]
        for row in rows
        if row["effective_controller_did"] is None
        and (include_managed or row["namespace_type"] != "managed")
    ]
    if unresolved:
        raise ValueError(
            "Cannot migrate namespaces with null controller_did after backfill: "
            + ", ".join(sorted(unresolved))
        )
    if include_managed:
        return rows
    return [row for row in rows if row["namespace_type"] != "managed"]


async def _copy_namespaces(*, source, target, include_managed: bool) -> int:
    rows = await _resolved_namespaces(source=source, include_managed=include_managed)
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id, domain, controller_did, verification_status,
                 last_verified_at, created_at, deleted_at, namespace_type, scope_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (namespace_id) DO NOTHING
            """,
            row["namespace_id"],
            row["domain"],
            row["effective_controller_did"],
            row["verification_status"],
            row["last_verified_at"],
            row["created_at"],
            row["deleted_at"],
            row["namespace_type"],
            row["scope_id"],
        )
    return len(rows)


async def _copy_addresses(*, source, target, include_managed: bool) -> int:
    if include_managed:
        rows = await source.fetch_all(
            """
            SELECT pa.address_id, pa.namespace_id, pa.name, pa.did_aw, pa.current_did_key,
                   pa.reachability, pa.created_at, pa.deleted_at
            FROM {{tables.public_addresses}} pa
            JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
            """
        )
    else:
        rows = await source.fetch_all(
            """
            SELECT pa.address_id, pa.namespace_id, pa.name, pa.did_aw, pa.current_did_key,
                   pa.reachability, pa.created_at, pa.deleted_at
            FROM {{tables.public_addresses}} pa
            JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
            WHERE ns.namespace_type <> 'managed'
            """
        )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.public_addresses}}
                (address_id, namespace_id, name, did_aw, current_did_key,
                 reachability, created_at, deleted_at)
            VALUES ($1, $2, $3, $4, $5,
                    $6, $7, $8)
            ON CONFLICT (address_id) DO NOTHING
            """,
            row["address_id"],
            row["namespace_id"],
            row["name"],
            row["did_aw"],
            row["current_did_key"],
            row["reachability"],
            row["created_at"],
            row["deleted_at"],
        )
    return len(rows)


async def _copy_replacements(*, source, target, include_managed: bool) -> int:
    if include_managed:
        rows = await source.fetch_all(
            """
            SELECT ra.announcement_id, ra.project_id, ra.old_agent_id, ra.new_agent_id,
                   ra.namespace_id, ra.address_name, ra.old_did, ra.new_did,
                   ra.controller_did, ra.replacement_timestamp, ra.controller_signature,
                   ra.authorized_by, ra.created_at
            FROM {{tables.replacement_announcements}} ra
            JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = ra.namespace_id
            """
        )
    else:
        rows = await source.fetch_all(
            """
            SELECT ra.announcement_id, ra.project_id, ra.old_agent_id, ra.new_agent_id,
                   ra.namespace_id, ra.address_name, ra.old_did, ra.new_did,
                   ra.controller_did, ra.replacement_timestamp, ra.controller_signature,
                   ra.authorized_by, ra.created_at
            FROM {{tables.replacement_announcements}} ra
            JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = ra.namespace_id
            WHERE ns.namespace_type <> 'managed'
            """
        )
    for row in rows:
        await target.execute(
            """
            INSERT INTO {{tables.replacement_announcements}}
                (announcement_id, project_id, old_agent_id, new_agent_id,
                 namespace_id, address_name, old_did, new_did,
                 controller_did, replacement_timestamp, controller_signature,
                 authorized_by, created_at)
            VALUES ($1, $2, $3, $4,
                    $5, $6, $7, $8,
                    $9, $10, $11,
                    $12, $13)
            ON CONFLICT (announcement_id) DO NOTHING
            """,
            row["announcement_id"],
            row["project_id"],
            row["old_agent_id"],
            row["new_agent_id"],
            row["namespace_id"],
            row["address_name"],
            row["old_did"],
            row["new_did"],
            row["controller_did"],
            row["replacement_timestamp"],
            row["controller_signature"],
            row["authorized_by"],
            row["created_at"],
        )
    return len(rows)
