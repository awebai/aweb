from __future__ import annotations

import json
from uuid import UUID

import asyncpg.exceptions
from pgdbm import AsyncDatabaseManager, TransactionManager

from aweb.bootstrap import BootstrapIdentityResult, bootstrap_identity


DatabaseHandle = AsyncDatabaseManager | TransactionManager


class _EmbeddedDbInfra:
    def __init__(self, aweb_db: DatabaseHandle):
        self._aweb_db = aweb_db

    def get_manager(self, name: str = "aweb"):
        if name != "aweb":
            raise KeyError(name)
        return self._aweb_db


def _parse_context(raw):
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return dict(raw)


async def bootstrap_scope_agent(*, aweb_db: DatabaseHandle, scope_id: str, payload: dict, mint_api_key: bool = True) -> dict:
    project = await aweb_db.fetch_one(
        """
        SELECT project_id, slug, name
        FROM {{tables.projects}}
        WHERE project_id = $1 AND deleted_at IS NULL
        """,
        UUID(scope_id),
    )
    if not project:
        raise ValueError("Scope not found")

    db_infra = _EmbeddedDbInfra(aweb_db)
    try:
        result: BootstrapIdentityResult = await bootstrap_identity(
            db_infra,
            project_slug=str(project["slug"]),
            project_name=(project.get("name") or "").strip(),
            project_id=str(project["project_id"]),
            alias=payload.get("alias"),
            human_name=payload.get("human_name") or "",
            agent_type=(payload.get("agent_type") or "agent").strip() or "agent",
            did=payload.get("did"),
            public_key=payload.get("public_key"),
            custody=payload.get("custody"),
            lifetime=payload.get("lifetime") or "ephemeral",
            role=payload.get("role"),
            program=payload.get("program"),
            context=payload.get("context"),
            access_mode=payload.get("access_mode") or "open",
            mint_api_key=mint_api_key,
        )
    except asyncpg.exceptions.UniqueViolationError:
        result = await bootstrap_identity(
            db_infra,
            project_slug=str(project["slug"]),
            project_name=(project.get("name") or "").strip(),
            project_id=str(project["project_id"]),
            alias=payload.get("alias"),
            human_name=payload.get("human_name") or "",
            agent_type=(payload.get("agent_type") or "agent").strip() or "agent",
            did=payload.get("did"),
            public_key=payload.get("public_key"),
            custody=payload.get("custody"),
            lifetime=payload.get("lifetime") or "ephemeral",
            role=payload.get("role"),
            program=payload.get("program"),
            context=payload.get("context"),
            access_mode=payload.get("access_mode") or "open",
            mint_api_key=mint_api_key,
        )

    out = {
        "scope_id": scope_id,
        "agent_id": result.agent_id,
        "alias": result.alias,
        "agent_type": result.agent_type,
        "created": result.created,
        "did": result.did,
        "stable_id": result.stable_id,
        "custody": result.custody,
        "lifetime": result.lifetime,
        "namespace": result.namespace,
        "address": result.address,
    }
    if result.api_key is not None:
        out["api_key"] = result.api_key
    return out


async def list_scope_agents(*, aweb_db: DatabaseHandle, scope_id: str) -> list[dict]:
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, stable_id, custody, lifetime, status,
               role, program, context
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        UUID(scope_id),
    )
    return [
        {
            "agent_id": str(row["agent_id"]),
            "alias": row["alias"],
            "human_name": row.get("human_name"),
            "agent_type": row.get("agent_type"),
            "access_mode": row.get("access_mode", "open"),
            "did": row.get("did"),
            "stable_id": row.get("stable_id"),
            "custody": row.get("custody"),
            "lifetime": row.get("lifetime", "ephemeral"),
            "status": row.get("status", "active"),
            "role": row.get("role"),
            "program": row.get("program"),
            "context": _parse_context(row.get("context")),
        }
        for row in rows
    ]


async def get_scope_agent(*, aweb_db: DatabaseHandle, scope_id: str, agent_ref: str) -> dict:
    row = None
    try:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias, human_name, agent_type, access_mode,
                   did, stable_id, custody, lifetime, status,
                   role, program, context
            FROM {{tables.agents}}
            WHERE project_id = $1 AND agent_id = $2 AND deleted_at IS NULL
            """,
            UUID(scope_id),
            UUID(agent_ref),
        )
    except ValueError:
        pass

    if row is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias, human_name, agent_type, access_mode,
                   did, stable_id, custody, lifetime, status,
                   role, program, context
            FROM {{tables.agents}}
            WHERE project_id = $1 AND stable_id = $2 AND deleted_at IS NULL
            """,
            UUID(scope_id),
            agent_ref,
        )

    if row is None:
        raise ValueError("Agent not found")

    return {
        "agent_id": str(row["agent_id"]),
        "alias": row["alias"],
        "human_name": row.get("human_name"),
        "agent_type": row.get("agent_type"),
        "access_mode": row.get("access_mode", "open"),
        "did": row.get("did"),
        "stable_id": row.get("stable_id"),
        "custody": row.get("custody"),
        "lifetime": row.get("lifetime", "ephemeral"),
        "status": row.get("status", "active"),
        "role": row.get("role"),
        "program": row.get("program"),
        "context": _parse_context(row.get("context")),
    }


async def find_scope_agent_id_by_stable_id(
    *,
    aweb_db: DatabaseHandle,
    scope_ids: list[str],
    stable_id: str,
) -> str | None:
    if not stable_id:
        return None
    for scope_id in scope_ids:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id
            FROM {{tables.agents}}
            WHERE project_id = $1
              AND stable_id = $2
              AND deleted_at IS NULL
            """,
            UUID(scope_id),
            stable_id,
        )
        if row is not None:
            return str(row["agent_id"])
    return None
