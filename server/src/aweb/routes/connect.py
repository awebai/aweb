"""POST /v1/connect — agent auto-provisioning via team certificate.

Called by `aw init`. Auto-provisions team and agent rows from the
verified certificate, creates or updates a workspace.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter
from pgdbm import AsyncDatabaseManager
from pydantic import BaseModel, Field

from aweb.coordination.routes.repos import canonicalize_git_url

router = APIRouter(prefix="/v1", tags=["connect"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ConnectRequest(BaseModel):
    hostname: str = Field(default="", max_length=256)
    workspace_path: str = Field(default="", max_length=1024)
    repo_origin: str = Field(default="", max_length=1024)
    role: str = Field(default="", max_length=50)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)


class ConnectResponse(BaseModel):
    team_address: str
    alias: str
    agent_id: str
    workspace_id: str
    role: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_team_address(team_address: str) -> tuple[str, str]:
    """Split 'acme.com/backend' into ('acme.com', 'backend')."""
    parts = team_address.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Invalid team_address format: {team_address}")
    return parts[0], parts[1]


async def _ensure_team(
    db: AsyncDatabaseManager,
    team_address: str,
    team_did_key: str,
) -> None:
    """Create the team row if it doesn't exist."""
    namespace, team_name = _parse_team_address(team_address)
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (team_address) DO NOTHING
        """,
        team_address,
        namespace,
        team_name,
        team_did_key,
    )


async def _ensure_agent(
    db: AsyncDatabaseManager,
    team_address: str,
    did_key: str,
    alias: str,
    lifetime: str,
    human_name: str,
    agent_type: str,
    role: str,
) -> str:
    """Find or create the agent row. Returns agent_id as string."""
    agent_id = uuid.uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, human_name, agent_type, role)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (team_address, alias) DO NOTHING
        """,
        agent_id,
        team_address,
        did_key,
        alias,
        lifetime,
        human_name,
        agent_type,
        role,
    )
    # Re-fetch to get the authoritative agent_id (may have been a no-op)
    row = await db.fetch_one(
        """
        SELECT agent_id FROM {{tables.agents}}
        WHERE team_address = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_address,
        did_key,
    )
    return str(row["agent_id"])


async def _ensure_workspace(
    db: AsyncDatabaseManager,
    team_address: str,
    agent_id: str,
    alias: str,
    hostname: str,
    workspace_path: str,
    repo_origin: str,
    role: str,
    human_name: str,
) -> str:
    """Find or create a workspace row. Returns workspace_id as string.

    On reconnect (same team_address + alias), updates the existing workspace
    with fresh hostname/path/role/agent_id info.
    """
    repo_id = None
    if repo_origin:
        repo_id = await _ensure_repo(db, team_address, repo_origin)

    # Check for existing active workspace for this alias
    existing = await db.fetch_one(
        """
        SELECT workspace_id FROM {{tables.workspaces}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_address,
        alias,
    )

    if existing:
        workspace_id = existing["workspace_id"]
        await db.execute(
            """
            UPDATE {{tables.workspaces}}
            SET hostname = $1, workspace_path = $2, role = $3,
                human_name = $4, repo_id = COALESCE($5, repo_id),
                agent_id = $6, last_seen_at = NOW(), updated_at = NOW()
            WHERE workspace_id = $7
            """,
            hostname,
            workspace_path,
            role,
            human_name,
            repo_id,
            uuid.UUID(agent_id),
            workspace_id,
        )
        return str(workspace_id)

    workspace_id = uuid.uuid4()
    workspace_type = "agent" if repo_origin else "manual"
    await db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_address, agent_id, repo_id, alias, human_name,
             role, hostname, workspace_path, workspace_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (team_address, alias) WHERE deleted_at IS NULL DO UPDATE SET
            hostname = EXCLUDED.hostname,
            workspace_path = EXCLUDED.workspace_path,
            role = EXCLUDED.role,
            human_name = EXCLUDED.human_name,
            repo_id = COALESCE(EXCLUDED.repo_id, {{tables.workspaces}}.repo_id),
            agent_id = EXCLUDED.agent_id,
            last_seen_at = NOW(),
            updated_at = NOW()
        RETURNING workspace_id
        """,
        workspace_id,
        team_address,
        uuid.UUID(agent_id),
        repo_id,
        alias,
        human_name,
        role,
        hostname,
        workspace_path,
        workspace_type,
    )
    # Re-fetch in case of upsert
    row = await db.fetch_one(
        """
        SELECT workspace_id FROM {{tables.workspaces}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_address,
        alias,
    )
    return str(row["workspace_id"])


async def _ensure_repo(
    db: AsyncDatabaseManager,
    team_address: str,
    repo_origin: str,
) -> uuid.UUID:
    """Find or create a repo row. Returns repo id."""
    canonical = canonicalize_git_url(repo_origin)
    name = canonical.rsplit("/", 1)[-1] if "/" in canonical else canonical

    repo_id = uuid.uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.repos}} (id, team_address, origin_url, canonical_origin, name)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (team_address, canonical_origin) DO NOTHING
        """,
        repo_id,
        team_address,
        repo_origin,
        canonical,
        name,
    )
    row = await db.fetch_one(
        """
        SELECT id FROM {{tables.repos}}
        WHERE team_address = $1 AND canonical_origin = $2 AND deleted_at IS NULL
        """,
        team_address,
        canonical,
    )
    return row["id"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def connect_agent(
    *,
    db: AsyncDatabaseManager,
    cert_info: dict[str, str],
    team_did_key: str,
    hostname: str,
    workspace_path: str,
    repo_origin: str,
    role: str,
    human_name: str,
    agent_type: str,
) -> dict[str, Any]:
    """Auto-provision team + agent + workspace from certificate info.

    Args:
        db: The aweb database manager.
        cert_info: Verified certificate fields (team_address, alias, did_key, lifetime).
        team_did_key: The team's public key from awid registry.
        hostname: Agent's hostname.
        workspace_path: Agent's workspace path.
        repo_origin: Git remote URL (empty if none).
        role: Agent role.
        human_name: Agent display name.
        agent_type: Agent type (agent, etc).

    Returns:
        Dict with team_address, alias, agent_id, workspace_id, role.
    """
    team_address = cert_info["team_address"]
    alias = cert_info["alias"]
    did_key = cert_info["did_key"]
    lifetime = cert_info["lifetime"]

    await _ensure_team(db, team_address, team_did_key)

    agent_id = await _ensure_agent(
        db,
        team_address=team_address,
        did_key=did_key,
        alias=alias,
        lifetime=lifetime,
        human_name=human_name,
        agent_type=agent_type,
        role=role,
    )

    workspace_id = await _ensure_workspace(
        db,
        team_address=team_address,
        agent_id=agent_id,
        alias=alias,
        hostname=hostname,
        workspace_path=workspace_path,
        repo_origin=repo_origin,
        role=role,
        human_name=human_name,
    )

    return {
        "team_address": team_address,
        "alias": alias,
        "agent_id": agent_id,
        "workspace_id": workspace_id,
        "role": role,
    }
