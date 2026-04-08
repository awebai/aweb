"""POST /v1/connect — agent auto-provisioning via team certificate.

Called by `aw init`. Auto-provisions team and agent rows from the
verified certificate, creates or updates a workspace.
"""

from __future__ import annotations

import uuid
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager
from pgdbm.errors import QueryError
from pydantic import BaseModel, Field

from aweb.coordination.routes.repos import canonicalize_git_url
from aweb.deps import get_db
from aweb.team_auth_deps import verify_request_certificate

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


class AliasConflictError(ValueError):
    """Raised when an alias is already owned by another active agent."""

    pass


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
    did_aw: str,
    address: str,
    alias: str,
    lifetime: str,
    human_name: str,
    agent_type: str,
    role: str,
) -> str:
    """Find or create the agent row. Returns agent_id as string.

    did_aw and address come from the certificate's member_did_aw /
    member_address fields. Empty strings are stored as NULL (ephemeral
    certificates do not carry these fields).
    """
    existing_alias = await db.fetch_one(
        """
        SELECT agent_id, did_key FROM {{tables.agents}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_address,
        alias,
    )
    if existing_alias and existing_alias["did_key"] != did_key:
        raise AliasConflictError(
            f"alias {alias!r} is already in use by another active agent in team {team_address}"
        )

    agent_id = uuid.uuid4()
    try:
        await db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, team_address, did_key, did_aw, address,
                 alias, lifetime, human_name, agent_type, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (team_address, did_key) DO NOTHING
            """,
            agent_id,
            team_address,
            did_key,
            did_aw or None,
            address or None,
            alias,
            lifetime,
            human_name,
            agent_type,
            role,
        )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(exc.__cause__, asyncpg.exceptions.UniqueViolationError):
            raise
        existing_alias = await db.fetch_one(
            """
            SELECT agent_id, did_key FROM {{tables.agents}}
            WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            team_address,
            alias,
        )
        if existing_alias and existing_alias["did_key"] != did_key:
            raise AliasConflictError(
                f"alias {alias!r} is already in use by another active agent in team {team_address}"
            ) from exc
        raise

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

    async def _get_existing_workspace():
        return await db.fetch_one(
            """
            SELECT workspace_id, agent_id FROM {{tables.workspaces}}
            WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            team_address,
            alias,
        )

    async def _update_existing_workspace(workspace_id: uuid.UUID | str) -> str:
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

    existing = await _get_existing_workspace()
    if existing:
        if str(existing["agent_id"]) != agent_id:
            raise AliasConflictError(
                f"alias {alias!r} is already in use by another active agent in team {team_address}"
            )
        return await _update_existing_workspace(existing["workspace_id"])

    workspace_id = uuid.uuid4()
    workspace_type = "agent" if repo_origin else "manual"
    try:
        row = await db.fetch_one(
            """
            INSERT INTO {{tables.workspaces}}
                (workspace_id, team_address, agent_id, repo_id, alias, human_name,
                 role, hostname, workspace_path, workspace_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        return str(row["workspace_id"])
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(exc.__cause__, asyncpg.exceptions.UniqueViolationError):
            raise
        existing = await _get_existing_workspace()
        if existing and str(existing["agent_id"]) == agent_id:
            return await _update_existing_workspace(existing["workspace_id"])
        raise AliasConflictError(
            f"alias {alias!r} is already in use by another active agent in team {team_address}"
        ) from exc


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
    did_aw = cert_info.get("member_did_aw", "")
    address = cert_info.get("member_address", "")

    await _ensure_team(db, team_address, team_did_key)

    agent_id = await _ensure_agent(
        db,
        team_address=team_address,
        did_key=did_key,
        did_aw=did_aw,
        address=address,
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


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


@router.post("/connect", response_model=ConnectResponse)
async def connect_endpoint(
    request: Request, payload: ConnectRequest, db=Depends(get_db)
) -> ConnectResponse:
    """Agent connects with certificate. Auto-provisions team + agent + workspace.

    Uses certificate-only auth (no agent lookup) since the agent may not
    exist yet — this endpoint creates the agent row.
    """
    cert_info = await verify_request_certificate(request, db)

    aweb_db = db.get_manager("aweb")

    # Use the registry-resolved team key (verified by verify_request_certificate)
    team_did_key = cert_info.get("verified_team_did_key", "")

    try:
        result = await connect_agent(
            db=aweb_db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname=payload.hostname,
            workspace_path=payload.workspace_path,
            repo_origin=payload.repo_origin,
            role=payload.role or cert_info["alias"],
            human_name=payload.human_name,
            agent_type=payload.agent_type,
        )
    except AliasConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return ConnectResponse(**result)


class TeamInfoResponse(BaseModel):
    team_address: str
    namespace: str
    team_name: str
    team_did_key: str
    member_count: int


@router.get("/team", response_model=TeamInfoResponse)
async def get_team_info(
    request: Request, db=Depends(get_db)
) -> TeamInfoResponse:
    """Get team info from the authenticated certificate."""
    from aweb.team_auth_deps import get_team_identity

    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    team = await aweb_db.fetch_one(
        "SELECT * FROM {{tables.teams}} WHERE team_address = $1",
        identity.team_address,
    )
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    count = await aweb_db.fetch_one(
        "SELECT COUNT(*)::int AS cnt FROM {{tables.agents}} WHERE team_address = $1 AND deleted_at IS NULL",
        identity.team_address,
    )

    return TeamInfoResponse(
        team_address=team["team_address"],
        namespace=team["namespace"],
        team_name=team["team_name"],
        team_did_key=team["team_did_key"],
        member_count=count["cnt"] if count else 0,
    )
