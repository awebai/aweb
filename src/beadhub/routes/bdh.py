"""bdh coordination endpoints.

These endpoints are used by the `bdh` CLI wrapper to:
- preflight/record command execution (`POST /v1/bdh/command`)
- upload beads issue updates (`POST /v1/bdh/sync`)

They are intentionally thin wrappers around existing BeadHub primitives:
- auth comes from embedded aweb (`aw_sk_*` keys)
- bead sync uses `beadhub.beads_sync`
- notifications use the outbox pipeline in `beadhub.notifications`
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

if TYPE_CHECKING:
    from pgdbm import AsyncDatabaseManager

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from redis.asyncio import Redis

from beadhub.auth import enforce_actor_binding, validate_workspace_id
from beadhub.aweb_context import resolve_aweb_identity
from beadhub.aweb_introspection import get_identity_from_auth
from beadhub.beads_sync import (
    DEFAULT_BRANCH,
    BeadsSyncResult,
    _sync_issues_to_db,
    delete_issues_by_id,
    is_valid_alias,
    is_valid_canonical_origin,
    is_valid_human_name,
    validate_issues_from_list,
)
from beadhub.routes.repos import canonicalize_git_url, extract_repo_name

from ..db import DatabaseInfra, get_db_infra
from ..events import BeadClaimedEvent, BeadUnclaimedEvent, publish_bead_status_events, publish_event
from ..jsonl import JSONLParseError, parse_jsonl
from ..notifications import process_notification_outbox, record_notification_intents
from ..presence import get_workspace_id_by_alias
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/bdh", tags=["bdh"])

MAX_JSONL_SIZE = 10 * 1024 * 1024  # 10MB
MAX_ISSUES_COUNT = 10000
MAX_JSON_DEPTH = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_command_line(command_line: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (command, bead_id, status) best-effort, or (None, None, None)."""

    parts = command_line.split()
    if not parts:
        return None, None, None
    cmd = parts[0].strip()
    bead_id: Optional[str] = None
    status: Optional[str] = None
    if cmd in ("update", "close", "delete", "reopen") and len(parts) >= 2:
        candidate = parts[1].strip()
        if not candidate.startswith("--"):
            bead_id = candidate

    if cmd == "update":
        # Handle: --status in_progress OR --status=in_progress
        for i, p in enumerate(parts):
            if p == "--status" and i + 1 < len(parts):
                status = parts[i + 1].strip()
                break
            if p.startswith("--status="):
                status = p.split("=", 1)[1].strip()
                break

    return cmd, bead_id, status


async def _ensure_workspace_alive_or_410(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    workspace_id: str,
) -> dict[str, Any]:
    server_db = db_infra.get_manager("server")
    row = await server_db.fetch_one(
        """
        SELECT workspace_id, alias, human_name, role, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND project_id = $2
        """,
        UUID(workspace_id),
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if row.get("deleted_at") is not None:
        raise HTTPException(status_code=410, detail="Workspace was deleted")
    return row


async def _touch_workspace_last_seen(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    workspace_id: str,
    human_name: str,
    role: Optional[str],
) -> None:
    server_db = db_infra.get_manager("server")
    await server_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET last_seen_at = $3,
            human_name = $4,
            role = $5
        WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(workspace_id),
        UUID(project_id),
        _now(),
        human_name,
        role,
    )


async def _list_beads_in_progress(
    db_infra: DatabaseInfra, *, project_id: str
) -> list[dict[str, Any]]:
    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        """
        SELECT bead_id, workspace_id, alias, human_name, claimed_at
        FROM {{tables.bead_claims}}
        WHERE project_id = $1
        ORDER BY claimed_at DESC
        LIMIT 200
        """,
        UUID(project_id),
    )
    return [
        {
            "bead_id": r["bead_id"],
            "workspace_id": str(r["workspace_id"]),
            "alias": r["alias"],
            "human_name": r["human_name"],
            "started_at": r["claimed_at"].isoformat(),
            "title": None,
            "role": None,
        }
        for r in rows
    ]


async def _resolve_claim_apex(
    db_infra: DatabaseInfra,
    project_id: str,
    bead_id: str,
    max_depth: int = 20,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve the apex for a bead by walking parent_id links.

    Returns (apex_bead_id, apex_repo_name, apex_branch). If the bead isn't found
    in beads_issues, returns (None, None, None).
    """
    beads_db = db_infra.get_manager("beads")
    current = await beads_db.fetch_one(
        """
        SELECT bead_id, repo, branch, parent_id
        FROM {{tables.beads_issues}}
        WHERE project_id = $1 AND bead_id = $2
        ORDER BY synced_at DESC
        LIMIT 1
        """,
        UUID(project_id),
        bead_id,
    )
    if not current:
        return None, None, None

    depth = 0
    while current.get("parent_id") and depth < max_depth:
        parent = current["parent_id"]
        if isinstance(parent, str):
            try:
                parent = json.loads(parent)
            except (json.JSONDecodeError, RecursionError):
                break
        if not isinstance(parent, dict):
            break
        parent_repo = parent.get("repo")
        parent_branch = parent.get("branch")
        parent_bead_id = parent.get("bead_id")
        if not parent_repo or not parent_branch or not parent_bead_id:
            break

        parent_row = await beads_db.fetch_one(
            """
            SELECT bead_id, repo, branch, parent_id
            FROM {{tables.beads_issues}}
            WHERE project_id = $1
              AND repo = $2
              AND branch = $3
              AND bead_id = $4
            ORDER BY synced_at DESC
            LIMIT 1
            """,
            UUID(project_id),
            parent_repo,
            parent_branch,
            parent_bead_id,
        )
        if not parent_row:
            break
        current = parent_row
        depth += 1

    return current["bead_id"], current["repo"], current["branch"]


async def _upsert_claim(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    workspace_id: str,
    alias: str,
    human_name: str,
    bead_id: str,
) -> Optional[dict[str, Any]]:
    """Attempt to claim a bead. Returns None on success, or the conflicting
    claim dict (with alias, human_name, workspace_id) if already held by
    another workspace."""
    server_db = db_infra.get_manager("server")

    # Resolve apex (root parent) for this bead
    apex_bead_id, apex_repo_name, apex_branch = await _resolve_claim_apex(
        db_infra, project_id, bead_id
    )

    async with server_db.transaction() as tx:
        # Check if another workspace already holds this claim.
        existing = await tx.fetch_one(
            """
            SELECT workspace_id, alias, human_name
            FROM {{tables.bead_claims}}
            WHERE project_id = $1 AND bead_id = $2 AND workspace_id != $3
            """,
            UUID(project_id),
            bead_id,
            UUID(workspace_id),
        )
        if existing:
            return {
                "workspace_id": str(existing["workspace_id"]),
                "alias": existing["alias"],
                "human_name": existing["human_name"],
            }

        await tx.execute(
            """
            INSERT INTO {{tables.bead_claims}} (
                project_id, workspace_id, alias, human_name, bead_id,
                apex_bead_id, apex_repo_name, apex_branch, claimed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (project_id, bead_id, workspace_id)
            DO UPDATE SET
                alias = EXCLUDED.alias,
                human_name = EXCLUDED.human_name,
                apex_bead_id = EXCLUDED.apex_bead_id,
                apex_repo_name = EXCLUDED.apex_repo_name,
                apex_branch = EXCLUDED.apex_branch,
                claimed_at = EXCLUDED.claimed_at
            """,
            UUID(project_id),
            UUID(workspace_id),
            alias,
            human_name,
            bead_id,
            apex_bead_id,
            apex_repo_name,
            apex_branch,
            _now(),
        )

    # Update workspace focus_apex fields for team status display
    if apex_bead_id:
        await server_db.execute(
            """
            UPDATE {{tables.workspaces}}
            SET focus_apex_bead_id = $1,
                focus_apex_repo_name = $2,
                focus_apex_branch = $3,
                focus_updated_at = NOW(),
                updated_at = NOW()
            WHERE project_id = $4 AND workspace_id = $5
            """,
            apex_bead_id,
            apex_repo_name,
            apex_branch,
            UUID(project_id),
            UUID(workspace_id),
        )

    return None


async def _delete_claim(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    workspace_id: str,
    bead_id: str,
) -> None:
    """Remove a single workspace's claim on a bead and update its focus."""
    await _release_bead_claims(
        db_infra, project_id=project_id, bead_id=bead_id, workspace_id=workspace_id
    )


async def _release_bead_claims(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    bead_id: str,
    workspace_id: str | None = None,
) -> None:
    """Release claims on a bead and update affected workspaces' focus.

    If workspace_id is provided, only that workspace's claim is removed.
    If workspace_id is None, ALL claims on the bead are removed (used when
    a bead is closed/deleted, since any workspace's claim becomes stale).
    """
    server_db = db_infra.get_manager("server")
    async with server_db.transaction() as tx:
        # Find affected workspaces before deleting.
        if workspace_id:
            affected_ws_ids = [UUID(workspace_id)]
            await tx.execute(
                """
                DELETE FROM {{tables.bead_claims}}
                WHERE project_id = $1 AND workspace_id = $2 AND bead_id = $3
                """,
                UUID(project_id),
                UUID(workspace_id),
                bead_id,
            )
        else:
            rows = await tx.fetch_all(
                """
                DELETE FROM {{tables.bead_claims}}
                WHERE project_id = $1 AND bead_id = $2
                RETURNING workspace_id
                """,
                UUID(project_id),
                bead_id,
            )
            affected_ws_ids = [row["workspace_id"] for row in rows]

        # Update each affected workspace's focus to its next active claim.
        for ws_id in affected_ws_ids:
            next_claim = await tx.fetch_one(
                """
                SELECT apex_bead_id, apex_repo_name, apex_branch
                FROM {{tables.bead_claims}}
                WHERE project_id = $1 AND workspace_id = $2
                ORDER BY claimed_at DESC
                LIMIT 1
                """,
                UUID(project_id),
                ws_id,
            )
            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET focus_apex_bead_id = $1,
                    focus_apex_repo_name = $2,
                    focus_apex_branch = $3,
                    focus_updated_at = NOW(),
                    updated_at = NOW()
                WHERE project_id = $4 AND workspace_id = $5
                """,
                next_claim["apex_bead_id"] if next_claim else None,
                next_claim["apex_repo_name"] if next_claim else None,
                next_claim["apex_branch"] if next_claim else None,
                UUID(project_id),
                ws_id,
            )


async def _get_bead_title(
    beads_db: AsyncDatabaseManager, project_id: str, bead_id: str
) -> str | None:
    """Look up the title of a bead from the issues table."""
    row = await beads_db.fetch_one(
        "SELECT title FROM {{tables.beads_issues}} "
        "WHERE project_id = $1 AND bead_id = $2 ORDER BY synced_at DESC LIMIT 1",
        UUID(project_id),
        bead_id,
    )
    return row["title"] if row else None


async def _get_bead_titles(
    beads_db: AsyncDatabaseManager, project_id: str, bead_ids: list[str]
) -> dict[str, str | None]:
    """Batch look up titles for multiple beads. Returns {bead_id: title}."""
    if not bead_ids:
        return {}
    rows = await beads_db.fetch_all(
        "SELECT DISTINCT ON (bead_id) bead_id, title FROM {{tables.beads_issues}} "
        "WHERE project_id = $1 AND bead_id = ANY($2) ORDER BY bead_id, synced_at DESC",
        UUID(project_id),
        bead_ids,
    )
    return {row["bead_id"]: row["title"] for row in rows}


async def ensure_repo(
    db: DatabaseInfra,
    project_id: UUID,
    origin_url: str,
) -> UUID:
    """Ensure a repo exists for the given project and origin.

    Returns the repo_id (existing or newly created).
    """
    canonical_origin = canonicalize_git_url(origin_url)
    repo_name = extract_repo_name(canonical_origin)

    server_db = db.get_manager("server")
    # Also clear deleted_at to undelete soft-deleted repos when re-registered
    result = await server_db.fetch_one(
        """
        INSERT INTO {{tables.repos}} (project_id, origin_url, canonical_origin, name)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (project_id, canonical_origin)
        DO UPDATE SET origin_url = EXCLUDED.origin_url, deleted_at = NULL
        RETURNING id
        """,
        project_id,
        origin_url,
        canonical_origin,
        repo_name,
    )
    return result["id"]


async def upsert_workspace(
    db: DatabaseInfra,
    workspace_id: str,
    project_id: UUID,
    repo_id: UUID,
    alias: str,
    human_name: str,
    role: Optional[str] = None,
    hostname: Optional[str] = None,
    workspace_path: Optional[str] = None,
) -> None:
    """Upsert workspace into persistent workspaces table.

    Creates or updates the workspace record. The workspace_id is the constant
    identifier. project_id, repo_id, alias, hostname, and workspace_path are
    immutable after creation (hostname/workspace_path can be set once if NULL).
    Only human_name, role, current_branch, deleted_at, and last_seen_at can be updated.

    last_seen_at is updated on every bdh command to track workspace activity.
    """
    server_db = db.get_manager("server")
    await server_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (workspace_id, project_id, repo_id, alias, human_name, role, hostname, workspace_path, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (workspace_id) DO UPDATE SET
            human_name = EXCLUDED.human_name,
            role = COALESCE(EXCLUDED.role, {{tables.workspaces}}.role),
            hostname = COALESCE({{tables.workspaces}}.hostname, EXCLUDED.hostname),
            workspace_path = COALESCE({{tables.workspaces}}.workspace_path, EXCLUDED.workspace_path),
            last_seen_at = NOW(),
            updated_at = NOW()
        """,
        workspace_id,
        project_id,
        repo_id,
        alias,
        human_name,
        role,
        hostname,
        workspace_path,
    )


async def check_alias_collision(
    db: DatabaseInfra,
    redis: Redis,
    project_id: UUID,
    workspace_id: str,
    alias: str,
) -> Optional[str]:
    """Check if alias is already used by another workspace within the same project.

    Aliases are unique per project (not globally). Projects are tenant boundaries
    with no cross-project communication, so per-project uniqueness is sufficient.

    Returns:
        The workspace_id using this alias if collision, None if available.
    """
    server_db = db.get_manager("server")

    # Check workspaces table first (authoritative source)
    row = await server_db.fetch_one(
        """
        SELECT workspace_id
        FROM {{tables.workspaces}}
        WHERE project_id = $1 AND alias = $2 AND workspace_id != $3 AND deleted_at IS NULL
        LIMIT 1
        """,
        project_id,
        alias,
        UUID(workspace_id),
    )
    if row:
        return str(row["workspace_id"])

    # Also check bead_claims for another workspace with same alias
    # (handles race conditions before workspace is persisted)
    row = await server_db.fetch_one(
        """
        SELECT DISTINCT workspace_id
        FROM {{tables.bead_claims}}
        WHERE project_id = $1 AND alias = $2 AND workspace_id != $3
        LIMIT 1
        """,
        project_id,
        alias,
        UUID(workspace_id),
    )
    if row:
        return str(row["workspace_id"])

    # Check Redis presence for another workspace with same alias
    # Uses O(1) secondary index instead of SCAN
    colliding_workspace = await get_workspace_id_by_alias(redis, str(project_id), alias)
    if colliding_workspace and colliding_workspace != workspace_id:
        return colliding_workspace

    return None


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(..., min_length=1)
    repo_id: str | None = None
    alias: str = Field(..., min_length=1, max_length=64)
    human_name: str = Field(..., min_length=0, max_length=64)
    repo_origin: str = Field(..., min_length=1, max_length=2048)
    role: str | None = Field(default=None, max_length=50)
    command_line: str = Field(..., min_length=1, max_length=8192)

    @field_validator("workspace_id")
    @classmethod
    def _validate_workspace_id(cls, v: str) -> str:
        return validate_workspace_id(v)

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, v: str) -> str:
        if not is_valid_alias(v):
            raise ValueError("Invalid alias format")
        return v

    @field_validator("human_name")
    @classmethod
    def _validate_human_name(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not is_valid_human_name(v):
            raise ValueError("Invalid human_name format")
        return v


class CommandContext(BaseModel):
    messages_waiting: int = 0
    beads_in_progress: list[dict[str, Any]] = Field(default_factory=list)


class CommandResponse(BaseModel):
    approved: bool
    reason: str = ""
    context: CommandContext | None = None


@router.post("/command", response_model=CommandResponse)
async def command(
    request: Request,
    payload: CommandRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> CommandResponse:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id

    enforce_actor_binding(identity, payload.workspace_id)

    # Ensure workspace exists, belongs to project, and is not deleted (410).
    await _ensure_workspace_alive_or_410(
        db_infra, project_id=project_id, workspace_id=payload.workspace_id
    )

    await _touch_workspace_last_seen(
        db_infra,
        project_id=project_id,
        workspace_id=payload.workspace_id,
        human_name=payload.human_name or "",
        role=payload.role,
    )

    beads_in_progress = await _list_beads_in_progress(db_infra, project_id=project_id)

    # Check if this is a claim command and the bead is already claimed by another workspace.
    cmd, bead_id, status = _parse_command_line(payload.command_line or "")
    if cmd == "update" and status == "in_progress" and bead_id:
        for claim in beads_in_progress:
            if claim["bead_id"] == bead_id and claim["workspace_id"] != payload.workspace_id:
                return CommandResponse(
                    approved=False,
                    reason=f"{bead_id} is being worked on by {claim['alias']} ({claim['human_name']})",
                    context=CommandContext(messages_waiting=0, beads_in_progress=beads_in_progress),
                )

    return CommandResponse(
        approved=True,
        context=CommandContext(messages_waiting=0, beads_in_progress=beads_in_progress),
    )


class SyncStats(BaseModel):
    received: int = 0
    inserted: int = 0
    updated: int = 0
    deleted: int = 0


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(..., min_length=1)
    repo_id: str | None = None
    alias: str = Field(..., min_length=1, max_length=64)
    human_name: str = Field(..., min_length=0, max_length=64)
    repo_origin: str = Field(..., min_length=1, max_length=2048)
    role: str | None = Field(default=None, max_length=50)

    # Full sync mode
    issues_jsonl: str | None = Field(default=None, max_length=MAX_JSONL_SIZE)

    # Incremental sync mode
    sync_mode: str | None = Field(default=None, max_length=32)
    changed_issues: str | None = Field(default=None, max_length=MAX_JSONL_SIZE)
    deleted_ids: list[str] = Field(default_factory=list)
    sync_protocol_version: int | None = None

    # Command context for claim attribution (best-effort)
    command_line: str | None = Field(default=None, max_length=8192)

    @field_validator("workspace_id")
    @classmethod
    def _validate_workspace_id(cls, v: str) -> str:
        return validate_workspace_id(v)

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, v: str) -> str:
        if not is_valid_alias(v):
            raise ValueError("Invalid alias format")
        return v

    @field_validator("human_name")
    @classmethod
    def _validate_human_name(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not is_valid_human_name(v):
            raise ValueError("Invalid human_name format")
        return v


class SyncResponse(BaseModel):
    synced: bool = True
    issues_count: int = 0
    context: CommandContext | None = None
    stats: SyncStats | None = None
    sync_protocol_version: int = 1
    claim_rejected: bool = False
    claim_rejected_reason: str = ""


@router.post("/sync", response_model=SyncResponse)
async def sync(
    request: Request,
    payload: SyncRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> SyncResponse:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id

    enforce_actor_binding(identity, payload.workspace_id)

    await _ensure_workspace_alive_or_410(
        db_infra, project_id=project_id, workspace_id=payload.workspace_id
    )

    # Touch workspace activity for "gone workspace" and status displays.
    await _touch_workspace_last_seen(
        db_infra,
        project_id=project_id,
        workspace_id=payload.workspace_id,
        human_name=payload.human_name or "",
        role=payload.role,
    )

    canonical_origin = canonicalize_git_url(payload.repo_origin)
    if not is_valid_canonical_origin(canonical_origin):
        raise HTTPException(status_code=422, detail="Invalid repo_origin")

    beads_db = db_infra.get_manager("beads")

    mode = (payload.sync_mode or "full").strip().lower()
    if mode not in ("full", "incremental"):
        raise HTTPException(status_code=422, detail="sync_mode must be 'full' or 'incremental'")

    received = 0
    inserted = 0
    updated = 0
    deleted = 0
    deleted_titles: dict[str, str | None] = {}

    result: Optional[BeadsSyncResult] = None
    if mode == "full":
        body = (payload.issues_jsonl or "").strip()
        if not body:
            raise HTTPException(status_code=422, detail="issues_jsonl is required for full sync")
        try:
            issues_raw = parse_jsonl(body, max_depth=MAX_JSON_DEPTH, max_count=MAX_ISSUES_COUNT)
        except JSONLParseError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        issues = validate_issues_from_list(issues_raw)
        received = len(issues)
        result = await _sync_issues_to_db(
            issues,
            beads_db,
            project_id=project_id,
            repo=canonical_origin,
            branch=DEFAULT_BRANCH,
        )
        inserted = result.issues_added
        updated = result.issues_updated
    else:
        if (
            payload.changed_issues is None or payload.changed_issues.strip() == ""
        ) and not payload.deleted_ids:
            raise HTTPException(
                status_code=422, detail="incremental sync requires changes or deletions"
            )

        if payload.changed_issues is not None and payload.changed_issues.strip():
            try:
                issues_raw = parse_jsonl(
                    payload.changed_issues, max_depth=MAX_JSON_DEPTH, max_count=MAX_ISSUES_COUNT
                )
            except JSONLParseError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e
            issues = validate_issues_from_list(issues_raw)
            received = len(issues)
            result = await _sync_issues_to_db(
                issues,
                beads_db,
                project_id=project_id,
                repo=canonical_origin,
                branch=DEFAULT_BRANCH,
            )
            inserted = result.issues_added
            updated = result.issues_updated

        if payload.deleted_ids:
            # Pre-fetch titles before deletion so events can include them.
            deleted_titles = await _get_bead_titles(beads_db, project_id, payload.deleted_ids)
            deleted = await delete_issues_by_id(
                beads_db,
                project_id=project_id,
                bead_ids=payload.deleted_ids,
                repo=canonical_origin,
                branch=DEFAULT_BRANCH,
            )

    # Update claims based on the bd command that succeeded (best-effort).
    claim_conflict: Optional[dict[str, Any]] = None
    cmd, bead_id, status = _parse_command_line(payload.command_line or "")

    # Lazy project_slug for event enrichment (only queried if needed).
    _slug_cache: list[str | None] = []  # empty = not yet fetched

    async def _get_project_slug() -> str | None:
        if not _slug_cache:
            server_db = db_infra.get_manager("server")
            row = await server_db.fetch_one(
                "SELECT slug FROM {{tables.projects}} WHERE id = $1",
                UUID(project_id),
            )
            _slug_cache.append(row["slug"] if row else None)
        return _slug_cache[0]

    if bead_id:
        if cmd == "update" and status == "in_progress":
            claim_conflict = await _upsert_claim(
                db_infra,
                project_id=project_id,
                workspace_id=payload.workspace_id,
                alias=payload.alias,
                human_name=payload.human_name or "",
                bead_id=bead_id,
            )
            if claim_conflict is None:
                title = await _get_bead_title(beads_db, project_id, bead_id)
                await publish_event(
                    redis,
                    BeadClaimedEvent(
                        workspace_id=payload.workspace_id,
                        project_slug=await _get_project_slug(),
                        bead_id=bead_id,
                        alias=payload.alias,
                        title=title,
                    ),
                )
        elif cmd in ("close", "delete") or (cmd == "update" and status and status != "in_progress"):
            # Release ALL claims on this bead — not just the syncing
            # workspace's.  A closed/deleted bead should have no claims.
            await _release_bead_claims(
                db_infra,
                project_id=project_id,
                bead_id=bead_id,
            )
            title = await _get_bead_title(beads_db, project_id, bead_id)
            await publish_event(
                redis,
                BeadUnclaimedEvent(
                    workspace_id=payload.workspace_id,
                    project_slug=await _get_project_slug(),
                    bead_id=bead_id,
                    alias=payload.alias,
                    title=title,
                ),
            )

    if payload.deleted_ids:
        # Deleted beads should have no claims from any workspace.
        for bid in payload.deleted_ids:
            await _release_bead_claims(
                db_infra,
                project_id=project_id,
                bead_id=bid,
            )
            await publish_event(
                redis,
                BeadUnclaimedEvent(
                    workspace_id=payload.workspace_id,
                    project_slug=await _get_project_slug(),
                    bead_id=bid,
                    alias=payload.alias,
                    title=deleted_titles.get(bid),
                ),
            )

    # Record notification intents in outbox, then process them.
    notifications_sent = 0
    notifications_failed = 0
    if result is not None and result.status_changes:
        await record_notification_intents(result.status_changes, project_id, db_infra)
        sender = await resolve_aweb_identity(request, db_infra)
        notifications_sent, notifications_failed = await process_notification_outbox(
            project_id,
            db_infra,
            sender_agent_id=sender.agent_id,
            sender_alias=sender.alias,
        )
        await publish_bead_status_events(
            redis,
            workspace_id=payload.workspace_id,
            project_slug=sender.project_slug,
            status_changes=result.status_changes,
            alias=payload.alias,
        )

    # Update audit log (best-effort; don't fail the sync on logging issues).
    try:
        server_db = db_infra.get_manager("server")
        await server_db.execute(
            """
            INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
            VALUES ($1, $2, $3::jsonb)
            """,
            UUID(project_id),
            "bdh_sync",
            json.dumps(
                {
                    "project_id": project_id,
                    "repo": canonical_origin,
                    "mode": mode,
                    "received": received,
                    "inserted": inserted,
                    "updated": updated,
                    "deleted": deleted,
                    "notifications_sent": notifications_sent,
                    "notifications_failed": notifications_failed,
                }
            ),
        )
    except Exception:
        logger.exception("Failed to write audit log for bdh sync")

    # Count total issues for this (project, repo, branch) after sync.
    count_row = await beads_db.fetch_one(
        """
        SELECT COUNT(*) AS c
        FROM {{tables.beads_issues}}
        WHERE project_id = $1 AND repo = $2 AND branch = $3
        """,
        UUID(project_id),
        canonical_origin,
        DEFAULT_BRANCH,
    )
    issues_count = int(count_row["c"]) if count_row else 0

    resp = SyncResponse(
        synced=True,
        issues_count=issues_count,
        stats=SyncStats(received=received, inserted=inserted, updated=updated, deleted=deleted),
        sync_protocol_version=1,
    )
    if claim_conflict:
        resp.claim_rejected = True
        resp.claim_rejected_reason = (
            f"{bead_id} is being worked on by"
            f" {claim_conflict['alias']} ({claim_conflict['human_name']})"
        )
    return resp
