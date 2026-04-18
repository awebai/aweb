"""Canonical coordination lifecycle cascade helpers.

This module intentionally owns only OSS coordination cleanup:
workspace lifecycle state, task claim release, task/team unclaim events, and
presence cleanup. Identity lifecycle meaning, registry/address operations,
custody material, API keys, and audit records belong to callers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from redis.asyncio import Redis

from .events import (
    TaskUnclaimedEvent,
    TeamTaskUnclaimedEvent,
    publish_event,
    publish_team_event,
)
from .presence import clear_workspace_presence

logger = logging.getLogger(__name__)

LifecycleOperation = Literal[
    "delete_ephemeral_workspace",
    "cleanup_agent_coordination_state",
    "agent_deleted_cascade",
]
WorkspaceScope = Literal["explicit", "latest_for_agent", "all_for_agent"]
ActorType = Literal["agent", "human", "support", "system"]
PresenceCleanupStatus = Literal[
    "not_run",
    "planned",
    "cleared",
    "skipped_no_redis",
    "failed",
]
PostCommitStatus = Literal["not_run", "completed", "failed", "skipped_no_redis"]


@dataclass(frozen=True)
class LifecycleActor:
    actor_id: str | None
    actor_type: ActorType
    authority: str


@dataclass(frozen=True)
class LifecycleCascadeRequest:
    operation: LifecycleOperation
    actor: LifecycleActor
    team_id: str | None = None
    target_agent_id: str | None = None
    target_workspace_ids: tuple[str, ...] = ()
    workspace_scope: WorkspaceScope = "explicit"
    reason: str | None = None
    ticket_id: str | None = None
    dry_run: bool = False
    require_lifetime: Literal["ephemeral", "persistent"] | None = None
    stale_before: datetime | None = None
    deleted_at: datetime | None = None
    mark_ephemeral_agent_deleted: bool = False


@dataclass(frozen=True)
class LifecycleError:
    code: str
    message: str
    target: str | None = None


@dataclass(frozen=True)
class WorkspaceLifecycleChange:
    workspace_id: str
    team_id: str
    alias: str
    agent_id: str | None
    action: str
    status: str
    lifetime: str | None = None


@dataclass(frozen=True)
class LifecycleEventIntent:
    event_kind: Literal["workspace_task_unclaimed", "team_task_unclaimed"]
    workspace_id: str
    team_id: str
    task_ref: str
    alias: str


@dataclass(frozen=True)
class LifecycleCascadeResult:
    operation: str
    dry_run: bool
    target_agent_id: str | None
    workspace_changes: tuple[WorkspaceLifecycleChange, ...] = ()
    planned_mutations: tuple[str, ...] = ()
    completed_mutations: tuple[str, ...] = ()
    task_unclaim_count: int = 0
    workspace_event_count: int = 0
    team_event_count: int = 0
    event_intents: tuple[LifecycleEventIntent, ...] = ()
    failed_event_intents: tuple[LifecycleEventIntent, ...] = ()
    presence_cleanup_status: PresenceCleanupStatus = "not_run"
    presence_cleared_count: int | None = None
    post_commit_status: PostCommitStatus = "not_run"
    identity_deleted: bool = False
    errors: tuple[LifecycleError, ...] = ()


_VALID_OPERATIONS = {
    "delete_ephemeral_workspace",
    "cleanup_agent_coordination_state",
    "agent_deleted_cascade",
}
_VALID_SCOPES = {"explicit", "latest_for_agent", "all_for_agent"}


def _planned_mutations(request: LifecycleCascadeRequest) -> tuple[str, ...]:
    mutations = [
        "workspace.soft_delete",
        "task_claims.release",
        "task_unclaim_events.publish",
        "presence.clear",
    ]
    if request.mark_ephemeral_agent_deleted:
        mutations.append("agent.mark_ephemeral_deleted")
    return tuple(mutations)


def _error_result(
    request: LifecycleCascadeRequest,
    errors: list[LifecycleError],
    *,
    workspace_changes: tuple[WorkspaceLifecycleChange, ...] = (),
    task_unclaim_count: int = 0,
    presence_cleanup_status: PresenceCleanupStatus = "not_run",
) -> LifecycleCascadeResult:
    return LifecycleCascadeResult(
        operation=request.operation,
        dry_run=request.dry_run,
        target_agent_id=request.target_agent_id,
        workspace_changes=workspace_changes,
        planned_mutations=_planned_mutations(request),
        task_unclaim_count=task_unclaim_count,
        presence_cleanup_status=presence_cleanup_status,
        errors=tuple(errors),
    )


def _validate_request(request: LifecycleCascadeRequest) -> list[LifecycleError]:
    errors: list[LifecycleError] = []
    if request.operation not in _VALID_OPERATIONS:
        errors.append(
            LifecycleError(
                code="unknown_lifecycle_operation",
                message=f"Unknown lifecycle operation: {request.operation}",
            )
        )
    if request.workspace_scope not in _VALID_SCOPES:
        errors.append(
            LifecycleError(
                code="unknown_workspace_scope",
                message=f"Unknown workspace scope: {request.workspace_scope}",
            )
        )
    if request.workspace_scope == "explicit" and not request.target_workspace_ids:
        errors.append(
            LifecycleError(
                code="missing_workspace_scope_target",
                message="Explicit workspace scope requires target_workspace_ids.",
            )
        )
    if (
        request.workspace_scope in {"latest_for_agent", "all_for_agent"}
        and not request.target_agent_id
    ):
        errors.append(
            LifecycleError(
                code="missing_agent_scope_target",
                message="Agent workspace scope requires target_agent_id.",
            )
        )
    return errors


def _workspace_id_values(workspace_ids: tuple[str, ...]) -> list[UUID]:
    return [UUID(str(workspace_id)) for workspace_id in workspace_ids]


async def _load_target_workspaces(db, request: LifecycleCascadeRequest) -> list[dict]:
    select_sql = """
        SELECT
            w.workspace_id,
            w.team_id,
            w.agent_id,
            w.alias,
            w.deleted_at,
            w.last_seen_at,
            a.lifetime AS agent_lifetime
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.agents}} a
          ON a.agent_id = w.agent_id
         AND a.team_id = w.team_id
         AND a.deleted_at IS NULL
    """
    if request.workspace_scope == "explicit":
        if request.team_id is None:
            rows = await db.fetch_all(
                select_sql
                + """
        WHERE w.workspace_id = ANY($1::uuid[])
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
                """,
                _workspace_id_values(request.target_workspace_ids),
            )
        else:
            rows = await db.fetch_all(
                select_sql
                + """
        WHERE w.workspace_id = ANY($1::uuid[])
          AND w.team_id = $2
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
                """,
                _workspace_id_values(request.target_workspace_ids),
                request.team_id,
            )
        return [dict(row) for row in rows]

    if request.workspace_scope == "latest_for_agent":
        if request.team_id is None:
            row = await db.fetch_one(
                select_sql
                + """
        WHERE w.agent_id = $1
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
        LIMIT 1
                """,
                UUID(str(request.target_agent_id)),
            )
        else:
            row = await db.fetch_one(
                select_sql
                + """
        WHERE w.agent_id = $1
          AND w.team_id = $2
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
        LIMIT 1
                """,
                UUID(str(request.target_agent_id)),
                request.team_id,
            )
        return [dict(row)] if row is not None else []

    if request.team_id is None:
        rows = await db.fetch_all(
            select_sql
            + """
        WHERE w.agent_id = $1
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
            """,
            UUID(str(request.target_agent_id)),
        )
    else:
        rows = await db.fetch_all(
            select_sql
            + """
        WHERE w.agent_id = $1
          AND w.team_id = $2
          AND w.deleted_at IS NULL
        ORDER BY w.updated_at DESC, w.workspace_id DESC
            """,
            UUID(str(request.target_agent_id)),
            request.team_id,
        )
    return [dict(row) for row in rows]


def _precondition_errors(
    request: LifecycleCascadeRequest, workspaces: list[dict]
) -> list[LifecycleError]:
    errors: list[LifecycleError] = []
    for workspace in workspaces:
        workspace_id = str(workspace["workspace_id"])
        lifetime = str(workspace.get("agent_lifetime") or "").strip()
        if request.require_lifetime and not lifetime:
            errors.append(
                LifecycleError(
                    code="unknown_lifetime_no_cleanup",
                    message="Workspace is missing an active bound identity lifetime.",
                    target=workspace_id,
                )
            )
            continue
        if request.require_lifetime and lifetime != request.require_lifetime:
            code = (
                "persistent_identity_not_cleanup_eligible"
                if lifetime == "persistent"
                else "lifecycle_lifetime_precondition_failed"
            )
            errors.append(
                LifecycleError(
                    code=code,
                    message=(
                        f"Workspace identity lifetime {lifetime!r} does not match "
                        f"required lifetime {request.require_lifetime!r}."
                    ),
                    target=workspace_id,
                )
            )
        last_seen_at = workspace.get("last_seen_at")
        if (
            request.stale_before is not None
            and last_seen_at is not None
            and last_seen_at > request.stale_before
        ):
            errors.append(
                LifecycleError(
                    code="ephemeral_workspace_still_active",
                    message="Workspace presence is not stale enough for lifecycle cleanup.",
                    target=workspace_id,
                )
            )
    return errors


async def _plan_claim_count(db, workspace_ids: list[str]) -> int:
    if not workspace_ids:
        return 0
    count = await db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.task_claims}}
        WHERE workspace_id = ANY($1::uuid[])
        """,
        _workspace_id_values(tuple(workspace_ids)),
    )
    return int(count or 0)


def _workspace_changes(
    workspaces: list[dict], *, status: str
) -> tuple[WorkspaceLifecycleChange, ...]:
    return tuple(
        WorkspaceLifecycleChange(
            workspace_id=str(workspace["workspace_id"]),
            team_id=str(workspace["team_id"]),
            alias=str(workspace.get("alias") or ""),
            agent_id=(
                str(workspace["agent_id"])
                if workspace.get("agent_id") is not None
                else None
            ),
            action="soft_delete",
            status=status,
            lifetime=str(workspace.get("agent_lifetime") or "") or None,
        )
        for workspace in workspaces
    )


async def plan_lifecycle_cascade(
    db, request: LifecycleCascadeRequest
) -> LifecycleCascadeResult:
    """Return planned coordination lifecycle effects without mutating state."""
    errors = _validate_request(request)
    if errors:
        return _error_result(request, errors)

    workspaces = await _load_target_workspaces(db, request)
    precondition_errors = _precondition_errors(request, workspaces)
    workspace_changes = _workspace_changes(workspaces, status="planned")
    workspace_ids = [str(workspace["workspace_id"]) for workspace in workspaces]
    claim_count = await _plan_claim_count(db, workspace_ids)

    if precondition_errors:
        return _error_result(
            request,
            precondition_errors,
            workspace_changes=workspace_changes,
            task_unclaim_count=claim_count,
            presence_cleanup_status="planned",
        )

    return LifecycleCascadeResult(
        operation=request.operation,
        dry_run=True,
        target_agent_id=request.target_agent_id,
        workspace_changes=workspace_changes,
        planned_mutations=_planned_mutations(request),
        task_unclaim_count=claim_count,
        presence_cleanup_status="planned" if workspace_ids else "not_run",
    )


async def _publish_event_intents(
    redis: Redis | None, event_intents: tuple[LifecycleEventIntent, ...]
) -> tuple[int, int, tuple[LifecycleEventIntent, ...], PostCommitStatus]:
    if not event_intents:
        return 0, 0, (), "completed"
    if redis is None:
        return 0, 0, event_intents, "skipped_no_redis"

    workspace_event_count = 0
    team_event_count = 0
    failed: list[LifecycleEventIntent] = []
    for intent in event_intents:
        try:
            if intent.event_kind == "workspace_task_unclaimed":
                await publish_event(
                    redis,
                    TaskUnclaimedEvent(
                        workspace_id=intent.workspace_id,
                        task_ref=intent.task_ref,
                        alias=intent.alias,
                    ),
                )
                workspace_event_count += 1
            else:
                await publish_team_event(
                    redis,
                    TeamTaskUnclaimedEvent(
                        team_id=intent.team_id,
                        task_ref=intent.task_ref,
                        alias=intent.alias,
                        title="",
                    ),
                )
                team_event_count += 1
        except Exception:
            logger.warning(
                "Failed to publish lifecycle event intent",
                extra={
                    "event_kind": intent.event_kind,
                    "workspace_id": intent.workspace_id,
                    "team_id": intent.team_id,
                    "task_ref": intent.task_ref,
                },
                exc_info=True,
            )
            failed.append(intent)
    return (
        workspace_event_count,
        team_event_count,
        tuple(failed),
        "failed" if failed else "completed",
    )


async def _clear_presence(
    redis: Redis | None, workspace_ids: list[str]
) -> tuple[PresenceCleanupStatus, int | None]:
    if not workspace_ids:
        return "not_run", 0
    if redis is None:
        return "skipped_no_redis", None
    try:
        return "cleared", await clear_workspace_presence(redis, workspace_ids)
    except Exception:
        logger.warning(
            "Failed to clear lifecycle workspace presence",
            extra={"workspace_ids": workspace_ids},
            exc_info=True,
        )
        return "failed", None


async def apply_lifecycle_cascade(
    db, redis: Redis | None, request: LifecycleCascadeRequest
) -> LifecycleCascadeResult:
    """Apply the coordination lifecycle cascade and report post-commit status.

    Event intents are captured from SQL ``DELETE ... RETURNING`` before commit
    and published after commit. If the process dies after commit and before
    publish, those task refs are not durably recoverable without a future
    outbox; callers receive failed intents only for immediate retry/reporting.
    """
    if request.dry_run:
        return await plan_lifecycle_cascade(db, request)

    errors = _validate_request(request)
    if errors:
        return _error_result(request, errors)

    deleted_at = request.deleted_at or datetime.now(timezone.utc)
    event_intents: list[LifecycleEventIntent] = []
    identity_deleted = False

    async with db.transaction() as tx:
        workspaces = await _load_target_workspaces(tx, request)
        precondition_errors = _precondition_errors(request, workspaces)
        workspace_changes = _workspace_changes(workspaces, status="planned")
        if precondition_errors:
            return _error_result(
                request,
                precondition_errors,
                workspace_changes=workspace_changes,
                task_unclaim_count=await _plan_claim_count(
                    tx, [str(workspace["workspace_id"]) for workspace in workspaces]
                ),
                presence_cleanup_status="planned",
            )

        for workspace in workspaces:
            workspace_id = str(workspace["workspace_id"])
            team_id = str(workspace["team_id"])
            alias = str(workspace.get("alias") or "")
            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET deleted_at = $2
                WHERE workspace_id = $1
                  AND deleted_at IS NULL
                """,
                UUID(workspace_id),
                deleted_at,
            )
            claimed_rows = await tx.fetch_all(
                """
                DELETE FROM {{tables.task_claims}}
                WHERE workspace_id = $1
                RETURNING task_ref
                """,
                UUID(workspace_id),
            )
            for row in claimed_rows:
                task_ref = str(row["task_ref"])
                event_intents.append(
                    LifecycleEventIntent(
                        event_kind="workspace_task_unclaimed",
                        workspace_id=workspace_id,
                        team_id=team_id,
                        task_ref=task_ref,
                        alias=alias,
                    )
                )
                event_intents.append(
                    LifecycleEventIntent(
                        event_kind="team_task_unclaimed",
                        workspace_id=workspace_id,
                        team_id=team_id,
                        task_ref=task_ref,
                        alias=alias,
                    )
                )
            if (
                request.mark_ephemeral_agent_deleted
                and workspace.get("agent_id") is not None
            ):
                deleted_agent = await tx.fetch_one(
                    """
                    UPDATE {{tables.agents}}
                    SET deleted_at = $2,
                        status = 'deleted'
                    WHERE agent_id = $1
                      AND team_id = $3
                      AND deleted_at IS NULL
                      AND lifetime = 'ephemeral'
                    RETURNING agent_id
                    """,
                    workspace["agent_id"],
                    deleted_at,
                    team_id,
                )
                identity_deleted = identity_deleted or deleted_agent is not None

    workspace_changes = _workspace_changes(workspaces, status="completed")
    workspace_ids = [change.workspace_id for change in workspace_changes]
    workspace_event_count, team_event_count, failed_event_intents, event_status = (
        await _publish_event_intents(redis, tuple(event_intents))
    )
    presence_status, presence_cleared_count = await _clear_presence(redis, workspace_ids)

    post_commit_status: PostCommitStatus
    if event_status == "failed" or presence_status == "failed":
        post_commit_status = "failed"
    elif event_status == "skipped_no_redis" or presence_status == "skipped_no_redis":
        post_commit_status = "skipped_no_redis"
    else:
        post_commit_status = "completed"

    completed_mutations = ["workspace.soft_delete", "task_claims.release"]
    if identity_deleted:
        completed_mutations.append("agent.mark_ephemeral_deleted")
    if event_status == "completed":
        completed_mutations.append("task_unclaim_events.publish")
    if presence_status == "cleared":
        completed_mutations.append("presence.clear")

    return LifecycleCascadeResult(
        operation=request.operation,
        dry_run=False,
        target_agent_id=request.target_agent_id,
        workspace_changes=workspace_changes,
        planned_mutations=_planned_mutations(request),
        completed_mutations=tuple(completed_mutations),
        task_unclaim_count=len(event_intents) // 2,
        workspace_event_count=workspace_event_count,
        team_event_count=team_event_count,
        event_intents=tuple(event_intents),
        failed_event_intents=failed_event_intents,
        presence_cleanup_status=presence_status,
        presence_cleared_count=presence_cleared_count,
        post_commit_status=post_commit_status,
        identity_deleted=identity_deleted,
    )
