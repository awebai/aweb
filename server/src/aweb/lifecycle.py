"""Canonical coordination lifecycle cascade helpers.

This module intentionally owns only OSS coordination lifecycle cleanup:
workspace lifecycle state, agent lifecycle row state when explicitly requested,
task claim and reservation release, chat participant cleanup, task/team unclaim
events, and presence cleanup. Registry/address operations, custody material
outside the aweb.agents row, API keys, and audit records belong to callers.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pgdbm import TransactionManager
from redis.asyncio import Redis

from .events import (
    TaskUnclaimedEvent,
    TeamTaskUnclaimedEvent,
    publish_event,
    publish_team_event,
)
from .identity_scope import normalize_identity_scope
from .messaging.waiting import unregister_waiting
from .presence import clear_workspace_presence

logger = logging.getLogger(__name__)

LifecycleOperation = Literal[
    "delete_local_workspace",
    "cleanup_agent_coordination_state",
    "agent_deleted_cascade",
    "archive_global_agent",
]
WorkspaceScope = Literal["explicit", "latest_for_agent", "all_for_agent"]
ActorType = Literal["agent", "human", "support", "system"]
PresenceCleanupStatus = Literal[
    "not_run",
    "planned",
    "pending",
    "cleared",
    "skipped_no_redis",
    "failed",
]
PostCommitStatus = Literal[
    "not_run",
    "pending",
    "completed",
    "failed",
    "skipped_no_redis",
]


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
    require_identity_scope: Literal["local", "global"] | None = None
    require_lifetime: Literal["ephemeral", "persistent"] | None = None
    stale_before: datetime | None = None
    deleted_at: datetime | None = None
    mark_local_agent_deleted: bool = False


@dataclass(frozen=True)
class LifecycleError:
    """Lifecycle error.

    ``code`` is the stable contract field. ``message`` is diagnostic text for
    humans and may change.
    """

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
    identity_scope: str | None = None


@dataclass(frozen=True)
class LifecycleEventIntent:
    event_kind: Literal["workspace_task_unclaimed", "team_task_unclaimed"]
    workspace_id: str
    team_id: str
    task_ref: str
    alias: str
    timestamp: str


@dataclass(frozen=True)
class LifecycleOutboxReplayResult:
    attempted_count: int = 0
    delivered_count: int = 0
    pending_count: int = 0
    workspace_event_count: int = 0
    team_event_count: int = 0
    chat_waiting_cleared_count: int = 0
    presence_cleared_count: int = 0
    failed_event_intents: tuple[LifecycleEventIntent, ...] = ()
    failed_effect_kinds: tuple[str, ...] = ()
    pending_effect_kinds: tuple[str, ...] = ()
    skipped_no_redis: bool = False


@dataclass(frozen=True)
class LifecycleCascadeResult:
    operation: str
    dry_run: bool
    target_agent_id: str | None
    workspace_changes: tuple[WorkspaceLifecycleChange, ...] = ()
    planned_mutations: tuple[str, ...] = ()
    completed_mutations: tuple[str, ...] = ()
    task_unclaim_count: int = 0
    reservation_release_count: int = 0
    chat_participant_cleanup_count: int = 0
    chat_waiting_cleanup_status: PresenceCleanupStatus = "not_run"
    chat_waiting_session_clear_count: int = 0
    chat_waiting_cleared_count: int | None = None
    workspace_event_count: int = 0
    team_event_count: int = 0
    event_intents: tuple[LifecycleEventIntent, ...] = ()
    failed_event_intents: tuple[LifecycleEventIntent, ...] = ()
    presence_cleanup_status: PresenceCleanupStatus = "not_run"
    presence_cleared_count: int | None = None
    post_commit_status: PostCommitStatus = "not_run"
    outbox_operation_id: str | None = None
    identity_deleted: bool = False
    identity_archived: bool = False
    errors: tuple[LifecycleError, ...] = ()


_VALID_OPERATIONS = {
    "delete_local_workspace",
    "cleanup_agent_coordination_state",
    "agent_deleted_cascade",
    "archive_global_agent",
}
_VALID_SCOPES = {"explicit", "latest_for_agent", "all_for_agent"}


def _planned_mutations(request: LifecycleCascadeRequest) -> tuple[str, ...]:
    mutations = [
        "workspace.soft_delete",
        "task_claims.release",
        "reservations.release",
        "chat_participants.remove",
        "chat_waiting.clear",
        "task_unclaim_events.publish",
        "presence.clear",
    ]
    if request.mark_local_agent_deleted:
        mutations.append("agent.mark_local_deleted")
    if request.operation == "archive_global_agent":
        mutations.append("agent.archive_global")
    return tuple(mutations)


def _error_result(
    request: LifecycleCascadeRequest,
    errors: list[LifecycleError],
    *,
    workspace_changes: tuple[WorkspaceLifecycleChange, ...] = (),
    task_unclaim_count: int = 0,
    reservation_release_count: int = 0,
    chat_participant_cleanup_count: int = 0,
    presence_cleanup_status: PresenceCleanupStatus = "not_run",
) -> LifecycleCascadeResult:
    return LifecycleCascadeResult(
        operation=request.operation,
        dry_run=request.dry_run,
        target_agent_id=request.target_agent_id,
        workspace_changes=workspace_changes,
        planned_mutations=_planned_mutations(request),
        task_unclaim_count=task_unclaim_count,
        reservation_release_count=reservation_release_count,
        chat_participant_cleanup_count=chat_participant_cleanup_count,
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
    if request.operation == "archive_global_agent" and not request.target_agent_id:
        errors.append(
            LifecycleError(
                code="global_archive_requires_agent_target",
                message="Global archive requires target_agent_id.",
            )
        )
    if (
        request.operation == "archive_global_agent"
        and request.workspace_scope != "all_for_agent"
    ):
        errors.append(
            LifecycleError(
                code="global_archive_requires_all_agent_workspaces",
                message="Global archive must clean all active workspaces for the target agent.",
            )
        )
    required_archive_scope = request.require_identity_scope or (
        normalize_identity_scope(request.require_lifetime) if request.require_lifetime else None
    )
    if (
        request.operation == "archive_global_agent"
        and required_archive_scope != "global"
    ):
        errors.append(
            LifecycleError(
                code="global_archive_requires_global_scope",
                message="Global archive requires require_identity_scope='global'.",
            )
        )
    if (
        request.operation == "archive_global_agent"
        and request.mark_local_agent_deleted
    ):
        errors.append(
            LifecycleError(
                code="conflicting_agent_lifecycle_action",
                message="Global archive cannot also mark a local agent deleted.",
            )
        )
    return errors


def _workspace_id_values(workspace_ids: tuple[str, ...]) -> list[UUID]:
    return [UUID(str(workspace_id)) for workspace_id in workspace_ids]


async def _load_target_agent(db, request: LifecycleCascadeRequest) -> dict | None:
    if not request.target_agent_id:
        return None
    if request.team_id is None:
        row = await db.fetch_one(
            """
            SELECT agent_id, team_id, identity_scope, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1
              AND deleted_at IS NULL
            """,
            UUID(str(request.target_agent_id)),
        )
    else:
        row = await db.fetch_one(
            """
            SELECT agent_id, team_id, identity_scope, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1
              AND team_id = $2
              AND deleted_at IS NULL
            """,
            UUID(str(request.target_agent_id)),
            request.team_id,
        )
    return None if row is None else dict(row)


async def _load_target_workspaces(db, request: LifecycleCascadeRequest) -> list[dict]:
    select_sql = """
        SELECT
            w.workspace_id,
            w.team_id,
            w.agent_id,
            w.alias,
            w.deleted_at,
            w.last_seen_at,
            a.identity_scope AS agent_identity_scope
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
        identity_scope = str(workspace.get("agent_identity_scope") or "").strip()
        required_scope = request.require_identity_scope or (normalize_identity_scope(request.require_lifetime) if request.require_lifetime else None)
        if required_scope and not identity_scope:
            errors.append(
                LifecycleError(
                    code="unknown_identity_scope_no_cleanup",
                    message="Workspace is missing an active bound identity scope.",
                    target=workspace_id,
                )
            )
            continue
        if required_scope and normalize_identity_scope(identity_scope) != required_scope:
            code = (
                "global_identity_not_cleanup_eligible"
                if normalize_identity_scope(identity_scope) == "global"
                else "lifecycle_identity_scope_precondition_failed"
            )
            errors.append(
                LifecycleError(
                    code=code,
                    message=(
                        f"Workspace identity scope {identity_scope!r} does not match "
                        f"required scope {required_scope!r}."
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
                    code="local_workspace_still_active",
                    message="Workspace presence is not stale enough for lifecycle cleanup.",
                    target=workspace_id,
                )
            )
    return errors


def _agent_precondition_errors(
    request: LifecycleCascadeRequest, agent: dict | None
) -> list[LifecycleError]:
    if request.operation != "archive_global_agent":
        return []
    if agent is None:
        return [
            LifecycleError(
                code="agent_not_found",
                message="Global archive target agent was not found.",
                target=request.target_agent_id,
            )
        ]
    identity_scope = str(agent.get("identity_scope") or "").strip()
    if normalize_identity_scope(identity_scope) != "global":
        return [
            LifecycleError(
                code="lifecycle_identity_scope_precondition_failed",
                message=(
                    f"Target agent identity scope {identity_scope!r} does not match "
                    "required scope 'global'."
                ),
                target=str(agent["agent_id"]),
            )
        ]
    return []


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


def _workspace_agent_ids(workspaces: list[dict]) -> list[UUID]:
    agent_ids: list[UUID] = []
    seen: set[UUID] = set()
    for workspace in workspaces:
        agent_id = workspace.get("agent_id")
        if agent_id is None:
            continue
        value = UUID(str(agent_id))
        if value not in seen:
            seen.add(value)
            agent_ids.append(value)
    return agent_ids


def _target_agent_ids(
    request: LifecycleCascadeRequest, workspaces: list[dict]
) -> list[UUID]:
    agent_ids = _workspace_agent_ids(workspaces)
    if request.operation == "archive_global_agent" and request.target_agent_id:
        target_agent_id = UUID(str(request.target_agent_id))
        if target_agent_id not in agent_ids:
            agent_ids.append(target_agent_id)
    return agent_ids


async def _plan_reservation_count(
    db, agent_ids: list[UUID], team_id: str | None
) -> int:
    if not agent_ids:
        return 0
    if team_id is None:
        count = await db.fetch_value(
            """
            SELECT COUNT(*)
            FROM {{tables.reservations}}
            WHERE holder_agent_id = ANY($1::uuid[])
            """,
            agent_ids,
        )
    else:
        count = await db.fetch_value(
            """
            SELECT COUNT(*)
            FROM {{tables.reservations}}
            WHERE holder_agent_id = ANY($1::uuid[])
              AND team_id = $2
            """,
            agent_ids,
            team_id,
        )
    return int(count or 0)


async def _plan_chat_participant_count(
    db, agent_ids: list[UUID], team_id: str | None
) -> int:
    if not agent_ids:
        return 0
    if team_id is None:
        count = await db.fetch_value(
            """
            SELECT COUNT(*)
            FROM {{tables.chat_participants}}
            WHERE agent_id = ANY($1::uuid[])
            """,
            agent_ids,
        )
    else:
        count = await db.fetch_value(
            """
            SELECT COUNT(*)
            FROM {{tables.chat_participants}} p
            JOIN {{tables.chat_sessions}} s
              ON s.session_id = p.session_id
            WHERE p.agent_id = ANY($1::uuid[])
              AND s.team_id = $2
            """,
            agent_ids,
            team_id,
        )
    return int(count or 0)


async def _release_reservations(db, agent_ids: list[UUID], team_id: str | None) -> int:
    if not agent_ids:
        return 0
    if team_id is None:
        rows = await db.fetch_all(
            """
            DELETE FROM {{tables.reservations}}
            WHERE holder_agent_id = ANY($1::uuid[])
            RETURNING resource_key
            """,
            agent_ids,
        )
    else:
        rows = await db.fetch_all(
            """
            DELETE FROM {{tables.reservations}}
            WHERE holder_agent_id = ANY($1::uuid[])
              AND team_id = $2
            RETURNING resource_key
            """,
            agent_ids,
            team_id,
        )
    return len(rows)


async def _cleanup_chat_participants(
    db, agent_ids: list[UUID], team_id: str | None
) -> tuple[tuple[tuple[str, str], ...], int]:
    if not agent_ids:
        return (), 0
    if team_id is None:
        rows = await db.fetch_all(
            """
            DELETE FROM {{tables.chat_participants}}
            WHERE agent_id = ANY($1::uuid[])
            RETURNING session_id, did
            """,
            agent_ids,
        )
        wait_rows = await db.fetch_all(
            """
            UPDATE {{tables.chat_sessions}}
            SET wait_seconds = NULL,
                wait_started_at = NULL,
                wait_started_by = NULL
            WHERE wait_started_by = ANY($1::uuid[])
            RETURNING session_id
            """,
            agent_ids,
        )
    else:
        rows = await db.fetch_all(
            """
            DELETE FROM {{tables.chat_participants}} p
            USING {{tables.chat_sessions}} s
            WHERE p.session_id = s.session_id
              AND p.agent_id = ANY($1::uuid[])
              AND s.team_id = $2
            RETURNING p.session_id, p.did
            """,
            agent_ids,
            team_id,
        )
        wait_rows = await db.fetch_all(
            """
            UPDATE {{tables.chat_sessions}}
            SET wait_seconds = NULL,
                wait_started_at = NULL,
                wait_started_by = NULL
            WHERE wait_started_by = ANY($1::uuid[])
              AND team_id = $2
            RETURNING session_id
            """,
            agent_ids,
            team_id,
        )
    participants = tuple((str(row["session_id"]), str(row["did"])) for row in rows)
    return participants, len(wait_rows)


async def _clear_chat_waiting(
    redis: Redis | None, participants: tuple[tuple[str, str], ...]
) -> tuple[PresenceCleanupStatus, int | None]:
    if not participants:
        return "not_run", 0
    if redis is None:
        return "skipped_no_redis", None
    cleared_count = 0
    try:
        for session_id, did in participants:
            await unregister_waiting(redis, session_id, did)
            cleared_count += 1
        return "cleared", cleared_count
    except Exception:
        logger.warning(
            "Failed to clear lifecycle chat waiting state",
            extra={"participant_count": len(participants)},
            exc_info=True,
        )
        return "failed", None


async def _table_has_column(db, column_name: str) -> bool:
    row = await db.fetch_one(
        """
        SELECT EXISTS (
            SELECT 1
            FROM pg_attribute
            WHERE attrelid = to_regclass('{{tables.agents}}')
              AND attname = $1
              AND NOT attisdropped
        ) AS has_column
        """,
        column_name,
    )
    return bool(row and row["has_column"])


async def _archive_global_agents(
    db, agent_ids: list[UUID], team_id: str | None, deleted_at: datetime
) -> int:
    if not agent_ids:
        return 0
    signing_key_update = (
        ", signing_key_enc = NULL" if await _table_has_column(db, "signing_key_enc") else ""
    )
    if team_id is None:
        rows = await db.fetch_all(
            f"""
            UPDATE {{{{tables.agents}}}}
            SET deleted_at = $2,
                status = 'archived'
                {signing_key_update}
            WHERE agent_id = ANY($1::uuid[])
              AND deleted_at IS NULL
              AND identity_scope = 'global'
            RETURNING agent_id
            """,
            agent_ids,
            deleted_at,
        )
    else:
        rows = await db.fetch_all(
            f"""
            UPDATE {{{{tables.agents}}}}
            SET deleted_at = $2,
                status = 'archived'
                {signing_key_update}
            WHERE agent_id = ANY($1::uuid[])
              AND team_id = $3
              AND deleted_at IS NULL
              AND identity_scope = 'global'
            RETURNING agent_id
            """,
            agent_ids,
            deleted_at,
            team_id,
        )
    return len(rows)


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
            identity_scope=str(workspace.get("agent_identity_scope") or "local"),
        )
        for workspace in workspaces
    )


async def plan_lifecycle_cascade(
    db, request: LifecycleCascadeRequest
) -> LifecycleCascadeResult:
    """Return planned coordination lifecycle effects without mutating state.

    The result always reports ``dry_run=True`` because this entry point is a
    planner even if the request itself was not marked dry-run. An empty target
    workspace set is an intentional idempotent no-op.
    """
    errors = _validate_request(request)
    if errors:
        return _error_result(request, errors)

    agent = await _load_target_agent(db, request)
    workspaces = await _load_target_workspaces(db, request)
    precondition_errors = _agent_precondition_errors(
        request, agent
    ) + _precondition_errors(request, workspaces)
    workspace_changes = _workspace_changes(workspaces, status="planned")
    workspace_ids = [str(workspace["workspace_id"]) for workspace in workspaces]
    agent_ids = _target_agent_ids(request, workspaces)
    claim_count = await _plan_claim_count(db, workspace_ids)
    reservation_count = await _plan_reservation_count(db, agent_ids, request.team_id)
    chat_participant_count = await _plan_chat_participant_count(
        db, agent_ids, request.team_id
    )

    if precondition_errors:
        return _error_result(
            request,
            precondition_errors,
            workspace_changes=workspace_changes,
            task_unclaim_count=claim_count,
            reservation_release_count=reservation_count,
            chat_participant_cleanup_count=chat_participant_count,
            presence_cleanup_status="planned",
        )

    return LifecycleCascadeResult(
        operation=request.operation,
        dry_run=True,
        target_agent_id=request.target_agent_id,
        workspace_changes=workspace_changes,
        planned_mutations=_planned_mutations(request),
        task_unclaim_count=claim_count,
        reservation_release_count=reservation_count,
        chat_participant_cleanup_count=chat_participant_count,
        chat_waiting_cleanup_status="planned" if chat_participant_count else "not_run",
        presence_cleanup_status="planned" if workspace_ids else "not_run",
    )


def _decode_outbox_payload(value) -> dict:
    if isinstance(value, str):
        return json.loads(value)
    return dict(value)


def _event_intent_from_payload(effect_kind: str, payload: dict) -> LifecycleEventIntent:
    return LifecycleEventIntent(
        event_kind=effect_kind,
        workspace_id=str(payload["workspace_id"]),
        team_id=str(payload["team_id"]),
        task_ref=str(payload["task_ref"]),
        alias=str(payload.get("alias") or ""),
        timestamp=str(payload["timestamp"]),
    )


def _lifecycle_side_effects(
    event_intents: tuple[LifecycleEventIntent, ...],
    chat_participants: tuple[tuple[str, str], ...],
    presence_ids: list[str],
    *,
    team_id: str,
) -> list[tuple[str, dict]]:
    effects: list[tuple[str, dict]] = []
    for intent in event_intents:
        effects.append(
            (
                intent.event_kind,
                {
                    "workspace_id": intent.workspace_id,
                    "team_id": intent.team_id,
                    "task_ref": intent.task_ref,
                    "alias": intent.alias,
                    "timestamp": intent.timestamp,
                },
            )
        )
    if chat_participants:
        effects.append(
            (
                "chat_waiting_clear",
                {
                    "team_id": team_id,
                    "participants": [list(participant) for participant in chat_participants],
                },
            )
        )
    if presence_ids:
        effects.append(
            (
                "presence_clear",
                {"team_id": team_id, "workspace_ids": presence_ids},
            )
        )
    return effects


async def _enqueue_lifecycle_side_effects(
    tx,
    *,
    operation_id: UUID,
    team_id: str,
    effects: list[tuple[str, dict]],
) -> None:
    for effect_order, (effect_kind, payload) in enumerate(effects):
        await tx.execute(
            """
            INSERT INTO {{tables.lifecycle_side_effect_outbox}} (
                operation_id, effect_order, team_id, effect_kind, payload_json
            )
            VALUES ($1, $2, $3, $4, $5::jsonb)
            ON CONFLICT (operation_id, effect_order) DO NOTHING
            """,
            operation_id,
            effect_order,
            team_id,
            effect_kind,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
        )


async def _deliver_lifecycle_side_effect(
    redis: Redis,
    *,
    effect_kind: str,
    payload: dict,
) -> tuple[int, int, int, int]:
    if effect_kind == "workspace_task_unclaimed":
        intent = _event_intent_from_payload(effect_kind, payload)
        await publish_event(
            redis,
            TaskUnclaimedEvent(
                workspace_id=intent.workspace_id,
                task_ref=intent.task_ref,
                alias=intent.alias,
                timestamp=intent.timestamp,
            ),
        )
        return 1, 0, 0, 0
    if effect_kind == "team_task_unclaimed":
        intent = _event_intent_from_payload(effect_kind, payload)
        await publish_team_event(
            redis,
            TeamTaskUnclaimedEvent(
                team_id=intent.team_id,
                task_ref=intent.task_ref,
                alias=intent.alias,
                title="",
                timestamp=intent.timestamp,
            ),
        )
        return 0, 1, 0, 0
    if effect_kind == "chat_waiting_clear":
        participants = tuple(
            (str(participant[0]), str(participant[1]))
            for participant in payload.get("participants", [])
        )
        status, cleared_count = await _clear_chat_waiting(redis, participants)
        if status != "cleared":
            raise RuntimeError(f"chat waiting cleanup returned {status}")
        return 0, 0, int(cleared_count or 0), 0
    if effect_kind == "presence_clear":
        workspace_ids = [str(value) for value in payload.get("workspace_ids", [])]
        status, cleared_count = await _clear_presence(redis, workspace_ids)
        if status != "cleared":
            raise RuntimeError(f"presence cleanup returned {status}")
        return 0, 0, 0, int(cleared_count or 0)
    raise ValueError(f"unknown lifecycle outbox effect kind: {effect_kind}")


async def replay_lifecycle_side_effects(
    db,
    redis: Redis | None,
    *,
    operation_id: UUID | str | None = None,
    limit: int | None = None,
) -> LifecycleOutboxReplayResult:
    """Deliver committed lifecycle side effects at least once.

    Rows are locked while publishing so concurrent replay workers cannot deliver
    the same committed row. Operation-specific replay waits for competing
    workers and drains the complete operation by default; global replay uses a
    bounded 100-row batch. A crash after Redis accepts a publication but before
    PostgreSQL records ``delivered_at`` may replay that event; consumers must
    continue treating lifecycle events as state-change hints and read SQL truth.
    """
    operation_uuid = UUID(str(operation_id)) if operation_id is not None else None
    row_limit = max(1, limit) if limit is not None else (
        2_147_483_647 if operation_uuid is not None else 100
    )
    if redis is None:
        pending_count = int(
            await db.fetch_value(
                """
                SELECT COUNT(*)
                FROM {{tables.lifecycle_side_effect_outbox}}
                WHERE delivered_at IS NULL
                  AND ($1::uuid IS NULL OR operation_id = $1)
                """,
                operation_uuid,
            )
            or 0
        )
        pending_rows = await db.fetch_all(
            """
            SELECT DISTINCT effect_kind
            FROM {{tables.lifecycle_side_effect_outbox}}
            WHERE delivered_at IS NULL
              AND ($1::uuid IS NULL OR operation_id = $1)
            ORDER BY effect_kind
            """,
            operation_uuid,
        )
        return LifecycleOutboxReplayResult(
            pending_count=pending_count,
            pending_effect_kinds=tuple(str(row["effect_kind"]) for row in pending_rows),
            skipped_no_redis=True,
        )

    attempted_count = 0
    delivered_count = 0
    workspace_event_count = 0
    team_event_count = 0
    chat_waiting_cleared_count = 0
    presence_cleared_count = 0
    failed_event_intents: list[LifecycleEventIntent] = []
    failed_effect_kinds: list[str] = []

    lock_clause = "FOR UPDATE" if operation_uuid is not None else "FOR UPDATE SKIP LOCKED"
    async with db.transaction() as tx:
        rows = await tx.fetch_all(
            f"""
            SELECT outbox_id, effect_kind, payload_json
            FROM {{{{tables.lifecycle_side_effect_outbox}}}}
            WHERE delivered_at IS NULL
              AND ($1::uuid IS NULL OR operation_id = $1)
            ORDER BY created_at, operation_id, effect_order
            {lock_clause}
            LIMIT $2
            """,
            operation_uuid,
            row_limit,
        )
        for row in rows:
            attempted_count += 1
            effect_kind = str(row["effect_kind"])
            payload = _decode_outbox_payload(row["payload_json"])
            try:
                workspace_count, team_count, waiting_count, presence_count = (
                    await _deliver_lifecycle_side_effect(
                        redis,
                        effect_kind=effect_kind,
                        payload=payload,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Failed to replay lifecycle outbox effect",
                    extra={
                        "outbox_id": str(row["outbox_id"]),
                        "effect_kind": effect_kind,
                    },
                    exc_info=True,
                )
                await tx.execute(
                    """
                    UPDATE {{tables.lifecycle_side_effect_outbox}}
                    SET attempt_count = attempt_count + 1,
                        last_error = $2
                    WHERE outbox_id = $1
                      AND delivered_at IS NULL
                    """,
                    row["outbox_id"],
                    type(exc).__name__,
                )
                failed_effect_kinds.append(effect_kind)
                if effect_kind in {
                    "workspace_task_unclaimed",
                    "team_task_unclaimed",
                }:
                    failed_event_intents.append(
                        _event_intent_from_payload(effect_kind, payload)
                    )
                continue

            await tx.execute(
                """
                UPDATE {{tables.lifecycle_side_effect_outbox}}
                SET delivered_at = NOW(),
                    attempt_count = attempt_count + 1,
                    last_error = NULL
                WHERE outbox_id = $1
                  AND delivered_at IS NULL
                """,
                row["outbox_id"],
            )
            delivered_count += 1
            workspace_event_count += workspace_count
            team_event_count += team_count
            chat_waiting_cleared_count += waiting_count
            presence_cleared_count += presence_count

    pending_count = int(
        await db.fetch_value(
            """
            SELECT COUNT(*)
            FROM {{tables.lifecycle_side_effect_outbox}}
            WHERE delivered_at IS NULL
              AND ($1::uuid IS NULL OR operation_id = $1)
            """,
            operation_uuid,
        )
        or 0
    )
    pending_rows = await db.fetch_all(
        """
        SELECT DISTINCT effect_kind
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE delivered_at IS NULL
          AND ($1::uuid IS NULL OR operation_id = $1)
        ORDER BY effect_kind
        """,
        operation_uuid,
    )
    return LifecycleOutboxReplayResult(
        attempted_count=attempted_count,
        delivered_count=delivered_count,
        pending_count=pending_count,
        workspace_event_count=workspace_event_count,
        team_event_count=team_event_count,
        chat_waiting_cleared_count=chat_waiting_cleared_count,
        presence_cleared_count=presence_cleared_count,
        failed_event_intents=tuple(failed_event_intents),
        failed_effect_kinds=tuple(failed_effect_kinds),
        pending_effect_kinds=tuple(str(row["effect_kind"]) for row in pending_rows),
    )


_outbox_replay_tasks: set[asyncio.Task] = set()


def _schedule_replay_after_outer_transaction(
    tx: TransactionManager,
    redis: Redis | None,
    *,
    operation_id: UUID,
    effect_count: int,
) -> None:
    async def _replay_after_transaction_finishes() -> None:
        try:
            while True:
                try:
                    in_transaction = tx.connection.is_in_transaction()
                except Exception:
                    # The outer context may release its pooled connection before
                    # this task observes the final transaction state. The durable
                    # outbox visibility check below still distinguishes commit
                    # (rows visible) from rollback (no rows).
                    break
                if not in_transaction:
                    break
                await asyncio.sleep(0.01)
            await replay_lifecycle_side_effects(
                tx._db,
                redis,
                operation_id=operation_id,
                limit=max(1, effect_count),
            )
        except Exception:
            logger.warning(
                "Deferred lifecycle outbox replay failed",
                extra={"operation_id": str(operation_id)},
                exc_info=True,
            )

    task = asyncio.create_task(_replay_after_transaction_finishes())
    _outbox_replay_tasks.add(task)
    task.add_done_callback(_outbox_replay_tasks.discard)


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

    Redis event and cleanup intents are captured from SQL mutation results and
    inserted into the lifecycle outbox in the same transaction. Plain-handle
    calls attempt replay after commit. Transaction-handle calls return pending
    and schedule replay only after the caller's outer transaction finishes.

    An empty target workspace set is an intentional idempotent no-op.
    """
    if request.dry_run:
        return await plan_lifecycle_cascade(db, request)

    errors = _validate_request(request)
    if errors:
        return _error_result(request, errors)

    deleted_at = request.deleted_at or datetime.now(timezone.utc)
    operation_id = uuid4()
    event_intents: list[LifecycleEventIntent] = []
    task_unclaim_count = 0
    reservation_release_count = 0
    chat_participants: tuple[tuple[str, str], ...] = ()
    chat_participant_cleanup_count = 0
    chat_waiting_session_clear_count = 0
    identity_deleted = False
    identity_archived = False

    async with db.transaction() as tx:
        agent = await _load_target_agent(tx, request)
        workspaces = await _load_target_workspaces(tx, request)
        precondition_errors = _agent_precondition_errors(
            request, agent
        ) + _precondition_errors(request, workspaces)
        workspace_changes = _workspace_changes(workspaces, status="planned")
        workspace_ids = [str(workspace["workspace_id"]) for workspace in workspaces]
        agent_ids = _target_agent_ids(request, workspaces)
        if precondition_errors:
            return _error_result(
                request,
                precondition_errors,
                workspace_changes=workspace_changes,
                task_unclaim_count=await _plan_claim_count(tx, workspace_ids),
                reservation_release_count=await _plan_reservation_count(
                    tx, agent_ids, request.team_id
                ),
                chat_participant_cleanup_count=await _plan_chat_participant_count(
                    tx, agent_ids, request.team_id
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
            task_unclaim_count += len(claimed_rows)
            for row in claimed_rows:
                task_ref = str(row["task_ref"])
                event_timestamp = datetime.now(timezone.utc).isoformat()
                event_intents.append(
                    LifecycleEventIntent(
                        event_kind="workspace_task_unclaimed",
                        workspace_id=workspace_id,
                        team_id=team_id,
                        task_ref=task_ref,
                        alias=alias,
                        timestamp=event_timestamp,
                    )
                )
                event_intents.append(
                    LifecycleEventIntent(
                        event_kind="team_task_unclaimed",
                        workspace_id=workspace_id,
                        team_id=team_id,
                        task_ref=task_ref,
                        alias=alias,
                        timestamp=event_timestamp,
                    )
                )
            if (
                request.mark_local_agent_deleted
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
                      AND identity_scope = 'local'
                    RETURNING agent_id
                    """,
                    workspace["agent_id"],
                    deleted_at,
                    team_id,
                )
                identity_deleted = identity_deleted or deleted_agent is not None

        reservation_release_count = await _release_reservations(
            tx, agent_ids, request.team_id
        )
        chat_participants, chat_waiting_session_clear_count = (
            await _cleanup_chat_participants(tx, agent_ids, request.team_id)
        )
        chat_participant_cleanup_count = len(chat_participants)

        if request.operation == "archive_global_agent":
            identity_archived = (
                await _archive_global_agents(
                    tx, agent_ids, request.team_id, deleted_at
                )
                > 0
            )

        workspace_changes = _workspace_changes(workspaces, status="completed")
        workspace_ids = [change.workspace_id for change in workspace_changes]
        presence_ids = list(workspace_ids)
        if identity_deleted or request.operation == "agent_deleted_cascade":
            presence_ids.extend(str(agent_id) for agent_id in agent_ids)
            presence_ids = list(dict.fromkeys(presence_ids))
        outbox_team_id = str(
            request.team_id
            or (workspace_changes[0].team_id if workspace_changes else "")
        )
        effects = _lifecycle_side_effects(
            tuple(event_intents),
            chat_participants,
            presence_ids,
            team_id=outbox_team_id,
        )
        await _enqueue_lifecycle_side_effects(
            tx,
            operation_id=operation_id,
            team_id=outbox_team_id,
            effects=effects,
        )

    if isinstance(db, TransactionManager):
        _schedule_replay_after_outer_transaction(
            db,
            redis,
            operation_id=operation_id,
            effect_count=len(effects),
        )
        workspace_event_count = 0
        team_event_count = 0
        failed_event_intents: tuple[LifecycleEventIntent, ...] = ()
        event_status: PostCommitStatus = "pending" if event_intents else "completed"
        chat_waiting_status: PresenceCleanupStatus = (
            "pending" if chat_participants else "not_run"
        )
        chat_waiting_cleared_count = 0 if not chat_participants else None
        presence_status: PresenceCleanupStatus = (
            "pending" if presence_ids else "not_run"
        )
        presence_cleared_count = 0 if not presence_ids else None
        post_commit_status: PostCommitStatus = "pending" if effects else "completed"
    else:
        replay_result = await replay_lifecycle_side_effects(
            db,
            redis,
            operation_id=operation_id,
            limit=max(1, len(effects)),
        )
        workspace_event_count = replay_result.workspace_event_count
        team_event_count = replay_result.team_event_count
        failed_event_intents = replay_result.failed_event_intents

        failed_kinds = set(replay_result.failed_effect_kinds)
        pending_kinds = set(replay_result.pending_effect_kinds)
        if replay_result.skipped_no_redis and event_intents:
            event_status = "skipped_no_redis"
        elif failed_kinds & {
            "workspace_task_unclaimed",
            "team_task_unclaimed",
        }:
            event_status = "failed"
        elif pending_kinds & {
            "workspace_task_unclaimed",
            "team_task_unclaimed",
        }:
            event_status = "pending"
        else:
            event_status = "completed"

        if not chat_participants:
            chat_waiting_status = "not_run"
            chat_waiting_cleared_count = 0
        elif replay_result.skipped_no_redis:
            chat_waiting_status = "skipped_no_redis"
            chat_waiting_cleared_count = None
        elif "chat_waiting_clear" in failed_kinds:
            chat_waiting_status = "failed"
            chat_waiting_cleared_count = None
        elif "chat_waiting_clear" in pending_kinds:
            chat_waiting_status = "pending"
            chat_waiting_cleared_count = None
        else:
            chat_waiting_status = "cleared"
            chat_waiting_cleared_count = replay_result.chat_waiting_cleared_count

        if not presence_ids:
            presence_status = "not_run"
            presence_cleared_count = 0
        elif replay_result.skipped_no_redis:
            presence_status = "skipped_no_redis"
            presence_cleared_count = None
        elif "presence_clear" in failed_kinds:
            presence_status = "failed"
            presence_cleared_count = None
        elif "presence_clear" in pending_kinds:
            presence_status = "pending"
            presence_cleared_count = None
        else:
            presence_status = "cleared"
            presence_cleared_count = replay_result.presence_cleared_count

        if "failed" in {event_status, chat_waiting_status, presence_status}:
            post_commit_status = "failed"
        elif "skipped_no_redis" in {
            event_status,
            chat_waiting_status,
            presence_status,
        }:
            post_commit_status = "skipped_no_redis"
        elif "pending" in {event_status, chat_waiting_status, presence_status}:
            post_commit_status = "pending"
        else:
            post_commit_status = "completed"

    completed_mutations = ["workspace.soft_delete", "task_claims.release"]
    if reservation_release_count:
        completed_mutations.append("reservations.release")
    if chat_participant_cleanup_count:
        completed_mutations.append("chat_participants.remove")
    if chat_waiting_status == "cleared" or chat_waiting_session_clear_count:
        completed_mutations.append("chat_waiting.clear")
    if identity_deleted:
        completed_mutations.append("agent.mark_local_deleted")
    if identity_archived:
        completed_mutations.append("agent.archive_global")
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
        task_unclaim_count=task_unclaim_count,
        reservation_release_count=reservation_release_count,
        chat_participant_cleanup_count=chat_participant_cleanup_count,
        chat_waiting_cleanup_status=chat_waiting_status,
        chat_waiting_session_clear_count=chat_waiting_session_clear_count,
        chat_waiting_cleared_count=chat_waiting_cleared_count,
        workspace_event_count=workspace_event_count,
        team_event_count=team_event_count,
        event_intents=tuple(event_intents),
        failed_event_intents=failed_event_intents,
        presence_cleanup_status=presence_status,
        presence_cleared_count=presence_cleared_count,
        post_commit_status=post_commit_status,
        outbox_operation_id=str(operation_id) if effects else None,
        identity_deleted=identity_deleted,
        identity_archived=identity_archived,
    )
