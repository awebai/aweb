"""Translate aweb mutation hooks into SSE events.

aweb fires app.state.on_mutation(event_type, context) after successful
mutations. This module registers a handler that publishes corresponding
Event dataclasses to Redis pub/sub for the SSE event stream.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

from redis.asyncio import Redis

from .claims import fetch_workspace_aliases, release_task_claims, upsert_claim
from .events import (
    ChatMessageEvent,
    Event,
    MessageAcknowledgedEvent,
    MessageDeliveredEvent,
    ReservationAcquiredEvent,
    ReservationReleasedEvent,
    TaskClaimedEvent,
    TaskCreatedEvent,
    TaskStatusChangedEvent,
    TaskUnclaimedEvent,
    publish_chat_session_signal,
    publish_event,
)
from .presence import clear_workspace_presence, get_agent_presence, get_workspace_project_slug

if TYPE_CHECKING:
    from .db import DatabaseInfra

logger = logging.getLogger(__name__)


def create_mutation_handler(redis: Redis, db_infra: DatabaseInfra):
    """Create an on_mutation callback that publishes SSE events.

    The returned async callable matches aweb's hook signature:
        async def on_mutation(event_type: str, context: dict) -> None
    """

    async def on_mutation(event_type: str, context: dict) -> None:
        # Side-effect hooks (cascades that modify state).
        # These run before SSE translation and do NOT prevent SSE publication.
        if event_type == "agent.deleted":
            try:
                await _cascade_agent_deleted(redis, db_infra, context)
            except Exception:
                logger.error("Failed to cascade agent.deleted", exc_info=True)

        if event_type == "task.status_changed":
            try:
                await _cascade_task_status_changed(redis, db_infra, context)
            except Exception:
                logger.error("Failed to cascade task.status_changed", exc_info=True)

        if event_type == "task.deleted":
            try:
                await _cascade_task_deleted(redis, db_infra, context)
            except Exception:
                logger.error("Failed to cascade task.deleted", exc_info=True)

        try:
            event = _translate(event_type, context)
            if event is None:
                return
            if not event.workspace_id:
                logger.warning("Skipping %s event: no workspace_id in context", event_type)
                return
            try:
                await _enrich(event, redis, db_infra)
            except Exception:
                logger.warning(
                    "Enrichment failed for %s, publishing with defaults", event_type, exc_info=True
                )
            await publish_event(redis, event)
            if event_type == "chat.message_sent":
                session_id = str(context.get("session_id", "")).strip()
                if session_id:
                    await publish_chat_session_signal(
                        redis,
                        session_id=session_id,
                        signal_type="message",
                        agent_id=str(context.get("from_agent_id", "")).strip() or None,
                        message_id=str(context.get("message_id", "")).strip() or None,
                    )
        except Exception:
            logger.warning("Failed to publish event for %s", event_type, exc_info=True)

    return on_mutation


async def _cascade_agent_deleted(
    redis: Redis, db_infra: "DatabaseInfra", context: dict
) -> None:
    """Cascade ephemeral identity deletion to workspace cleanup.

    workspace_id = agent_id (v1 mapping). Soft-deletes the workspace,
    releases task claims, publishes unclaim events, and clears presence.

    Note: agent.retired is intentionally NOT cascaded here. Retired agents
    designate a successor and their workspace data may be needed for handoff.
    """
    agent_id = context.get("agent_id", "").strip()
    if not agent_id:
        return

    try:
        agent_uuid = UUID(agent_id)
    except ValueError:
        logger.warning("agent.deleted event has non-UUID agent_id: %r", agent_id)
        return

    server_db = db_infra.get_manager("server")

    # Check if a workspace exists for this agent (workspace_id = agent_id)
    workspace = await server_db.fetch_one(
        """
        SELECT workspace_id, alias
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        agent_uuid,
    )
    if workspace is None:
        return

    alias = workspace["alias"]

    # Soft-delete the workspace and capture claimed tasks before releasing
    async with server_db.transaction() as tx:
        await tx.execute(
            """
            UPDATE {{tables.workspaces}}
            SET deleted_at = NOW()
            WHERE workspace_id = $1
            """,
            agent_uuid,
        )
        claimed_rows = await tx.fetch_all(
            """
            DELETE FROM {{tables.task_claims}}
            WHERE workspace_id = $1
            RETURNING task_ref
            """,
            agent_uuid,
        )

    # Publish unclaim events for each released task claim
    project_slug = await get_workspace_project_slug(redis, agent_id)
    for row in claimed_rows:
        await publish_event(
            redis,
            TaskUnclaimedEvent(
                workspace_id=agent_id,
                project_slug=project_slug,
                task_ref=row["task_ref"],
                alias=alias,
            ),
        )

    # Clear presence from Redis (best-effort, not transactional with SQL)
    await clear_workspace_presence(redis, [agent_id])

    logger.info(
        "Cascaded agent deletion to workspace %s (alias=%s, claims_released=%d)",
        agent_id,
        alias,
        len(claimed_rows),
    )


async def _cascade_task_status_changed(
    redis: Redis, db_infra: "DatabaseInfra", context: dict
) -> None:
    """Translate task status changes into task claim lifecycle operations.

    When an aweb task moves to in_progress, create a task claim for the
    acting workspace. When it moves away from in_progress (closed, etc.),
    release all claims on that task.
    """
    actor_id = context.get("actor_agent_id", "").strip()
    task_ref = context.get("task_ref", "").strip()
    new_status = context.get("new_status", "")
    title = context.get("title")
    claim_preacquired = bool(context.get("claim_preacquired", False))

    if not actor_id or not task_ref:
        return

    try:
        actor_uuid = UUID(actor_id)
    except ValueError:
        logger.warning("task.status_changed has non-UUID actor_agent_id: %r", actor_id)
        return

    server_db = db_infra.get_manager("server")
    workspace = await server_db.fetch_one(
        """
        SELECT project_id, alias, human_name
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        actor_uuid,
    )
    if workspace is None:
        logger.warning("task.status_changed: no workspace for actor %s", actor_id)
        return

    project_id = str(workspace["project_id"])
    alias = workspace["alias"]
    project_slug = await get_workspace_project_slug(redis, actor_id)

    if new_status == "in_progress":
        if not claim_preacquired:
            conflict = await upsert_claim(
                db_infra,
                project_id=project_id,
                workspace_id=actor_id,
                alias=alias,
                human_name=workspace["human_name"] or "",
                task_ref=task_ref,
            )
            if conflict:
                logger.info(
                    "Task %s already claimed by %s, skipping event", task_ref, conflict["alias"]
                )
                return

        await publish_event(
            redis,
            TaskClaimedEvent(
                workspace_id=actor_id,
                project_slug=project_slug,
                task_ref=task_ref,
                alias=alias,
                title=title,
            ),
        )
    else:
        claimant_ids = await release_task_claims(
            db_infra,
            project_id=project_id,
            task_ref=task_ref,
        )
        if claimant_ids:
            claimant_aliases = await fetch_workspace_aliases(db_infra, project_id, claimant_ids)
            for cid in claimant_ids:
                await publish_event(
                    redis,
                    TaskUnclaimedEvent(
                        workspace_id=cid,
                        project_slug=project_slug,
                        task_ref=task_ref,
                        alias=claimant_aliases.get(cid, ""),
                        title=title,
                    ),
                )

    await publish_event(
        redis,
        TaskStatusChangedEvent(
            workspace_id=actor_id,
            project_slug=project_slug,
            project_id=project_id,
            task_ref=task_ref,
            old_status=context.get("old_status", "") or "",
            new_status=new_status,
            title=title,
            alias=alias,
        ),
    )


async def _cascade_task_deleted(redis: Redis, db_infra: "DatabaseInfra", context: dict) -> None:
    """Release all claims on a deleted task and publish unclaim events.

    The task.deleted hook provides {task_id, task_ref}; use task_id as the
    source of truth for project lookup so colliding project slugs cannot
    release claims in another project.
    """
    task_id = context.get("task_id", "").strip()
    task_ref = context.get("task_ref", "").strip()
    if not task_id or not task_ref:
        return

    server_db = db_infra.get_manager("server")
    task_row = await server_db.fetch_one(
        "SELECT project_id FROM {{tables.tasks}} WHERE task_id = $1",
        UUID(task_id),
    )
    if task_row is None:
        return

    project_id = str(task_row["project_id"])
    claimant_ids = await release_task_claims(
        db_infra,
        project_id=project_id,
        task_ref=task_ref,
    )
    if claimant_ids:
        claimant_aliases = await fetch_workspace_aliases(db_infra, project_id, claimant_ids)
        for cid in claimant_ids:
            project_slug = await get_workspace_project_slug(redis, cid)
            await publish_event(
                redis,
                TaskUnclaimedEvent(
                    workspace_id=cid,
                    project_slug=project_slug,
                    task_ref=task_ref,
                    alias=claimant_aliases.get(cid, ""),
                    title=context.get("title"),
                ),
            )


async def _alias_for(redis: Redis, workspace_id: str) -> str:
    """Resolve alias from Redis presence. Returns empty string if unavailable."""
    presence = await get_agent_presence(redis, workspace_id)
    if presence is None:
        return ""
    return presence.get("alias", "")


async def _enrich(event: Event, redis: Redis, db_infra: DatabaseInfra) -> None:
    """Add aliases, subjects, and previews via Redis/DB lookups."""

    if isinstance(event, MessageDeliveredEvent):
        event.from_alias = await _alias_for(redis, event.from_workspace)
        event.to_alias = await _alias_for(redis, event.workspace_id)
        event.project_slug = await get_workspace_project_slug(redis, event.workspace_id)

    elif isinstance(event, MessageAcknowledgedEvent):
        if event.message_id:
            aweb_db = db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT from_alias, subject FROM {{tables.messages}} WHERE message_id = $1",
                UUID(event.message_id),
            )
            if row:
                event.from_alias = row["from_alias"]
                event.subject = row["subject"] or ""
        event.project_slug = await get_workspace_project_slug(redis, event.workspace_id)

    elif isinstance(event, ChatMessageEvent):
        event.from_alias = await _alias_for(redis, event.workspace_id)
        aweb_db = db_infra.get_manager("aweb")
        if event.session_id and event.workspace_id:
            participants = await aweb_db.fetch_all(
                "SELECT alias FROM {{tables.chat_session_participants}} "
                "WHERE session_id = $1 AND agent_id != $2",
                UUID(event.session_id),
                UUID(event.workspace_id),
            )
            event.to_aliases = [r["alias"] for r in participants]
        if event.message_id:
            msg = await aweb_db.fetch_one(
                "SELECT body FROM {{tables.chat_messages}} WHERE message_id = $1",
                UUID(event.message_id),
            )
            if msg and msg["body"]:
                event.preview = msg["body"][:80]
        event.project_slug = await get_workspace_project_slug(redis, event.workspace_id)

    elif isinstance(event, TaskCreatedEvent):
        server_db = db_infra.get_manager("server")
        workspace = await server_db.fetch_one(
            """
            SELECT alias
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND deleted_at IS NULL
            """,
            UUID(event.workspace_id),
        )
        if workspace and workspace.get("alias"):
            event.alias = workspace["alias"]
        else:
            event.alias = await _alias_for(redis, event.workspace_id)
        event.project_slug = await get_workspace_project_slug(redis, event.workspace_id)

    elif isinstance(event, (ReservationAcquiredEvent, ReservationReleasedEvent)):
        event.alias = await _alias_for(redis, event.workspace_id)
        event.project_slug = await get_workspace_project_slug(redis, event.workspace_id)


def _translate(event_type: str, ctx: dict):
    """Map an aweb mutation event to a aweb Event dataclass."""

    if event_type == "message.sent":
        return MessageDeliveredEvent(
            workspace_id=ctx.get("to_agent_id", ""),
            message_id=ctx.get("message_id", ""),
            from_workspace=ctx.get("from_agent_id", ""),
            subject=ctx.get("subject", ""),
        )

    if event_type == "message.acknowledged":
        return MessageAcknowledgedEvent(
            workspace_id=ctx.get("agent_id", ""),
            message_id=ctx.get("message_id", ""),
        )

    if event_type == "chat.message_sent":
        return ChatMessageEvent(
            workspace_id=ctx.get("from_agent_id", ""),
            session_id=ctx.get("session_id", ""),
            message_id=ctx.get("message_id", ""),
        )

    if event_type == "task.created":
        return TaskCreatedEvent(
            workspace_id=ctx.get("actor_agent_id", ""),
            project_id=ctx.get("project_id", ""),
            task_ref=ctx.get("task_ref", ""),
            title=ctx.get("title"),
        )

    if event_type == "reservation.acquired":
        return ReservationAcquiredEvent(
            workspace_id=ctx.get("holder_agent_id", ""),
            paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
            ttl_seconds=ctx.get("ttl_seconds", 0),
        )

    if event_type == "reservation.released":
        return ReservationReleasedEvent(
            workspace_id=ctx.get("holder_agent_id", ""),
            paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
        )

    return None
