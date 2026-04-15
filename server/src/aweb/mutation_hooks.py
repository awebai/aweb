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
    TeamMessageSentEvent,
    TeamTaskClaimedEvent,
    TeamTaskCreatedEvent,
    TeamTaskStatusChangedEvent,
    TeamTaskUnclaimedEvent,
    publish_chat_session_signal,
    publish_event,
    publish_team_event,
)
from .identity_metadata import lookup_identity_metadata_by_agent_id, lookup_identity_metadata_by_did
from .presence import clear_workspace_presence, get_agent_presence

if TYPE_CHECKING:
    from .db import DatabaseInfra

logger = logging.getLogger(__name__)


async def _enrich_identity_context(db_infra: "DatabaseInfra", context: dict) -> dict:
    ctx = dict(context)
    identity_fields = (
        ("actor_agent_id", "actor_did", "actor_did_aw"),
        ("from_agent_id", "from_did", "from_did_aw"),
        ("holder_agent_id", "holder_did", "holder_did_aw"),
    )

    agent_ids = [
        str(ctx.get(agent_key, "")).strip()
        for agent_key, _, stable_key in identity_fields
        if not str(ctx.get(stable_key, "")).strip() and str(ctx.get(agent_key, "")).strip()
    ]
    dids = [
        str(ctx.get(did_key, "")).strip()
        for _, did_key, stable_key in identity_fields
        if not str(ctx.get(stable_key, "")).strip() and str(ctx.get(did_key, "")).strip()
    ]

    agent_meta = await lookup_identity_metadata_by_agent_id(db_infra, agent_ids)
    did_meta = await lookup_identity_metadata_by_did(db_infra, dids)

    for agent_key, did_key, stable_key in identity_fields:
        if str(ctx.get(stable_key, "")).strip():
            continue
        stable_id = ""
        agent_id = str(ctx.get(agent_key, "")).strip()
        did = str(ctx.get(did_key, "")).strip()
        if agent_id:
            stable_id = (agent_meta.get(agent_id, {}).get("stable_id") or "").strip()
        if not stable_id and did:
            stable_id = (did_meta.get(did, {}).get("stable_id") or "").strip()
        if stable_id:
            ctx[stable_key] = stable_id
    return ctx


async def _enrich_workspace_context(db_infra: "DatabaseInfra", context: dict) -> dict:
    ctx = dict(context)
    workspace_fields = (
        ("actor_workspace_id", "actor_agent_id"),
        ("holder_workspace_id", "holder_agent_id"),
    )

    agent_ids = [
        str(ctx.get(agent_key, "")).strip()
        for workspace_key, agent_key in workspace_fields
        if not str(ctx.get(workspace_key, "")).strip() and str(ctx.get(agent_key, "")).strip()
    ]
    if not agent_ids:
        return ctx

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, workspace_id
        FROM {{tables.workspaces}}
        WHERE deleted_at IS NULL AND agent_id = ANY($1::uuid[])
        ORDER BY updated_at DESC, workspace_id DESC
        """,
        [UUID(agent_id) for agent_id in agent_ids],
    )
    workspace_by_agent: dict[str, str] = {}
    for row in rows:
        agent_id = str(row["agent_id"])
        workspace_by_agent.setdefault(agent_id, str(row["workspace_id"]))

    for workspace_key, agent_key in workspace_fields:
        if str(ctx.get(workspace_key, "")).strip():
            continue
        agent_id = str(ctx.get(agent_key, "")).strip()
        workspace_id = workspace_by_agent.get(agent_id, "")
        if workspace_id:
            ctx[workspace_key] = workspace_id
    return ctx


def create_mutation_handler(redis: Redis, db_infra: DatabaseInfra):
    """Create an on_mutation callback that publishes SSE events.

    The returned async callable matches aweb's hook signature:
        async def on_mutation(event_type: str, context: dict) -> None
    """

    async def on_mutation(event_type: str, context: dict) -> None:
        context = await _enrich_identity_context(db_infra, context)
        context = await _enrich_workspace_context(db_infra, context)

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
            team_event = _translate_team_event(event_type, context)
            if event is None and team_event is None:
                return
            if event is not None:
                if not event.workspace_id:
                    logger.warning("Skipping %s event: no workspace_id in context", event_type)
                else:
                    try:
                        await _enrich(event, redis, db_infra)
                    except Exception:
                        logger.warning(
                            "Enrichment failed for %s, publishing with defaults", event_type, exc_info=True
                        )
                    await publish_event(redis, event)
            if team_event is not None:
                await publish_team_event(redis, team_event)
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

    aweb_db = db_infra.get_manager("aweb")

    # Check if a workspace exists for this agent (workspace_id = agent_id)
    workspace = await aweb_db.fetch_one(
        """
        SELECT workspace_id, alias, team_id
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        agent_id,
    )
    if workspace is None:
        return

    alias = workspace["alias"]
    team_id = str(workspace["team_id"])

    # Soft-delete the workspace and capture claimed tasks before releasing
    async with aweb_db.transaction() as tx:
        await tx.execute(
            """
            UPDATE {{tables.workspaces}}
            SET deleted_at = NOW()
            WHERE workspace_id = $1
            """,
            agent_id,
        )
        claimed_rows = await tx.fetch_all(
            """
            DELETE FROM {{tables.task_claims}}
            WHERE workspace_id = $1
            RETURNING task_ref
            """,
            agent_id,
        )

    # Publish unclaim events for each released task claim
    for row in claimed_rows:
        await publish_event(
            redis,
            TaskUnclaimedEvent(
                workspace_id=agent_id,
                task_ref=row["task_ref"],
                alias=alias,
            ),
        )
        await publish_team_event(
            redis,
            TeamTaskUnclaimedEvent(
                team_id=team_id,
                task_ref=row["task_ref"],
                alias=alias,
                title="",
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
    actor_workspace_id = context.get("actor_workspace_id", "").strip()
    task_ref = context.get("task_ref", "").strip()
    new_status = context.get("new_status", "")
    title = context.get("title")
    claim_preacquired = bool(context.get("claim_preacquired", False))

    if not actor_workspace_id or not task_ref:
        return

    aweb_db = db_infra.get_manager("aweb")
    workspace = await aweb_db.fetch_one(
        """
        SELECT team_id, alias, human_name
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        actor_workspace_id,
    )
    if workspace is None:
        logger.warning("task.status_changed: no workspace for actor %s", actor_workspace_id)
        return

    team_id = str(workspace["team_id"])
    alias = workspace["alias"]
    if new_status == "in_progress":
        if not claim_preacquired:
            conflict = await upsert_claim(
                db_infra,
                team_id=team_id,
                workspace_id=actor_workspace_id,
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
                workspace_id=actor_workspace_id,
                task_ref=task_ref,
                alias=alias,
                title=title,
            ),
        )
        await publish_team_event(
            redis,
            TeamTaskClaimedEvent(
                team_id=team_id,
                task_ref=task_ref,
                alias=alias,
                title=title or "",
            ),
        )
    else:
        claimant_ids = await release_task_claims(
            db_infra,
            team_id=team_id,
            task_ref=task_ref,
        )
        if claimant_ids:
            claimant_aliases = await fetch_workspace_aliases(db_infra, team_id, claimant_ids)
            for cid in claimant_ids:
                await publish_event(
                    redis,
                    TaskUnclaimedEvent(
                        workspace_id=cid,
                        task_ref=task_ref,
                        alias=claimant_aliases.get(cid, ""),
                        title=title,
                    ),
                )
                await publish_team_event(
                    redis,
                    TeamTaskUnclaimedEvent(
                        team_id=team_id,
                        task_ref=task_ref,
                        alias=claimant_aliases.get(cid, ""),
                        title=title or "",
                    ),
                )

    await publish_event(
        redis,
        TaskStatusChangedEvent(
            workspace_id=actor_workspace_id,
            team_id=team_id,
            task_ref=task_ref,
            old_status=context.get("old_status", "") or "",
            new_status=new_status,
            title=title,
            alias=alias,
        ),
    )
    await publish_team_event(
        redis,
        TeamTaskStatusChangedEvent(
            team_id=team_id,
            task_ref=task_ref,
            title=title or "",
            old_status=context.get("old_status", "") or "",
            new_status=new_status,
        ),
    )


async def _cascade_task_deleted(redis: Redis, db_infra: "DatabaseInfra", context: dict) -> None:
    """Release all claims on a deleted task and publish unclaim events.

    The task.deleted hook provides {task_id, task_ref}; use task_id as the
    source of truth for team lookup so colliding task refs cannot release
    claims in another team.
    """
    task_id = context.get("task_id", "").strip()
    task_ref = context.get("task_ref", "").strip()
    if not task_id or not task_ref:
        return

    aweb_db = db_infra.get_manager("aweb")
    task_row = await aweb_db.fetch_one(
        "SELECT team_id FROM {{tables.tasks}} WHERE task_id = $1",
        task_id,
    )
    if task_row is None:
        return

    team_id = str(task_row["team_id"])
    claimant_ids = await release_task_claims(
        db_infra,
        team_id=team_id,
        task_ref=task_ref,
    )
    if claimant_ids:
        claimant_aliases = await fetch_workspace_aliases(db_infra, team_id, claimant_ids)
        for cid in claimant_ids:
            await publish_event(
                redis,
                TaskUnclaimedEvent(
                    workspace_id=cid,
                    task_ref=task_ref,
                    alias=claimant_aliases.get(cid, ""),
                    title=context.get("title"),
                ),
            )
            await publish_team_event(
                redis,
                TeamTaskUnclaimedEvent(
                    team_id=team_id,
                    task_ref=task_ref,
                    alias=claimant_aliases.get(cid, ""),
                    title=str(context.get("title") or ""),
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

    elif isinstance(event, ChatMessageEvent):
        event.from_alias = await _alias_for(redis, event.workspace_id)
        aweb_db = db_infra.get_manager("aweb")
        if event.session_id and event.workspace_id:
            participants = await aweb_db.fetch_all(
                "SELECT alias FROM {{tables.chat_participants}} "
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

    elif isinstance(event, TaskCreatedEvent):
        aweb_db = db_infra.get_manager("aweb")
        workspace = await aweb_db.fetch_one(
            """
            SELECT alias
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND deleted_at IS NULL
            """,
            event.workspace_id,
        )
        if workspace and workspace.get("alias"):
            event.alias = workspace["alias"]
        else:
            event.alias = await _alias_for(redis, event.workspace_id)

    elif isinstance(event, (ReservationAcquiredEvent, ReservationReleasedEvent)):
        event.alias = await _alias_for(redis, event.workspace_id)


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
            workspace_id=ctx.get("actor_workspace_id", ""),
            team_id=ctx.get("team_id", ""),
            task_ref=ctx.get("task_ref", ""),
            title=ctx.get("title"),
        )

    if event_type == "reservation.acquired":
        return ReservationAcquiredEvent(
            workspace_id=ctx.get("holder_workspace_id", ""),
            paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
            ttl_seconds=ctx.get("ttl_seconds", 0),
        )

    if event_type == "reservation.released":
        return ReservationReleasedEvent(
            workspace_id=ctx.get("holder_workspace_id", ""),
            paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
        )

    return None


def _translate_team_event(event_type: str, ctx: dict):
    if event_type == "message.sent":
        team_id = str(ctx.get("team_id", "")).strip()
        if not team_id:
            return None
        return TeamMessageSentEvent(
            team_id=team_id,
            message_id=str(ctx.get("message_id", "")).strip(),
            from_alias=str(ctx.get("from_alias", "")).strip(),
            to_alias=str(ctx.get("to_alias", "")).strip(),
            subject=str(ctx.get("subject", "") or ""),
            priority=str(ctx.get("priority", "normal") or "normal"),
        )

    if event_type == "task.created":
        team_id = str(ctx.get("team_id", "")).strip()
        if not team_id:
            return None
        return TeamTaskCreatedEvent(
            team_id=team_id,
            task_ref=str(ctx.get("task_ref", "")).strip(),
            title=str(ctx.get("title", "") or ""),
            status="open",
        )

    return None
