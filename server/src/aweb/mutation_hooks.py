"""Translate aweb mutation hooks into SSE events.

aweb fires app.state.on_mutation(event_type, context) after successful
mutations. This module registers a handler that publishes corresponding
Event dataclasses to Redis pub/sub for the SSE event stream.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable
from uuid import UUID

from redis.asyncio import Redis

from .claims import fetch_workspace_aliases
from .event_types import MutationEventType
from .events import (
    ChatMessageEvent,
    Event,
    MessageAcknowledgedEvent,
    MessageDeliveredEvent,
    ReservationAcquiredEvent,
    ReservationReleasedEvent,
    ReservationRenewedEvent,
    TaskClaimedEvent,
    TaskCreatedEvent,
    TaskStatusChangedEvent,
    TaskUnclaimedEvent,
    TeamAgentStatusEvent,
    TeamEvent,
    TeamReservationAcquiredEvent,
    TeamReservationReleasedEvent,
    TeamReservationRenewedEvent,
    TeamTaskAssigneeChangedEvent,
    TeamTaskClaimedEvent,
    TeamTaskCreatedEvent,
    TeamTaskStatusChangedEvent,
    TeamTaskUnclaimedEvent,
    publish_chat_session_signal,
    publish_event,
    publish_team_event,
)
from .hooks import (
    MutationCallback,
    MutationDeliveryFailed,
    MutationDeliveryOutcome,
    MutationDeliveryStage,
    MutationDeliveryStatus,
)
from .identity_metadata import (
    lookup_identity_metadata_by_agent_id,
    lookup_identity_metadata_by_did,
)
from .lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from .presence import get_agent_presence, list_agent_presences_by_workspace_ids

if TYPE_CHECKING:
    from .db import DatabaseInfrastructure

logger = logging.getLogger(__name__)

# These mutations remain available to host callbacks. They deliberately have no
# native SSE projection; deletion has its separate coordination cascade.
INTENTIONALLY_UNPUBLISHED_EVENTS = frozenset(
    {
        MutationEventType.TASK_UPDATED,
        MutationEventType.TASK_COMMENT_ADDED,
        MutationEventType.TASK_DEPENDENCY_ADDED,
        MutationEventType.TASK_DEPENDENCY_REMOVED,
        MutationEventType.AGENT_DELETED,
        MutationEventType.TASK_DELETED,
        MutationEventType.ROOM_MESSAGE_SENT,
    }
)


def _event_is_encrypted(ctx: dict) -> bool:
    return str(ctx.get("content_mode") or "").strip() == "encrypted_v2"


def _event_subject(ctx: dict) -> str:
    if _event_is_encrypted(ctx):
        return ""
    return str(ctx.get("subject", "") or "")


async def _enrich_identity_context(
    db_infra: "DatabaseInfrastructure", context: dict
) -> dict:
    ctx = dict(context)
    identity_fields = (
        ("actor_agent_id", "actor_did", "actor_did_aw"),
        ("from_agent_id", "from_did", "from_did_aw"),
        ("holder_agent_id", "holder_did", "holder_did_aw"),
    )

    agent_ids = [
        str(ctx.get(agent_key, "")).strip()
        for agent_key, _, stable_key in identity_fields
        if not str(ctx.get(stable_key, "")).strip()
        and str(ctx.get(agent_key, "")).strip()
    ]
    dids = [
        str(ctx.get(did_key, "")).strip()
        for _, did_key, stable_key in identity_fields
        if not str(ctx.get(stable_key, "")).strip()
        and str(ctx.get(did_key, "")).strip()
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


async def _enrich_workspace_context(
    db_infra: "DatabaseInfrastructure", context: dict
) -> dict:
    ctx = dict(context)
    workspace_fields = (
        ("actor_workspace_id", "actor_agent_id", "team_id"),
        ("holder_workspace_id", "holder_agent_id", "team_id"),
    )

    agent_ids = [
        str(ctx.get(agent_key, "")).strip()
        for workspace_key, agent_key, _team_key in workspace_fields
        if not str(ctx.get(workspace_key, "")).strip()
        and str(ctx.get(agent_key, "")).strip()
    ]
    if not agent_ids:
        return ctx

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, team_id, workspace_id
        FROM {{tables.workspaces}}
        WHERE deleted_at IS NULL AND agent_id = ANY($1::uuid[])
        ORDER BY updated_at DESC, workspace_id DESC
        """,
        [UUID(agent_id) for agent_id in agent_ids],
    )
    workspace_by_agent_team: dict[tuple[str, str], str] = {}
    workspace_by_agent: dict[str, str] = {}
    for row in rows:
        agent_id = str(row["agent_id"])
        team_id = str(row["team_id"])
        workspace_id = str(row["workspace_id"])
        workspace_by_agent_team.setdefault((agent_id, team_id), workspace_id)
        workspace_by_agent.setdefault(agent_id, workspace_id)

    for workspace_key, agent_key, team_key in workspace_fields:
        if str(ctx.get(workspace_key, "")).strip():
            continue
        agent_id = str(ctx.get(agent_key, "")).strip()
        team_id = str(ctx.get(team_key, "")).strip()
        workspace_id = (
            workspace_by_agent_team.get((agent_id, team_id), "")
            if team_id
            else workspace_by_agent.get(agent_id, "")
        )
        if workspace_id:
            ctx[workspace_key] = workspace_id
    return ctx


def create_mutation_handler(
    redis: Redis, db_infra: DatabaseInfrastructure
) -> MutationCallback:
    """Create an on_mutation callback that publishes SSE events.

    The returned async callable matches aweb's hook signature:
        async def on_mutation(event_type: str, context: dict) -> None
    """

    async def on_mutation(event_type: str, context: dict) -> MutationDeliveryOutcome:
        """Translate the mutation and report incomplete native work by stage."""
        failures: list[MutationDeliveryStage] = []

        def outcome() -> MutationDeliveryOutcome:
            """Return all reached failures while preserving first-failure order."""
            return MutationDeliveryOutcome(
                status=MutationDeliveryStatus.FAILED
                if failures
                else MutationDeliveryStatus.DELIVERED,
                failed_stages=tuple(dict.fromkeys(failures)),
            )

        try:
            context = await _enrich_identity_context(db_infra, context)
            context = await _enrich_workspace_context(db_infra, context)
        except Exception:
            logger.exception("Mutation context enrichment failed")
            failures.append(MutationDeliveryStage.CONTEXT_ENRICHMENT)

        # Additional event publication and the legacy agent cleanup path.
        if event_type == MutationEventType.AGENT_DELETED:
            try:
                await _cascade_agent_deleted(redis, db_infra, context)
            except Exception:
                logger.error("Failed to cascade agent.deleted", exc_info=True)
                failures.append(MutationDeliveryStage.AGENT_CASCADE)

        status_changed = event_type == MutationEventType.TASK_STATUS_CHANGED
        if status_changed or (
            event_type == MutationEventType.TASK_UPDATED
            and context.get("released_claim_workspace_ids")
        ):
            try:
                await _announce_task_claim_changes(
                    redis, db_infra, context, status_changed=status_changed
                )
            except Exception:
                logger.error(
                    "Failed to publish task claim changes for %s",
                    event_type,
                    exc_info=True,
                )
                failures.append(MutationDeliveryStage.TASK_STATUS_CASCADE)

        if event_type == MutationEventType.TASK_DELETED:
            try:
                await _publish_task_unclaims(
                    redis, db_infra, context, team_id=context.get("team_id")
                )
            except Exception:
                logger.error(
                    "Failed to publish task.deleted claim releases", exc_info=True
                )
                failures.append(MutationDeliveryStage.PUBLICATION)

        try:
            if event_type in INTENTIONALLY_UNPUBLISHED_EVENTS:
                return outcome()
            event = _translate(event_type, context)
            team_event = _translate_team_event(event_type, context)
            if event is None and team_event is None:
                return outcome()
            if event is not None:
                if not event.workspace_id:
                    logger.warning(
                        "Skipping %s event: no workspace_id in context", event_type
                    )
                else:
                    try:
                        await _enrich(event, redis, db_infra, context)
                    except Exception:
                        logger.warning(
                            "Enrichment failed for %s, publishing with defaults",
                            event_type,
                            exc_info=True,
                        )
                    await publish_event(redis, event)
            if team_event is not None:
                await publish_team_event(redis, team_event)
            if event_type == MutationEventType.CHAT_MESSAGE_SENT:
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
            failures.append(MutationDeliveryStage.PUBLICATION)
        return outcome()

    return on_mutation


async def _cascade_agent_deleted(
    redis: Redis, db_infra: "DatabaseInfrastructure", context: dict
) -> None:
    """Cascade ephemeral identity deletion to workspace cleanup.

    Soft-deletes the agent's workspace, releases task claims, publishes
    unclaim events, and clears presence.

    Note: agent.retired is intentionally NOT cascaded here. Retired agents
    designate a successor and their workspace data may be needed for handoff.
    """
    agent_id = context.get("agent_id", "").strip()
    if not agent_id:
        return

    aweb_db = db_infra.get_manager("aweb")
    result = await apply_lifecycle_cascade(
        aweb_db,
        redis,
        LifecycleCascadeRequest(
            operation="agent_deleted_cascade",
            actor=LifecycleActor(
                actor_id=str(
                    context.get("actor_agent_id") or context.get("agent_id") or ""
                ),
                actor_type="system",
                authority="mutation_hook",
            ),
            team_id=str(context.get("team_id") or "") or None,
            target_agent_id=agent_id,
            workspace_scope="latest_for_agent",
        ),
        registry_client=None,
    )
    if result.errors:
        logger.warning(
            "agent.deleted cascade skipped due to lifecycle precondition errors",
            extra={
                "agent_id": agent_id,
                "errors": [error.code for error in result.errors],
            },
        )
        raise MutationDeliveryFailed(
            MutationDeliveryOutcome(
                status=MutationDeliveryStatus.FAILED,
                failed_stages=(MutationDeliveryStage.AGENT_CASCADE,),
            )
        )

    logger.info(
        "Cascaded agent deletion coordination cleanup "
        "(agent_id=%s, workspaces=%d, claims_released=%d, post_commit_status=%s)",
        agent_id,
        len(result.workspace_changes),
        result.task_unclaim_count,
        result.post_commit_status,
    )


async def _announce_task_claim_changes(
    redis: Redis,
    db_infra: "DatabaseInfrastructure",
    context: dict,
    *,
    status_changed: bool,
) -> None:
    """Announce committed releases before a replacement claim."""
    actor_workspace_id = context.get("actor_workspace_id", "").strip()
    task_ref = context.get("task_ref", "").strip()
    new_status = context.get("new_status", "")
    title = context.get("title")
    claim_preacquired = bool(context.get("claim_preacquired", False))

    if not task_ref:
        return
    aweb_db = db_infra.get_manager("aweb")
    task = await aweb_db.fetch_one(
        "SELECT team_id FROM {{tables.tasks}} WHERE task_id=$1",
        context.get("task_id"),
    )
    if task is None:
        return
    team_id = str(task["team_id"])
    alias = context.get("actor_alias") or ""
    await _publish_task_unclaims(redis, db_infra, context, team_id=team_id)
    if new_status == "in_progress" and claim_preacquired and actor_workspace_id:
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
    if status_changed and actor_workspace_id:
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


async def _publish_task_unclaims(
    redis: Redis,
    db_infra: "DatabaseInfrastructure",
    context: dict,
    *,
    team_id: str | None,
) -> None:
    """Publish the releases recorded by the committed task transaction."""
    task_ref = context.get("task_ref") or ""
    claimant_ids = context.get("released_claim_workspace_ids") or []
    if not task_ref or not claimant_ids:
        return
    if not team_id:
        raise ValueError("Committed claim releases require a team_id")
    claimant_aliases = await fetch_workspace_aliases(db_infra, team_id, claimant_ids)
    title = context.get("title")
    for workspace_id in claimant_ids:
        alias = claimant_aliases.get(workspace_id, "")
        await publish_event(
            redis,
            TaskUnclaimedEvent(
                workspace_id=workspace_id, task_ref=task_ref, alias=alias, title=title
            ),
        )
        await publish_team_event(
            redis,
            TeamTaskUnclaimedEvent(
                team_id=team_id, task_ref=task_ref, alias=alias, title=title or ""
            ),
        )


async def _alias_for(redis: Redis, workspace_id: str) -> str:
    """Resolve alias from Redis presence. Returns empty string if unavailable."""
    presence = await get_agent_presence(redis, workspace_id)
    if presence is None:
        return ""
    return presence.get("alias", "")


async def _enrich(
    event: Event, redis: Redis, db_infra: DatabaseInfrastructure, context: dict
) -> None:
    """Add aliases, subjects, and previews via Redis/DB lookups."""

    if isinstance(event, MessageDeliveredEvent):
        workspaces = list(dict.fromkeys((event.from_workspace, event.workspace_id)))
        presence = await list_agent_presences_by_workspace_ids(redis, workspaces)
        aliases = {row.get("workspace_id"): row.get("alias", "") for row in presence}
        event.from_alias = aliases.get(event.from_workspace, "")
        event.to_alias = aliases.get(event.workspace_id, "")

    elif isinstance(event, MessageAcknowledgedEvent):
        if event.message_id:
            aweb_db = db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT from_alias, subject, content_mode FROM {{tables.messages}} WHERE message_id = $1",
                UUID(event.message_id),
            )
            if row:
                event.from_alias = row["from_alias"]
                event.content_mode = str(
                    row.get("content_mode") or "legacy_plaintext_v1"
                )
                event.encrypted = event.content_mode == "encrypted_v2"
                event.subject = "" if event.encrypted else (row["subject"] or "")

    elif isinstance(event, ChatMessageEvent):
        event.from_alias = await _alias_for(redis, event.workspace_id)
        aweb_db = db_infra.get_manager("aweb")
        # A sender that already holds the recipients' aliases and the preview
        # supplies them; only an event without them (a recovered outbox row)
        # reads them back.
        if event.session_id and event.workspace_id and "to_aliases" not in context:
            participants = await aweb_db.fetch_all(
                "SELECT alias FROM {{tables.chat_participants}} "
                "WHERE session_id = $1 AND agent_id != $2",
                UUID(event.session_id),
                UUID(event.workspace_id),
            )
            event.to_aliases = [r["alias"] for r in participants]
        if event.message_id and "preview" not in context:
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

    elif isinstance(
        event,
        (ReservationAcquiredEvent, ReservationReleasedEvent, ReservationRenewedEvent),
    ):
        event.alias = await _alias_for(redis, event.workspace_id)


def _workspace_mail_sent(ctx: dict) -> Event | None:
    encrypted = _event_is_encrypted(ctx)
    return MessageDeliveredEvent(
        workspace_id=ctx.get("to_agent_id", ""),
        message_id=ctx.get("message_id", ""),
        from_workspace=ctx.get("from_agent_id", ""),
        subject=_event_subject(ctx),
        content_mode=str(ctx.get("content_mode") or "legacy_plaintext_v1"),
        encrypted=encrypted,
    )


def _workspace_mail_acknowledged(ctx: dict) -> Event | None:
    encrypted = _event_is_encrypted(ctx)
    return MessageAcknowledgedEvent(
        workspace_id=ctx.get("agent_id", ""),
        message_id=ctx.get("message_id", ""),
        subject=_event_subject(ctx),
        content_mode=str(ctx.get("content_mode") or "legacy_plaintext_v1"),
        encrypted=encrypted,
    )


def _workspace_chat_message_sent(ctx: dict) -> Event | None:
    return ChatMessageEvent(
        workspace_id=ctx.get("from_agent_id", ""),
        session_id=ctx.get("session_id", ""),
        message_id=ctx.get("message_id", ""),
        to_aliases=list(ctx.get("to_aliases") or []),
        preview=str(ctx.get("preview") or ""),
    )


def _workspace_task_created(ctx: dict) -> Event | None:
    return TaskCreatedEvent(
        workspace_id=ctx.get("actor_workspace_id", ""),
        team_id=ctx.get("team_id", ""),
        task_ref=ctx.get("task_ref", ""),
        title=ctx.get("title"),
    )


def _workspace_task_claimed(ctx: dict) -> Event | None:
    return TaskClaimedEvent(
        workspace_id=ctx.get("actor_workspace_id", "") or ctx.get("workspace_id", ""),
        task_ref=ctx.get("task_ref", ""),
        alias=ctx.get("actor_alias", "") or ctx.get("alias", ""),
        title=ctx.get("title"),
    )


def _workspace_task_unclaimed(ctx: dict) -> Event | None:
    return TaskUnclaimedEvent(
        workspace_id=ctx.get("actor_workspace_id", "") or ctx.get("workspace_id", ""),
        task_ref=ctx.get("task_ref", ""),
        alias=ctx.get("actor_alias", "") or ctx.get("alias", ""),
        title=ctx.get("title"),
    )


def _workspace_reservation_acquired(ctx: dict) -> Event | None:
    return ReservationAcquiredEvent(
        workspace_id=ctx.get("holder_workspace_id", ""),
        paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
        ttl_seconds=ctx.get("ttl_seconds", 0),
    )


def _workspace_reservation_released(ctx: dict) -> Event | None:
    return ReservationReleasedEvent(
        workspace_id=ctx.get("holder_workspace_id", ""),
        paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
    )


def _workspace_reservation_renewed(ctx: dict) -> Event | None:
    return ReservationRenewedEvent(
        workspace_id=ctx.get("holder_workspace_id", ""),
        paths=[ctx["resource_key"]] if ctx.get("resource_key") else [],
        ttl_seconds=ctx.get("ttl_seconds", 0),
    )


_WORKSPACE_BUILDERS: dict[str, Callable[[dict], Event | None]] = {
    MutationEventType.MAIL_SENT: _workspace_mail_sent,
    MutationEventType.MAIL_ACKNOWLEDGED: _workspace_mail_acknowledged,
    MutationEventType.CHAT_MESSAGE_SENT: _workspace_chat_message_sent,
    MutationEventType.TASK_CREATED: _workspace_task_created,
    MutationEventType.TASK_CLAIMED: _workspace_task_claimed,
    MutationEventType.TASK_UNCLAIMED: _workspace_task_unclaimed,
    MutationEventType.RESERVATION_ACQUIRED: _workspace_reservation_acquired,
    MutationEventType.RESERVATION_RELEASED: _workspace_reservation_released,
    MutationEventType.RESERVATION_RENEWED: _workspace_reservation_renewed,
}


def _translate(event_type: str, ctx: dict) -> Event | None:
    """Build the supported stream projection; custom names remain unhandled."""
    builder = _WORKSPACE_BUILDERS.get(event_type)
    return builder(ctx) if builder is not None else None


def _team_id_from_context(ctx: dict) -> str:
    return str(ctx.get("team_id", "")).strip()


def _paths_from_context(ctx: dict) -> list[str]:
    paths = ctx.get("paths")
    if isinstance(paths, list):
        return [str(path).strip() for path in paths if str(path).strip()]
    resource_key = str(ctx.get("resource_key", "")).strip()
    return [resource_key] if resource_key else []


def _team_agent_status(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamAgentStatusEvent(
        team_id=team_id,
        agent_id=str(ctx.get("agent_id", "") or ""),
        alias=str(ctx.get("alias", "") or ""),
        reachable=str(ctx.get("reachable", "") or ""),
        reason_code=ctx.get("reason_code"),
        reason_text=ctx.get("reason_text"),
        fixing_by=ctx.get("fixing_by"),
        fixing_text=ctx.get("fixing_text"),
        observed_at=str(ctx.get("observed_at", "") or ""),
        valid_until=str(ctx.get("valid_until", "") or ""),
    )


def _team_task_created(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamTaskCreatedEvent(
        team_id=team_id,
        task_ref=str(ctx.get("task_ref", "")).strip(),
        alias=str(ctx.get("actor_alias", "") or ""),
        title=str(ctx.get("title", "") or ""),
        status="open",
        assignee_alias=ctx.get("assignee_alias"),
    )


def _team_task_status_changed(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamTaskStatusChangedEvent(
        team_id=team_id,
        task_ref=str(ctx.get("task_ref", "")).strip(),
        alias=str(ctx.get("actor_alias", "") or ""),
        title=str(ctx.get("title", "") or ""),
        old_status=str(ctx.get("old_status", "") or ""),
        new_status=str(ctx.get("new_status", "") or ""),
        assignee_alias=ctx.get("assignee_alias"),
    )


def _team_task_assignee_changed(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamTaskAssigneeChangedEvent(
        team_id=team_id,
        task_ref=str(ctx.get("task_ref", "")).strip(),
        alias=str(ctx.get("actor_alias", "") or ""),
        title=str(ctx.get("title", "") or ""),
        old_assignee_alias=ctx.get("old_assignee_alias"),
        assignee_alias=ctx.get("assignee_alias"),
    )


def _team_task_claimed(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamTaskClaimedEvent(
        team_id=team_id,
        task_ref=str(ctx.get("task_ref", "")).strip(),
        alias=str(ctx.get("actor_alias", "") or ctx.get("alias", "") or ""),
        title=str(ctx.get("title", "") or ""),
    )


def _team_task_unclaimed(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamTaskUnclaimedEvent(
        team_id=team_id,
        task_ref=str(ctx.get("task_ref", "")).strip(),
        alias=str(ctx.get("actor_alias", "") or ctx.get("alias", "") or ""),
        title=str(ctx.get("title", "") or ""),
    )


def _team_reservation_acquired(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamReservationAcquiredEvent(
        team_id=team_id,
        alias=str(ctx.get("alias", "") or ctx.get("holder_alias", "")).strip(),
        paths=_paths_from_context(ctx),
    )


def _team_reservation_released(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamReservationReleasedEvent(
        team_id=team_id,
        alias=str(ctx.get("alias", "") or ctx.get("holder_alias", "")).strip(),
        paths=_paths_from_context(ctx),
    )


def _team_reservation_renewed(ctx: dict) -> TeamEvent | None:
    team_id = _team_id_from_context(ctx)
    if not team_id:
        return None
    return TeamReservationRenewedEvent(
        team_id=team_id,
        alias=str(ctx.get("alias", "") or ctx.get("holder_alias", "")).strip(),
        paths=_paths_from_context(ctx),
    )


_TEAM_BUILDERS: dict[str, Callable[[dict], TeamEvent | None]] = {
    MutationEventType.AGENT_STATUS: _team_agent_status,
    MutationEventType.TASK_CREATED: _team_task_created,
    MutationEventType.TASK_STATUS_CHANGED: _team_task_status_changed,
    MutationEventType.TASK_ASSIGNEE_CHANGED: _team_task_assignee_changed,
    MutationEventType.TASK_CLAIMED: _team_task_claimed,
    MutationEventType.TASK_UNCLAIMED: _team_task_unclaimed,
    MutationEventType.RESERVATION_ACQUIRED: _team_reservation_acquired,
    MutationEventType.RESERVATION_RELEASED: _team_reservation_released,
    MutationEventType.RESERVATION_RENEWED: _team_reservation_renewed,
}


def _translate_team_event(event_type: str, ctx: dict) -> TeamEvent | None:
    """Build the supported stream projection; custom names remain unhandled."""
    builder = _TEAM_BUILDERS.get(event_type)
    return builder(ctx) if builder is not None else None
