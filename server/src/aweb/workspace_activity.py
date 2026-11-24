"""Workspace activity shared by lifecycle eligibility and coordination readers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from redis.asyncio import Redis
from starlette.requests import Request
from awid.registry import RegistryClient

from .config import get_presence_ttl_seconds
from .grant_liveness import (
    valid_grant_liveness_by_workspace,
    valid_grant_liveness_from_workspace_rows,
)
from .grant_liveness_policy import GrantLivenessFailurePolicy
from .presence import list_agent_presences_by_workspace_ids


class PresenceStatus(StrEnum):
    ACTIVE = "active"
    OFFLINE = "offline"


class WorkspaceActivityRefusal(StrEnum):
    STILL_ACTIVE = "local_workspace_still_active"


def workspace_stale_cutoff(*, now: datetime) -> datetime:
    """Use the configured window for all activity (docs/aweb-sot.md:1199–1205)."""
    return now - timedelta(seconds=get_presence_ttl_seconds())


@dataclass(frozen=True)
class WorkspaceActivity:
    last_seen_at: datetime | None
    presence: Mapping[str, str] | None

    def is_newer_than(self, *, cutoff: datetime, reserved_at: datetime | None = None) -> bool:
        """Check observed activity, with a reservation fallback for lifecycle callers."""
        timestamp = self.last_seen_at if self.last_seen_at is not None else reserved_at
        return timestamp is not None and timestamp > cutoff

    def is_online(self, *, now: datetime) -> bool:
        """All displays use the configured activity window (docs/agent-health.md)."""
        return self.is_newer_than(cutoff=workspace_stale_cutoff(now=now))

    def display_status(self, *, now: datetime) -> str:
        """Keep the observed status only while this workspace is online."""
        if not self.is_online(now=now):
            return PresenceStatus.OFFLINE
        return (self.presence or {}).get("status") or PresenceStatus.ACTIVE


@dataclass(frozen=True)
class AgentWorkspaceActivity:
    workspace: Mapping[str, Any]
    activity: WorkspaceActivity | None


def latest_workspace_activity(
    rows: Sequence[Mapping[str, Any]],
    observations: Mapping[str, WorkspaceActivity],
) -> dict[str, AgentWorkspaceActivity]:
    """Choose one agent context by effective activity, preserving row order for ties."""
    selected: dict[str, AgentWorkspaceActivity] = {}
    for row in rows:
        agent_id = str(row["agent_id"])
        candidate = observations.get(str(row["workspace_id"]))
        prior = selected.get(agent_id)
        previous = prior.activity if prior else None
        if prior is None or (
            candidate
            and candidate.last_seen_at
            and (
                previous is None
                or previous.last_seen_at is None
                or candidate.last_seen_at > previous.last_seen_at
            )
        ):
            selected[agent_id] = AgentWorkspaceActivity(row, candidate)
    return selected


def _presence_timestamp(presence: Mapping[str, str]) -> datetime | None:
    raw = presence.get("last_seen")
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("Workspace presence timestamp must be a string")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Workspace presence timestamp is malformed") from exc
    if value.tzinfo is None:
        raise ValueError("Workspace presence timestamp must have a timezone")
    return value.astimezone(UTC)


async def workspace_activity_by_id(
    db,
    redis: Redis | None,
    *,
    workspace_ids: list[str],
    registry_client: RegistryClient,
    failure_policy: GrantLivenessFailurePolicy,
    request: Request | None = None,
    workspace_rows: Sequence[Mapping[str, Any]] | None = None,
    presence_display_fields: tuple[str, ...] | None = None,
) -> dict[str, WorkspaceActivity]:
    """Combine the timestamps written by root, MCP and valid grant heartbeats.

    Implements docs/agent-health.md:366–368 and docs/aweb-sot.md:1199–1205.
    Grant heartbeats retain their separate records and cannot rewrite shared
    metadata; expired/revoked grants cannot keep a stale workspace alive.
    Missing Redis is supported for SQL-only embedding callers. A failed or
    malformed Redis read raises, so lifecycle cleanup cannot mistake it for
    proof of inactivity.
    A projected display still reads workspace, team and timestamp evidence.
    """
    if not workspace_ids:
        return {}
    # A roster may lend its actual workspace/candidate statement. Other callers,
    # including destructive lifecycle checks, still acquire their own evidence.
    if workspace_rows is None:
        rows = await db.fetch_all(
            """
            SELECT workspace_id, team_id, agent_id, last_seen_at
            FROM {{tables.workspaces}}
            WHERE workspace_id = ANY($1::uuid[]) AND deleted_at IS NULL
            """,
            [UUID(value) for value in workspace_ids],
        )
        grants = await valid_grant_liveness_by_workspace(
            db,
            workspace_ids,
            registry_client=registry_client,
            failure_policy=failure_policy,
            request=request,
            ttl_seconds=get_presence_ttl_seconds(),
        )
    else:
        grants = await valid_grant_liveness_from_workspace_rows(
            workspace_rows,
            registry_client=registry_client,
            failure_policy=failure_policy,
            request=request,
        )
        rows = list({str(row["workspace_id"]): row for row in workspace_rows}.values())
    workspace_ids = list(dict.fromkeys(workspace_ids))
    fields = (
        ("workspace_id", "team_id", "last_seen", *presence_display_fields)
        if presence_display_fields is not None else None
    )
    presences = (
        await list_agent_presences_by_workspace_ids(redis, workspace_ids, fields=fields)
        if redis is not None
        else []
    )
    presence_by_id = {
        record["workspace_id"]: record for record in presences if record.get("workspace_id")
    }
    result = {}
    for row in rows:
        workspace_id = str(row["workspace_id"])
        seen = [row["last_seen_at"]] if row["last_seen_at"] is not None else []
        presence = presence_by_id.get(workspace_id)
        if presence is not None and presence.get("team_id") != row["team_id"]:
            presence = None
        if presence is not None:
            timestamp = _presence_timestamp(presence)
            if timestamp is not None:
                seen.append(timestamp)
        grant = grants.get(workspace_id)
        if grant is not None and str(grant["subject_agent_id"]) == str(row["agent_id"]):
            seen.append(grant["last_seen_at"])
        result[workspace_id] = WorkspaceActivity(
            last_seen_at=max(seen) if seen else None, presence=presence
        )
    return result
