"""Workspace activity shared by lifecycle eligibility and coordination readers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from redis.asyncio import Redis
from starlette.requests import Request
from awid.registry import RegistryClient

from .config import get_presence_ttl_seconds
from .grant_liveness import valid_grant_liveness_by_workspace
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

    def is_newer_than(self, *, cutoff: datetime) -> bool:
        """Whether any valid heartbeat observed activity strictly after the cutoff."""
        return self.last_seen_at is not None and self.last_seen_at > cutoff


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
    request: Request | None = None,
) -> dict[str, WorkspaceActivity]:
    """Combine the timestamps written by root, MCP and valid grant heartbeats.

    Implements docs/agent-health.md:366–368 and docs/aweb-sot.md:1199–1205.
    Grant heartbeats retain their separate records and cannot rewrite shared
    metadata; expired/revoked grants cannot keep a stale workspace alive.
    Missing Redis is supported for SQL-only embedding callers. A failed or
    malformed Redis read raises, so lifecycle cleanup cannot mistake it for
    proof of inactivity.
    """
    if not workspace_ids:
        return {}
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
        request=request,
        ttl_seconds=get_presence_ttl_seconds(),
    )
    presences = (
        await list_agent_presences_by_workspace_ids(redis, workspace_ids)
        if redis is not None
        else []
    )
    presence_by_id = {
        record["workspace_id"]: record
        for record in presences
        if record.get("workspace_id")
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
