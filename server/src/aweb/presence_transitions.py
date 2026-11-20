"""Presence projections and atomic transitions, independent of stream readers.

Activity authority is workspace_activity (docs/aweb-sot.md, workspace lifecycle).
This owner publishes observations only; it never expires claims or grants.
"""

from __future__ import annotations

from aweb.member_team_key import current_member_sql

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from awid.registry import RegistryClient
from redis.asyncio import Redis
from redis.exceptions import WatchError
from starlette.requests import Request

from aweb.events import TeamAgentOfflineEvent, TeamAgentOnlineEvent, queue_team_event
from aweb.grant_liveness_policy import GrantLivenessFailurePolicy
from aweb.human_kind import agent_listing_predicate_sql
from aweb.workspace_activity import workspace_activity_by_id

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PresenceReconciliationResult:
    teams_observed: int
    teams_changed: int
    events_published: int


@dataclass(frozen=True)
class PresenceReconciliationFailure:
    team_id: str
    error: Exception


class PresenceReconciliationError(RuntimeError):
    """Some teams could not be observed/published; healthy teams still progress."""

    def __init__(self, failures: tuple[PresenceReconciliationFailure, ...]):
        self.failures = failures
        super().__init__(
            f"Presence reconciliation incomplete for {len(failures)} team(s)"
        )


async def team_online_aliases(
    db,
    redis: Redis | None,
    *,
    team_id: str,
    registry_client: RegistryClient,
    failure_policy: GrantLivenessFailurePolicy,
    request: Request | None = None,
) -> list[str]:
    """Read the same root/Redis/valid-grant activity used by lifecycle and displays."""
    rows = await db.fetch_all(
        f"""
        SELECT w.workspace_id, a.alias
        FROM {{{{tables.workspaces}}}} w
        JOIN {{{{tables.agents}}}} a ON a.agent_id=w.agent_id AND a.team_id=w.team_id
        WHERE w.team_id=$1 AND w.deleted_at IS NULL
          AND {current_member_sql("a")}
          AND {agent_listing_predicate_sql("a")}
        """,
        team_id,
    )
    activity = await workspace_activity_by_id(
        db,
        redis,
        workspace_ids=[str(row["workspace_id"]) for row in rows],
        registry_client=registry_client,
        failure_policy=failure_policy,
        request=request,
    )
    now = datetime.now(UTC)
    return sorted(
        {
            row["alias"]
            for row in rows
            if (observed := activity.get(str(row["workspace_id"]))) is not None
            and observed.is_online(now=now)
        }
    )


def _snapshot(raw: str | bytes | None) -> tuple[datetime | None, set[str]]:
    if raw is None:
        return None, set()
    state = json.loads(raw)
    if not isinstance(state, dict) or set(state) != {"observed_at", "online_aliases"}:
        raise ValueError("Malformed presence transition snapshot")
    aliases = state["online_aliases"]
    if not isinstance(aliases, list) or any(
        not isinstance(alias, str) or not alias for alias in aliases
    ):
        raise ValueError("Malformed presence transition aliases")
    observed_at = datetime.fromisoformat(state["observed_at"])
    if observed_at.tzinfo is None:
        raise ValueError("Presence transition time lacks timezone")
    return observed_at, set(aliases)


async def _publish_transition(
    redis: Redis,
    *,
    team_id: str,
    aliases: list[str],
    observed_at: datetime,
) -> int:
    # One small snapshot per registered team. Do not expire the ordering witness:
    # an older in-flight observer must never resurrect a removed alias.
    key = "presence-transitions:" + hashlib.sha256(team_id.encode()).hexdigest()
    state = json.dumps(
        {"observed_at": observed_at.isoformat(), "online_aliases": aliases}
    )
    for _ in range(4):
        async with redis.pipeline(transaction=True) as pipeline:
            try:
                await pipeline.watch(key)
                previous_at, previous = _snapshot(await pipeline.get(key))
                if previous_at is not None and previous_at >= observed_at:
                    return 0
                current = set(aliases)
                events = [
                    TeamAgentOnlineEvent(team_id=team_id, alias=alias)
                    for alias in sorted(current - previous)
                ] + [
                    TeamAgentOfflineEvent(team_id=team_id, alias=alias)
                    for alias in sorted(previous - current)
                ]
                pipeline.multi()
                pipeline.set(key, state)
                for event in events:
                    queue_team_event(pipeline, event)
                await pipeline.execute()
                return len(events)
            except WatchError:
                continue
    raise RuntimeError("Presence transition contention did not converge")


async def reconcile_presence(
    db_infra,
    redis: Redis,
    *,
    registry_client: RegistryClient,
) -> PresenceReconciliationResult:
    """Observe every team, atomically recording each transition with publication.

    Called by the shared native/HOST maintenance owner, never by viewers. Unknown
    grant authority cannot manufacture offline transitions. Failed teams retain
    their prior snapshot; after other teams are attempted an explicit error is
    raised. A result counts queued publications, not subscriber delivery.
    """
    db = db_infra.get_manager("aweb")
    teams = await db.fetch_all("SELECT team_id FROM {{tables.teams}} ORDER BY team_id")
    changed = published = 0
    failures = []
    for team in teams:
        team_id = team["team_id"]
        observed_at = datetime.now(UTC)
        try:
            aliases = await team_online_aliases(
                db,
                redis,
                team_id=team_id,
                registry_client=registry_client,
                failure_policy=GrantLivenessFailurePolicy.REQUIRE_KNOWN,
            )
            count = await _publish_transition(
                redis,
                team_id=team_id,
                aliases=aliases,
                observed_at=observed_at,
            )
            changed += bool(count)
            published += count
        except Exception as exc:
            logger.error(
                "Presence reconciliation failed for %s: %s",
                team_id,
                type(exc).__name__,
                exc_info=True,
            )
            failures.append(PresenceReconciliationFailure(team_id, exc))
    if failures:
        raise PresenceReconciliationError(tuple(failures))
    return PresenceReconciliationResult(len(teams), changed, published)
