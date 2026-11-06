"""Bounded, value-free activity projection in the console's authority transaction.

The caller owns OWNER/S4/F6/session checks. This service only reads original
operational records; mutable definitions and response entities have no seam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from pgdbm.core import TransactionManager


@dataclass(frozen=True)
class ActivityCursor:
    occurred_at: datetime
    event_id: UUID

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("an activity cursor requires an aware timestamp")
        if not isinstance(self.event_id, UUID):
            raise ValueError("an activity cursor requires an event UUID")


@dataclass(frozen=True)
class ActivityEntry:
    event_id: UUID
    occurred_at: datetime
    install_generation: int
    action: str
    outcome: str | None
    refusal_code: str | None
    principal_did: str | None
    secret_id: str | None
    secret_ref: str | None
    request_id: str | None
    request_ref: str | None
    dispatch_id: UUID | None
    operation_id: str | None
    operation_digest: str | None
    job_id: str | None
    job_digest: str | None
    runner_id: str | None
    approval_id: str | None
    approval_ref: str | None
    principal_alias: str | None = None


@dataclass(frozen=True)
class ActivityPage:
    entries: tuple[ActivityEntry, ...]
    next_cursor: ActivityCursor | None


def _text(payload, name: str) -> str | None:
    value = payload.get(name)
    return value if isinstance(value, str) else None


def _principal_alias(actor: object, principal_did: str | None) -> str | None:
    if not isinstance(actor, dict) or not isinstance(principal_did, str):
        return None
    if principal_did.startswith("did:aw:"):
        bound = actor.get("did_aw") == principal_did
    elif principal_did.startswith("did:key:"):
        bound = actor.get("did_key") == principal_did and actor.get("did_aw") is None
    else:
        return None
    alias = actor.get("alias")
    return alias if bound and isinstance(alias, str) and alias.strip() else None


class ActivityReads:
    async def page(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        before: ActivityCursor | None = None,
        limit: int = 50,
    ) -> ActivityPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("activity page limit must be between 1 and 100")
        if before is not None and not isinstance(before, ActivityCursor):
            raise ValueError("activity pagination requires an ActivityCursor")
        rows = await tx.fetch_all(
            "SELECT e.event_id,e.occurred_at,e.install_generation,e.action,e.dispatch_id,"
            "e.payload,e.actor,e.correlation,i.principal_did,i.request_id,i.intent_id,"
            "i.secret_id,i.operation_id,i.operation_digest"
            " FROM {{tables.broker_use_events}} e"
            " LEFT JOIN {{tables.use_contexts}} c ON c.dispatch_id=e.dispatch_id"
            " AND c.installation_id=e.installation_id AND c.team_id=e.team_id"
            " AND c.install_generation=e.install_generation"
            " LEFT JOIN {{tables.intents}} i ON i.intent_id=c.intent_id"
            " AND i.installation_id=c.installation_id AND i.team_id=c.team_id"
            " AND i.install_generation=c.install_generation"
            " WHERE e.installation_id=$1 AND e.team_id=$2"
            " AND ($3::timestamptz IS NULL OR (e.occurred_at,e.event_id)<($3,$4::uuid))"
            " ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT $5",
            installation_id,
            team_id,
            None if before is None else before.occurred_at,
            None if before is None else before.event_id,
            limit + 1,
        )
        entries = []
        for row in rows[:limit]:
            payload = json.loads(row["payload"])
            correlation = json.loads(row["correlation"])
            # Historical events predate correlation snapshots. Only original,
            # immutable intent columns may fill those gaps; never live records.
            for name, column in (
                ("principal_did", "principal_did"),
                ("secret_id", "secret_id"),
                ("request_id", "request_id"),
                ("request_ref", "intent_id"),
                ("operation_id", "operation_id"),
                ("operation_digest", "operation_digest"),
            ):
                if name not in correlation and row[column] is not None:
                    correlation[name] = row[column]
            entries.append(
                ActivityEntry(
                    event_id=row["event_id"],
                    occurred_at=row["occurred_at"],
                    install_generation=row["install_generation"],
                    action=row["action"],
                    outcome=_text(payload, "dispatch_state") or _text(payload, "approval_decision"),
                    refusal_code=_text(payload, "refusal_code"),
                    principal_did=_text(correlation, "principal_did"),
                    principal_alias=_principal_alias(
                        json.loads(row["actor"]), _text(correlation, "principal_did")
                    ),
                    secret_id=_text(correlation, "secret_id"),
                    secret_ref=_text(correlation, "secret_ref"),
                    request_id=_text(correlation, "request_id"),
                    request_ref=_text(correlation, "request_ref"),
                    dispatch_id=row["dispatch_id"],
                    operation_id=_text(correlation, "operation_id"),
                    operation_digest=_text(correlation, "operation_digest"),
                    job_id=_text(correlation, "job_id"),
                    job_digest=_text(correlation, "job_digest"),
                    runner_id=_text(correlation, "runner_id"),
                    approval_id=_text(correlation, "approval_id"),
                    approval_ref=_text(correlation, "approval_ref"),
                )
            )
        cursor = None
        if len(rows) > limit:
            last = entries[-1]
            cursor = ActivityCursor(last.occurred_at, last.event_id)
        return ActivityPage(tuple(entries), cursor)
