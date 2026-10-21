"""Admitting a hook delivery to the log (audit-substrate.md §B2).

Admission is an ordered list of steps, each failing closed with its own
status and code: transport, binding, provenance, schema, dedup, append. The
steps here need neither the team's server nor AWID: the event's schema and a
client member's quota.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_naapp.hooks.catalog import Catalog, PayloadRefused
from aweb_naapp.hooks.envelope import Envelope

# How far an event's occurred_at may lead logs' clock: the delivery
# credential's own replay window.
CLOCK_SKEW = timedelta(seconds=300)
_EVENT_TIME = "%Y-%m-%dT%H:%M:%S.%fZ"


class IngestRefused(Exception):
    """A delivery logs does not admit: the HTTP status it answers and a stable code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.status = status
        self.code = code
        self.detail = detail


def check_schema(event: Envelope, catalog: Catalog, *, received_at: datetime) -> None:
    """Step 4: the event's catalog is the one logs reads, its payload is within
    its hook's allowlist, and it did not occur after logs received it."""
    named = event.fields["catalog"]
    if (named["id"], named["version"]) != (catalog.id, catalog.version):
        raise IngestRefused(422, "unknown_catalog", f"{named['id']} v{named['version']}")
    try:
        catalog.validate(event.hook, event.fields["payload"])
    except PayloadRefused as refused:
        raise IngestRefused(422, f"schema_{refused.code}", refused.field or "") from None
    occurred_at = datetime.strptime(event.fields["occurred_at"], _EVENT_TIME).replace(tzinfo=UTC)
    if occurred_at > received_at + CLOCK_SKEW:
        raise IngestRefused(422, "occurred_after_receipt", event.fields["occurred_at"])


@dataclass(frozen=True)
class ClientQuota:
    """How much one member's client events may add to the log per minute."""

    events_per_minute: int
    bytes_per_minute: int


async def charge_client_quota(
    tx: Any, quota: ClientQuota, *, team_id: str, member: str, size: int, now: datetime
) -> None:
    """Count one client event of ``size`` bytes against its member's minute, in
    the admission's transaction; past either limit it is refused (429) and,
    with the transaction, nothing is counted."""
    window = now.astimezone(UTC).replace(second=0, microsecond=0)
    row = await tx.fetch_one(
        """
        INSERT INTO {{tables.client_ingest_usage}} (team_id, member, window_start, events, bytes)
        VALUES ($1, $2, $3, 1, $4)
        ON CONFLICT (team_id, member, window_start)
        DO UPDATE SET events = {{tables.client_ingest_usage}}.events + 1,
                      bytes = {{tables.client_ingest_usage}}.bytes + EXCLUDED.bytes
        RETURNING events, bytes
        """,
        team_id,
        member,
        window,
        size,
    )
    if row["events"] > quota.events_per_minute or row["bytes"] > quota.bytes_per_minute:
        raise IngestRefused(429, "client_quota_exceeded", f"member {member}")
