"""Ingest admission steps that need neither the team's server nor AWID: the
event's schema and a client member's quota (audit-substrate.md §B2)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.catalog import load_catalog
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.ingest import ClientQuota, IngestRefused, charge_client_quota, check_schema

from .fixtures import TEAM_ID, signed_event

AWEB_ROOT = Path(__file__).resolve().parents[3]
CATALOG = load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())
RECEIVED = datetime(2026, 10, 20, 12, 0, 5, tzinfo=UTC)


def _event(kind: str, **changes):
    signing, signature = signed_event(kind, **changes)
    return hook_envelope.verify(signing, signature, team_id=TEAM_ID)


@pytest.mark.parametrize("kind", ["core", "app", "client"])
def test_an_allowed_event_passes_the_schema(kind: str) -> None:
    check_schema(_event(kind), CATALOG, received_at=RECEIVED)


def test_a_payload_outside_its_allowlist_is_refused_with_its_fault() -> None:
    core = _event("core")
    payload = {**core.fields["payload"], "subject": "not in the allowlist"}
    with pytest.raises(IngestRefused) as caught:
        check_schema(_event("core", payload=payload), CATALOG, received_at=RECEIVED)
    assert (caught.value.status, caught.value.code) == (422, "schema_unknown_field")


def test_an_event_from_the_future_is_refused() -> None:
    later = (RECEIVED + timedelta(seconds=301)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with pytest.raises(IngestRefused) as caught:
        check_schema(_event("core", occurred_at=later), CATALOG, received_at=RECEIVED)
    assert (caught.value.status, caught.value.code) == (422, "occurred_after_receipt")
    within = (RECEIVED + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    check_schema(_event("core", occurred_at=within), CATALOG, received_at=RECEIVED)


def test_an_event_of_another_catalog_is_refused() -> None:
    other = type(CATALOG)(
        id="aweb.hooks", version=2, hooks=CATALOG.hooks, precedence=CATALOG.precedence
    )
    with pytest.raises(IngestRefused) as caught:
        check_schema(_event("core"), other, received_at=RECEIVED)
    assert (caught.value.status, caught.value.code) == (422, "unknown_catalog")


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_ingest")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


QUOTA = ClientQuota(events_per_minute=3, bytes_per_minute=1000)


async def _charge(db, *, member: str = "c_41", size: int = 100, now: datetime = RECEIVED) -> None:
    async with db.transaction() as tx:
        await charge_client_quota(tx, QUOTA, team_id=TEAM_ID, member=member, size=size, now=now)


async def test_a_member_is_held_to_its_event_rate(db: AsyncDatabaseManager) -> None:
    for _ in range(3):
        await _charge(db)
    with pytest.raises(IngestRefused) as caught:
        await _charge(db)
    assert (caught.value.status, caught.value.code) == (429, "client_quota_exceeded")
    await _charge(db, member="c_77")
    await _charge(db, now=RECEIVED + timedelta(minutes=1))


async def test_a_member_is_held_to_its_byte_rate(db: AsyncDatabaseManager) -> None:
    await _charge(db, size=900)
    with pytest.raises(IngestRefused) as caught:
        await _charge(db, size=101)
    assert caught.value.code == "client_quota_exceeded"
    await _charge(db, size=100)


async def test_a_refused_charge_counts_nothing(db: AsyncDatabaseManager) -> None:
    await _charge(db, size=1000)
    for _ in range(3):
        with pytest.raises(IngestRefused):
            await _charge(db, size=1)
    await _charge(db, size=0)
