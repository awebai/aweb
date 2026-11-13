"""A restored Logs never serves content purged after its backup
(audit-substrate.md §B6; D1's backup-tombstone rule, agent-pages.md §11).

Every purge leaves a tombstone, keyed by event id, in a separate purge-ledger
database that is never restored from a content backup. Logs reapplies the
tombstones before it serves, and a redelivered event that has one is appended
already purged. Real PostgreSQL, a real ``pg_dump`` backup and ``pg_restore``,
real deliveries through Logs' ingest route.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from aweb_naapp.hooks.strictjson import decode_base64url
from aweb_naapp_testing.databases import back_up, restore
from pgdbm import AsyncDatabaseManager

from aweb_logs.app import create_app
from aweb_logs.chain import open_receipt
from aweb_logs.export import export_bundle
from aweb_logs.ledger import load_epoch
from aweb_logs.purge_ledger import PurgeLedger
from aweb_logs.read_store import EventFilter, query
from aweb_logs.retention import apply_retention, purge
from aweb_logs.verify import verify_chain

from .deployment import no_mail
from .test_ingest_http import ORIGIN, World, world_fixture  # noqa: F401
from .test_retention import retention_setting

RETENTION_DAYS = 30


@asynccontextmanager
async def logs_started(world: World):
    """A Logs process started on ``world``'s databases as they are now, as an
    operator starts it after restoring the content database."""
    service = create_app(
        world.settings,
        email=no_mail(),
        awid_transport=world.coordination.registry.transport,
        team_server_transport=world.coordination.server.transport,
        now=lambda: world.now,
    )
    async with service.api_app.router.lifespan_context(service.api_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=service), base_url=ORIGIN
        ) as client:
            yield client


async def acknowledged(world: World, delivery, client: httpx.AsyncClient | None = None) -> dict:
    response = await (client or world.client).post(
        delivery.path, headers=delivery.headers, content=delivery.body
    )
    assert response.status_code == 200, response.text
    return response.json()


async def delivered(world: World, delivery, client: httpx.AsyncClient | None = None) -> str:
    return (await acknowledged(world, delivery, client))["event_id"]


def receipt_key(ack: dict) -> frozenset[str]:
    receipt = ack["receipt"]
    signed = open_receipt(
        decode_base64url(receipt["signing_bytes"], "receipt"), receipt["signature"]
    )
    return frozenset({signed.did_key})


async def position(db: AsyncDatabaseManager, team_id: str, event_id: str) -> tuple[int, int]:
    row = await db.fetch_one(
        "SELECT chain_epoch, team_seq FROM {{tables.chain_events}}"
        " WHERE team_id = $1 AND event_id = $2",
        team_id,
        UUID(event_id),
    )
    return row["chain_epoch"], row["team_seq"]


async def erase(world: World, event_id: str) -> str:
    """Purge one event as ``logs.erase`` does, through the purge every act uses."""
    act = f"logs.erase:{uuid4()}"
    team_id = world.member.team_id
    async with world.db.transaction() as tx:
        await purge(
            tx, PurgeLedger(world.ledger), team_id,
            [await position(world.db, team_id, event_id)], act=act,
        )  # fmt: skip
    return act


async def stored_content(world: World) -> dict[str, str | None]:
    """Each stored event's purge act, None while its content is kept."""
    rows = await world.db.fetch_all(
        "SELECT event_id, signing_bytes IS NULL AS purged, purge_act"
        " FROM {{tables.chain_events}} WHERE team_id = $1",
        world.member.team_id,
    )
    return {str(row["event_id"]): row["purge_act"] if row["purged"] else None for row in rows}


async def exported_content(world: World) -> dict[str, bool]:
    """Whether each event in the team's export carries its content."""
    lines = [json.loads(line) async for line in export_bundle(world.db, world.member.team_id)]
    events = [line["event"] for line in lines if "event" in line]
    return {event["link"]["event_id"]: "content" in event for event in events}


async def queried_content(world: World) -> dict[str, bool]:
    """Whether a reader's query shows each event's content."""
    page = await query(world.db, world.member.team_id, EventFilter())
    return {event["event_id"]: not event.get("purged", False) for event in page.events}


async def test_a_restored_logs_serves_no_content_purged_after_its_backup(world, tmp_path):
    kept = await delivered(world, world.delivery("app"))
    erased = await delivered(world, world.delivery("app"))
    expired = await delivered(world, world.delivery("core"))
    backup = await back_up(world.db, tmp_path / "logs-content.dump")

    erase_act = await erase(world, erased)
    retention_event = await retention_setting(
        world.db, world.member.team_id, "post-mutation-hook", days=RETENTION_DAYS
    )
    await apply_retention(
        world.db,
        PurgeLedger(world.ledger),
        now=world.now + timedelta(days=RETENTION_DAYS + 1),
        logs_origin=ORIGIN,
    )
    retention_act = f"logs.retention.set:{retention_event}"

    await restore(world.db, backup)
    # The backup predates both purges: its content is all there.
    assert await stored_content(world) == {kept: None, erased: None, expired: None}

    async with logs_started(world):
        purged = {kept: None, erased: erase_act, expired: retention_act}
        assert await stored_content(world) == purged
        assert await exported_content(world) == {kept: True, erased: False, expired: False}
        assert await queried_content(world) == {kept: True, erased: False, expired: False}
        genesis, events = await load_epoch(world.db, world.member.team_id, 1)
        report = verify_chain(
            genesis, events, receipt_keys=frozenset(), checkpoint_keys=frozenset()
        )
        assert {item.act for item in report.purged} == {erase_act, retention_act}


async def test_an_event_erased_after_the_backup_stays_purged_when_it_is_redelivered(
    world, tmp_path
):
    backup = await back_up(world.db, tmp_path / "logs-content.dump")
    delivery = world.delivery("app")
    erased = await delivered(world, delivery)
    erase_act = await erase(world, erased)

    await restore(world.db, backup)
    assert await stored_content(world) == {}

    async with logs_started(world) as client:
        # The producer redelivers what the restored chain no longer holds.
        ack = await acknowledged(world, delivery, client)
        assert (ack["event_id"], ack["disposition"]) == (erased, "appended")
        assert await stored_content(world) == {erased: erase_act}
        assert await exported_content(world) == {erased: False}
        genesis, events = await load_epoch(world.db, world.member.team_id, 1)
        report = verify_chain(
            genesis, events, receipt_keys=receipt_key(ack), checkpoint_keys=frozenset()
        )
        assert report.intact
        assert [item.act for item in report.purged] == [erase_act]


async def test_a_purge_made_before_the_ledger_existed_survives_a_restore_of_an_older_backup(
    world, tmp_path
):
    erased = await delivered(world, world.delivery("app"))
    backup = await back_up(world.db, tmp_path / "logs-content.dump")
    # A Logs without the purge ledger purged the event in place.
    act = f"logs.erase:{uuid4()}"
    await world.db.execute(
        "UPDATE {{tables.chain_events}}"
        " SET salt = NULL, signing_bytes = NULL, signature = NULL, purge_act = $3"
        " WHERE team_id = $1 AND event_id = $2",
        world.member.team_id,
        UUID(erased),
        act,
    )
    # The upgraded Logs starts on the live content database.
    async with logs_started(world):
        pass

    await restore(world.db, backup)
    assert await stored_content(world) == {erased: None}

    async with logs_started(world):
        assert await stored_content(world) == {erased: act}


async def test_logs_refuses_to_start_with_its_purge_ledger_in_its_content_database(world):
    world.settings = world.settings.model_copy(
        update={"purge_ledger_database_url": world.settings.database_url}
    )
    with pytest.raises(ValueError, match="separate database"):
        async with logs_started(world):
            pass
