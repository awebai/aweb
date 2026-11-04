"""Outbox rows are delivered by their writers and recovered on a timer, never by reads."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.db import DatabaseInfra
from aweb.federation.delivery import deliver_federated_phase_b
from aweb.outbox_recovery import recover_outboxes, start_outbox_recovery, stop_outbox_recovery
from tests.test_federation_activation_delivery import _DB, _envelope, _seed_recipient_and_authority


@pytest_asyncio.fixture
async def redis():
    async with Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True) as client:
        await client.ping()
        yield client


@pytest_asyncio.fixture
async def db_infra(shared_test_pool):
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_test_pool)
    yield infra


async def _leave_undelivered_federation_row(aweb_db) -> str:
    """A committed federated delivery whose after-commit hook failed."""
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(aweb_db, envelope)
    await deliver_federated_phase_b(
        _DB(aweb_db), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )
    return envelope.message_id


async def _leave_undelivered_lifecycle_rows(aweb_db, count: int) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.lifecycle_side_effect_outbox}} (
            operation_id, effect_order, team_id, effect_kind, payload_json
        )
        SELECT $1, g, 'backend:acme.com', 'presence_clear',
               jsonb_build_object('workspace_ids', jsonb_build_array(gen_random_uuid()::text))
        FROM generate_series(1, $2) g
        """,
        uuid4(), count,
    )


async def _undelivered(aweb_db) -> tuple[int, int]:
    lifecycle = await aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE delivered_at IS NULL"
    )
    federation = await aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.federation_mutation_outbox}} WHERE delivered_at IS NULL"
    )
    return lifecycle, federation


def _recording_hook():
    delivered = []

    async def on_mutation(event_type, payload):
        delivered.append((event_type, payload.get("message_id")))

    return delivered, on_mutation


@pytest.mark.asyncio
async def test_a_read_request_replays_no_outbox(db_infra, redis, monkeypatch):
    async def _noop_mount(_app, _db_infra, _redis, _registry_client):
        return None

    monkeypatch.setattr("aweb.api._mount_mcp_app", _noop_mount)
    aweb_db = db_infra.get_manager("aweb")
    await _leave_undelivered_federation_row(aweb_db)
    await _leave_undelivered_lifecycle_rows(aweb_db, 1)
    delivered, on_mutation = _recording_hook()
    app = create_app(db_infra=db_infra, redis=redis)
    app.state.db = db_infra
    app.state.redis = redis
    app.state.on_mutation = on_mutation

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(3):
            assert (await client.get("/health")).status_code == 200
    await asyncio.sleep(0.3)

    assert delivered == []
    assert await _undelivered(aweb_db) == (1, 1)


@pytest.mark.asyncio
async def test_recovery_delivers_the_rows_writers_left_behind(db_infra, redis):
    aweb_db = db_infra.get_manager("aweb")
    message_id = await _leave_undelivered_federation_row(aweb_db)
    await _leave_undelivered_lifecycle_rows(aweb_db, 250)
    delivered, on_mutation = _recording_hook()

    await recover_outboxes(aweb_db=aweb_db, redis=redis, on_mutation=on_mutation)

    assert delivered == [("message.sent", message_id)]
    assert await _undelivered(aweb_db) == (0, 0)


@pytest.mark.asyncio
async def test_recovery_runs_on_a_timer_until_stopped(db_infra, redis):
    aweb_db = db_infra.get_manager("aweb")
    delivered, on_mutation = _recording_hook()
    app = SimpleNamespace(state=SimpleNamespace(db=db_infra, redis=redis, on_mutation=on_mutation))

    start_outbox_recovery(app, interval_seconds=0.05)
    try:
        await asyncio.sleep(0.1)
        message_id = await _leave_undelivered_federation_row(aweb_db)
        await _leave_undelivered_lifecycle_rows(aweb_db, 1)
        for _ in range(40):
            if await _undelivered(aweb_db) == (0, 0):
                break
            await asyncio.sleep(0.05)
    finally:
        await stop_outbox_recovery(app)

    assert delivered == [("message.sent", message_id)]
    assert await _undelivered(aweb_db) == (0, 0)
    assert app.state.outbox_recovery_task.done()
