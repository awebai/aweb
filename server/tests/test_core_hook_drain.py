"""The core's shared drain delivers real signed requests through DNS and TLS."""

import asyncio
import json
from datetime import UTC, datetime
from ipaddress import ip_network

import pytest
from fastapi import FastAPI

from aweb.hook_producer import MutationHookContext, enqueue_mutation_hook, start_core_hooks, stop_core_hooks
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp.outbox import latest_receipt
from tests.test_core_hook_key_config import configured
from tests.test_core_hook_producer import db, origin, registration, SYSTEM, TEAM

pytestmark = pytest.mark.asyncio


async def test_started_drain_delivers_and_stops_before_database_shutdown(db, origin, configured):
    target = await registration(db, target_origin=origin.url)
    received = asyncio.Event()

    async def ingest(seen):
        checked = verify_delivery("POST", "/hooks/ingest", dict(seen.headers), seen.body, ReceiveOptions(
            audience=origin.url, binding_id=target, now=datetime.now(UTC),
        ))
        assert checked.envelope.producer_kind == "core"
        received.set()
        return 200, json.dumps({"event_id": checked.envelope.event_id, "disposition": "appended", "receipt": {"seq": 1}}).encode(), []

    origin.tls.respond = ingest
    app = FastAPI()
    app.state.public_origin = "https://core.example"
    start_core_hooks(app, db, egress=origin.fetcher.egress, internal_cidr=ip_network(f"{origin.tls.host}/32"))
    task = app.state.core_hooks_drain
    try:
        async with db.transaction() as tx:
            event_id = await enqueue_mutation_hook(tx, team_id=TEAM, hook_context=MutationHookContext(app.state.core_hooks, SYSTEM), payload={
                "mutation_type": "app_key.revoked", "target_ref": "app:fixture", "app_id": "fixture", "kid": "retired", "purposes": ["hook-event"],
            })
        await asyncio.wait_for(received.wait(), timeout=10)
    finally:
        await stop_core_hooks(app)
    assert task.done() and not task.cancelled() and task.exception() is None
    assert await db.fetch_value("SELECT state FROM {{tables.outbox_deliveries}} WHERE event_id=$1", event_id) == "delivered"
    assert json.loads(await latest_receipt(db, target)) == {"seq": 1}


async def test_no_key_configuration_starts_no_worker(db, monkeypatch):
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KID", raising=False)
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KEY_FILE", raising=False)
    app = FastAPI()
    app.state.public_origin = "https://core.example"
    start_core_hooks(app, db)
    assert app.state.core_hooks is None
    assert not hasattr(app.state, "core_hooks_drain")
    await stop_core_hooks(app)


async def test_unconfigured_restart_keeps_old_registration_and_accounts_for_new_effect(db, configured, monkeypatch):
    from aweb_naapp.outbox import outbox_status

    binding = await registration(db)
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KID")
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KEY_FILE")
    app = FastAPI()
    app.state.public_origin = "https://core.example"
    start_core_hooks(app, db)
    assert app.state.core_hooks is None
    try:
        async with db.transaction() as tx:
            await enqueue_mutation_hook(tx, team_id=TEAM, hook_context=MutationHookContext(
                None, SYSTEM, origin=app.state.public_origin, diagnostics=app.state.core_hook_diagnostics,
            ), payload={"mutation_type": "app_key.revoked", "target_ref": "app:fixture", "app_id": "fixture", "kid": "old", "purposes": ["hook-event"]})
    finally:
        await stop_core_hooks(app)
    row = await db.fetch_one("SELECT * FROM {{tables.outbox_events}}")
    assert row["record_type"] == "missing_production"
    assert row["producer_origin"] == app.state.public_origin
    assert row["owed_binding_ids"] == [binding]
    status = await outbox_status(db, "hooks")
    assert not status.targets and not status.unmaterialized and not status.faults
