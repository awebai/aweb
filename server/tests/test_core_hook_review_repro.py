"""Pre-fix reproductions for review c73c9205 on unshipped core 62a586d54.

Real queued delivery/key expiry and the actual logging output configuration.
No product signing, clock, formatter or transport is substituted.
"""

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network

import pytest
from aweb.hook_producer import (
    CoreRegistrations,
    MutationHookContext,
    enqueue_mutation_hook,
    load_core_hooks,
    start_core_hooks,
    stop_core_hooks,
)
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, hook_targets
from aweb_naapp.outbox import RetryPolicy, _materialize
from fastapi import FastAPI
from tests.test_core_hook_key_config import configured as configured  # noqa: PLC0414
from tests.test_core_hook_producer import SYSTEM, TEAM, registration
from tests.test_core_hook_producer import db as db  # noqa: PLC0414
from tests.test_core_hook_producer import origin as origin  # noqa: PLC0414


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
@pytest.mark.parametrize("stage", ["materialization", "transport"])
async def test_queued_valid_event_does_not_get_a_fresh_expired_key_credential(
    db, origin, configured, monkeypatch, expired, stage,
):
    binding = await registration(db, target_origin=origin.url)
    received = []
    raw = []
    active_from = await db.fetch_value("SELECT active_from FROM {{tables.app_hook_bindings}} WHERE binding_id=$1", binding)
    _, _, entry = configured
    deadline = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=4 if expired else 60)
    entry = dict(entry, valid_until=deadline.strftime("%Y-%m-%dT%H:%M:%SZ"))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([entry]))
    hooks = load_core_hooks("https://core.example")
    async with db.transaction() as tx:
        event_id = await enqueue_mutation_hook(
            tx, team_id=TEAM, hook_context=MutationHookContext(hooks, SYSTEM), payload={
                "mutation_type": "app_key.revoked", "target_ref": "app:fixture",
                "app_id": "fixture", "kid": "old", "purposes": ["hook-event"],
            },
        )
    original = await db.fetch_one("SELECT payload_sha256,signature FROM {{tables.outbox_events}} WHERE event_id=$1", event_id)
    if stage == "transport":
        # Use the real kit materializer and real core resolver to commit the
        # delivery first. The lock below then delays transport's own awaited
        # lookup, rather than its earlier materialization lookup.
        assert await _materialize(
            db, HOOKS_CHANNEL, hook_targets(CoreRegistrations(db)),
            RetryPolicy(stalled_after=timedelta(days=1)), 100,
        ) == 1

    async def ingest(seen):
        raw.append((datetime.now(UTC), seen.request_line.split(" ")[1]))
        verified = verify_delivery("POST", "/hooks/ingest", dict(seen.headers), seen.body, ReceiveOptions(
            audience=origin.url, binding_id=binding, now=datetime.now(UTC),
        ))
        received.append(verified.envelope.event_id)
        return 200, json.dumps({"event_id": verified.envelope.event_id, "disposition": "appended", "receipt": {"seq": 1}}).encode(), []

    origin.tls.respond = ingest
    app = FastAPI()
    app.state.public_origin = "https://core.example"
    try:
        # Hold S1 resolution behind a real second PG session until after the
        # key expires. The immutable event was already queued while valid.
        async with db.transaction() as blocker:
            await blocker.execute("LOCK TABLE {{tables.app_hook_bindings}} IN ACCESS EXCLUSIVE MODE")
            start_core_hooks(app, db, egress=origin.fetcher.egress, internal_cidr=ip_network(f"{origin.tls.host}/32"))
            for _ in range(40):
                waiting = await db.fetch_value("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='aweb.app_hook_bindings'::regclass AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)")
                if waiting:
                    break
                await asyncio.sleep(0.025)
            assert waiting and datetime.now(UTC) < deadline
            if expired:
                await asyncio.sleep(max(0, (deadline-datetime.now(UTC)).total_seconds())+0.02)
        for _ in range(160):
            row = await db.fetch_one("SELECT state,attempts,acked_at FROM {{tables.outbox_deliveries}} WHERE event_id=$1", event_id)
            if row and row["attempts"] >= 1:
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("the real drain never finished its first delivery attempt")
    finally:
        await stop_core_hooks(app)
    retained = await db.fetch_one("SELECT payload_sha256,signature FROM {{tables.outbox_events}} WHERE event_id=$1", event_id)
    assert retained == original
    if expired:
        assert origin.tls.seen == []
        assert raw == []
        assert (received, row["state"] in ("pending", "stalled"), row["acked_at"]) == ([], True, None)
    else:
        assert len(origin.tls.seen) == 1
        assert len(raw) == 1
        assert active_from <= raw[0][0] < deadline and raw[0][1] == "/hooks/ingest"
        assert received == [str(event_id)]
        assert row["state"] == "delivered" and row["acked_at"] is not None


@pytest.mark.parametrize("json_format", [True, False])
def test_signer_fault_fields_survive_actual_configured_logging_output(json_format):
    # A subprocess uses configure_logging itself, isolating its root-handler
    # replacement from pytest's logging capture. Generated private bytes are
    # never logged; markers below are deliberately nonsecret negative controls.
    script = '''
import logging
import sys
from datetime import UTC, datetime
from nacl.signing import SigningKey
from awid.log_config import configure_logging
from aweb.config import HookProducerKey
from aweb.hook_producer import CoreHookDiagnostics, CoreHooks
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
configure_logging(json_format=sys.argv[1] == "json")
producer = HookProducer(ServerProducer.core(origin="https://core.example", kid="display-current", seed=bytes(SigningKey.generate())))
key = HookProducerKey(kid="display-current", did_key=producer.producer.did_key, valid_from="2000-01-01T00:00:00Z", valid_until="2001-01-01T00:00:00Z")
diagnostics = CoreHookDiagnostics()
diagnostics.observe(CoreHooks(producer, key), now=datetime(2002,1,1,tzinfo=UTC))
diagnostics.observe(CoreHooks(producer, key), now=datetime(2002,1,2,tzinfo=UTC))
logging.getLogger("formatter-control").error("unrelated-safe-message", extra={"payload":"PAYLOAD_MARKER", "actor":"ACTOR_MARKER", "trace":"TRACE_MARKER", "seed":"SEED_MARKER"})
'''
    result = subprocess.run([sys.executable, "-c", script, "json" if json_format else "text"],
                            env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    for marker in ("PAYLOAD_MARKER", "ACTOR_MARKER", "TRACE_MARKER", "SEED_MARKER"):
        assert marker not in result.stdout
    lines = result.stdout.splitlines()
    assert len(lines) == 2  # repeated unavailable state stays suppressed
    expected = {"component": "core_hook_producer", "reason": "key_out_of_window",
                "kid": "display-current", "valid_until": "2001-01-01T00:00:00Z"}
    if json_format:
        emitted = json.loads(lines[0])
        diagnostic = emitted if all(key in emitted for key in expected) else json.loads(emitted["message"])
    else:
        # Text mode carries the explicitly structured diagnostic through the
        # real formatter's message; it does not require a new global schema.
        start = lines[0].find("{")
        assert start >= 0, lines[0]
        diagnostic = json.loads(lines[0][start:])
    assert isinstance(diagnostic, dict)
    assert {key: diagnostic.get(key) for key in expected} == expected
    assert all(type(diagnostic[key]) is str for key in expected)
