"""Publication failures still commit a catalog-valid, correlated refusal."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.strictjson import Refused

from aweb_secrets.run_context import original_run
from aweb_secrets.runner_protocol import RunnerRefused, parse_request
from tests.test_broker_audit import envelopes
from tests.test_run_dispatch_service import setup
from tests.test_use_approvals import TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


@pytest.mark.parametrize("failure", ["clock_skew", "audit_target_unavailable"])
async def test_publication_refusal_is_recorded_with_original_public_ref(uses, failure):
    context = await setup(uses, producer_clock=uses.clock)
    service, db = context.service, uses.world.db
    admitted = await service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.status == 202
    async with db.transaction() as tx:
        original = await original_run(
            tx, await tx.fetch_value("SELECT dispatch_id FROM {{tables.run_contexts}}")
        )
    # Deterministic form of the loaded train failure: S3 timestamps from live
    # PostgreSQL exceed a frozen producer clock's five-second skew allowance.
    database_now = await db.fetch_value("SELECT clock_timestamp()")
    if failure == "clock_skew":
        uses.clock.now = database_now - timedelta(seconds=6)
    else:
        context.available[0] = False
    signed = context.signed("/runner/v1/claim")
    grant = await service._runner_grant(parse_request(signed.header))
    opened = await service._open(original)
    view = await context.arguments["registration_view"](TEAM)
    before = await envelopes(db)
    with pytest.raises(Refused) as failed:
        await service._publish(signed, grant, original, opened, view)
    assert failed.value.code == (
        "invalid_value" if failure == "clock_skew" else "audit_target_unavailable"
    )
    assert await db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "admitted"
    assert await db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}") is None
    assert await db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 0
    assert await envelopes(db) == before

    # Drive the exact claim recovery path with its real failure code, with the
    # clock now aligned so this isolates the second (catalog) failure layer.
    uses.clock.now = datetime.now(UTC)
    with pytest.raises(RunnerRefused) as refused:
        await service._preparation_failed(signed, grant, original, failed.value.code)
    assert refused.value.code == "runner_unavailable"
    assert await db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "refused"
    events = [e for e in await envelopes(db) if e["hook"] == "post-secret-use-hook"]
    assert [e["payload"]["action"] for e in events] == ["admitted", "refused"]
    assert events[-1]["payload"]["refusal_code"] == (
        "runner_unavailable" if failure == "clock_skew" else "audit_target_unavailable"
    )
    assert all(e["payload"]["use_ref"] == admitted.body["request_ref"] for e in events)
    rows = await db.fetch_all("SELECT correlation FROM {{tables.broker_use_events}}")
    assert all(
        json.loads(row["correlation"])["request_ref"] == admitted.body["request_ref"]
        for row in rows
    )
    assert await db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 1
