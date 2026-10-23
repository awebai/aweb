"""Signer diagnostics cannot grant authority or manufacture missing events."""

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from aweb.config import HookProducerKey
from aweb.hook_producer import (
    CoreHookDiagnostics,
    CoreHooks,
    _warning_lead,
    require_core_hook_signer,
    start_core_hooks,
    stop_core_hooks,
)
from aweb.service_errors import ConflictError
from fastapi import FastAPI
from tests.test_core_hook_key_config import configured as configured  # noqa: PLC0414 - pytest fixture export
from tests.test_core_hook_producer import context
from tests.test_core_hook_producer import db as db  # noqa: PLC0414 - pytest fixture export


def authority(deadline):
    producer = context().hooks.producer
    return CoreHooks(
        producer,
        HookProducerKey(
            kid=producer.producer.kid,
            did_key=producer.producer.did_key,
            valid_from="2026-01-01T00:00:00Z",
            valid_until=deadline.strftime("%Y-%m-%dT%H:%M:%SZ") if deadline else None,
        ),
    )


def test_warning_boundaries_state_changes_and_half_open_expiry(caplog):
    caplog.set_level(logging.WARNING, logger="aweb.hook_producer")
    deadline = datetime(2026, 11, 1, tzinfo=UTC)
    hooks = authority(deadline)
    diagnostics = CoreHookDiagnostics()
    diagnostics.observe(hooks, now=deadline - timedelta(days=7, microseconds=1))
    assert not caplog.records
    diagnostics.observe(hooks, now=deadline - timedelta(days=7))
    diagnostics.observe(hooks, now=deadline - timedelta(seconds=1))
    assert [r.reason for r in caplog.records] == ["key_expiring"]
    diagnostics.observe(hooks, now=deadline)
    diagnostics.observe(hooks, now=deadline + timedelta(days=1))
    assert [r.reason for r in caplog.records] == ["key_expiring", "key_out_of_window"]
    assert caplog.records[-1].levelno == logging.ERROR
    diagnostics.observe(None, now=deadline)
    diagnostics.observe(None, now=deadline)
    assert [r.reason for r in caplog.records] == [
        "key_expiring",
        "key_out_of_window",
        "key_unconfigured",
    ]
    # A changed deadline is a new warning state; unbounded keys never warn.
    diagnostics.observe(authority(None), now=deadline)
    diagnostics.observe(authority(deadline + timedelta(days=1)), now=deadline)
    assert caplog.records[-1].reason == "key_expiring"
    assert len(caplog.records) == 4
    for record in caplog.records:
        assert record.component == "core_hook_producer"
        assert not any(
            name in record.__dict__ for name in ("payload", "actor", "trace", "seed")
        )


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "invalid"])
def test_warning_lead_requires_positive_finite_seconds(monkeypatch, value):
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_WARNING_LEAD_SECONDS", value)
    with pytest.raises(ValueError):
        _warning_lead()


def test_warning_lead_configuration_has_no_authority_grace(monkeypatch, configured):
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_WARNING_LEAD_SECONDS", "60")
    assert _warning_lead() == timedelta(seconds=60)
    with pytest.raises(ConflictError, match="core_hook_producer_unconfigured"):
        require_core_hook_signer(authority(datetime.now(UTC) - timedelta(seconds=1)))
    require_core_hook_signer(authority(None))


@pytest.mark.asyncio
async def test_idle_drain_maintenance_reports_warning_and_runtime_expiry(
    db, configured, monkeypatch, caplog
):
    _, _, entry = configured
    deadline = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=4)
    entry = dict(entry, valid_until=deadline.strftime("%Y-%m-%dT%H:%M:%SZ"))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([entry]))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_WARNING_LEAD_SECONDS", "2")
    caplog.set_level(logging.WARNING, logger="aweb.hook_producer")
    app = FastAPI()
    app.state.public_origin = "https://core.example"
    start_core_hooks(app, db)
    try:
        for _ in range(70):
            if any(
                getattr(r, "reason", None) == "key_out_of_window"
                for r in caplog.records
            ):
                break
            await asyncio.sleep(0.1)
        reasons = [r.reason for r in caplog.records if r.name == "aweb.hook_producer"]
        assert reasons == ["key_expiring", "key_out_of_window"]
    finally:
        await stop_core_hooks(app)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 0
