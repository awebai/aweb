"""Maintenance orchestration tests; authority stays with the real owner tests."""

from unittest.mock import AsyncMock

import pytest

from aweb.application_state import RegistryClientUnavailable
from aweb.maintenance import (
    NativeMaintenanceError,
    NativeMaintenanceStage,
    run_native_maintenance,
)
from aweb.presence_transitions import PresenceReconciliationResult


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outbox_fails,presence_fails",
    [(False, False), (True, False), (False, True), (True, True)],
)
async def test_each_stage_is_attempted_with_the_same_borrowed_resources(
    monkeypatch, outbox_fails, presence_fails
):
    from types import SimpleNamespace

    db, redis, registry, callback = object(), object(), object(), object()
    infra = SimpleNamespace(get_manager=lambda name: db if name == "aweb" else None)
    outbox_error = RuntimeError("outbox publisher unavailable")
    presence_error = RuntimeError("grant evidence unavailable")
    presence_result = PresenceReconciliationResult(3, 1, 2)
    outboxes = AsyncMock(side_effect=outbox_error if outbox_fails else None)
    presence = AsyncMock(
        side_effect=presence_error if presence_fails else None,
        return_value=presence_result,
    )
    monkeypatch.setattr("aweb.maintenance.recover_outboxes", outboxes)
    monkeypatch.setattr("aweb.maintenance.reconcile_presence", presence)
    arguments = dict(
        db_infra=infra, redis=redis, registry_client=registry, on_mutation=callback
    )
    if outbox_fails or presence_fails:
        with pytest.raises(NativeMaintenanceError) as refused:
            await run_native_maintenance(**arguments)
        expected = []
        if outbox_fails:
            expected.append((NativeMaintenanceStage.OUTBOX_RECOVERY, outbox_error))
        if presence_fails:
            expected.append(
                (NativeMaintenanceStage.PRESENCE_RECONCILIATION, presence_error)
            )
        assert [
            (failure.stage, failure.error) for failure in refused.value.failures
        ] == expected
        assert refused.value.completed_stages == frozenset(NativeMaintenanceStage) - {
            stage for stage, _ in expected
        }
        assert str(refused.value).endswith(
            "Restore the named stage's database, registry or publisher dependency and retry maintenance; inspect failures for the cause."
        )
    else:
        assert (await run_native_maintenance(**arguments)).presence is presence_result
    outboxes.assert_awaited_once_with(aweb_db=db, redis=redis, on_mutation=callback)
    presence.assert_awaited_once_with(infra, redis, registry_client=registry)


@pytest.mark.asyncio
async def test_missing_registry_reports_presence_failure_after_outbox_progress(
    monkeypatch,
):
    from types import SimpleNamespace

    infra = SimpleNamespace(get_manager=lambda name: None)
    outboxes = AsyncMock()
    presence = AsyncMock()
    monkeypatch.setattr("aweb.maintenance.recover_outboxes", outboxes)
    monkeypatch.setattr("aweb.maintenance.reconcile_presence", presence)
    with pytest.raises(NativeMaintenanceError) as refused:
        await run_native_maintenance(
            db_infra=infra, redis=None, registry_client=None, on_mutation=None
        )
    outboxes.assert_awaited_once()
    presence.assert_not_awaited()
    assert refused.value.completed_stages == frozenset(
        {NativeMaintenanceStage.OUTBOX_RECOVERY}
    )
    assert len(refused.value.failures) == 1
    assert (
        refused.value.failures[0].stage
        is NativeMaintenanceStage.PRESENCE_RECONCILIATION
    )
    assert isinstance(refused.value.failures[0].error, RegistryClientUnavailable)
    assert refused.value.failures[0].error.message == RegistryClientUnavailable.message
