"""Public producer mappings preserve accepted values and optional projection keys."""

from dataclasses import FrozenInstanceError

import pytest

from aweb.event_types import MutationEventType
from aweb.hook_contexts import (
    AgentStatusContext,
    TaskCreatedContext,
    TaskStatusChangedContext,
)
from aweb.hooks import (
    MutationDeliveryFailed,
    MutationDeliveryOutcome,
    MutationDeliveryStage,
    MutationDeliveryStatus,
    fire_mutation_callback,
)
from aweb.mutation_hooks import (
    INTENTIONALLY_UNPUBLISHED_EVENTS,
    _translate,
    _translate_team_event,
)


def test_optional_absence_and_explicit_null_survive_context_construction():
    context = TaskCreatedContext(task_id="t", task_ref="t-1234", title=None)
    assert context.to_context() == {"task_id": "t", "task_ref": "t-1234", "title": None}
    with pytest.raises(FrozenInstanceError):
        context.task_id = "different"
    assert context.event_type is MutationEventType.TASK_CREATED


def test_status_context_does_not_rewrite_accepted_metadata():
    context = AgentStatusContext(
        team_id="team",
        agent_id="a",
        reachable="custom-value",
        reason_text="  accepted text  ",
        fixing_by=None,
    )
    assert context.to_context() == dict(
        team_id="team",
        agent_id="a",
        reachable="custom-value",
        reason_text="  accepted text  ",
        fixing_by=None,
    )
    event = _translate_team_event(context.event_type, context.to_context())
    assert event.reachable == "custom-value"
    assert event.reason_text == "  accepted text  "


def test_status_projection_retains_claim_transition_evidence():
    released = ["workspace-a", "workspace-b"]
    context = TaskStatusChangedContext(
        task_id="t",
        task_ref="t-1234",
        team_id="team",
        old_status="open",
        new_status="closed",
        claim_preacquired=True,
        released_claim_workspace_ids=released,
    )
    assert context.to_context()["released_claim_workspace_ids"] is released
    assert context.to_context()["claim_preacquired"] is True
    assert (
        _translate_team_event(context.event_type, context.to_context()).new_status
        == "closed"
    )


@pytest.mark.asyncio
async def test_custom_callback_names_and_additive_fields_remain_open(caplog):
    observed = []

    async def callback(name, context):
        observed.append((name, context))

    context = {"custom": object(), "nullable": None}
    delivered = await fire_mutation_callback(callback, "host.custom", context)
    assert delivered.status is MutationDeliveryStatus.DELIVERED
    assert observed == [("host.custom", context)]
    assert _translate("host.custom", context) is None
    assert _translate_team_event("host.custom", context) is None
    assert MutationEventType.TASK_UPDATED in INTENTIONALLY_UNPUBLISHED_EVENTS

    async def failing_callback(name, context):
        raise RuntimeError("callback unavailable")

    failed = await fire_mutation_callback(failing_callback, "host.custom", context)
    assert failed.status is MutationDeliveryStatus.FAILED
    assert failed.failed_stages == (MutationDeliveryStage.CALLBACK,)
    assert "on_mutation callback failed for host.custom" in caplog.text


@pytest.mark.asyncio
async def test_native_failed_outcome_survives_the_shared_callback_adapter():
    incomplete = MutationDeliveryOutcome(
        status=MutationDeliveryStatus.FAILED,
        failed_stages=(MutationDeliveryStage.TASK_CLAIM_RELEASE,),
    )

    async def callback(name, context):
        return incomplete

    assert await fire_mutation_callback(callback, "task.deleted", {}) is incomplete
    with pytest.raises(MutationDeliveryFailed) as refused:
        incomplete.require_delivery()
    assert refused.value.outcome is incomplete
    assert (
        str(refused.value)
        == "Mutation delivery is incomplete. Retry the pending delivery or cleanup operation."
    )
    absent = await fire_mutation_callback(None, "task.deleted", {})
    assert absent.status is MutationDeliveryStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_native_claim_release_failure_is_not_a_successful_callback():
    from aweb.db import DatabaseInfra
    from aweb.mutation_hooks import create_mutation_handler

    # A real uninitialized native DB resource fails at the release boundary;
    # no substitute registry/database implementation supplies an outcome.
    handler = create_mutation_handler(None, DatabaseInfra())
    outcome = await fire_mutation_callback(
        handler,
        "task.deleted",
        {
            "task_id": "8f1bbc04-b998-4680-bc82-cc3de1bd714d",
            "task_ref": "t-1234",
        },
    )
    assert outcome.status is MutationDeliveryStatus.FAILED
    assert outcome.failed_stages == (MutationDeliveryStage.TASK_CLAIM_RELEASE,)
