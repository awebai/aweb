"""Lifecycle request choices and empty-effect completion without services."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from aweb.lifecycle_agent import apply_agent_disposition_on, clear_agent_coordination_on
from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    LifecycleCascadeResult,
    _CommittedLifecycleEffects,
    _agent_precondition_errors,
    _complete_lifecycle_effects,
    _requested_disposition,
    _validate_request,
    plan_lifecycle_cascade,
)

ACTOR = LifecycleActor(actor_id="owner", actor_type="system", authority="embedding")
AGENT = "00000000-0000-0000-0000-000000000001"


@pytest.mark.parametrize("disposition", list(AgentDisposition))
def test_named_disposition_supports_zero_workspace_agent_cleanup(disposition):
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=ACTOR,
        target_agent_id=AGENT,
        workspace_scope="all_for_agent",
        agent_disposition=disposition,
    )
    assert _validate_request(request) == []


def test_released_local_delete_option_uses_deleted_disposition():
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=ACTOR,
        target_agent_id=AGENT,
        mark_local_agent_deleted=True,
    )
    assert _requested_disposition(request) == AgentDisposition.DELETED


def test_named_disposition_cannot_be_combined_with_released_delete_option():
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=ACTOR,
        target_agent_id=AGENT,
        workspace_scope="all_for_agent",
        mark_local_agent_deleted=True,
        agent_disposition=AgentDisposition.PREPARED_REMOVAL,
    )
    assert [error.code for error in _validate_request(request)] == [
        "conflicting_agent_lifecycle_action"
    ]


def test_named_disposition_requires_an_agent_target():
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=ACTOR,
        target_workspace_ids=(AGENT,),
        agent_disposition=AgentDisposition.DELETED,
    )
    assert [error.code for error in _validate_request(request)] == [
        "agent_disposition_requires_target"
    ]


def test_prepared_removal_cannot_restore_a_terminal_agent():
    request = LifecycleCascadeRequest(
        operation="cleanup_agent_coordination_state",
        actor=ACTOR,
        target_agent_id=AGENT,
        agent_disposition=AgentDisposition.PREPARED_REMOVAL,
    )
    row = {"agent_id": AGENT, "identity_scope": "global", "status": "retired"}
    assert [error.code for error in _agent_precondition_errors(request, row)] == [
        "terminal_agent_cannot_prepare_removal"
    ]


def test_released_local_delete_cannot_delete_a_global_identity_without_workspaces():
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=ACTOR,
        target_agent_id=AGENT,
        mark_local_agent_deleted=True,
    )
    row = {"agent_id": AGENT, "identity_scope": "global", "status": "active"}
    assert [error.code for error in _agent_precondition_errors(request, row)] == [
        "lifecycle_identity_scope_precondition_failed"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("team_id", [None, "", "  "])
async def test_native_lifecycle_writers_reject_missing_team_before_sql(team_id):
    # Invalid scope must be refused even for an empty target set.
    with pytest.raises(ValueError, match="nonempty team_id"):
        await clear_agent_coordination_on(None, agent_ids=[], team_id=team_id)
    with pytest.raises(ValueError, match="nonempty team_id"):
        await apply_agent_disposition_on(
            None,
            agent_ids=[],
            team_id=team_id,
            disposition=AgentDisposition.DELETED,
            deleted_at=datetime.now(timezone.utc),
        )


@pytest.mark.asyncio
async def test_planner_refusal_is_always_reported_as_a_dry_run():
    request = LifecycleCascadeRequest(operation="cleanup_agent_coordination_state", actor=ACTOR)
    result = await plan_lifecycle_cascade(None, request, registry_client=None)
    assert [error.code for error in result.errors] == ["missing_workspace_scope_target"]
    assert result.dry_run is True
    assert request.dry_run is False


@pytest.mark.asyncio
async def test_zero_effect_completion_requires_no_replay_handle():
    result = await _complete_lifecycle_effects(
        None,
        None,
        base=LifecycleCascadeResult(
            operation="delete_local_workspace", dry_run=False, target_agent_id=None
        ),
        effects=_CommittedLifecycleEffects(
            operation_id=uuid4(), effect_count=0, chat_participants=(), presence_ids=()
        ),
    )
    assert result.post_commit_status == "completed"
    assert result.outbox_operation_id is None
    assert result.chat_waiting_cleared_count == 0
    assert result.presence_cleared_count == 0
