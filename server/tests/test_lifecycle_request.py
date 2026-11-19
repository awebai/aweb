"""Public lifecycle request choices and compatibility, without service doubles."""

import pytest
from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    _agent_precondition_errors,
    _requested_disposition,
    _validate_request,
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
