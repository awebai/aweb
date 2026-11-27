"""Pure constructor preconditions, before any storage or registry access."""

import uuid

import pytest

from aweb.routes.connect import (
    ConnectIdentityRefusal,
    ConnectIdentityRefusalReason,
    PlannedIdentityIds,
    connect_agent,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [False, True])
async def test_connect_refuses_wrong_observation_with_stable_code_and_actionable_message(
    kind,
):
    arguments = dict(
        db=None,
        cert_info={
            "team_id": "team:example.com",
            "alias": "member",
            "did_key": "member",
        },
        team_did_key="team",
        hostname="",
        workspace_path="",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    if kind:
        arguments["identity_kind"] = {"did_key": "member"}
    else:
        arguments["cert_info"]["member_did_aw"] = "did:aw:unobserved"
    with pytest.raises(ConnectIdentityRefusal) as refused:
        await connect_agent(**arguments)
    reason = (
        ConnectIdentityRefusalReason.KIND_MISMATCH
        if kind
        else ConnectIdentityRefusalReason.BINDING_MISMATCH
    )
    assert refused.value.reason is reason
    assert str(refused.value) == reason.value
    assert refused.value.message == (
        "Verify the certificate's exact identity kind before connecting this agent."
        if kind
        else "Verify the certificate's exact identity and address before connecting this agent."
    )


def test_planned_ids_require_uuid_values():
    with pytest.raises(
        TypeError, match="Pass UUID values for the planned agent and workspace IDs."
    ):
        PlannedIdentityIds(agent_id="invalid", workspace_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_workspace_profile_requires_the_bounded_named_input():
    from aweb.service_errors import ValidationError

    with pytest.raises(ValidationError) as refused:
        await connect_agent(
            db=None,
            cert_info={
                "team_id": "t:example.com",
                "alias": "member",
                "did_key": "member",
            },
            team_did_key="team",
            hostname="",
            workspace_path="",
            repo_origin="",
            role="",
            human_name="",
            agent_type="agent",
            workspace_profile="hosted_mcp",
        )
    assert refused.value.status_code == 422
    assert refused.value.detail == {
        "code": "workspace_profile_invalid",
        "message": "Choose WorkspaceProfile.MANUAL or WorkspaceProfile.HOSTED_MCP, then retry.",
    }
