"""Ordinary metadata imports use checked controller authority, never a mint."""

from contextlib import aclosing
from uuid import uuid4

import pytest

from aweb.controller_import import verify_controller_import
from aweb.routes.connect import PlannedIdentityIds, connect_agent
from tests.test_controller_import_registry import (
    context,
    import_request,
    registered_import_team,
)


def arguments(stack, planned):
    return dict(
        db=stack.aweb_db,
        planned_ids=planned,
        hostname="",
        workspace_path="",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )


@pytest.mark.asyncio
async def test_import_requires_the_actual_checked_member_before_any_storage():
    with pytest.raises(TypeError, match="Pass a checked controller-import member"):
        await connect_agent(
            db=None,
            controller_import={},
            hostname="",
            workspace_path="",
            repo_origin="",
            role="",
            human_name="",
            agent_type="agent",
        )


async def checked_member(stack):
    sdk, namespace, controller, member = await registered_import_team(stack)
    request = import_request()
    async with aclosing(sdk):
        proof = await verify_controller_import(
            context=context(stack, sdk),
            request=request,
            controller_signature=request.sign(signing_key=controller),
        )
    return proof.members[0], namespace, controller, member


@pytest.mark.asyncio
async def test_metadata_import_projects_exact_independent_resources_without_artifact(real_stack):
    proof, _, _, member = await checked_member(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    result = await connect_agent(
        **arguments(real_stack, planned), controller_import=proof
    )
    assert result["agent_id"] == str(planned.agent_id)
    assert result["workspace_id"] == str(planned.workspace_id)
    assert result["agent_id"] != result["workspace_id"]
    assert result["workspace_type"] == "manual"
    row = await real_stack.aweb_db.fetch_one(
        "SELECT did_key,certificate_id,accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
        planned.agent_id,
    )
    assert dict(row) == dict(
        did_key=proof.certificate.member_did_key,
        certificate_id=proof.certificate.certificate_id,
        accepted_team_did_key=proof.verified_team_did_key,
    )
    assert await connect_agent(
        **arguments(real_stack, planned), controller_import=proof
    ) == result


@pytest.mark.asyncio
async def test_import_reuse_preserves_member_and_repository_workspace_profiles(real_stack):
    proof, _, _, _ = await checked_member(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    initial = arguments(real_stack, planned)
    initial.update(
        human_name="Existing display", role="Existing role", agent_type="worker",
        hostname="workstation", workspace_path="/work/project",
        repo_origin="https://example.com/owned.git",
    )
    # The existing signed-request constructor establishes the stored profile;
    # the checked import supplies authority for subsequent metadata refresh.
    await connect_agent(
        **initial,
        cert_info={
            "team_id": proof.team_id, "did_key": proof.certificate.member_did_key,
            "alias": proof.certificate.alias, "identity_scope": "local",
            "certificate_id": proof.certificate.certificate_id,
        },
        team_did_key=proof.verified_team_did_key,
    )
    before_agent = dict(await real_stack.aweb_db.fetch_one(
        "SELECT human_name,role,agent_type,human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
        planned.agent_id,
    ))
    before_workspace = dict(await real_stack.aweb_db.fetch_one(
        "SELECT agent_id,repo_id,workspace_type,human_name,role,hostname,workspace_path FROM {{tables.workspaces}} WHERE workspace_id=$1",
        planned.workspace_id,
    ))
    result = await connect_agent(**arguments(real_stack, planned), controller_import=proof)
    assert result["role"] == "Existing role"
    assert result["agent_type"] == "worker"
    assert result["workspace_type"] == "agent"
    assert dict(await real_stack.aweb_db.fetch_one(
        "SELECT human_name,role,agent_type,human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
        planned.agent_id,
    )) == before_agent
    assert dict(await real_stack.aweb_db.fetch_one(
        "SELECT agent_id,repo_id,workspace_type,human_name,role,hostname,workspace_path FROM {{tables.workspaces}} WHERE workspace_id=$1",
        planned.workspace_id,
    )) == before_workspace
