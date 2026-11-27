"""Ordinary metadata imports use checked controller authority, never a mint."""

from contextlib import aclosing
from uuid import uuid4

import pytest

from awid.did import did_key_from_signing_key
from awid.registry import RegistryClient
from awid.signing import sign_message
from awid.team_certificate import issue_team_certificate

from aweb.certificate_auth import verify_certificate_generation
from aweb.controller_import import verify_controller_import
from aweb.identity_binding import observe_identity_binding
from aweb.team_admission import admit_team
from aweb.routes.connect import (
    ConnectIdentityRefusal,
    ConnectIdentityRefusalReason,
    PlannedIdentityConflict,
)
from tests.real_stack import REGISTRY_URL
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
            controller_signature=sign_message(controller, request.signing_bytes()),
        )
    return proof.members[0], namespace, controller, member


@pytest.mark.asyncio
async def test_metadata_import_projects_exact_independent_resources_without_artifact(
    real_stack,
):
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
    assert (
        await connect_agent(**arguments(real_stack, planned), controller_import=proof)
        == result
    )


@pytest.mark.asyncio
async def test_import_reuse_preserves_member_and_repository_workspace_profiles(
    real_stack,
):
    proof, _, controller, member = await checked_member(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    initial = arguments(real_stack, planned)
    initial.update(
        human_name="Existing display",
        role="Existing role",
        agent_type="worker",
        hostname="workstation",
        workspace_path="/work/project",
        repo_origin="https://example.com/owned.git",
    )
    # Genuine prior admission supplies the profile being preserved. The
    # ordinary import itself still receives no member artifact or signing key.
    _, encoded = issue_team_certificate(
        team_id=proof.team_id,
        team_signing_key=controller,
        member_did_key=did_key_from_signing_key(member),
        alias=proof.certificate.alias,
        identity_scope="local",
        certificate_id=proof.certificate.certificate_id,
    )
    async with aclosing(
        RegistryClient(
            registry_url=REGISTRY_URL,
            transport=real_stack.awid,
            service_token=real_stack.service_token,
        )
    ) as sdk:
        generation = await verify_certificate_generation(
            context=context(real_stack, sdk),
            team_id=proof.team_id,
            encoded_certificate=encoded,
            member_did_key=did_key_from_signing_key(member),
        )
    await connect_agent(**initial, generation=generation)
    before_agent = dict(
        await real_stack.aweb_db.fetch_one(
            "SELECT human_name,role,agent_type,human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
            planned.agent_id,
        )
    )
    before_workspace = dict(
        await real_stack.aweb_db.fetch_one(
            "SELECT agent_id,repo_id,workspace_type,human_name,role,hostname,workspace_path FROM {{tables.workspaces}} WHERE workspace_id=$1",
            planned.workspace_id,
        )
    )
    result = await connect_agent(
        **arguments(real_stack, planned), controller_import=proof
    )
    assert result["role"] == "Existing role"
    assert result["agent_type"] == "worker"
    assert result["workspace_type"] == "agent"
    assert (
        dict(
            await real_stack.aweb_db.fetch_one(
                "SELECT human_name,role,agent_type,human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
                planned.agent_id,
            )
        )
        == before_agent
    )
    assert (
        dict(
            await real_stack.aweb_db.fetch_one(
                "SELECT agent_id,repo_id,workspace_type,human_name,role,hostname,workspace_path FROM {{tables.workspaces}} WHERE workspace_id=$1",
                planned.workspace_id,
            )
        )
        == before_workspace
    )


@pytest.mark.asyncio
async def test_import_conflicts_preserve_exact_existing_projection(real_stack):
    proof, _, _, _ = await checked_member(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    initial = await connect_agent(
        **arguments(real_stack, planned), controller_import=proof
    )
    before = dict(
        await real_stack.aweb_db.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", planned.agent_id
        )
    )
    for supplied in (
        {"alias": "another"},
        {"did_key": "another"},
        {"certificate_id": "another"},
        {"team_id": "another:local"},
        {"team_did_key": "another"},
        {"identity_scope": "global"},
    ):
        with pytest.raises(ConnectIdentityRefusal) as refusal:
            await connect_agent(
                **arguments(real_stack, planned),
                controller_import=proof,
                cert_info=supplied,
            )
        assert refusal.value.reason is ConnectIdentityRefusalReason.IMPORT_MISMATCH
        assert refusal.value.message == (
            "Use the checked import's exact live member and controller fields, then retry importing."
        )
    for changed_ids in (
        PlannedIdentityIds(agent_id=uuid4(), workspace_id=planned.workspace_id),
        PlannedIdentityIds(agent_id=planned.agent_id, workspace_id=uuid4()),
    ):
        with pytest.raises(PlannedIdentityConflict):
            await connect_agent(
                **arguments(real_stack, changed_ids), controller_import=proof
            )
    assert (
        dict(
            await real_stack.aweb_db.fetch_one(
                "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", planned.agent_id
            )
        )
        == before
    )
    assert initial["workspace_id"] == str(planned.workspace_id)
    assert (
        await real_stack.aweb_db.fetch_value(
            "SELECT count(*) FROM {{tables.workspaces}} WHERE team_id=$1", proof.team_id
        )
        == 1
    )


@pytest.mark.asyncio
async def test_import_uses_the_callers_transaction_and_rolls_back_projection(
    real_stack,
):
    proof, _, _, _ = await checked_member(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    with pytest.raises(RuntimeError, match="completion failed"):
        async with real_stack.aweb_db.transaction() as tx:
            values = arguments(real_stack, planned)
            values["db"] = tx
            await connect_agent(**values, controller_import=proof)
            raise RuntimeError("completion failed")
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE agent_id=$1)",
        planned.agent_id,
    )
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.workspaces}} WHERE workspace_id=$1)",
        planned.workspace_id,
    )


@pytest.mark.asyncio
async def test_controller_move_after_import_snapshot_refuses_old_projection(
    real_stack, monkeypatch
):
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "false")
    proof, namespace, _, _ = await checked_member(real_stack)
    # Establish the existing admission before moving its pin through the real
    # registry/key owner, exactly as the supported rotation path does.
    await admit_team(
        db=real_stack.aweb_db,
        team_id=proof.team_id,
        team_did_key=proof.verified_team_did_key,
    )
    next_controller = bytes([85]) * 32
    async with aclosing(
        RegistryClient(
            registry_url=REGISTRY_URL,
            transport=real_stack.awid,
            service_token=real_stack.service_token,
        )
    ) as sdk:
        await sdk.rotate_team_key(
            "local",
            "import",
            new_team_did_key=did_key_from_signing_key(next_controller),
            namespace_controller_signing_key=namespace,
        )
        request = import_request()
        current = await verify_controller_import(
            context=context(real_stack, sdk),
            request=request,
            controller_signature=sign_message(next_controller, request.signing_bytes()),
        )
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    with pytest.raises(ConnectIdentityRefusal) as refusal:
        await connect_agent(**arguments(real_stack, planned), controller_import=proof)
    assert refusal.value.reason is ConnectIdentityRefusalReason.IMPORT_STALE
    assert refusal.value.message == (
        "Read and verify the import again under the team's current controller, then retry importing."
    )
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE agent_id=$1)",
        planned.agent_id,
    )
    result = await connect_agent(
        **arguments(real_stack, planned), controller_import=current.members[0]
    )
    assert result["workspace_id"] == str(planned.workspace_id)


@pytest.mark.asyncio
async def test_import_global_claims_still_require_actual_independent_binding(
    real_stack,
):
    sdk, _, controller, member = await registered_import_team(real_stack)
    member_key = did_key_from_signing_key(member)
    async with aclosing(sdk):
        identity = await sdk.register_did(member_key, member)
        await sdk.revoke_team_certificate(
            "local",
            "import",
            team_controller_signing_key=controller,
            certificate_id="live-certificate",
        )
        _, encoded = issue_team_certificate(
            team_id="import:local",
            team_signing_key=controller,
            member_did_key=member_key,
            member_did_aw=identity.did_aw,
            alias="live",
            identity_scope="global",
            certificate_id="global-certificate",
        )
        await sdk.register_team_certificate(
            "local",
            "import",
            team_controller_signing_key=controller,
            certificate_id="global-certificate",
            member_did_key=member_key,
            member_did_aw=identity.did_aw,
            member_address=None,
            alias="live",
            identity_scope="global",
            certificate=encoded,
        )
        request = import_request()
        batch = await verify_controller_import(
            context=context(real_stack, sdk),
            request=request,
            controller_signature=sign_message(controller, request.signing_bytes()),
        )
        proof = next(
            x
            for x in batch.members
            if x.certificate.certificate_id == "global-certificate"
        )
        binding = await observe_identity_binding(
            sdk, did_key=member_key, did_aw=identity.did_aw
        )
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    with pytest.raises(ConnectIdentityRefusal) as refusal:
        await connect_agent(**arguments(real_stack, planned), controller_import=proof)
    assert refusal.value.reason is ConnectIdentityRefusalReason.BINDING_MISMATCH
    assert refusal.value.message == (
        "Verify the certificate's exact identity and address before connecting this agent."
    )
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE agent_id=$1)",
        planned.agent_id,
    )
    result = await connect_agent(
        **arguments(real_stack, planned),
        controller_import=proof,
        identity_binding=binding,
    )
    assert result["agent_id"] == str(planned.agent_id)
    assert (
        await real_stack.aweb_db.fetch_value(
            "SELECT did_aw_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
            planned.agent_id,
        )
        == member_key
    )
