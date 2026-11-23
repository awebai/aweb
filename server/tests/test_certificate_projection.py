"""Existing members replace certificates using real registry/generation evidence."""

from contextlib import aclosing
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aweb.certificate_auth import verify_certificate_generation
from aweb.certificate_projection import (
    CertificateProjectionConflict,
    CertificateProjectionConflictReason,
    CertificateProjectionDisposition,
    replace_member_certificate,
)
from aweb.identity_binding import observe_identity_binding
from aweb.routes.connect import PlannedIdentityIds, WorkspaceProfile, connect_agent
from awid.did import did_key_from_signing_key
from awid.team_certificate import issue_team_certificate
from test_certificate_generation import _context, _registered_team


@pytest_asyncio.fixture
async def projection_member(real_stack):
    sdk, team, member, _, _ = await _registered_team(real_stack)
    async with aclosing(sdk):

        async def proof(*, did_aw="", alias="worker", scope="global"):
            certificate, header = issue_team_certificate(
                team_id="generation:local",
                team_signing_key=team,
                member_did_key=did_key_from_signing_key(member),
                alias=alias,
                identity_scope=scope,
                member_did_aw=did_aw,
            )
            checked = await verify_certificate_generation(
                context=_context(real_stack, sdk),
                team_id=certificate["team_id"],
                encoded_certificate=header,
                member_did_key=did_key_from_signing_key(member),
            )
            return checked

        initial = await proof()
        planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
        arguments = dict(
            db=real_stack.aweb_db,
            generation=initial,
            planned_ids=planned,
            hostname="preserve-host",
            workspace_path="/preserve",
            repo_origin="",
            role="preserve-role",
            human_name="preserve-name",
            agent_type="agent",
        )
        connected = await connect_agent(
            **arguments, workspace_profile=WorkspaceProfile.HOSTED_MCP
        )
        yield SimpleNamespace(
            stack=real_stack,
            sdk=sdk,
            member=member,
            team=team,
            initial=initial,
            planned=planned,
            proof=proof,
            connected=connected,
            arguments=arguments,
        )


async def _row(env):
    return dict(
        await env.stack.aweb_db.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id=$1",
            env.planned.agent_id,
        )
    )


def _replace_arguments(env, generation):
    return dict(
        db=env.stack.aweb_db,
        agent_id=env.planned.agent_id,
        team_id="generation:local",
        member_did_key=did_key_from_signing_key(env.member),
        generation=generation,
        expected_certificate_id=env.initial.certificate.claims["certificate_id"],
    )


async def _fresh_binding(env):
    registered = await env.sdk.register_did(
        did_key_from_signing_key(env.member), env.member
    )
    return await observe_identity_binding(
        env.sdk, did_key=did_key_from_signing_key(env.member), did_aw=registered.did_aw
    )


@pytest.mark.asyncio
async def test_unchanged_verified_claims_replace_only_certificate_fields(
    projection_member,
):
    env = projection_member
    before = await _row(env)
    workspace = await env.stack.aweb_db.fetch_one(
        "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.planned.workspace_id,
    )
    generation = await env.proof()
    result = await replace_member_certificate(**_replace_arguments(env, generation))
    assert result.disposition is CertificateProjectionDisposition.UPDATED
    assert result.agent_id == env.planned.agent_id
    assert result.certificate_fingerprint == generation.certificate_fingerprint
    after = await _row(env)
    expected = {
        **before,
        "certificate_id": generation.certificate.claims["certificate_id"],
        "accepted_team_did_key": generation.verified_team_did_key,
    }
    assert after == expected
    assert (
        await env.stack.aweb_db.fetch_one(
            "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1",
            env.planned.workspace_id,
        )
        == workspace
    )
    retry = await replace_member_certificate(**_replace_arguments(env, generation))
    assert retry.disposition is CertificateProjectionDisposition.UNCHANGED
    assert await _row(env) == after


@pytest.mark.asyncio
async def test_changed_claims_and_matching_fresh_binding_commit_together(
    projection_member,
):
    env = projection_member
    before = await _row(env)
    binding = await _fresh_binding(env)
    generation = await env.proof(did_aw=binding.did_aw)
    await replace_member_certificate(
        **_replace_arguments(env, generation), identity_binding=binding
    )
    assert await _row(env) == {
        **before,
        "certificate_id": generation.certificate.claims["certificate_id"],
        "accepted_team_did_key": generation.verified_team_did_key,
        "did_aw": binding.did_aw,
        "address": None,
        "did_aw_verified_key": did_key_from_signing_key(env.member),
    }


@pytest.mark.asyncio
async def test_changed_claims_without_binding_refuse_without_writes(projection_member):
    env = projection_member
    binding = await _fresh_binding(env)
    generation = await env.proof(did_aw=binding.did_aw)
    before = await _row(env)
    with pytest.raises(CertificateProjectionConflict) as refused:
        await replace_member_certificate(**_replace_arguments(env, generation))
    assert refused.value.reason is CertificateProjectionConflictReason.BINDING
    assert refused.value.detail == {
        "code": "certificate_binding_conflict",
        "message": "Supply a fresh IdentityBinding for the certificate's exact member key, stable identity and address, then retry the replacement.",
    }
    assert await _row(env) == before


@pytest.mark.asyncio
async def test_changed_claims_with_mismatching_actual_binding_refuse_without_writes(
    projection_member,
):
    env = projection_member
    binding = await _fresh_binding(env)
    generation = await env.proof(did_aw=binding.did_aw)
    other_key = bytes([57]) * 32
    registered = await env.sdk.register_did(
        did_key_from_signing_key(other_key), other_key
    )
    different = await observe_identity_binding(
        env.sdk, did_key=did_key_from_signing_key(other_key), did_aw=registered.did_aw
    )
    before = await _row(env)
    with pytest.raises(CertificateProjectionConflict) as refused:
        await replace_member_certificate(
            **_replace_arguments(env, generation), identity_binding=different
        )
    assert refused.value.reason is CertificateProjectionConflictReason.BINDING
    assert (
        refused.value.message
        == "Supply a fresh IdentityBinding for the certificate's exact member key, stable identity and address, then retry the replacement."
    )
    assert await _row(env) == before


@pytest.mark.asyncio
async def test_replacement_checks_expected_certificate_alias_scope_and_member(
    projection_member,
):
    env = projection_member
    before = await _row(env)
    generation = await env.proof()
    with pytest.raises(CertificateProjectionConflict) as refused:
        await replace_member_certificate(
            **{
                **_replace_arguments(env, generation),
                "expected_certificate_id": "stale",
            }
        )
    assert (
        refused.value.reason is CertificateProjectionConflictReason.EXPECTED_CERTIFICATE
    )
    assert (
        refused.value.message
        == "Reload the member's current certificate ID and retry the retained replacement with that expected value."
    )
    for different in (await env.proof(alias="other"), await env.proof(scope="local")):
        with pytest.raises(CertificateProjectionConflict) as refused:
            await replace_member_certificate(**_replace_arguments(env, different))
        assert refused.value.reason is CertificateProjectionConflictReason.MEMBER
    assert await _row(env) == before


@pytest.mark.asyncio
async def test_workspace_profile_result_and_repo_bound_reuse(projection_member):
    env = projection_member
    result = env.connected
    assert result["workspace_type"] == "hosted_mcp"
    assert (await connect_agent(**env.arguments))["workspace_type"] == "hosted_mcp"
    manual = await connect_agent(
        **env.arguments, workspace_profile=WorkspaceProfile.MANUAL
    )
    assert manual["workspace_type"] == "manual"
    repo = await connect_agent(
        **{**env.arguments, "repo_origin": "https://github.com/example/project.git"},
        workspace_profile=WorkspaceProfile.HOSTED_MCP,
    )
    assert repo["workspace_type"] == "agent"
    preserved = await connect_agent(
        **env.arguments, workspace_profile=WorkspaceProfile.MANUAL
    )
    assert preserved["workspace_type"] == "agent"
    assert (
        preserved["agent_id"] == result["agent_id"]
        and preserved["workspace_id"] == result["workspace_id"]
    )
    row = await env.stack.aweb_db.fetch_one(
        "SELECT workspace_type,repo_id FROM {{tables.workspaces}} WHERE workspace_id=$1",
        UUID(result["workspace_id"]),
    )
    assert row["workspace_type"] == "agent" and row["repo_id"] is not None
