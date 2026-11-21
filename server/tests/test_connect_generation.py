"""The one native constructor consumes actual generation proof and retained IDs."""

from contextlib import aclosing
import socket
from uuid import uuid4

import pytest
from awid.did import did_key_from_signing_key
from awid.registry import RegistryClient

from aweb.certificate_auth import (
    TeamControllerUnavailable,
    verify_certificate_generation,
)
from aweb.routes.connect import (
    ConnectIdentityRefusal,
    ConnectIdentityRefusalReason,
    PlannedIdentityIds,
    connect_agent,
)
from test_certificate_generation import _context, _registered_team


def _arguments(stack, planned):
    return dict(
        db=stack.aweb_db,
        planned_ids=planned,
        hostname="hosted",
        workspace_path="",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )


@pytest.mark.asyncio
async def test_verified_generation_connects_exact_resources_without_registration(
    real_stack,
):
    sdk, team, member, certificate, header = await _registered_team(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    async with aclosing(sdk):
        proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id=certificate["team_id"],
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
        assert await sdk.list_team_certificates("local", "generation") == []
    # The acquisition client is closed before projection. Constructor admission
    # uses the checked artifact and admitted evidence; it does not read registry.
    result = await connect_agent(**_arguments(real_stack, planned), generation=proof)
    assert result["agent_id"] == str(planned.agent_id)
    assert result["workspace_id"] == str(planned.workspace_id)
    row = await real_stack.aweb_db.fetch_one(
        "SELECT did_key, certificate_id, accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
        planned.agent_id,
    )
    assert dict(row) == dict(
        did_key=did_key_from_signing_key(member),
        certificate_id=certificate["certificate_id"],
        accepted_team_did_key=did_key_from_signing_key(team),
    )
    assert (
        await connect_agent(**_arguments(real_stack, planned), generation=proof)
        == result
    )
    assert proof.certificate.claims["certificate_id"] == certificate["certificate_id"]
    # Equivalent supported scope spelling and absent optional claims retain
    # their existing meaning when accompanying the actual generation proof.
    assert (
        await connect_agent(
            **_arguments(real_stack, planned),
            generation=proof,
            cert_info={
                "lifetime": "ephemeral",
                "member_did_aw": None,
                "member_address": "",
            },
        )
        == result
    )


@pytest.mark.asyncio
async def test_unconfirmed_mint_has_no_native_row_until_current_key_verification(
    real_stack,
):
    sdk, team, member, certificate, header = await _registered_team(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    async with aclosing(sdk):
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            async with aclosing(
                RegistryClient(
                    registry_url=f"http://127.0.0.1:{unavailable.getsockname()[1]}",
                    timeout_seconds=0.2,
                )
            ) as refused:
                with pytest.raises(TeamControllerUnavailable) as error:
                    await verify_certificate_generation(
                        context=_context(real_stack, refused),
                        team_id=certificate["team_id"],
                        encoded_certificate=header,
                        member_did_key=did_key_from_signing_key(member),
                    )
        assert error.value.message == (
            "The team's current controller could not be confirmed. "
            "The agent is not usable yet. Repeat the creation request when the "
            "registry is reachable and the team's controller can be confirmed."
        )
        assert not await real_stack.aweb_db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE agent_id=$1)",
            planned.agent_id,
        )
        assert not await real_stack.aweb_db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.workspaces}} WHERE workspace_id=$1)",
            planned.workspace_id,
        )
        proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id=certificate["team_id"],
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
        result = await connect_agent(
            **_arguments(real_stack, planned), generation=proof
        )
        assert result["agent_id"] == str(planned.agent_id)
        assert await real_stack.aweb_db.fetch_value(
            "SELECT accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
            planned.agent_id,
        ) == did_key_from_signing_key(team)


@pytest.mark.asyncio
async def test_generation_rejects_contradictory_issuer_fields_before_projection(
    real_stack,
):
    sdk, _, member, certificate, header = await _registered_team(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    async with aclosing(sdk):
        proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id=certificate["team_id"],
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
    for contradictory in (
        {"team_did_key": "different"},
        {"cert_info": {"team_did_key": "different"}},
        {"cert_info": {"alias": "different"}},
        {"cert_info": {"certificate_id": "another-mint"}},
    ):
        with pytest.raises(ConnectIdentityRefusal) as error:
            await connect_agent(
                **_arguments(real_stack, planned), generation=proof, **contradictory
            )
        assert error.value.reason is ConnectIdentityRefusalReason.GENERATION_MISMATCH
        assert (
            error.value.message
            == "Use the verified generation's exact certificate claims and current team key, then retry connecting."
        )
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.agents}})"
    )
    assert not await real_stack.aweb_db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.workspaces}})"
    )


@pytest.mark.asyncio
async def test_controller_move_after_generation_cannot_restore_old_member_acceptance(
    real_stack, monkeypatch
):
    from aweb.certificate_auth import EvidenceMode
    from aweb.team_admission import admit_team
    from awid.team_certificate import issue_team_certificate

    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "false")
    sdk, team, member, certificate, header = await _registered_team(real_stack)
    planned = PlannedIdentityIds(agent_id=uuid4(), workspace_id=uuid4())
    async with aclosing(sdk):
        old_proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id=certificate["team_id"],
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
        await admit_team(
            db=real_stack.aweb_db,
            team_id=certificate["team_id"],
            team_did_key=did_key_from_signing_key(team),
        )
        next_team = bytes([45]) * 32
        await sdk.rotate_team_key(
            "local",
            "generation",
            new_team_did_key=did_key_from_signing_key(next_team),
            namespace_controller_signing_key=bytes([41]) * 32,
        )
        _, next_header = issue_team_certificate(
            team_id=certificate["team_id"],
            team_signing_key=next_team,
            member_did_key=did_key_from_signing_key(member),
            alias="worker",
            identity_scope="local",
        )
        current_proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id=certificate["team_id"],
            encoded_certificate=next_header,
            member_did_key=did_key_from_signing_key(member),
            evidence=EvidenceMode.FRESH,
        )
        with pytest.raises(ConnectIdentityRefusal) as error:
            await connect_agent(**_arguments(real_stack, planned), generation=old_proof)
        assert error.value.reason is ConnectIdentityRefusalReason.GENERATION_STALE
        assert (
            error.value.message
            == "Verify the retained certificate under the team's current controller key, then retry connecting."
        )
        assert not await real_stack.aweb_db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.agents}})"
        )
        result = await connect_agent(
            **_arguments(real_stack, planned), generation=current_proof
        )
        assert result["agent_id"] == str(planned.agent_id)
        assert await real_stack.aweb_db.fetch_value(
            "SELECT accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
            planned.agent_id,
        ) == did_key_from_signing_key(next_team)
