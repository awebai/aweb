"""Fresh controller admission against real public registry registrations."""

from contextlib import aclosing
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_control_requests import UnownedTeamClaimRequest

from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
)
from aweb.unowned_team_claim import (
    UnownedTeamClaimTarget,
    VerifiedUnownedTeamClaim,
    verify_unowned_team_claim,
)
from tests.real_stack import REGISTRY_URL


async def registered_claim_team(stack):
    namespace, controller = bytes([72]) * 32, bytes([73]) * 32
    sdk = RegistryClient(
        registry_url=REGISTRY_URL,
        transport=stack.awid,
        service_token=stack.service_token,
    )
    await sdk.register_namespace(
        "local", did_key_from_signing_key(namespace), namespace
    )
    await sdk.register_team(
        domain="local",
        name="claim",
        display_name="Claim",
        team_did_key=did_key_from_signing_key(controller),
        visibility="public",
        namespace_controller_signing_key=namespace,
    )
    return sdk, namespace, controller


def request():
    return UnownedTeamClaimRequest(
        awid_team_id="claim:local",
        email="owner@example.com",
        username="owner",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


TARGET = UnownedTeamClaimTarget(
    team_id="claim:local", email="owner@example.com", username="owner"
)


def context(stack, sdk):
    return TeamControlAuthorityContext(
        db=stack.aweb_db,
        registry_client=sdk,
        txt_resolver=SystemTXTOutcomeResolver(),
    )


@pytest.mark.asyncio
async def test_actual_current_controller_claim_is_immutable_and_projects_no_member(
    real_stack,
):
    sdk, _, controller = await registered_claim_team(real_stack)
    artifact = request().sign(signing_key=controller)
    async with aclosing(sdk):
        proof = await verify_unowned_team_claim(
            context=context(real_stack, sdk), claim=artifact.to_json(), target=TARGET
        )
        assert isinstance(proof, VerifiedUnownedTeamClaim)
        assert proof.artifact == artifact
        assert proof.verified_team_did_key == did_key_from_signing_key(controller)
        proof.require_target(target=TARGET)
        with pytest.raises(FrozenInstanceError):
            proof.verified_team_did_key = "another"
        assert (
            await real_stack.aweb_db.fetch_value(
                "SELECT count(*) FROM {{tables.agents}} WHERE team_id=$1",
                TARGET.team_id,
            )
            == 0
        )


@pytest.mark.asyncio
async def test_self_valid_member_key_never_becomes_current_controller_claim(real_stack):
    sdk, _, _ = await registered_claim_team(real_stack)
    artifact = request().sign(signing_key=bytes([74]) * 32)
    artifact.verify_integrity()
    async with aclosing(sdk):
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk),
                claim=artifact.to_dict(),
                target=TARGET,
            )
    assert error.value.reason is TeamControlRequestReason.CONTROLLER_MISMATCH
    assert error.value.status_code == 422
    assert error.value.message == (
        "The claim signer is not the team's current controller. "
        "Regenerate the claim with the current controller key and retry."
    )


@pytest.mark.asyncio
async def test_claim_does_not_reuse_pre_rotation_registry_controller(real_stack):
    sdk, namespace, old_controller = await registered_claim_team(real_stack)
    artifact = request().sign(signing_key=old_controller)
    new_controller = bytes([75]) * 32
    async with aclosing(sdk):
        assert (
            await sdk.get_team_public_key("local", "claim") == artifact.signer_did_key
        )
        await sdk.rotate_team_key(
            "local",
            "claim",
            new_team_did_key=did_key_from_signing_key(new_controller),
            namespace_controller_signing_key=namespace,
        )
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk), claim=artifact, target=TARGET
            )
        assert error.value.reason is TeamControlRequestReason.CONTROLLER_MISMATCH
        proof = await verify_unowned_team_claim(
            context=context(real_stack, sdk),
            claim=request().sign(signing_key=new_controller),
            target=TARGET,
        )
        assert proof.verified_team_did_key == did_key_from_signing_key(new_controller)
