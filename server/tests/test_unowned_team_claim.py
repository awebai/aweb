"""Claim proof guards use real signed artifacts, never fabricated authority."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest
from awid.unowned_team_claim import UnownedTeamClaimRequest

from aweb.team_control_authority import (
    TeamControlAuthorityUnavailable,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
)
from aweb.unowned_team_claim import (
    UnownedTeamClaimInvalid,
    UnownedTeamClaimReason,
    UnownedTeamClaimTarget,
    verify_unowned_team_claim,
)
from tests.test_team_control_authority import unreachable_context


def signed_claim(**changes):
    request = UnownedTeamClaimRequest(
        awid_team_id="operators:local",
        email="owner@example.com",
        username="owner",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    return replace(request, **changes).sign(signing_key=bytes([71]) * 32)


TARGET = UnownedTeamClaimTarget(
    team_id="operators:local", email="owner@example.com", username="owner"
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"awid_team_id": "other:local"},
        {"email": "other@example.com"},
        {"username": "other"},
        {"email": "Owner@example.com"},
    ],
)
async def test_claim_target_mismatch_refuses_before_any_authority_read(change):
    async with unreachable_context() as context:
        with pytest.raises(UnownedTeamClaimInvalid) as error:
            await verify_unowned_team_claim(
                context=context, claim=signed_claim(**change).to_dict(), target=TARGET
            )
    assert error.value.reason is UnownedTeamClaimReason.TARGET_MISMATCH
    assert error.value.message == (
        "The controller claim names a different team or account. "
        "Regenerate it for the exact team, email and username being claimed."
    )


@pytest.mark.asyncio
async def test_stale_claim_requires_a_new_signature_before_registry_io():
    async with unreachable_context() as context:
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_unowned_team_claim(
                context=context,
                claim=signed_claim(timestamp="1990-01-01T00:00:00Z").to_dict(),
                target=TARGET,
            )
    assert error.value.reason is TeamControlRequestReason.TIMESTAMP_INVALID


@pytest.mark.asyncio
async def test_tampered_signed_claim_refuses_before_registry_io():
    artifact = signed_claim().to_dict()
    artifact["request"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    async with unreachable_context() as context:
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_unowned_team_claim(
                context=context, claim=artifact, target=TARGET
            )
    assert error.value.reason is TeamControlRequestReason.SIGNATURE_INVALID
    assert error.value.__cause__ is not None


@pytest.mark.asyncio
async def test_unknown_controller_cannot_turn_an_integral_artifact_into_authority():
    async with unreachable_context() as context:
        with pytest.raises(TeamControlAuthorityUnavailable) as error:
            await verify_unowned_team_claim(
                context=context, claim=signed_claim().to_json(), target=TARGET
            )
    assert error.value.status_code == 503
    assert error.value.code == "team_control_authority_unavailable"
    assert error.value.__cause__ is not None


@pytest.mark.asyncio
async def test_claim_schema_is_owned_by_the_shared_reader():
    artifact = signed_claim().to_dict()
    artifact["authorized_controller"] = True
    async with unreachable_context() as context:
        with pytest.raises(UnownedTeamClaimInvalid) as error:
            await verify_unowned_team_claim(
                context=context, claim=artifact, target=TARGET
            )
    assert error.value.reason is UnownedTeamClaimReason.ARTIFACT_INVALID
    assert error.value.message == (
        "The controller claim file is malformed. "
        "Regenerate it with aw id team claim-human-request and retry."
    )


def test_target_retains_the_account_owners_normalized_values_verbatim():
    assert TARGET.email == "owner@example.com"
    with pytest.raises(FrozenInstanceError):
        TARGET.email = "other@example.com"
