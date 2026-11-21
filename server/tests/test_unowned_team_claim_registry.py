"""Fresh controller admission against real public registry registrations."""

import json
import subprocess
from contextlib import aclosing
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import MalformedTeamKeyError, RegistryClient
from awid.unowned_team_claim import UnownedTeamClaimRequest
from test_cli_human_reply import _pem

from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlRegistryDataInvalid,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
    TeamControlTeamNotFound,
)
from aweb.team_control_error_transport import team_control_error_response
from aweb.unowned_team_claim import (
    UnownedTeamClaimInvalid,
    UnownedTeamClaimReason,
    UnownedTeamClaimTarget,
    VerifiedUnownedTeamClaim,
    verify_unowned_team_claim,
)
from tests.real_stack import REGISTRY_URL


async def registered_claim_team(stack, *, name="claim", controller=bytes([73]) * 32):
    namespace = bytes([72]) * 32
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
        name=name,
        display_name="Claim",
        team_did_key=did_key_from_signing_key(controller),
        visibility="public",
        namespace_controller_signing_key=namespace,
    )
    return sdk, namespace, controller


@pytest.mark.asyncio
async def test_cli_controller_claim_interoperates_with_python_verifier(
    real_stack, aw_cli_binary, tmp_path
):
    vector_root = Path(__file__).resolve().parents[2] / "docs" / "vectors"
    vector = json.loads((vector_root / "team-control-requests-v1.json").read_text())
    case = vector["claim_cases"][0]
    controller = bytes.fromhex(vector["seed_hex"])
    name, _ = case["input"]["awid_team_id"].split(":")
    sdk, _, _ = await registered_claim_team(
        real_stack, name=name, controller=controller
    )
    async with aclosing(sdk):
        # Keep the vector's signer, team name and account. Use the isolated registry
        # namespace and real current time so the admission reader checks authority.
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
        claim_request = UnownedTeamClaimRequest(
            **{
                **case["input"],
                "awid_team_id": f"{name}:local",
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            }
        )
        target = UnownedTeamClaimTarget(
            team_id=claim_request.awid_team_id,
            username=claim_request.username,
            email=claim_request.email,
        )
        key_dir = tmp_path / ".awid" / "team-keys" / "local"
        key_dir.mkdir(parents=True, mode=0o700)
        _pem(key_dir / f"{name}.key", "ED25519 PRIVATE KEY", controller)
        result = subprocess.run(
            [
                str(aw_cli_binary),
                "id",
                "team",
                "claim-human-request",
                "--team",
                name,
                "--namespace",
                "local",
                "--username",
                target.username,
                "--email",
                target.email,
                "--timestamp",
                claim_request.timestamp,
            ],
            cwd=tmp_path,
            env={"HOME": str(tmp_path), "AW_NO_UPDATE_CHECK": "1"},
            capture_output=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr.decode()
        admission = context(real_stack, sdk)
        proof = await verify_unowned_team_claim(
            context=admission, claim=result.stdout, target=target
        )
        assert proof.verified_team_did_key == vector["signer_did_key"]
        assert proof.artifact == claim_request.sign(signing_key=controller)

        changed = json.loads(result.stdout)
        changed["request"]["timestamp"] = (timestamp - timedelta(seconds=1)).isoformat()
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_unowned_team_claim(
                context=admission, claim=json.dumps(changed), target=target
            )
        assert error.value.reason is TeamControlRequestReason.SIGNATURE_INVALID


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
        with pytest.raises(UnownedTeamClaimInvalid) as error:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk),
                claim=artifact.to_dict(),
                target=TARGET,
            )
    assert error.value.reason is UnownedTeamClaimReason.CONTROLLER_MISMATCH
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
        with pytest.raises(UnownedTeamClaimInvalid) as error:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk), claim=artifact, target=TARGET
            )
        assert error.value.reason is UnownedTeamClaimReason.CONTROLLER_MISMATCH
        proof = await verify_unowned_team_claim(
            context=context(real_stack, sdk),
            claim=request().sign(signing_key=new_controller),
            target=TARGET,
        )
        assert proof.verified_team_did_key == did_key_from_signing_key(new_controller)


@pytest.mark.asyncio
async def test_claim_preserves_definitive_unregistered_team_refusal(real_stack):
    sdk, _, controller = await registered_claim_team(real_stack)
    target = replace(TARGET, team_id="missing:local")
    artifact = replace(request(), awid_team_id=target.team_id).sign(
        signing_key=controller
    )
    async with aclosing(sdk):
        with pytest.raises(TeamControlTeamNotFound) as refusal:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk), claim=artifact, target=target
            )
    response = team_control_error_response(refusal.value)
    assert response.status_code == 404
    assert json.loads(response.body)["detail"]["code"] == "awid_team_not_found"


@pytest.mark.asyncio
async def test_claim_preserves_invalid_controller_record_refusal(
    real_stack, monkeypatch
):
    sdk, _, controller = await registered_claim_team(real_stack)
    artifact = request().sign(signing_key=controller)

    def omit_controller_key(http_request, http_response):
        if (
            http_request.method != "GET"
            or http_request.url.path != "/v1/namespaces/local/teams/claim"
        ):
            return None
        assert http_response.status_code == 200
        body = http_response.json()
        assert body.pop("team_did_key") == artifact.signer_did_key
        return httpx.Response(200, json=body)

    monkeypatch.setattr(real_stack.awid, "fault", omit_controller_key)
    async with aclosing(sdk):
        with pytest.raises(TeamControlRegistryDataInvalid) as refusal:
            await verify_unowned_team_claim(
                context=context(real_stack, sdk), claim=artifact, target=TARGET
            )
    cause = refusal.value.__cause__
    assert isinstance(cause, MalformedTeamKeyError)
    assert isinstance(cause.__cause__, KeyError)
    assert cause.__cause__.args == ("team_did_key",)
    response = team_control_error_response(refusal.value)
    assert response.status_code == 422
    assert json.loads(response.body)["detail"]["code"] == "registry_response_unusable"
