"""Ordinary imports acquire exact fresh metadata from the real registry."""

import json
import logging
from contextlib import aclosing
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import httpx
import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.signing import sign_message
from awid.team_certificate import issue_team_certificate
from awid.team_control_requests import TeamImportRequest

from aweb.controller_import import (
    VerifiedControllerImportMember,
    verify_controller_import,
)
from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlRegistryDataInvalid,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
    TeamControlTeamNotFound,
)
from aweb.team_control_error_transport import team_control_error_response
from tests.real_stack import REGISTRY_URL


async def registered_import_team(stack):
    namespace, controller, member = (bytes([n]) * 32 for n in (81, 82, 83))
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
        name="import",
        display_name="Import",
        team_did_key=did_key_from_signing_key(controller),
        visibility="public",
        namespace_controller_signing_key=namespace,
    )
    # Enroll through the current signed-artifact API. The import caller and
    # factory still receive only the roster, with no member key or artifact.
    for certificate_id, alias in (
        ("live-certificate", "live"),
        ("revoked-certificate", "revoked"),
    ):
        _, encoded = issue_team_certificate(
            team_id="import:local", team_signing_key=controller,
            member_did_key=did_key_from_signing_key(member if alias == "live" else bytes([84]) * 32),
            alias=alias, identity_scope="local", certificate_id=certificate_id,
        )
        await sdk.register_team_certificate(
            "local",
            "import",
            team_controller_signing_key=controller,
            certificate_id=certificate_id,
            member_did_key=did_key_from_signing_key(
                member if alias == "live" else bytes([84]) * 32
            ),
            member_did_aw=None,
            member_address=None,
            alias=alias,
            identity_scope="local",
            certificate=encoded,
        )
    await sdk.revoke_team_certificate(
        "local",
        "import",
        team_controller_signing_key=controller,
        certificate_id="revoked-certificate",
    )
    return sdk, namespace, controller, member


def import_request(*, dry_run=False):
    return TeamImportRequest(
        awid_team_id="import:local",
        organization_id="organization-1",
        team_id=None,
        dry_run=dry_run,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def context(stack, sdk):
    return TeamControlAuthorityContext(
        db=stack.aweb_db,
        registry_client=sdk,
        txt_resolver=SystemTXTOutcomeResolver(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [True, False])
async def test_owner_snapshot_retains_revoked_planning_but_only_live_admission(
    real_stack, dry_run
):
    sdk, _, controller, member = await registered_import_team(real_stack)
    request = import_request(dry_run=dry_run)
    async with aclosing(sdk):
        proof = await verify_controller_import(
            context=context(real_stack, sdk),
            request=request,
            controller_signature=sign_message(controller, request.signing_bytes()),
        )
    assert proof.request is request
    assert proof.controller_signature == sign_message(controller, request.signing_bytes())
    assert proof.request.organization_id == "organization-1"
    assert proof.request.team_id is None
    assert proof.team.team_id == "import:local"
    assert {row.certificate_id for row in proof.certificates} == {
        "live-certificate",
        "revoked-certificate",
    }
    assert len(proof.members) == (0 if dry_run else 1)
    if dry_run:
        # Planning reads the snapshot; a preview signature supplies no native
        # admission result that could accidentally be applied.
        return
    admitted = proof.members[0]
    assert isinstance(admitted, VerifiedControllerImportMember)
    assert admitted.team_id == "import:local"
    assert admitted.controller_signature == proof.controller_signature
    assert admitted.verified_team_did_key == did_key_from_signing_key(controller)
    assert admitted.certificate.certificate_id == "live-certificate"
    assert admitted.certificate.member_did_key == did_key_from_signing_key(member)
    assert admitted.certificate.alias == "live"
    assert admitted.certificate.identity_scope == "local"
    assert admitted.certificate.member_did_aw is None
    assert admitted.certificate.member_address is None
    admitted.require_freshness()
    with pytest.raises(FrozenInstanceError):
        admitted.certificate.alias = "changed"
    assert (
        await real_stack.aweb_db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE team_id=$1", admitted.team_id
        )
        == 0
    )


@pytest.mark.asyncio
async def test_member_signed_selector_request_is_not_controller_import_authority(
    real_stack,
):
    sdk, _, _, member = await registered_import_team(real_stack)
    request = import_request()
    async with aclosing(sdk):
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_controller_import(
                context=context(real_stack, sdk),
                request=request,
                controller_signature=sign_message(member, request.signing_bytes()),
            )
    assert error.value.reason is TeamControlRequestReason.SIGNATURE_INVALID
    assert error.value.message == (
        "The controller signature is invalid. "
        "Regenerate the signed request with the controller key and retry."
    )


@pytest.mark.asyncio
async def test_pre_rotation_import_signature_cannot_accept_new_controller_roster(
    real_stack,
):
    sdk, namespace, old_controller, _ = await registered_import_team(real_stack)
    request = import_request()
    signature = sign_message(old_controller, request.signing_bytes())
    async with aclosing(sdk):
        await sdk.rotate_team_key(
            "local",
            "import",
            new_team_did_key=did_key_from_signing_key(bytes([84]) * 32),
            namespace_controller_signing_key=namespace,
        )
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_controller_import(
                context=context(real_stack, sdk),
                request=request,
                controller_signature=signature,
            )
    assert error.value.reason is TeamControlRequestReason.SIGNATURE_INVALID


@pytest.mark.asyncio
async def test_unregistered_team_is_not_an_import_outage(real_stack):
    sdk, _, controller, _ = await registered_import_team(real_stack)
    request = replace(import_request(), awid_team_id="missing:local")
    async with aclosing(sdk):
        with pytest.raises(TeamControlTeamNotFound) as refusal:
            await verify_controller_import(
                context=context(real_stack, sdk),
                request=request,
                controller_signature=sign_message(controller, request.signing_bytes()),
            )
    response = team_control_error_response(refusal.value)
    assert response.status_code == 404
    assert json.loads(response.body) == {
        "detail": {
            "code": "awid_team_not_found",
            "message": (
                "The AWID team is not registered. "
                "Select a registered team or register it before importing."
            ),
        }
    }


@pytest.mark.asyncio
async def test_invalid_roster_is_a_nonretryable_import_refusal(
    real_stack, monkeypatch, caplog
):
    sdk, _, controller, _ = await registered_import_team(real_stack)
    request = import_request()
    bad_response_seen = False

    def corrupt_issued_time(http_request, http_response):
        nonlocal bad_response_seen
        if http_request.method != "GET" or not http_request.url.path.endswith("/certificates"):
            return None
        assert http_response.status_code == 200
        body = http_response.json()
        body["certificates"][0]["issued_at"] = "missing timezone"
        bad_response_seen = True
        return httpx.Response(200, json=body)

    monkeypatch.setattr(real_stack.awid, "fault", corrupt_issued_time)
    async with aclosing(sdk):
        with pytest.raises(TeamControlRegistryDataInvalid) as refusal:
            await verify_controller_import(
                context=context(real_stack, sdk),
                request=request,
                controller_signature=sign_message(controller, request.signing_bytes()),
            )
    assert bad_response_seen
    response = team_control_error_response(refusal.value)
    assert response.status_code == 422
    assert json.loads(response.body) == {
        "detail": {
            "code": "registry_response_unusable",
            "message": (
                "AWID returned invalid team or certificate data. "
                "Ask the registry operator to correct the team record before importing."
            ),
        }
    }
    records = [
        record for record in caplog.records
        if record.name == "aweb.team_control_error_transport" and record.levelno == logging.ERROR
    ]
    assert len(records) == 1
    assert records[0].exc_info is not None
    assert records[0].exc_info[1].__cause__ is not None
