"""Ordinary imports acquire exact fresh metadata from the real registry."""

from contextlib import aclosing
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_control_requests import TeamImportRequest

from aweb.controller_import import (
    VerifiedControllerImportMember,
    verify_controller_import,
)
from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
)
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
    # Metadata-only registration is a released API. No member secret or signed
    # certificate artifact is supplied to the import factory.
    for certificate_id, alias in (
        ("live-certificate", "live"),
        ("revoked-certificate", "revoked"),
    ):
        await sdk.register_team_certificate(
            "local",
            "import",
            team_controller_signing_key=controller,
            certificate_id=certificate_id,
            member_did_key=did_key_from_signing_key(member),
            member_did_aw=None,
            member_address=None,
            alias=alias,
            identity_scope="local",
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
            controller_signature=request.sign(signing_key=controller),
        )
    assert proof.request is request
    assert proof.request.organization_id == "organization-1"
    assert proof.request.team_id is None
    assert proof.team.team_id == "import:local"
    assert {row.certificate_id for row in proof.certificates} == {
        "live-certificate",
        "revoked-certificate",
    }
    assert len(proof.members) == 1
    admitted = proof.members[0]
    assert isinstance(admitted, VerifiedControllerImportMember)
    assert admitted.team_id == "import:local"
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
                controller_signature=request.sign(signing_key=member),
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
    signature = request.sign(signing_key=old_controller)
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
