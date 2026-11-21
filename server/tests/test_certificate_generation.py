"""Generation acceptance uses the real registry's controller, never mint bytes."""

from contextlib import aclosing
import socket

import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_certificate import TeamCertificateError, issue_team_certificate

from aweb.certificate_auth import (
    CertificateAuthorityContext,
    TeamControllerUnavailable,
    VerifiedCertificateGeneration,
    verify_certificate_generation,
)
from tests.real_stack import REGISTRY_URL


async def _registered_team(stack):
    controller, team, member = (bytes([n]) * 32 for n in (41, 42, 43))
    sdk = RegistryClient(
        registry_url=REGISTRY_URL,
        transport=stack.awid,
        service_token=stack.service_token,
    )
    await sdk.register_namespace(
        "local", did_key_from_signing_key(controller), controller
    )
    await sdk.register_team(
        domain="local",
        name="generation",
        display_name="Generation",
        team_did_key=did_key_from_signing_key(team),
        visibility="public",
        namespace_controller_signing_key=controller,
    )
    certificate, header = issue_team_certificate(
        team_id="generation:local",
        team_signing_key=team,
        member_did_key=did_key_from_signing_key(member),
        alias="worker",
        identity_scope="local",
    )
    return sdk, team, member, certificate, header


def _context(stack, sdk):
    return CertificateAuthorityContext(
        db=stack.aweb_db,
        registry_client=sdk,
        txt_resolver=SystemTXTOutcomeResolver(),
    )


@pytest.mark.asyncio
async def test_generation_under_registry_current_key_does_not_require_registration(
    real_stack,
):
    sdk, team, member, certificate, header = await _registered_team(real_stack)
    async with aclosing(sdk):
        proof = await verify_certificate_generation(
            context=_context(real_stack, sdk),
            team_id="generation:local",
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
        assert isinstance(proof, VerifiedCertificateGeneration)
        assert proof.verified_team_did_key == did_key_from_signing_key(team)
        assert (
            proof.certificate.claims["certificate_id"] == certificate["certificate_id"]
        )
        assert proof.certificate_fingerprint == proof.certificate.fingerprint
        assert await sdk.list_team_certificates("local", "generation") == []
        assert (
            await real_stack.aweb_db.fetch_value(
                "SELECT count(*) FROM {{tables.agents}} WHERE team_id=$1",
                "generation:local",
            )
            == 0
        )


@pytest.mark.asyncio
async def test_mint_without_controller_proof_cannot_produce_accepted_generation(
    real_stack,
):
    sdk, _, member, _, header = await _registered_team(real_stack)
    await sdk.aclose()
    before = await real_stack.aweb_db.fetch_all(
        "SELECT agent_id, accepted_team_did_key FROM {{tables.agents}} ORDER BY agent_id"
    )
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        async with aclosing(
            RegistryClient(registry_url=origin, timeout_seconds=0.2)
        ) as refused:
            with pytest.raises(TeamControllerUnavailable) as error:
                await verify_certificate_generation(
                    context=_context(real_stack, refused),
                    team_id="generation:local",
                    encoded_certificate=header,
                    member_did_key=did_key_from_signing_key(member),
                )
    assert error.value.status_code == 503
    assert "The agent is not usable yet." in error.value.message
    assert "Repeat the creation request" in error.value.message
    assert (
        await real_stack.aweb_db.fetch_all(
            "SELECT agent_id, accepted_team_did_key FROM {{tables.agents}} ORDER BY agent_id"
        )
        == before
    )


@pytest.mark.asyncio
async def test_generation_refuses_another_team_even_when_the_controller_key_matches(
    real_stack,
):
    sdk, team, member, _, _ = await _registered_team(real_stack)
    _, header = issue_team_certificate(
        team_id="another:local",
        team_signing_key=team,
        member_did_key=did_key_from_signing_key(member),
        alias="worker",
        identity_scope="local",
    )
    async with aclosing(sdk):
        with pytest.raises(TeamCertificateError) as refused:
            await verify_certificate_generation(
                context=_context(real_stack, sdk),
                team_id="generation:local",
                encoded_certificate=header,
                member_did_key=did_key_from_signing_key(member),
            )
    assert refused.value.reason == "certificate_binding_mismatch"
    assert refused.value.field == "team_id"


@pytest.mark.asyncio
async def test_generation_never_uses_the_minted_controller_as_current_evidence(
    real_stack,
):
    sdk, _, member, _, _ = await _registered_team(real_stack)
    _, header = issue_team_certificate(
        team_id="generation:local",
        team_signing_key=bytes([44]) * 32,
        member_did_key=did_key_from_signing_key(member),
        alias="worker",
        identity_scope="local",
    )
    before = sum(
        request.method == "GET"
        and request.url.path == "/v1/namespaces/local/teams/generation"
        for request in real_stack.awid.calls
    )
    async with aclosing(sdk):
        with pytest.raises(TeamCertificateError) as refused:
            await verify_certificate_generation(
                context=_context(real_stack, sdk),
                team_id="generation:local",
                encoded_certificate=header,
                member_did_key=did_key_from_signing_key(member),
            )
    assert refused.value.reason == "bad_signature"
    assert (
        sum(
            request.method == "GET"
            and request.url.path == "/v1/namespaces/local/teams/generation"
            for request in real_stack.awid.calls
        )
        - before
        == 1
    )
