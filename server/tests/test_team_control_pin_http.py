"""Real admission then public team recreation cannot silently replace a pin."""

from contextlib import aclosing
from datetime import datetime, timezone

import pytest
from aweb.api import create_app
from aweb.certificate_auth import verify_certificate_generation
from aweb.controller_import import verify_controller_import
from aweb.routes.connect import connect_agent
from aweb.team_control_authority import TeamControlAuthorityContext
from aweb.team_control_error_transport import install_team_control_error_handlers
from aweb.unowned_team_claim import UnownedTeamClaimTarget, verify_unowned_team_claim
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_certificate import issue_team_certificate
from awid.team_control_requests import TeamImportRequest, UnownedTeamClaimRequest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from tests.real_stack import REGISTRY_URL


@pytest.mark.asyncio
async def test_enforced_pin_refusal_keeps_shared401_for_claim_and_import_http(
    real_stack, monkeypatch
):
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    namespace, old, new, member = (bytes([n]) * 32 for n in (91, 92, 93, 94))
    sdk = RegistryClient(
        registry_url=REGISTRY_URL,
        transport=real_stack.awid,
        service_token=real_stack.service_token,
    )
    context = TeamControlAuthorityContext(
        db=real_stack.aweb_db,
        registry_client=sdk,
        txt_resolver=SystemTXTOutcomeResolver(),
    )
    target = UnownedTeamClaimTarget(
        team_id="pinned:local", email="owner@example.com", username="owner"
    )
    async with aclosing(sdk):
        await sdk.register_namespace(
            "local", did_key_from_signing_key(namespace), namespace
        )

        async def register(key):
            await sdk.register_team(
                domain="local",
                name="pinned",
                display_name="Pinned",
                team_did_key=did_key_from_signing_key(key),
                visibility="public",
                namespace_controller_signing_key=namespace,
            )

        await register(old)
        _, header = issue_team_certificate(
            team_id=target.team_id,
            team_signing_key=old,
            member_did_key=did_key_from_signing_key(member),
            alias="member",
            identity_scope="local",
        )
        generation = await verify_certificate_generation(
            context=context,
            team_id=target.team_id,
            encoded_certificate=header,
            member_did_key=did_key_from_signing_key(member),
        )
        # This is the released native constructor's verified-fields input,
        # derived only from the actual generation owner above. No SQL seed,
        # mint-only bytes, fabricated generation or second constructor.
        claims = generation.certificate.claims
        connected = await connect_agent(
            db=real_stack.aweb_db,
            cert_info={
                "team_id": claims["team_id"],
                "alias": claims["alias"],
                "did_key": claims["member_did_key"],
                "certificate_id": claims["certificate_id"],
                "identity_scope": claims["identity_scope"],
            },
            team_did_key=generation.verified_team_did_key,
            hostname="host",
            workspace_path="/member",
            repo_origin="",
            role="developer",
            human_name="",
            agent_type="agent",
        )
        assert connected["agent_id"]
        before = await real_stack.aweb_db.fetch_all(
            "SELECT agent_id, accepted_team_did_key FROM {{tables.agents}} WHERE team_id=$1",
            target.team_id,
        )
        assert len(before) == 1
        assert before[0]["accepted_team_did_key"] == did_key_from_signing_key(old)

        def claim(key):
            return UnownedTeamClaimRequest(
                awid_team_id=target.team_id,
                email=target.email,
                username=target.username,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ).sign(signing_key=key)

        # Real valid neighbor before the registry's generation changes.
        accepted = await verify_unowned_team_claim(
            context=context, claim=claim(old), target=target
        )
        assert accepted.verified_team_did_key == did_key_from_signing_key(old)
        request = TeamImportRequest(
            awid_team_id=target.team_id,
            organization_id="organization-1",
            dry_run=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        preview = await verify_controller_import(
            context=context,
            request=request,
            controller_signature=request.sign(signing_key=old),
        )
        assert preview.verified_team_did_key == did_key_from_signing_key(old)

        # Namespace-authorized deletion/recreation is a real public operation.
        # It yields a different controller with no continuity act for the old
        # native pin; no fabricated registry response or SQL rewrite is used.
        await sdk.delete_team("local", "pinned", namespace)
        await register(new)
        assert await sdk.get_team_key_act("local", "pinned") is None
        current_claim = claim(new)
        current_claim.verify_integrity()
        signature = request.sign(signing_key=new)
        outer = FastAPI()
        install_team_control_error_handlers(outer)
        for app in (create_app(), outer):

            @app.post("/claim-proof")
            async def claim_endpoint():
                await verify_unowned_team_claim(
                    context=context, claim=current_claim, target=target
                )
                return {"accepted": True}

            @app.post("/import-proof")
            async def import_endpoint():
                await verify_controller_import(
                    context=context, request=request, controller_signature=signature
                )
                return {"accepted": True}

            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False),
                base_url="https://native.test",
            ) as client:
                for path in ("/claim-proof", "/import-proof"):
                    response = await client.post(path)
                    assert response.status_code == 401, response.text
                    assert response.json() == {
                        "detail": (
                            "team_key_unverified: The team key change could not be verified. "
                            "Ask the team administrator to verify the namespace controller's current key-change record, then retry."
                        )
                    }
        assert (
            await real_stack.aweb_db.fetch_all(
                "SELECT agent_id, accepted_team_did_key FROM {{tables.agents}} WHERE team_id=$1",
                target.team_id,
            )
            == before
        )
        assert await real_stack.aweb_db.fetch_value(
            "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1", target.team_id
        ) == did_key_from_signing_key(old)
