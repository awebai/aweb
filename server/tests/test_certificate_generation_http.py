"""Actual unreachable generation evidence keeps its expected transport refusal."""

from contextlib import aclosing
import socket

import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_certificate import issue_team_certificate
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pgdbm import AsyncDatabaseManager, DatabaseConfig
from starlette.responses import JSONResponse

from aweb.api import create_app
from aweb.certificate_auth import (
    CertificateAuthorityContext,
    EvidenceMode,
    verify_certificate_generation,
)
from aweb.service_errors import INTERNAL_SERVICE_ERROR_MESSAGE, ServiceError


@pytest.mark.asyncio
@pytest.mark.parametrize("evidence", [EvidenceMode.CACHED, EvidenceMode.FRESH])
async def test_native_generation_keeps_unavailable_controller_503_and_action(evidence):
    await _assert_unavailable_generation_response(create_app(), evidence=evidence)


@pytest.mark.asyncio
async def test_outer_host_uses_the_same_generation_error_installer():
    from aweb.certificate_error_transport import install_certificate_error_handlers

    app = FastAPI()

    @app.exception_handler(ServiceError)
    async def generic(request, error):
        return JSONResponse(status_code=500, content={"detail": "generic"})

    install_certificate_error_handlers(app)
    await _assert_unavailable_generation_response(app, evidence=EvidenceMode.CACHED)


async def _assert_unavailable_generation_response(
    app: FastAPI, *, evidence: EvidenceMode
):
    team, member = bytes([51]) * 32, bytes([52]) * 32
    _, header = issue_team_certificate(
        team_id="generation:local",
        team_signing_key=team,
        member_did_key=did_key_from_signing_key(member),
        alias="worker",
        identity_scope="local",
    )
    db = AsyncDatabaseManager(
        DatabaseConfig(connection_string="postgresql://unused/test")
    )
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        async with aclosing(
            RegistryClient(
                registry_url=f"http://127.0.0.1:{reserved.getsockname()[1]}",
                timeout_seconds=0.1,
            )
        ) as sdk:
            context = CertificateAuthorityContext(
                db=db,
                registry_client=sdk,
                txt_resolver=SystemTXTOutcomeResolver(),
            )

            @app.post("/generation")
            async def generation():
                await verify_certificate_generation(
                    context=context,
                    team_id="generation:local",
                    encoded_certificate=header,
                    member_did_key=did_key_from_signing_key(member),
                    evidence=evidence,
                )
                pytest.fail("unreachable authority produced an accepted generation")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="https://native.test"
            ) as client:
                response = await client.post("/generation")
    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "team_controller_evidence_unavailable",
            "message": (
                "The team's current controller could not be confirmed. "
                "The agent is not usable yet. Repeat the creation request when the "
                "registry is reachable and the team's controller can be confirmed."
            ),
        },
    }


@pytest.mark.asyncio
async def test_unexpected_service_failure_still_hides_its_private_detail():
    app = create_app()

    @app.get("/unexpected-generation-failure")
    async def unexpected():
        raise ServiceError("private internal generation failure")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://native.test"
    ) as client:
        response = await client.get("/unexpected-generation-failure")
    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal server error",
        "message": INTERNAL_SERVICE_ERROR_MESSAGE,
    }
