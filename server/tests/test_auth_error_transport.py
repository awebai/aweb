"""Pure transport policy: expected native auth failures survive generic handlers."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.responses import JSONResponse
from aweb.application_state import (
    RegistryClientUnavailable,
    application_registry_client,
)
from aweb.auth_error_transport import install_auth_error_handlers
from aweb.service_errors import IdentityBindingCode, IdentityBindingError, ServiceError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,status,message",
    [
        (
            IdentityBindingCode.MISMATCH,
            403,
            "The claimed identity and signing key do not match. "
            "Check the identity and its current public-key binding, "
            "then correct the request and retry.",
        ),
        (
            IdentityBindingCode.UNAVAILABLE,
            503,
            "Identity verification is unavailable. Retry when the identity registry is available.",
        ),
    ],
)
async def test_binding_handler_preserves_reason_status_retry_and_action(
    code, status, message
):
    app = FastAPI()

    @app.exception_handler(ServiceError)
    async def generic(request, error):
        return JSONResponse(status_code=500, content={"detail": "generic"})

    install_auth_error_handlers(app)

    @app.get("/binding")
    async def binding():
        raise IdentityBindingError(code, headers={"Retry-After": "7"})

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://native.test"
    ) as client:
        response = await client.get("/binding")
    assert response.status_code == status
    assert response.json()["detail"] == code.value
    assert response.json()["message"] == message
    assert response.headers["Retry-After"] == "7"


@pytest.mark.asyncio
async def test_missing_serving_registry_keeps_its_expected_actionable_503():
    from fastapi import Request

    app = FastAPI()
    install_auth_error_handlers(app)

    @app.get("/registry")
    async def registry(request: Request):
        application_registry_client(request.app.state)
        pytest.fail("missing serving registry was accepted")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://native.test"
    ) as client:
        response = await client.get("/registry")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == RegistryClientUnavailable.code
    assert (
        "Configure the serving registry client" in response.json()["detail"]["message"]
    )
