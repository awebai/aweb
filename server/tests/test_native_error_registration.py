"""The production factory preserves typed auth errors beside generic services."""

import json

import pytest
from starlette.requests import Request

from aweb.api import create_app
from aweb.service_errors import IdentityBindingCode, IdentityBindingError, ServiceError


@pytest.mark.asyncio
async def test_native_factory_keeps_binding_unavailability_action_status_and_retry_header():
    app = create_app()
    assert ServiceError in app.exception_handlers
    refused = IdentityBindingError(
        IdentityBindingCode.UNAVAILABLE, headers={"Retry-After": "7"}
    )
    handler = app.exception_handlers[IdentityBindingError]
    response = await handler(Request({"type": "http"}), refused)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "7"
    assert json.loads(response.body) == {
        "detail": "identity_binding_unavailable",
        "message": "Identity verification is unavailable. Retry when the identity registry is available.",
    }
