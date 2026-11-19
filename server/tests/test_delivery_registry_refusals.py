"""Registry refusal boundaries retain status/action without upstream contents."""

import httpx
import pytest

from awid.registry import RegistryError
from aweb.messaging.refusals import (
    registry_configuration_refusal,
    registry_dependency_refusal,
)


@pytest.mark.parametrize(
    "error,status",
    [
        (httpx.ConnectError("request-content-marker"), 503),
        (
            RegistryError(
                "request-content-marker",
                status_code=503,
                detail="request-content-marker",
            ),
            503,
        ),
        (RuntimeError("request-content-marker"), 500),
    ],
)
def test_delivery_registry_refusal_keeps_status_and_action_without_input_text(
    error, status, caplog
):
    refusal = registry_dependency_refusal(
        error, operation="AWID remote chat route resolution"
    )
    assert refusal.status_code == status
    assert refusal.detail.endswith(
        "Retry when the registry is available; if this persists, ask the server operator to check the registry connection."
    )
    assert "request-content-marker" not in refusal.detail
    assert "request-content-marker" not in caplog.text
    assert f"failure_type={type(error).__name__} status={status}" in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_delivery_registry_configuration_refusal_explains_operator_recovery():
    refusal = registry_configuration_refusal(
        operation="AWID messaging recipient address lookup"
    )
    assert refusal.status_code == 500
    assert refusal.detail == (
        "AWID messaging recipient address lookup registry client not configured. Ask the server operator to configure the registry and retry."
    )
