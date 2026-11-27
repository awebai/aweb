"""Registry refusals preserve the public status, code and recovery action."""

import json

import httpx
import pytest

from awid.registry import RegistryError
from aweb.messaging.refusals import registry_dependency_refusal
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


@pytest.mark.parametrize(
    "error,status,action",
    [
        (
            httpx.ConnectError("request-content-marker"),
            503,
            "Retry when the registry is available",
        ),
        (
            RegistryError(
                "request-content-marker",
                status_code=503,
                detail="request-content-marker",
            ),
            503,
            "Retry when the registry is available",
        ),
        (
            RegistryError("request-content-marker", status_code=403),
            422,
            "Ask the server operator to check the registry",
        ),
        (
            RuntimeError("request-content-marker"),
            500,
            "Ask the server operator to investigate",
        ),
    ],
)
def test_delivery_registry_refusal_keeps_status_and_action_without_input_text(
    error, status, action, caplog
):
    refusal = registry_dependency_refusal(
        error, operation="AWID remote chat route resolution"
    )
    assert refusal.status_code == status
    if status == 422:
        assert refusal.detail["code"] == "registry_response_unusable"
        message = refusal.detail["message"]
    else:
        message = refusal.detail
    assert action in message
    assert ("retry" in message.lower()) == (status == 503)
    assert "request-content-marker" not in message
    assert "request-content-marker" not in caplog.text
    assert f"failure_type={type(error).__name__} status={status}" in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
async def test_mail_send_returns_coded_422_for_an_unusable_registry_response(
    privacy_app, caplog
):
    env = privacy_app
    actor = env.actors["alice"]
    # The real AWID address route refuses this namespace after canonicalization.
    registry_path = "/v1/namespaces/.../addresses/bob"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env.registry_app),
        base_url="http://registry.test",
    ) as registry:
        upstream = await registry.get(registry_path)
    assert upstream.status_code == 400, upstream.text
    assert upstream.json() == {"detail": "Invalid domain"}

    body = json.dumps(
        {"to_address": ".../bob", "subject": "Hello", "body": "Hello"}
    ).encode()
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    headers["Content-Type"] = "application/json"
    env.registry.transport.calls.clear()

    response = await env.client.post("/v1/messages", content=body, headers=headers)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == {
        "code": "registry_response_unusable",
        "message": (
            "AWID recipient address lookup received an unusable registry response. "
            "Ask the server operator to check the registry."
        ),
    }
    assert any(call.url.path == registry_path for call in env.registry.transport.calls)
    assert "Invalid domain" not in caplog.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
