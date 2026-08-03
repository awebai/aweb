from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from aweb.api import create_app
from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.routes.messages import SendMessageRequest


def _create_validation_test_app():
    app = create_app()
    app.dependency_overrides[get_db] = lambda: object()

    async def _messaging_auth() -> MessagingAuth:
        return MessagingAuth(
            did_key="did:key:z6MkValidationTest",
            did_aw=None,
            address=None,
        )

    app.dependency_overrides[get_messaging_auth] = _messaging_auth
    return app


@pytest.mark.asyncio
async def test_non_federation_field_validation_uses_fastapi_error_serialization():
    payload = {
        "to_address": "example.com/bob",
        "body": "hello",
        "message_id": "not-a-uuid",
    }
    with pytest.raises(ValidationError) as captured:
        SendMessageRequest.model_validate(payload)
    assert isinstance(captured.value.errors()[0]["ctx"]["error"], ValueError)

    app = _create_validation_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post("/v1/messages", json=payload)

    assert response.status_code == 422
    assert response.json()["detail"] == [
        {
            "type": "value_error",
            "loc": ["body", "message_id"],
            "msg": "Value error, Invalid message_id format",
            "input": "not-a-uuid",
            "ctx": {"error": {}},
        }
    ]


def _federation_validation_payload() -> dict:
    return {
        "envelope": {
            "version": 1,
            "type": "mail",
            "sender_did_aw": "did:aw:sender",
            "sender_current_did_key": "did:key:sender",
            "target_address": "example.com/bob",
            "target_did_aw": "did:aw:bob",
            "target_current_did_key": "did:key:bob",
            "target_delivery_origin": "https://example.com",
            "body": "hello",
            "message_id": "11111111-1111-4111-8111-111111111111",
            "timestamp": "2026-08-03T00:00:00Z",
        },
        "signature": "signature",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("message_id", "not-a-uuid", "federation_envelope_invalid"),
        ("timestamp", "not-a-timestamp", "federation_timestamp_invalid"),
    ],
)
async def test_federation_field_validation_keeps_authority_error_contract(
    field: str,
    value: str,
    reason: str,
):
    app = _create_validation_test_app()
    payload = _federation_validation_payload()
    payload["envelope"][field] = value
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/federation/messages",
            headers={"X-Correlation-ID": "correlation-fixture"},
            json=payload,
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": reason,
        "reason": reason,
        "retryable": False,
        "correlation_id": "correlation-fixture",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "reason", "correlation_id"),
    [
        (
            "message_id",
            "not-a-uuid",
            "federation_envelope_invalid",
            "mounted-correlation-fixture",
        ),
        ("timestamp", "not-a-timestamp", "federation_timestamp_invalid", None),
    ],
)
async def test_mounted_federation_validation_keeps_authority_error_contract(
    field: str,
    value: str,
    reason: str,
    correlation_id: str | None,
):
    parent_app = FastAPI()
    parent_app.mount("/api", _create_validation_test_app())
    payload = _federation_validation_payload()
    payload["envelope"][field] = value
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}

    async with AsyncClient(
        transport=ASGITransport(app=parent_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/federation/messages",
            headers=headers,
            json=payload,
        )

    assert response.status_code == 422
    body = response.json()
    assert body.keys() == {"detail", "reason", "retryable", "correlation_id"}
    assert body["detail"] == reason
    assert body["reason"] == reason
    assert body["retryable"] is False
    if correlation_id is None:
        UUID(body["correlation_id"])
    else:
        assert body["correlation_id"] == correlation_id
