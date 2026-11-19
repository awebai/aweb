"""Service refusal data survives HTTP/MCP while unexpected failures stay private."""

import json
import logging
from http import HTTPStatus

import httpx
import pytest
from fastapi import FastAPI
from aweb.error_responses import service_error_handler
from aweb.mcp.tools.errors import INTERNAL_DELIVERY_ERROR, messaging_tool
from aweb.mcp.tools.refusals import send_refusal
from aweb.messaging.kinds import MessageKind
from aweb.messaging.refusals import (
    DeliveryRefusal,
    DeliveryRefusalCode,
    SignedRecipientMismatch,
)
from aweb.service_errors import ServiceError


@pytest.mark.asyncio
async def test_http_keeps_age_code_and_structured_refusal_data():
    error = DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail="timestamp outside accepted skew. Sign the message again with the current UTC time and retry.",
        headers={"X-AWEB-Error-Code": DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW.value},
        code=DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW,
    )
    app = FastAPI()
    app.add_exception_handler(ServiceError, service_error_handler)

    @app.get("/refused")
    async def refused():
        raise error

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/refused")
    assert response.status_code == 422
    assert response.json() == {"detail": error.detail}
    assert response.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
    assert error.code is DeliveryRefusalCode.TIMESTAMP_OUTSIDE_SKEW


@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
def test_signed_recipient_mismatch_is_a_type_with_an_action(kind):
    error = SignedRecipientMismatch(kind=kind)
    assert error.status_code == 422
    assert error.code is DeliveryRefusalCode.SIGNED_RECIPIENT_MISMATCH
    assert error.detail.endswith("Check the recipient and sign the message again.")
    assert json.loads(send_refusal(error))["error"] == error.detail


@pytest.mark.asyncio
async def test_mcp_unexpected_error_is_logged_without_exposing_its_text(caplog):
    @messaging_tool
    async def broken():
        raise KeyError("private internal field")

    with caplog.at_level(logging.ERROR, logger="aweb.mcp.tools.errors"):
        response = json.loads(await broken())
    assert response == {"error": INTERNAL_DELIVERY_ERROR}
    assert response["error"].endswith("contact the server operator.")
    assert "private internal field" not in json.dumps(response)
    assert len(caplog.records) == 1
    assert isinstance(caplog.records[0].exc_info[1], KeyError)


@pytest.mark.asyncio
async def test_mcp_expected_refusal_and_success_keep_their_existing_shape():
    @messaging_tool
    async def refused():
        raise DeliveryRefusal(
            status_code=HTTPStatus.CONFLICT,
            detail="Choose the current conversation and try again.",
        )

    @messaging_tool
    async def accepted():
        return '{"delivered":true}'

    assert json.loads(await refused()) == {
        "error": "Choose the current conversation and try again."
    }
    assert json.loads(await accepted()) == {"delivered": True}


def test_routes_reexport_the_service_request_types_without_a_second_validator():
    from aweb.messaging.mail_models import SendMessageRequest as MailInput
    from aweb.messaging.chat_models import (
        CreateSessionRequest,
        SendMessageRequest as ChatInput,
    )
    from aweb.routes.messages import SendMessageRequest as MailRouteInput
    from aweb.routes.chat import (
        CreateSessionRequest as ChatCreateRoute,
        SendMessageRequest as ChatRouteInput,
    )

    assert MailRouteInput is MailInput
    assert ChatCreateRoute is CreateSessionRequest
    assert ChatRouteInput is ChatInput
