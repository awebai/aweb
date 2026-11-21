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
    assert response.json() == {
        "detail": "timestamp outside accepted skew. Sign the message again with the current UTC time and retry."
    }
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
    assert "failure_type=KeyError" in caplog.text
    assert "private internal field" not in caplog.text
    assert caplog.records[0].exc_info is None


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


@pytest.mark.asyncio
async def test_mcp_binding_unavailability_preserves_the_shared_refusal_action():
    from aweb.service_errors import IdentityBindingCode, IdentityBindingError

    error = IdentityBindingError(IdentityBindingCode.UNAVAILABLE)

    @messaging_tool
    async def refused():
        raise error

    assert json.loads(await refused()) == {
        "error": error.message,
        "reason": error.code.value,
    }


@pytest.mark.asyncio
async def test_mcp_missing_registry_configuration_keeps_the_shared_action():
    from aweb.application_state import RegistryClientUnavailable

    error = RegistryClientUnavailable()

    @messaging_tool
    async def refused():
        raise error

    assert json.loads(await refused()) == {
        "error": error.message,
        "reason": error.code,
    }


@pytest.mark.parametrize(
    "reason", ["federation_rate_limited", "recipient_custodial_no_e2ee"]
)
def test_mcp_federation_codes_keep_a_recovery_sentence_without_host_context(reason):
    from awid.federation_errors import FederationAuthorityError

    answer = json.loads(send_refusal(FederationAuthorityError(reason)))
    assert answer["error"] == reason
    assert answer["message"].endswith("retry.")


@pytest.mark.asyncio
async def test_http_internal_failure_has_an_action_without_exception_content(caplog):
    from aweb.error_responses import install_service_error_handlers

    app = FastAPI()
    install_service_error_handlers(app)

    @app.get("/failed")
    async def failed():
        raise ServiceError("private internal field")

    with caplog.at_level(logging.ERROR, logger="aweb.error_responses"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/failed")
    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal server error",
        "message": INTERNAL_DELIVERY_ERROR,
    }
    assert "failure_type=ServiceError" in caplog.text
    assert "private internal field" not in caplog.text


def test_unexpected_refusal_input_never_exposes_exception_content():
    assert json.loads(send_refusal(RuntimeError("private internal field"))) == {
        "error": INTERNAL_DELIVERY_ERROR,
    }


@pytest.mark.parametrize("mode", [True, False, "hosted_envelope", None])
def test_send_refusal_rejects_unnamed_mode_before_inspecting_the_error(mode):
    class UnreadableError(Exception):
        @property
        def detail(self):
            raise AssertionError("A wrong mode must not reach error interpretation")

    with pytest.raises(TypeError) as refused:
        send_refusal(UnreadableError(), mode=mode)
    assert str(refused.value) == (
        "Pass a named SendRefusalMode value before formatting a send refusal."
    )

    from aweb.mcp.tools.chat import _send_refusal
    from aweb.messaging.chat_policy import HumanChatRefused

    class UnreadableHumanChatRefused(HumanChatRefused):
        def body(self, *, correlation_id=None):
            raise AssertionError("A wrong mode must not reach human refusal formatting")

    with pytest.raises(TypeError) as human_refused:
        _send_refusal(UnreadableHumanChatRefused("peer"), mode=mode)
    assert str(human_refused.value) == str(refused.value)


@pytest.mark.asyncio
async def test_policy_refusal_code_and_action_reach_http_and_mcp():
    from aweb.messaging.delivery_policy import DeliveryPolicyRefused

    detail = "Recipient refuses this sender. Ask the recipient to add your exact address as a contact and retry."
    error = DeliveryPolicyRefused(
        code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED, detail=detail
    )
    app = FastAPI()
    app.add_exception_handler(ServiceError, service_error_handler)

    @app.get("/policy")
    async def policy():
        raise error

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/policy")
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Recipient refuses this sender. Ask the recipient to add your exact address as a contact and retry.",
        "reason": "recipient_policy_rejected",
    }
    assert json.loads(send_refusal(error)) == {
        "error": "Recipient refuses this sender. Ask the recipient to add your exact address as a contact and retry.",
        "reason": "recipient_policy_rejected",
    }


def test_encrypted_refusal_action_checks_delivery_before_creating_another_message():
    from aweb.messaging.refusals import encrypted_message_refusal

    refused = encrypted_message_refusal(detail="encrypted envelope expired")
    assert refused.status_code == 422
    assert refused.detail == (
        "encrypted envelope expired. Check whether the original message was delivered before preparing a new encrypted message."
    )
