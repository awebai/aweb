"""Frozen wire details and typed recovery stay separate from race detection."""

import json

import pytest
from starlette.requests import Request

from aweb.error_responses import service_error_handler
from aweb.mcp.tools.refusals import send_refusal
from aweb.messaging.mail_send import _lost_send_race
from aweb.messaging.refusals import DeliveryRefusal, MailConversationExists


@pytest.mark.asyncio
async def test_collision_keeps_released_detail_and_exposes_recovery_on_both_transports():
    refusal = MailConversationExists()
    response = await service_error_handler(Request({"type": "http"}), refusal)
    assert response.status_code == 409
    assert json.loads(response.body) == {
        "detail": "conversation_exists",
        "recovery_action": "Continue the existing conversation or choose a new conversation_id and retry.",
    }
    assert json.loads(send_refusal(refusal)) == {
        "error": "Continue the existing conversation or choose a new conversation_id and retry.",
        "reason": "conversation_exists",
    }
    assert _lost_send_race(refusal)
    assert not _lost_send_race(
        DeliveryRefusal(status_code=409, detail="conversation_exists")
    )
