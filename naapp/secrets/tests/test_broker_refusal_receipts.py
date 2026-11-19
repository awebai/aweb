"""Only fixed, value-free refusal explanations survive the durable boundary."""

import pytest
from aweb_naapp.dispatch import State
from aweb_secrets_values import ValueInvalid, ValueInvalidReason

from aweb_secrets.broker_outcomes import durable_broker_receipt, not_sent_message
from aweb_secrets.member_types import ToolReply


def test_a_kind_refusal_remains_actionable_in_the_durable_receipt():
    message = str(ValueInvalid(ValueInvalidReason.BASIC_USERNAME))
    receipt = durable_broker_receipt(
        ToolReply(503, {"state": State.NOT_SENT.value, "message": message})
    )
    assert receipt["message"] == message


@pytest.mark.parametrize("message", ["untrusted provider text", {"value": "untrusted"}])
def test_arbitrary_provider_details_are_not_persisted_as_refusal_explanations(message):
    receipt = durable_broker_receipt(
        ToolReply(503, {"state": State.NOT_SENT.value, "message": message})
    )
    assert "message" not in receipt
    assert not_sent_message({"state": State.NOT_SENT.value, "message": message}) is None


def test_the_shared_message_projection_accepts_only_not_sent_outcomes():
    message = str(ValueInvalid(ValueInvalidReason.BASIC_USERNAME))
    assert not_sent_message({"state": State.NOT_SENT.value, "message": message}) == message
    assert not_sent_message({"state": State.COMPLETED.value, "message": message}) is None
