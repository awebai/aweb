"""Review regressions at the refusal and managed-send component boundaries."""

import json
from types import SimpleNamespace

import pytest

from aweb.attachment_service import _send_context
from aweb.messaging.delivery_policy import DeliveryPolicyRefused
from aweb.messaging.kinds import MessageKind
from aweb.messaging.refusals import (
    DeliveryRefusalCode,
    MailConversationExists,
    RecipientAddressNotFound,
    SignedRecipientMismatch,
    unreachable_address_refusal,
)
from aweb.mcp.tools.refusals import send_refusal
from aweb.service_errors import ServiceError


@pytest.mark.parametrize(
    "error", [MailConversationExists(), SignedRecipientMismatch(kind=MessageKind.MAIL)]
)
def test_managed_send_does_not_relabel_another_owners_refusal(error):
    # Main's context propagates these same service responses unchanged.
    with pytest.raises(ServiceError) as caught:
        with _send_context(SimpleNamespace(bound=False)):
            raise error
    assert caught.value is error
    assert caught.value.status_code == error.status_code
    assert caught.value.detail == error.detail


def test_mcp_address_refusal_does_not_disclose_a_local_identity():
    address = "otherco.com/bob"
    local = DeliveryPolicyRefused(
        code=DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING,
        detail=unreachable_address_refusal(""),
    )
    local_result = json.loads(send_refusal(local, address=address))
    missing_result = json.loads(
        send_refusal(RecipientAddressNotFound(address=address), address=address)
    )
    assert local_result == missing_result
    assert local_result["reason"] == "recipient_identity_not_found"


def test_non_address_selector_refusal_describes_team_reachability():
    assert unreachable_address_refusal("") == (
        "The recipient is not reachable from outside its team. "
        "Use a teammate alias from inside its team, or ask the recipient "
        "for a registered address and retry."
    )
