"""Review regressions at the refusal and managed-send component boundaries."""

import json
from types import SimpleNamespace

import pytest
from awid.federation_errors import FederationAuthorityError

from aweb.attachment_service import _send_context
from aweb.federation.errors import RecipientNotResidentError
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


@pytest.mark.parametrize(
    "reason", ["recipient_identity_not_found", "local_recipient_route_missing"]
)
def test_mcp_address_missing_family_uses_the_same_privacy_refusal(reason):
    address = "otherco.com/bob"
    result = json.loads(send_refusal(FederationAuthorityError(reason), address=address))
    assert result == {
        "error": unreachable_address_refusal(address),
        "reason": "recipient_identity_not_found",
    }


def test_mcp_registered_nonresident_keeps_its_operator_action():
    result = json.loads(send_refusal(RecipientNotResidentError(), address="otherco.com/bob"))
    assert result == {
        "error": (
            "The recipient is not set up for messaging on the server this address points to. "
            "Ask the recipient or the person who manages that server to check the address "
            "and the recipient's messaging setup."
        ),
        "reason": "recipient_identity_not_found",
        "retryable": False,
    }
