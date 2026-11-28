"""Mail and chat sends the service refused, in the MCP tools' error shape."""

from __future__ import annotations

import json
from enum import Enum, auto

from fastapi import HTTPException
from aweb.service_errors import (
    ServiceError,
    IdentityBindingError,
    IdentityBindingCode,
    INTERNAL_SERVICE_ERROR_MESSAGE,
)
from aweb.application_state import RegistryClientUnavailable
from aweb.messaging.delivery_policy import DeliveryPolicyRefused

from awid.federation_errors import FederationAuthorityError
from aweb.messaging.refusals import (
    DeliveryRefusalCode,
    RecipientIdentityBindingError,
    MailConversationExists,
    RecipientAddressNotFound,
)
from aweb.e2ee_messages import E2EERecipientKeyMismatch
from aweb.federation.errors import (
    LocalRecipientNotFoundError,
    RecipientNotResidentError,
)
from aweb.messaging.address_auth import unreachable_address_refusal
from aweb.messaging.chat_send import LOCAL_DID_KEY_RECIPIENT_UNREACHABLE

REGISTRY_CANNOT_CONFIRM_ADDRESS = (
    "the registry can't confirm {address} right now; try again, or check the address"
)
SENDER_KEY_NOT_PUBLISHED = "your encryption key isn't published yet; try again shortly, and if it persists contact support"
SENDER_KEY_NOT_VERIFIABLE = (
    "your published encryption key can't be verified right now; try again shortly, "
    "and if it persists contact support"
)
RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE = (
    "this recipient's published encryption key can't be verified right now; try again later, "
    "and if it persists contact support"
)
RECIPIENT_KEY_CHANGED = "this recipient's key changed; resend the message"
RECIPIENT_UNREACHABLE_IN_CONVERSATION = (
    "this recipient can no longer be reached in this conversation; "
    "start a new conversation with them by alias or address"
)
CONVERSATION_CHANGED_DURING_SEND = (
    "this conversation changed while the message was being sent; send it again"
)

# What a hosted sender does next when the custody check refuses its envelope.
# The sender of a hosted envelope holds a hosted key, so the check refused
# because that key, or the recipient's, is not verifiably published here.
_HOSTED_ENVELOPE_NEXT_ACTIONS = {
    "recipient_custodial_no_e2ee": SENDER_KEY_NOT_PUBLISHED,
    "federation_envelope_invalid": SENDER_KEY_NOT_VERIFIABLE,
    "recipient_encryption_assertion_invalid_or_stale": RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE,
}


class SendRefusalMode(Enum):
    """Whether refusal wording describes an envelope prepared by hosted custody."""

    STANDARD = auto()
    HOSTED_ENVELOPE = auto()


def require_send_refusal_mode(mode: SendRefusalMode) -> None:
    """Reject unnamed formatting intent before interpreting any refusal subtype."""
    if not isinstance(mode, SendRefusalMode):
        raise TypeError(
            "Pass a named SendRefusalMode value before formatting a send refusal."
        )


def send_refusal(
    exc: Exception,
    *,
    address: str = "",
    mode: SendRefusalMode = SendRefusalMode.STANDARD,
) -> str:
    """A send the service refused, in the tools' error shape.

    The reader is a language model: a refusal it can act on is a sentence
    naming the next action, with the service's code beside it as ``reason``.
    ``address`` is the full address the send named. ``mode`` says whether
    hosted custody prepared the encrypted envelope. A full address that reaches
    no one is refused in one set of words, which do not say whether a local
    identity holds that name.
    """
    require_send_refusal_mode(mode)
    if isinstance(exc, DeliveryPolicyRefused):
        if address and exc.code is DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING:
            # MCP's released address refusal does not disclose a local identity.
            return json.dumps(
                {
                    "error": unreachable_address_refusal(address),
                    "reason": DeliveryRefusalCode.RECIPIENT_IDENTITY_NOT_FOUND.value,
                }
            )
        return json.dumps({"error": exc.detail, "reason": exc.code.value})
    if (
        isinstance(exc, RecipientIdentityBindingError)
        and exc.code is IdentityBindingCode.MISMATCH
    ):
        return json.dumps({"error": RECIPIENT_KEY_CHANGED, "reason": exc.code})
    if isinstance(exc, (IdentityBindingError, RegistryClientUnavailable)):
        return json.dumps({"error": exc.message, "reason": exc.code})
    if isinstance(exc, RecipientAddressNotFound) and address:
        return json.dumps(
            {"error": unreachable_address_refusal(address), "reason": exc.code.value}
        )
    if isinstance(exc, MailConversationExists):
        return json.dumps({"error": exc.recovery_action, "reason": exc.code.value})
    if (
        address
        and isinstance(exc, FederationAuthorityError)
        and not isinstance(exc, RecipientNotResidentError)
        and exc.reason
        in ("recipient_identity_not_found", "local_recipient_route_missing")
    ):
        # Normalize before local-miss subtype details (including R2's typed
        # local recipient refusal). A registered global nonresident retains
        # its distinct operator action; registry selection already found it.
        return json.dumps(
            {
                "error": unreachable_address_refusal(address),
                "reason": DeliveryRefusalCode.RECIPIENT_IDENTITY_NOT_FOUND.value,
            }
        )
    if isinstance(exc, (RecipientNotResidentError, LocalRecipientNotFoundError)):
        return json.dumps(
            {"error": exc.detail, "reason": exc.reason, "retryable": exc.retryable}
        )
    if isinstance(exc, FederationAuthorityError):
        if exc.reason in (
            "recipient_identity_not_found",
            "local_recipient_route_missing",
        ):
            reason = (
                DeliveryRefusalCode.RECIPIENT_IDENTITY_NOT_FOUND.value
                if address
                else exc.reason
            )
            return json.dumps(
                {"error": unreachable_address_refusal(address), "reason": reason}
            )
        next_action = None
        if address and exc.reason == "sender_registry_unavailable":
            next_action = REGISTRY_CANNOT_CONFIRM_ADDRESS.format(address=address)
        elif mode is SendRefusalMode.HOSTED_ENVELOPE:
            next_action = _HOSTED_ENVELOPE_NEXT_ACTIONS.get(exc.reason)
        if next_action is not None:
            return json.dumps({"error": next_action, "reason": exc.reason})
        return json.dumps(
            {
                "error": exc.reason,
                "message": (
                    "The federation service cannot complete this send now. Wait briefly and retry."
                    if exc.retryable
                    else "The federation service refused this send. Check the recipient and signed message with the server operator, then retry."
                ),
            }
        )
    detail = exc.detail if isinstance(exc, (ServiceError, HTTPException)) else None
    if (
        isinstance(exc, (ServiceError, HTTPException))
        and isinstance(detail, dict)
        and detail.get("code") == "address_evidence_unavailable"
    ):
        return json.dumps(
            {"error": detail["message"], "reason": detail["code"], "retryable": True}
        )
    if isinstance(exc.__cause__, E2EERecipientKeyMismatch):
        return json.dumps({"error": RECIPIENT_KEY_CHANGED})
    if detail == LOCAL_DID_KEY_RECIPIENT_UNREACHABLE:
        return json.dumps({"error": RECIPIENT_UNREACHABLE_IN_CONVERSATION})
    return json.dumps(
        {"error": detail if detail is not None else INTERNAL_SERVICE_ERROR_MESSAGE}
    )
