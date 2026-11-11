"""Mail and chat sends the service refused, in the MCP tools' error shape."""

from __future__ import annotations

import json

from fastapi import HTTPException

from awid.federation_errors import FederationAuthorityError
from aweb.e2ee_messages import E2EERecipientKeyMismatch
from aweb.federation.errors import RecipientNotResidentError
from aweb.messaging.address_auth import unreachable_address_refusal
from aweb.messaging.chat_send import LOCAL_DID_KEY_RECIPIENT_UNREACHABLE

REGISTRY_CANNOT_CONFIRM_ADDRESS = "the registry can't confirm {address} right now; try again, or check the address"
SENDER_KEY_NOT_PUBLISHED = (
    "your encryption key isn't published yet; try again shortly, and if it persists contact support"
)
SENDER_KEY_NOT_VERIFIABLE = (
    "your published encryption key can't be verified right now; try again shortly, "
    "and if it persists contact support"
)
RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE = (
    "this recipient's published encryption key can't be verified right now; try again later, "
    "and if it persists contact support"
)
RECIPIENT_KEY_CHANGED = "this recipient's key changed; resend the message"
RECIPIENT_NOT_AS_REGISTERED = (
    "this recipient's identity or key no longer matches the registry; check the address and resend"
)
REGISTRY_CANNOT_CONFIRM_RECIPIENT_KEY = (
    "the registry can't confirm this recipient's key right now; try again shortly"
)
RECIPIENT_UNREACHABLE_IN_CONVERSATION = (
    "this recipient can no longer be reached in this conversation; "
    "start a new conversation with them by alias or address"
)

# What a hosted sender does next when the custody check refuses its envelope.
# The sender of a hosted envelope holds a hosted key, so the check refused
# because that key, or the recipient's, is not verifiably published here.
_HOSTED_ENVELOPE_NEXT_ACTIONS = {
    "recipient_custodial_no_e2ee": SENDER_KEY_NOT_PUBLISHED,
    "federation_envelope_invalid": SENDER_KEY_NOT_VERIFIABLE,
    "recipient_encryption_assertion_invalid_or_stale": RECIPIENT_ENCRYPTION_KEY_NOT_VERIFIABLE,
}
_IDENTITY_BINDING_NEXT_ACTIONS = {
    "identity_binding_mismatch": RECIPIENT_NOT_AS_REGISTERED,
    "identity_binding_unavailable": REGISTRY_CANNOT_CONFIRM_RECIPIENT_KEY,
}


def send_refusal(exc: Exception, *, address: str = "", hosted_envelope: bool = False) -> str:
    """A send the service refused, in the tools' error shape.

    The reader is a language model: a refusal it can act on is a sentence
    naming the next action, with the service's code beside it as ``reason``.
    ``address`` is the full address the send named, ``hosted_envelope`` whether
    hosted custody encrypted it. A full address that reaches no one is refused
    in one set of words, which do not say whether a local identity holds that
    name.
    """
    if isinstance(exc, RecipientNotResidentError):
        return json.dumps({"error": exc.detail, "reason": exc.reason, "retryable": exc.retryable})
    if isinstance(exc, FederationAuthorityError):
        if address and exc.reason in ("recipient_identity_not_found", "local_recipient_route_missing"):
            return json.dumps({"error": unreachable_address_refusal(address)})
        next_action = None
        if address and exc.reason == "sender_registry_unavailable":
            next_action = REGISTRY_CANNOT_CONFIRM_ADDRESS.format(address=address)
        elif hosted_envelope:
            next_action = _HOSTED_ENVELOPE_NEXT_ACTIONS.get(exc.reason)
        if next_action is not None:
            return json.dumps({"error": next_action, "reason": exc.reason})
        return json.dumps({"error": exc.reason})
    detail = getattr(exc, "detail", None)
    # Mail refuses an unknown address without naming it; chat names it.
    if address and detail in ("Recipient address not found", f"Recipient address not found: {address}"):
        return json.dumps({"error": unreachable_address_refusal(address)})
    if isinstance(exc.__cause__, E2EERecipientKeyMismatch):
        return json.dumps({"error": RECIPIENT_KEY_CHANGED})
    if isinstance(exc, HTTPException) and isinstance(detail, str) and detail in _IDENTITY_BINDING_NEXT_ACTIONS:
        return json.dumps({"error": _IDENTITY_BINDING_NEXT_ACTIONS[detail], "reason": detail})
    if detail == LOCAL_DID_KEY_RECIPIENT_UNREACHABLE:
        return json.dumps({"error": RECIPIENT_UNREACHABLE_IN_CONVERSATION})
    return json.dumps({"error": detail or str(exc)})
