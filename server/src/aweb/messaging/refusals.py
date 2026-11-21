"""Stable delivery refusal codes shared by transport adapters."""

from enum import StrEnum
from http import HTTPStatus
import logging

from aweb.service_errors import IdentityBindingError, ServiceError, ValidationError
from aweb.messaging.kinds import MessageKind
from aweb.messaging.recipient_bindings import RecipientSelectorField

logger = logging.getLogger(__name__)


class RecipientIdentityBindingError(IdentityBindingError):
    """The recipient binding failed; sender authentication remains separate."""


class DeliveryRefusalCode(StrEnum):
    """Machine-readable reasons supplementing the existing human detail."""

    SIGNED_RECIPIENT_MISMATCH = "signed_recipient_mismatch"
    TIMESTAMP_OUTSIDE_SKEW = "message_timestamp_outside_skew"

    LOCAL_RECIPIENT_ROUTE_MISSING = "local_recipient_route_missing"
    RECIPIENT_POLICY_REJECTED = "recipient_policy_rejected"
    CONTACT_IDENTITY_BINDING_REQUIRED = "contact_identity_binding_required"
    CONVERSATION_EXISTS = "conversation_exists"
    RECIPIENT_IDENTITY_NOT_FOUND = "recipient_identity_not_found"
    REQUEST_INVALID = "request_invalid"


CONTACT_REBIND_ACTION = "This address now belongs to a different identity. Check the contact and explicitly bind it again before sending."


class ContactIdentityBindingRequired(ValidationError):
    """A saved identity constraint cannot authorize the current address holder."""

    code = DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED

    def __init__(self) -> None:
        super().__init__(CONTACT_REBIND_ACTION)


class DeliveryRefusal(ServiceError):
    """A delivery refusal whose data survives both HTTP and direct Python calls.

    docs/mail-and-chat.md describes one send contract for HTTP and hosted MCP.
    Adapters serialize status, detail and optional headers; services do not
    construct a framework exception or discard a structured detail.
    """

    def __init__(
        self,
        *,
        status_code: HTTPStatus | int,
        detail: str | dict,
        headers: dict[str, str] | None = None,
        code: DeliveryRefusalCode | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = int(status_code)
        self.headers = headers
        self.code = code


class RecipientAddressNotFound(DeliveryRefusal):
    """A recipient address has no usable route under the address binding rule."""

    code: DeliveryRefusalCode

    def __init__(self, *, address: str) -> None:
        super().__init__(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Recipient address not found: {address}. Check the address and try again.",
            code=DeliveryRefusalCode.RECIPIENT_IDENTITY_NOT_FOUND,
        )


class SignedRecipientMismatch(DeliveryRefusal):
    """Supplied signed recipient claims disagree with the selected identity."""

    def __init__(self, *, kind: MessageKind) -> None:
        target = "mail recipient" if kind is MessageKind.MAIL else "chat target"
        super().__init__(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=DeliveryRefusalCode.SIGNED_RECIPIENT_MISMATCH,
            detail=f"signed_payload recipient must match the {target}. Check the recipient and sign the message again.",
        )


class MailConversationExists(DeliveryRefusal):
    """Retain the frozen collision detail and add a separate recovery action."""

    code: DeliveryRefusalCode
    recovery_action = (
        "Continue the existing conversation or choose a new conversation_id and retry."
    )

    def __init__(self) -> None:
        # docs/aweb-sot.md:1008 fixes this detail as a released wire value.
        super().__init__(
            status_code=HTTPStatus.CONFLICT,
            detail="conversation_exists",
            code=DeliveryRefusalCode.CONVERSATION_EXISTS,
        )


def recipient_selector_mismatch(
    *, supplied: RecipientSelectorField, resolved: RecipientSelectorField
) -> DeliveryRefusal:
    """Explain conflicting explicit selectors before signing or storing a send."""
    return DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail=f"{supplied.value} must match the {resolved.value} recipient. Check the recipient and try again.",
    )


def registry_dependency_refusal(exc: Exception, *, operation: str) -> DeliveryRefusal:
    """Use the shared upstream classifier without importing HTTP into delivery."""
    from aweb.awid_error_handling import classify_awid_dependency_error

    # Keep upstream exception/body text out of the delivery log.
    status_code, detail = classify_awid_dependency_error(exc, operation=operation)
    logger.log(
        logging.ERROR if status_code == HTTPStatus.INTERNAL_SERVER_ERROR else logging.WARNING,
        "delivery_registry_dependency_failed failure_type=%s status=%d",
        type(exc).__name__,
        status_code,
    )
    return DeliveryRefusal(status_code=status_code, detail=detail)


def signed_chat_payload_refusal(*, detail: str) -> DeliveryRefusal:
    """Keep signed chat field failures actionable at every send/retry boundary.

    Implements the sender-artifact checks in
    Direct Address Send Protocol (docs/identity-messaging-contract.md:156-168).
    """
    return DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail=detail.rstrip(".") + ". Check the chat fields and sign the message again.",
    )


def encrypted_message_refusal(*, detail: str) -> DeliveryRefusal:
    """An encrypted artifact refusal never tells a timeout retry to duplicate it."""
    return DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=DeliveryRefusalCode.REQUEST_INVALID,
        detail=detail.rstrip(".")
        + ". Check whether the original message was delivered before preparing a new encrypted message.",
    )


def unreachable_address_refusal(address: str) -> str:
    """One not-routable action for address and other local-only selectors."""
    if not address:
        return (
            "The recipient is not reachable from outside its team. "
            "Use a teammate alias from inside its team, or ask the recipient "
            "for a registered address and retry."
        )
    return (
        f"{address} is not a registered address. A local identity has no address and "
        "is reachable only from inside its own team, by alias; a global identity is "
        "reachable by address once one is assigned. Check the address or use a teammate alias and retry."
    )
