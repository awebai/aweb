"""Stable delivery refusal codes shared by transport adapters."""

from enum import StrEnum
from http import HTTPStatus

from aweb.service_errors import ServiceError, ValidationError
from aweb.messaging.kinds import MessageKind
from aweb.messaging.recipient_bindings import RecipientSelectorField


class DeliveryRefusalCode(StrEnum):
    """Machine-readable reasons supplementing the existing human detail."""

    SIGNED_RECIPIENT_MISMATCH = "signed_recipient_mismatch"
    TIMESTAMP_OUTSIDE_SKEW = "message_timestamp_outside_skew"

    RECIPIENT_POLICY_REJECTED = "recipient_policy_rejected"
    CONTACT_IDENTITY_BINDING_REQUIRED = "contact_identity_binding_required"


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


class SignedRecipientMismatch(DeliveryRefusal):
    """Supplied signed recipient claims disagree with the selected identity."""

    def __init__(self, *, kind: MessageKind) -> None:
        target = "mail recipient" if kind is MessageKind.MAIL else "chat target"
        super().__init__(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=DeliveryRefusalCode.SIGNED_RECIPIENT_MISMATCH,
            detail=f"signed_payload recipient must match the {target}. Check the recipient and sign the message again.",
        )


def recipient_selector_mismatch(
    *, supplied: RecipientSelectorField, resolved: RecipientSelectorField
) -> DeliveryRefusal:
    """Explain conflicting explicit selectors before signing or storing a send."""
    return DeliveryRefusal(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail=f"{supplied.value} must match the {resolved.value} recipient. Check the recipient and try again.",
    )


def registry_configuration_refusal(*, operation: str) -> DeliveryRefusal:
    """Keep the registry's configuration diagnosis in the service carrier."""
    from aweb.awid_error_handling import awid_registry_not_configured_detail

    return DeliveryRefusal(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        detail=awid_registry_not_configured_detail(operation=operation),
    )


def registry_dependency_refusal(exc: Exception, *, operation: str) -> DeliveryRefusal:
    """Use the shared upstream classifier without importing HTTP into delivery."""
    from aweb.awid_error_handling import classify_awid_dependency_error

    status_code, detail = classify_awid_dependency_error(exc, operation=operation)
    return DeliveryRefusal(status_code=status_code, detail=detail)
