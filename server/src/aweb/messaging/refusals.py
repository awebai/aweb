"""Stable delivery refusal codes shared by transport adapters."""

from enum import StrEnum

from aweb.service_errors import ValidationError


class DeliveryRefusalCode(StrEnum):
    """Machine-readable reasons supplementing the existing human detail."""

    TIMESTAMP_OUTSIDE_SKEW = "message_timestamp_outside_skew"

    RECIPIENT_POLICY_REJECTED = "recipient_policy_rejected"
    CONTACT_IDENTITY_BINDING_REQUIRED = "contact_identity_binding_required"


CONTACT_REBIND_ACTION = "This address now belongs to a different identity. Check the contact and explicitly bind it again before sending."


class ContactIdentityBindingRequired(ValidationError):
    """A saved identity constraint cannot authorize the current address holder."""

    code = DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED

    def __init__(self) -> None:
        super().__init__(CONTACT_REBIND_ACTION)
