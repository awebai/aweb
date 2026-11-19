"""Stable delivery refusal codes shared by transport adapters."""

from enum import StrEnum


class DeliveryRefusalCode(StrEnum):
    """Machine-readable reasons supplementing the existing human detail."""

    TIMESTAMP_OUTSIDE_SKEW = "message_timestamp_outside_skew"

    RECIPIENT_POLICY_REJECTED = "recipient_policy_rejected"
    CONTACT_IDENTITY_BINDING_REQUIRED = "contact_identity_binding_required"
