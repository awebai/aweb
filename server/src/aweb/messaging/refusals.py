"""Stable delivery refusal codes shared by transport adapters."""

from enum import StrEnum


class DeliveryRefusalCode(StrEnum):
    """Machine-readable reasons supplementing the existing human detail."""

    TIMESTAMP_OUTSIDE_SKEW = "message_timestamp_outside_skew"
