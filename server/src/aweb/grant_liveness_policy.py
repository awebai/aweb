"""Canonical availability policy for grant-liveness consumers."""

from enum import StrEnum


class GrantLivenessFailurePolicy(StrEnum):
    """Keep unproven online display distinct from proof of stale eligibility."""

    OMIT_UNPROVEN = "omit_unproven"
    REQUIRE_KNOWN = "require_known"
