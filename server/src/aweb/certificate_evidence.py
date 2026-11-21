"""Certificate evidence strength, shared by acquisition and verification owners."""

from enum import StrEnum


class EvidenceMode(StrEnum):
    """The two strengths in team-auth-envelope-v2.md:60-70.

    CACHED retains the SDK's bounded freshness/grace policy. FRESH requires
    current acquisition and may never be answered by cached/grace evidence.
    Registration enforcement is the separate canonical RegistrationMode.
    """

    CACHED = "cached"
    FRESH = "fresh"
