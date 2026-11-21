"""RFC 3339 UTC timestamps at second precision, as signed AWID records carry them."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum, auto

# ASCII digits only: Python's \d also matches other scripts' digits, which
# strptime would accept and other verifiers refuse.
_UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def parse_utc_seconds(value: object) -> datetime:
    """Parse ``YYYY-MM-DDTHH:MM:SSZ`` naming a real calendar instant.

    Raises ValueError for anything else, including impossible dates.
    """
    if not isinstance(value, str) or not _UTC_SECONDS.fullmatch(value):
        raise ValueError("timestamp must be RFC 3339 UTC with Z and second precision")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class ZonedTimestampProfile(Enum):
    REQUEST = auto()
    SIGNED_TEAM_KEY_ACT = auto()


def parse_zoned_timestamp(
    value: str, *, profile: ZonedTimestampProfile = ZonedTimestampProfile.REQUEST
) -> datetime:
    """Parse released zoned grammars without narrowing strict-artifact seconds.

    Request timestamps normalize surrounding whitespace and UTC. Signed team-key
    acts retain the artifact's original offset and exact whitespace grammar.
    """
    normalized = value.strip() if profile is ZonedTimestampProfile.REQUEST else value
    if profile is ZonedTimestampProfile.SIGNED_TEAM_KEY_ACT:
        normalized = normalized.replace("Z", "+00:00")
    elif normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return (
        parsed.astimezone(timezone.utc)
        if profile is ZonedTimestampProfile.REQUEST
        else parsed
    )
