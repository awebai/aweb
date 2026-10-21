"""RFC 3339 UTC timestamps at second precision, as signed AWID records carry them."""

from __future__ import annotations

import re
from datetime import datetime, timezone

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
