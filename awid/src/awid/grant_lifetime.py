"""Shared default for newly issued grants; explicit deadlines remain authoritative."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

MIN_GRANT_TTL_SECONDS = 60
MAX_GRANT_TTL_SECONDS = 30 * 24 * 60 * 60


def default_grant_ttl_seconds() -> int | None:
    """Unset retains the approved no-expiry default. Configuration fails closed."""
    value = os.getenv("AWEB_GRANT_DEFAULT_TTL_SECONDS", "").strip()
    if not value or value == "never":
        return None
    try:
        seconds = int(value)
    except ValueError:
        raise ValueError("AWEB_GRANT_DEFAULT_TTL_SECONDS must be never or 60..2592000") from None
    if not MIN_GRANT_TTL_SECONDS <= seconds <= MAX_GRANT_TTL_SECONDS:
        raise ValueError("AWEB_GRANT_DEFAULT_TTL_SECONDS must be never or 60..2592000")
    return seconds


def grant_deadline(now: datetime, ttl_seconds: int | None) -> datetime | None:
    """Resolve a lifetime once at issuance, never while verifying a grant."""
    if ttl_seconds is None:
        return None
    if type(ttl_seconds) is not int or not MIN_GRANT_TTL_SECONDS <= ttl_seconds <= MAX_GRANT_TTL_SECONDS:
        raise ValueError("grant TTL must be 60..2592000 seconds")
    return now + timedelta(seconds=ttl_seconds)
