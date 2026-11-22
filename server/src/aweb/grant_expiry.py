"""Non-expiring grants use the existing non-null timestamp storage contract."""

from datetime import datetime
from enum import StrEnum


class GrantLifetimeState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


def add_years(value: datetime, years: int) -> datetime:
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        # February 29 when the target century is not a leap year.
        return value.replace(year=value.year + years, day=28)


def never_expires(issued_at: datetime | None, expires_at: datetime) -> bool:
    return issued_at is not None and expires_at >= add_years(issued_at, 99)


def grant_lifetime_state(
    *,
    issued_at: datetime | None,
    expires_at: datetime,
    revoked_at: datetime | None,
    now: datetime,
) -> GrantLifetimeState:
    """Apply a grant's own revocation and lifetime (docs/identity.md:755-769).

    A never-grant's storage timestamp is not a deadline. Revocation still
    ends it; subject and issuer eligibility are separate authority checks.
    """
    if revoked_at is not None:
        return GrantLifetimeState.REVOKED
    if not never_expires(issued_at, expires_at) and expires_at <= now:
        return GrantLifetimeState.EXPIRED
    return GrantLifetimeState.ACTIVE


def expiry_label(issued_at: datetime, expires_at: datetime) -> str:
    return "never" if never_expires(issued_at, expires_at) else expires_at.isoformat()
