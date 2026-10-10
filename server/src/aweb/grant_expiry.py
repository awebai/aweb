"""Non-expiring grants use the existing non-null timestamp storage contract."""
from datetime import datetime


def add_years(value: datetime, years: int) -> datetime:
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        # February 29 when the target century is not a leap year.
        return value.replace(year=value.year + years, day=28)


def never_expires(issued_at: datetime | None, expires_at: datetime) -> bool:
    return issued_at is not None and expires_at >= add_years(issued_at, 99)


def expiry_label(issued_at: datetime, expires_at: datetime) -> str:
    return "never" if never_expires(issued_at, expires_at) else expires_at.isoformat()
