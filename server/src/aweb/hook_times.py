"""The UTC millisecond spelling shared by hook binding and resolution routes."""

from datetime import datetime, timedelta, timezone


def format_hook_time(moment: datetime | None, *, round_up: bool = False) -> str | None:
    """A binding time in UTC to the millisecond, the hook event spelling.

    ``active_from`` rounds up to the next millisecond, never down, so a binding
    never reads as active earlier than it is; the other times truncate."""
    if moment is None:
        return None
    utc = moment.astimezone(timezone.utc)
    spare = utc.microsecond % 1000
    utc = utc.replace(microsecond=utc.microsecond - spare)
    if round_up and spare:
        utc += timedelta(milliseconds=1)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"
