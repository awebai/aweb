"""Capture issued values into the custody codec and compute their fixed deadlines.

Only validated owner-defined pointers select fields. No upstream bytes become
record metadata, and errors never retain those bytes in their messages.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_secrets.custody import encode_value
from aweb_secrets.responses import resolve_pointer

DEFAULT_MAX_TTL_S = 3600
_ABSOLUTE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


class CaptureInvalid(ValueError):
    """A definite response could not safely create a child; withhold it."""

    def __init__(self, reason: str) -> None:
        super().__init__("derived credential capture or expiry is invalid")
        self.reason = reason


@dataclass(frozen=True)
class CapturedValue:
    encoded: bytes = field(repr=False)
    upstream_expires_at: datetime
    expires_at: datetime


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureInvalid("capture_invalid")
        result[key] = value
    return result


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CaptureInvalid("expiry_invalid")
    return value.astimezone(UTC)


def effective_expiry(
    upstream_expires_at: datetime,
    *,
    dispatch_started_at: datetime,
    ancestor_expiries: Sequence[datetime] = (),
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
) -> datetime:
    """Narrow a deadline, also at use time when the current local cap is tighter."""
    if type(max_ttl_s) is not int or max_ttl_s <= 0:
        raise CaptureInvalid("expiry_invalid")
    try:
        capped = _utc(dispatch_started_at) + timedelta(seconds=max_ttl_s)
        return min(_utc(upstream_expires_at), capped, *map(_utc, ancestor_expiries))
    except (OverflowError, ValueError):
        raise CaptureInvalid("expiry_invalid") from None


def capture_response(
    body: bytes,
    *,
    store: Mapping[str, Any],
    dispatch_started_at: datetime,
    now: datetime,
    ancestor_expiries: Sequence[datetime] = (),
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
) -> CapturedValue:
    """Capture a complete bounded JSON response under a validated issuer definition.

    The caller rejects truncation, a non-success status, encoded bodies and
    disallowed media types before calling. It seals the returned codec bytes
    in the same transaction as child creation and the completed use record.
    """
    try:
        document = json.loads(body.decode("utf-8"), object_pairs_hook=_unique)
        value = {
            name: resolve_pointer(document, pointer) for name, pointer in store["capture"].items()
        }
        if store["derived_kind"] == "aws-sigv4" and "session_token" not in value:
            raise CaptureInvalid("capture_invalid")
        encoded = encode_value(store["derived_kind"], value)
    except (UnicodeError, ValueError, LookupError, RecursionError):
        raise CaptureInvalid("capture_invalid") from None
    try:
        start = _utc(dispatch_started_at)
        current = _utc(now)
        if start > current or ("expires_at" in store) == ("expires_in" in store):
            raise CaptureInvalid("expiry_invalid")
        if "expires_in" in store:
            seconds = resolve_pointer(document, store["expires_in"])
            if type(seconds) is not int or not 1 <= seconds <= 2**53 - 1:
                raise CaptureInvalid("expiry_invalid")
            upstream = start + timedelta(seconds=seconds)
        else:
            absolute = resolve_pointer(document, store["expires_at"])
            if not isinstance(absolute, str) or _ABSOLUTE.fullmatch(absolute) is None:
                raise CaptureInvalid("expiry_invalid")
            upstream = _utc(datetime.fromisoformat(absolute.upper()))
        expires = effective_expiry(
            upstream,
            dispatch_started_at=start,
            ancestor_expiries=ancestor_expiries,
            max_ttl_s=max_ttl_s,
        )
        if expires <= current:
            raise CaptureInvalid("expiry_invalid")
    except (LookupError, ValueError, OverflowError):
        raise CaptureInvalid("expiry_invalid") from None
    return CapturedValue(encoded, upstream, expires)
