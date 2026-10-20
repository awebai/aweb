"""Which caller-supplied request headers may be sent.

A header passes only if it is on the default allowlist or the destination's
``header_allow``, and is never one of the always-rejected names, whatever the
destination allows. The caller can refuse more through ``refuse``, for
example the names its own credential injection sets or values that look like
a credential.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence

from .refused import EgressRefused

DEFAULT_ALLOW = frozenset(
    name.lower()
    for name in (
        "Accept",
        "Accept-Language",
        "Content-Type",
        "If-Match",
        "If-None-Match",
        "X-Request-Id",
    )
)
ALWAYS_REJECTED = frozenset(
    name.lower()
    for name in (
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "X-Api-Key",
        "X-Amz-Security-Token",
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "TE",
        "Upgrade",
        "Forwarded",
        "User-Agent",
    )
)
ALWAYS_REJECTED_PREFIXES = ("x-forwarded-",)

_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_UNSAFE_VALUE = re.compile(r"[\r\n\x00]")

HeaderRefusal = Callable[[str, str], bool]


def check_headers(
    headers: Sequence[tuple[str, str]],
    *,
    header_allow: Iterable[str],
    refuse: HeaderRefusal | None = None,
) -> list[tuple[str, str]]:
    """Return ``headers`` unchanged, or refuse with ``header_not_allowed``."""
    allowed = DEFAULT_ALLOW | {name.lower() for name in header_allow}
    seen: set[str] = set()
    for name, value in headers:
        lowered = name.lower()
        if not _TOKEN.match(name) or _UNSAFE_VALUE.search(value):
            raise EgressRefused("header_not_allowed", "header", name)
        if lowered in seen:
            raise EgressRefused("header_not_allowed", "header", name)
        seen.add(lowered)
        if lowered in ALWAYS_REJECTED or lowered.startswith(ALWAYS_REJECTED_PREFIXES):
            raise EgressRefused("header_not_allowed", "header", name)
        if lowered not in allowed:
            raise EgressRefused("header_not_allowed", "header", name)
        if refuse is not None and refuse(name, value):
            raise EgressRefused("header_not_allowed", "header", name)
    return list(headers)
