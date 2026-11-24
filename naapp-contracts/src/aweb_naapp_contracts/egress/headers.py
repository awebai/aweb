"""Which caller-supplied request headers may be sent.

The contract is the headers section of the egress URL conformance vector in
``docs/vectors``. A header passes only if it is on the default allowlist, the
destination's ``header_allow`` or the operation's ``amz_allowed``, and none of
the refusals below applies, whatever the destination allows:

- an always-rejected name or prefix, including the ones the guard sets itself;
- a name the caller's own credential injection sets;
- an ``X-Amz-*`` name outside ``amz_allowed`` (``X-Amz-Security-Token`` always);
- a value the caller's credential-shape detector flags, or one holding a
  control character other than tab or a character outside latin-1.

The detector and the injected names belong to the caller's credential
handling, so :class:`HeaderRules` has no defaults: a caller cannot leave a
rule out by forgetting it. ``refuse`` can add refusals, never remove one.

The headers that credential handling injects pass :func:`check_injected`
instead: each must be a declared injected name, at most once, never one the
guard sets, and well formed. They skip the allowlist and the credential
detector, since carrying a credential is what they are for. A refusal names
the header, never its value.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

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
        "Accept-Encoding",
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
# The headers the guard writes itself; neither callers nor injection can set them.
GUARD_SET = frozenset(
    name.lower()
    for name in (
        "Host",
        "User-Agent",
        "Accept-Encoding",
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
    )
)
AMZ_PREFIX = "x-amz-"

_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

HeaderRefusal = Callable[[str, str], bool]


@dataclass(frozen=True)
class HeaderRules:
    """The caller's part of the header rules; every field is required.

    ``injected`` names the headers the caller's credential sets.
    ``amz_allowed`` names the ``X-Amz-*`` headers the operation fixes.
    ``is_credential`` says whether a value looks like a credential.
    """

    injected: Iterable[str]
    amz_allowed: Iterable[str]
    is_credential: Callable[[str], bool]


def check_headers(
    headers: Sequence[tuple[str, str]],
    *,
    header_allow: Iterable[str],
    rules: HeaderRules,
    refuse: HeaderRefusal | None = None,
) -> list[tuple[str, str]]:
    """Return ``headers`` unchanged, or refuse with ``header_not_allowed``."""
    injected = {name.lower() for name in rules.injected}
    amz_allowed = {name.lower() for name in rules.amz_allowed}
    allowed = DEFAULT_ALLOW | {name.lower() for name in header_allow} | amz_allowed
    seen: set[str] = set()
    for name, value in headers:
        if not _well_formed(name, value):
            raise EgressRefused("header_not_allowed", "header", "malformed header")
        lowered = name.lower()
        if lowered in seen:
            raise EgressRefused("header_not_allowed", "header", name)
        seen.add(lowered)
        if (
            lowered in ALWAYS_REJECTED
            or lowered.startswith(ALWAYS_REJECTED_PREFIXES)
            or lowered in injected
            or (lowered.startswith(AMZ_PREFIX) and lowered not in amz_allowed)
            or lowered not in allowed
        ):
            raise EgressRefused("header_not_allowed", "header", name)
        if rules.is_credential(value) or (refuse is not None and refuse(name, value)):
            raise EgressRefused("header_not_allowed", "header", name)
    return list(headers)


def check_injected(
    injected: Sequence[tuple[str, str]], *, rules: HeaderRules
) -> list[tuple[str, str]]:
    """Return ``injected`` unchanged, or refuse with ``header_not_allowed``."""
    declared = {name.lower() for name in rules.injected}
    seen: set[str] = set()
    for name, value in injected:
        if not _well_formed(name, value):
            raise EgressRefused("header_not_allowed", "header", "malformed injected header")
        lowered = name.lower()
        if lowered in GUARD_SET or lowered not in declared or lowered in seen:
            raise EgressRefused("header_not_allowed", "header", name)
        seen.add(lowered)
    return list(injected)


def _well_formed(name: str, value: str) -> bool:
    """True when the name is a token and the value is latin-1 without control characters."""
    if not _TOKEN.match(name) or _CONTROL.search(value):
        return False
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True
