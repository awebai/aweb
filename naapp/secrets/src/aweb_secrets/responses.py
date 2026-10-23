"""What an agent gets back from a brokered call (secrets §7.6).

A body with a ``Content-Encoding`` other than ``identity`` is withheld: the
broker asks for identity and never decompresses, so it never returns bytes it
could not redact or inspect. A named operation's response is also withheld
when its media type is not one the operation declares. Otherwise, in order: every known value is
redacted from the whole body as received; the body is cut at its bound, the
cut reported, and the tail of a cut body redacted so it never ends in part of
a value; only the allowed response headers pass, redacted; a named
operation's projection keeps only the values its JSON pointers name, redacted
again; and a body that still looks like it carries a credential is withheld.
The upstream effect has already happened when a result is withheld: the agent
gets the status, the filtered headers, the reason and the redaction count,
never the body.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import unquote

from aweb_secrets.credential_shapes import (
    has_credential_shape,
    has_credential_value,
    is_credential_field,
)
from aweb_secrets.redaction import KnownValues

_PASSED_HEADERS = frozenset(
    {"content-type", "content-length", "etag", "last-modified", "retry-after", "location"}
)
_PASSED_HEADER = re.compile(r"^(?:x-ratelimit-[a-z0-9-]+|(?:[a-z0-9]+-)*request-id)$")
_MISSING = object()


@dataclass(frozen=True)
class BrokeredResult:
    """The handled response. ``body`` is ``None`` when withheld.
    ``upstream_bytes`` counts the body as received, before the bound."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes | None
    disposition: Literal["returned", "withheld"]
    withheld_reason: Literal["credential_shaped", "content_encoded", "content_type_not_allowed"] | None
    undeclared_credential: bool
    redaction_count: int
    truncated: bool
    upstream_bytes: int


def _passes(name: str) -> bool:
    lowered = name.lower()
    return lowered in _PASSED_HEADERS or _PASSED_HEADER.fullmatch(lowered) is not None


def _is_encoded(headers: Sequence[tuple[str, str]]) -> bool:
    return any(
        name.lower() == "content-encoding"
        and any(coding.strip().lower() not in ("", "identity") for coding in value.split(","))
        for name, value in headers
    )


def _media_type(headers: Sequence[tuple[str, str]]) -> str | None:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return None


def _pointer_tokens(pointer: str) -> list[str]:
    """RFC 6901 reference tokens; a malformed pointer raises ValueError."""
    if not pointer.startswith("/"):
        raise ValueError(f"{pointer!r} is not a JSON pointer")
    tokens = pointer[1:].split("/")
    for token in tokens:
        if re.search(r"~(?![01])", token):
            raise ValueError(f"{pointer!r} has an invalid escape")
    return [token.replace("~1", "/").replace("~0", "~") for token in tokens]


def _resolve(document: Any, tokens: Sequence[str]) -> Any:
    current = document
    for token in tokens:
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            if token != "0" and token.startswith("0"):
                return _MISSING
            current = current[int(token)]
        else:
            return _MISSING
    return current


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve one validated JSON pointer, or raise LookupError for a missing value."""
    value = _resolve(document, _pointer_tokens(pointer))
    if value is _MISSING:
        raise LookupError("the JSON pointer has no value")
    return value


def _project(body: bytes, projection: Sequence[str], *, complete: bool) -> tuple[bytes, bool]:
    """The values the pointers name, keyed by pointer, and whether one of them
    contains a non-empty string under a credential-named field, including
    arrays and descendants. A body that is cut or
    is not JSON yields none."""
    parsed = [(pointer, _pointer_tokens(pointer)) for pointer in projection]
    projected: dict[str, Any] = {}
    names_credential = False
    if complete:
        try:
            document = json.loads(body)
        except ValueError:
            document = _MISSING
        if document is not _MISSING:
            for pointer, tokens in parsed:
                value = _resolve(document, tokens)
                if value is not _MISSING:
                    projected[pointer] = value
                    names_credential |= (
                        any(is_credential_field(token) for token in tokens)
                        and has_credential_value(value)
                    )
    encoded = json.dumps(projected, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return encoded, names_credential


def handle_response(
    *,
    status: int,
    headers: Sequence[tuple[str, str]],
    body: bytes,
    truncated: bool,
    max_bytes: int,
    projection: Sequence[str] | None,
    known: KnownValues,
    token_issuing: bool,
    content_types: Sequence[str] | None = None,
) -> BrokeredResult:
    """Handle one upstream response.

    ``truncated`` says whether the egress already cut the body. ``max_bytes`` is
    the operation's or policy's bound. ``token_issuing`` is whether the
    operation declares that it issues credentials; a credential-shaped result
    from one that does not is flagged ``undeclared_credential``.
    ``content_types`` are the media types a named operation accepts; ``None``
    accepts any.
    """
    upstream_bytes = len(body)
    redaction_count = 0
    passed: list[tuple[str, str]] = []
    for name, value in headers:
        if _passes(name):
            value, count = known.redact_text(value)
            redaction_count += count
            # Issued credentials are not yet known values. Inspect headers
            # independently of body projection/withholding; URL-decode names
            # such as access%5Ftoken as well as the raw header value.
            if has_credential_shape(value.encode()) or has_credential_shape(unquote(value).encode()):
                continue
            passed.append((name, value))

    def withheld(
        reason: Literal["credential_shaped", "content_encoded", "content_type_not_allowed"],
        undeclared: bool,
    ) -> BrokeredResult:
        return BrokeredResult(
            status=status,
            headers=passed,
            body=None,
            disposition="withheld",
            withheld_reason=reason,
            undeclared_credential=undeclared,
            redaction_count=redaction_count,
            truncated=truncated,
            upstream_bytes=upstream_bytes,
        )

    if _is_encoded(headers):
        return withheld("content_encoded", False)
    if content_types is not None and _media_type(headers) not in content_types:
        return withheld("content_type_not_allowed", False)

    body, count = known.redact(body)
    redaction_count += count
    if not truncated:
        body, count = known.redact_json(body)
        redaction_count += count
    if len(body) > max_bytes:
        body = body[:max_bytes]
        truncated = True
    if truncated:
        body, count = known.redact_tail(body)
        redaction_count += count

    # Projected values are keyed by pointer, so a credential field they name is
    # found by its pointer, not by the detector's field-name rule.
    names_credential = False
    if projection is not None:
        body, names_credential = _project(body, projection, complete=not truncated)
        for redact in (known.redact, known.redact_json):
            body, count = redact(body)
            redaction_count += count

    if names_credential or has_credential_shape(body):
        return withheld("credential_shaped", not token_issuing)
    return BrokeredResult(
        status=status,
        headers=passed,
        body=body,
        disposition="returned",
        withheld_reason=None,
        undeclared_credential=False,
        redaction_count=redaction_count,
        truncated=truncated,
        upstream_bytes=upstream_bytes,
    )
