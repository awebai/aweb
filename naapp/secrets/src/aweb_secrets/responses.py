"""What an agent gets back from a brokered call (secrets §7.6).

In order: the body is cut at its bound and the cut reported; only the allowed
response headers pass; a named operation's projection keeps only the values
its JSON pointers name; every known value is redacted from the body and the
passed headers; and a body that still looks like it carries a credential is
withheld. The upstream effect has already happened when a result is withheld:
the agent gets the status, the filtered headers, the reason and the redaction
count, never the body.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from aweb_secrets.credential_shapes import has_credential_shape
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
    withheld_reason: Literal["credential_shaped"] | None
    undeclared_credential: bool
    redaction_count: int
    truncated: bool
    upstream_bytes: int


def _passes(name: str) -> bool:
    lowered = name.lower()
    return lowered in _PASSED_HEADERS or _PASSED_HEADER.fullmatch(lowered) is not None


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


def _project(body: bytes, projection: Sequence[str], *, complete: bool) -> bytes:
    """The values the pointers name, keyed by pointer. A body that is cut or is
    not JSON yields none."""
    parsed = [(pointer, _pointer_tokens(pointer)) for pointer in projection]
    projected: dict[str, Any] = {}
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
    return json.dumps(projected, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
) -> BrokeredResult:
    """Handle one upstream response.

    ``truncated`` says whether the egress already cut the body. ``max_bytes`` is
    the operation's or policy's bound. ``token_issuing`` is whether the
    operation declares that it issues credentials; a credential-shaped result
    from one that does not is flagged ``undeclared_credential``.
    """
    upstream_bytes = len(body)
    if len(body) > max_bytes:
        body = body[:max_bytes]
        truncated = True

    redaction_count = 0
    passed: list[tuple[str, str]] = []
    for name, value in headers:
        if _passes(name):
            value, count = known.redact_text(value)
            redaction_count += count
            passed.append((name, value))

    if projection is not None:
        body = _project(body, projection, complete=not truncated)
    body, count = known.redact(body)
    redaction_count += count

    if has_credential_shape(body):
        return BrokeredResult(
            status=status,
            headers=passed,
            body=None,
            disposition="withheld",
            withheld_reason="credential_shaped",
            undeclared_credential=not token_issuing,
            redaction_count=redaction_count,
            truncated=truncated,
            upstream_bytes=upstream_bytes,
        )
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
