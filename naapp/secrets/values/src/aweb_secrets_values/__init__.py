"""The sealed value codec for console ingest, derived capture and broker opening.

Only the fields consumed by the kind's injector are stored: UTF-8 JSON, with
no record metadata. Invalid input never appears in an exception message.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

# The structured value fields of each kind, which a derived secret captures (§6.2).
CAPTURE_FIELDS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = {
    "bearer": (frozenset({"value"}), frozenset()),
    "header": (frozenset({"value"}), frozenset()),
    "query": (frozenset({"value"}), frozenset()),
    "basic": (frozenset({"username", "password"}), frozenset()),
    "oauth2-client-credentials": (frozenset({"client_id", "client_secret"}), frozenset()),
    "aws-sigv4": (frozenset({"access_key_id", "secret_access_key"}), frozenset({"session_token"})),
}


class ValueInvalid(ValueError):
    """The value is not the structured value of the specified auth kind."""


def _invalid() -> ValueInvalid:
    return ValueInvalid("the secret value does not match its kind")


def _validate(kind: str, value: Any) -> dict[str, str]:
    if kind not in CAPTURE_FIELDS or not isinstance(value, Mapping):
        raise _invalid()
    required, optional = CAPTURE_FIELDS[kind]
    if not required <= value.keys() or not value.keys() <= required | optional:
        raise _invalid()
    if any(not isinstance(v, str) or (not v and k != "username") for k, v in value.items()):
        raise _invalid()
    # Reject unpaired surrogates as invalid input, without retaining an encoder
    # exception that might print the value.
    try:
        for v in value.values():
            v.encode("utf-8")
    except UnicodeError:
        raise _invalid() from None
    return dict(value)


def encode_value(kind: str, value: Mapping[str, str]) -> bytes:
    """Validate and encode a kind's structured value. Never log the result."""
    return json.dumps(_validate(kind, value), sort_keys=True, separators=(",", ":")).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def decode_value(kind: str, value: bytes) -> dict[str, str]:
    """Decode and validate an opened value before the broker uses it."""
    try:
        decoded = json.loads(value.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError):
        raise _invalid() from None
    return _validate(kind, decoded)
