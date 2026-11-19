"""The sealed value codec for console ingest, derived capture and broker opening.

Only the fields consumed by the kind's injector are stored: UTF-8 JSON, with
no record metadata. Invalid input never appears in an exception message.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class ValueKind(StrEnum):
    BEARER = "bearer"
    HEADER = "header"
    QUERY = "query"
    BASIC = "basic"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2-client-credentials"
    AWS_SIGV4 = "aws-sigv4"


class ValueInvalidReason(StrEnum):
    SHAPE = "shape"
    BASIC_USERNAME = "basic_username"
    INJECTION_CONFIGURATION = "injection_configuration"


_REFUSALS = {
    ValueInvalidReason.SHAPE: "The secret value does not match its kind. Correct its fields and stage it again.",
    ValueInvalidReason.BASIC_USERNAME: "The basic username cannot contain ':'. Correct the username and stage it again.",
    ValueInvalidReason.INJECTION_CONFIGURATION: "The credential cannot be placed in this request. Correct the secret's kind configuration and retry.",
}

# The structured value fields of each kind, which a derived secret captures (§6.2).
CAPTURE_FIELDS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = {
    ValueKind.BEARER: (frozenset({"value"}), frozenset()),
    ValueKind.HEADER: (frozenset({"value"}), frozenset()),
    ValueKind.QUERY: (frozenset({"value"}), frozenset()),
    ValueKind.BASIC: (frozenset({"username", "password"}), frozenset()),
    ValueKind.OAUTH2_CLIENT_CREDENTIALS: (frozenset({"client_id", "client_secret"}), frozenset()),
    ValueKind.AWS_SIGV4: (
        frozenset({"access_key_id", "secret_access_key"}),
        frozenset({"session_token"}),
    ),
}


class ValueInvalid(ValueError):
    """The value is not the structured value of the specified auth kind."""

    def __init__(self, reason: ValueInvalidReason = ValueInvalidReason.SHAPE) -> None:
        self.reason = reason
        super().__init__(_REFUSALS[reason])


def _invalid() -> ValueInvalid:
    return ValueInvalid()


def _validate(kind: str, value: Any) -> dict[str, str]:
    """The sole value-fits-kind rule, including Basic's separator (§7.5)."""
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
    if kind == ValueKind.BASIC and ":" in value["username"]:
        raise ValueInvalid(ValueInvalidReason.BASIC_USERNAME)
    return dict(value)


def validate_value(kind: str, value: Mapping[str, str]) -> dict[str, str]:
    """Validate an in-memory value through the same rule as ingest and opening."""
    return _validate(kind, value)


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
