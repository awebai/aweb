"""Strict canonical JSON and strict base64 for aweb's domain-separated signatures.

The rules match the Go authority in ``cli/go/strictjson`` byte for byte:
printable-ASCII strings, safe-range integers, no floats or nulls, no duplicate
keys, nesting at most eight deep, and exactly one spelling of every signature
and base64url field. Every refusal carries the same code as in Go.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 8
SIGNATURE_LENGTH = 86

_SIGNATURE = re.compile(r"[A-Za-z0-9+/]{86}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


class Refused(ValueError):
    """A refusal with a stable code, the same code every implementation reports."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _check_depth(text: str) -> None:
    """Refuse nesting deeper than MAX_DEPTH before any recursive parse."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise Refused("too_deep", f"nesting deeper than {MAX_DEPTH}")
        elif char in "]}":
            depth -= 1


def _check_ascii(text: str) -> None:
    for char in text:
        if not 0x20 <= ord(char) <= 0x7E:
            raise Refused("string_not_ascii", f"character {ord(char):#04x}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_key", key)
        result[key] = value
    return result


def _parse_float(text: str) -> Any:
    raise Refused("float_value", text)


# 2**53 - 1 has 16 digits, so a longer integer is out of range. Refusing it by
# length first keeps unauthenticated input away from int()'s own digit limit.
_MAX_INTEGER_DIGITS = len(str(MAX_SAFE_INTEGER))


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > _MAX_INTEGER_DIGITS:
        raise Refused("invalid_value", "integer outside the safe range")
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise Refused("invalid_value", f"integer outside the safe range: {text}")
    return value


def _parse_constant(text: str) -> Any:
    raise Refused("invalid_json", text)


def _check_values(value: Any) -> None:
    if value is None:
        raise Refused("null_value", "null is never a value")
    if isinstance(value, str):
        _check_ascii(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_ascii(key)
            _check_values(item)
    elif isinstance(value, list):
        for item in value:
            _check_values(item)


def parse_strict(data: bytes) -> Any:
    """Parse one JSON value. Objects become dicts, arrays lists, numbers ints.

    It refuses duplicate keys, floats, integers outside the safe range, null,
    strings with a character outside printable ASCII, nesting deeper than
    MAX_DEPTH, and anything that is not one JSON value.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("string_not_ascii", "not UTF-8") from None
    _check_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_parse_float,
            parse_int=_parse_int,
            parse_constant=_parse_constant,
        )
    except json.JSONDecodeError as exc:
        raise Refused("invalid_json", str(exc)) from None
    _check_values(value)
    return value


def canonical(value: Any) -> bytes:
    """Encode a value as canonical JSON, refusing what no consumer reads alike."""
    _check_encodable(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "ascii"
    )


def _check_encodable(value: Any) -> None:
    if value is None:
        raise Refused("null_value", "null is never a value")
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise Refused("invalid_value", f"integer outside the safe range: {value}")
        return
    if isinstance(value, str):
        _check_ascii(value)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise Refused("invalid_value", "object keys are strings")
            _check_ascii(key)
            _check_encodable(item)
        return
    if isinstance(value, list):
        for item in value:
            _check_encodable(item)
        return
    raise Refused("invalid_value", f"unsupported value {type(value).__name__}")


def parse_canonical_object(data: bytes) -> dict[str, Any]:
    """Parse strictly and require an object whose canonical encoding is ``data``."""
    value = parse_strict(data)
    if not isinstance(value, dict):
        raise Refused("invalid_value", "not a JSON object")
    if canonical(value) != data:
        raise Refused("not_canonical", "bytes are not the canonical encoding")
    return value


def decode_signature(signature: str) -> bytes:
    """Accept exactly one spelling of a 64-byte Ed25519 signature: 86 characters
    of the standard base64 alphabet, no padding, and zero trailing bits."""
    if len(signature) != SIGNATURE_LENGTH or not _SIGNATURE.fullmatch(signature):
        raise Refused("signature_encoding", f"a signature is {SIGNATURE_LENGTH} characters")
    raw = base64.b64decode(signature + "==")
    if base64.b64encode(raw).decode("ascii").rstrip("=") != signature:
        raise Refused("signature_encoding", "nonzero trailing bits")
    return raw


def decode_base64url(text: str, what: str) -> bytes:
    """Accept exactly one spelling: the URL alphabet, no padding, zero trailing bits."""
    if not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        raise Refused("invalid_value", f"{what} is not strict unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise Refused("invalid_value", f"{what} is not strict unpadded base64url") from None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != text:
        raise Refused("invalid_value", f"{what} is not strict unpadded base64url")
    return raw


def encode_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def encode_signature(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")
