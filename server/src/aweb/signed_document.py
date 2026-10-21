"""Decoding shared by the host-signed documents: agent status and agent activity.

Each document travels as unpadded base64url of its canonical JSON bytes. The
helpers raise the caller's own error class, so each contract keeps its codes.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
import json
import re
from typing import Any

from awid.signing import canonical_json_bytes
from awid.utc_timestamps import parse_utc_seconds

MAX_SAFE_INTEGER = 2**53 - 1

# Base64url without padding, as the host encodes the canonical bytes.
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class SignedDocumentError(Exception):
    """A signed document refused with one of its contract's error codes."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def decode_payload(signed_payload: str, *, max_bytes: int, error: type[SignedDocumentError]) -> bytes:
    # Longer than the encoded length of max_bytes is oversize before decoding.
    if len(signed_payload) > (max_bytes * 4 + 2) // 3:
        raise error("document_too_large", f"the document exceeds {max_bytes} bytes")
    if not _B64URL.fullmatch(signed_payload):
        raise error("malformed_payload", "signed_payload is not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(signed_payload + "=" * (-len(signed_payload) % 4))
    except (binascii.Error, ValueError) as exc:
        raise error("malformed_payload", "signed_payload is not unpadded base64url") from exc
    if len(raw) > max_bytes:
        raise error("document_too_large", f"the document exceeds {max_bytes} bytes")
    return raw


def parse_json_object(raw: bytes, *, error: type[SignedDocumentError]) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise error("malformed_payload", "signed_payload is not a JSON document") from exc
    if not isinstance(document, dict):
        raise error("malformed_payload", "signed_payload is not a JSON object")
    return document


def require_canonical(document: dict[str, Any], raw: bytes, *, error: type[SignedDocumentError]) -> None:
    try:
        canonical = canonical_json_bytes(document)
    except UnicodeEncodeError as exc:
        # An escaped lone surrogate parses, but has no canonical UTF-8 form.
        raise error("non_canonical", "signed_payload has text with no UTF-8 form") from exc
    if canonical != raw:
        raise error("non_canonical", "signed_payload is not in canonical form")


def is_safe_positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_SAFE_INTEGER


def parse_timestamp(name: str, value: Any, *, error: type[SignedDocumentError]) -> datetime:
    try:
        return parse_utc_seconds(value)
    except ValueError as exc:
        raise error("invalid_value", f"{name} must be a valid YYYY-MM-DDTHH:MM:SSZ time") from exc
