"""Strict checks on original signed clientDataJSON, without reserialising it."""

import base64
import json
import re
from enum import StrEnum

from webauthn.helpers import base64url_to_bytes


class ClientDataType(StrEnum):
    REGISTRATION = "webauthn.create"
    ASSERTION = "webauthn.get"


def decode_challenge(value: str) -> bytes:
    """Keep the portable format's canonical unpadded challenge encoding."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ClientDataInvalid("invalid_challenge_encoding")
    raw = base64url_to_bytes(value)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ClientDataInvalid("invalid_challenge_encoding")
    return raw


class ClientDataInvalid(ValueError):
    """The signed client data did not match the expected ceremony."""


class _JSONNumber(str):
    # Preserve ignored JSON number tokens without float/int normalization.
    """A preserved JSON number token, distinct from signed text fields."""


def _unique_json_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClientDataInvalid("duplicate_client_member")
        result[key] = value
    return result


def _reject_constant(_):
    raise ClientDataInvalid("invalid_client_number")


def _check_text(value, depth=0):
    if depth > 32:
        raise ClientDataInvalid("client_data_too_deep")
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_text(key, depth + 1)
            _check_text(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_text(item, depth + 1)


def verify_client_data(
    raw: bytes,
    *,
    expected_type: ClientDataType,
    expected_challenge: bytes,
    expected_origin: str,
) -> None:
    """Exact signed members: docs/hook-events.md:714-719 and approval protocol:337-345."""
    if not isinstance(raw, bytes) or len(raw) > 1 << 20:
        raise ClientDataInvalid("client_data_size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_members,
            parse_int=_JSONNumber,
            parse_float=_JSONNumber,
            parse_constant=_reject_constant,
        )
        _check_text(value)
        if not isinstance(value, dict):
            raise ClientDataInvalid("client_data_object_required")
        if type(value.get("type")) is not str or value["type"] != expected_type:
            raise ClientDataInvalid("client_type_invalid")
        if type(value.get("origin")) is not str or value["origin"] != expected_origin:
            raise ClientDataInvalid("client_origin_invalid")
        if value.get("crossOrigin", False) is not False:
            raise ClientDataInvalid("cross_origin_refused")
        if (
            type(value.get("challenge")) is not str
            or decode_challenge(value["challenge"]) != expected_challenge
        ):
            raise ClientDataInvalid("client_challenge_invalid")
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ClientDataInvalid):
            raise
        raise ClientDataInvalid("client_data_invalid") from exc
