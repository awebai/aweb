"""The one value codec shared by console ingest, capture and broker opening."""

import json
import os

import pytest

from aweb_secrets.custody import ValueInvalid, decode_value, encode_value
from aweb_secrets.operation import CAPTURE_FIELDS


@pytest.mark.parametrize("kind", CAPTURE_FIELDS)
async def test_values_round_trip_with_the_kinds_fields(kind: str) -> None:
    required, optional = CAPTURE_FIELDS[kind]
    value = {name: os.urandom(24).hex() for name in required | optional}
    assert decode_value(kind, encode_value(kind, value)) == value


@pytest.mark.parametrize("kind", CAPTURE_FIELDS)
@pytest.mark.parametrize("defect", ["missing", "extra", "non_string", "empty"])
def test_invalid_values_are_refused_without_carrying_the_value(kind: str, defect: str) -> None:
    required, _ = CAPTURE_FIELDS[kind]
    canary = os.urandom(24).hex()
    value = dict.fromkeys(required, canary)
    key = next(name for name in required if name != "username")
    if defect == "missing":
        del value[key]
    elif defect == "extra":
        value[canary] = canary
    elif defect == "non_string":
        value[key] = {canary: canary}
    else:
        value[key] = ""
    with pytest.raises(ValueInvalid) as refused:
        encode_value(kind, value)
    assert canary not in str(refused.value)
    assert canary not in repr(refused.value)


@pytest.mark.parametrize("encoded", [b"{", b"[]", b"null", b"\xff", b'{"value":"a","value":"b"}'])
def test_decode_refuses_malformed_or_ambiguous_values(encoded: bytes) -> None:
    with pytest.raises(ValueInvalid):
        decode_value("bearer", encoded)


def test_basic_can_have_an_empty_username() -> None:
    value = {"username": "", "password": os.urandom(24).hex()}
    assert decode_value("basic", encode_value("basic", value)) == value


@pytest.mark.parametrize("source", ["new_ingest", "previously_stored"])
def test_native_aws_key_pairs_round_trip_without_a_session_token(source: str) -> None:
    value = {name: os.urandom(24).hex() for name in ("access_key_id", "secret_access_key")}
    encoded = (
        encode_value("aws-sigv4", value)
        if source == "new_ingest"
        else json.dumps(value).encode("utf-8")
    )
    assert decode_value("aws-sigv4", encoded) == value
