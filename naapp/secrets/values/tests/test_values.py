"""Freeze existing bytes and validation, including use without app dependencies."""

import json
import subprocess
import sys

import pytest

from aweb_secrets_values import (
    CAPTURE_FIELDS,
    ValueInvalid,
    ValueInvalidReason,
    decode_value,
    encode_value,
    validate_value,
)


@pytest.mark.parametrize("kind", CAPTURE_FIELDS)
def test_every_kind_uses_the_same_bytes_and_round_trips(kind):
    required, optional = CAPTURE_FIELDS[kind]
    value = {name: "fixture" for name in sorted(required | optional)}
    encoded = encode_value(kind, value)
    assert (
        encoded
        == ("{" + ",".join('"' + name + '":"fixture"' for name in sorted(value)) + "}").encode()
    )
    assert decode_value(kind, encoded) == value


def test_existing_unicode_bytes_and_optional_fields_are_preserved():
    assert encode_value("bearer", {"value": "é"}) == b'{"value":"\\u00e9"}'
    assert decode_value("basic", b'{"username":"","password":"fixture"}') == {
        "username": "",
        "password": "fixture",
    }
    assert decode_value(
        "aws-sigv4", b'{"access_key_id":"fixture","secret_access_key":"fixture"}'
    ) == {"access_key_id": "fixture", "secret_access_key": "fixture"}


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":"one","value":"two"}',
        b'{"value":42}',
        b'{"value":""}',
        b'{"value":"fixture","extra":"fixture"}',
        b"{}",
        b"null",
        b"[]",
        b"\xff",
        b'{"value":"\\ud800"}',
    ],
)
def test_invalid_material_is_not_retained_in_errors(raw):
    with pytest.raises(ValueInvalid) as error:
        decode_value("bearer", raw)
    assert error.value.reason is ValueInvalidReason.SHAPE
    assert error.value.__cause__ is None


def test_runtime_import_is_standalone():
    script = """
import sys
from aweb_secrets_values import encode_value
assert encode_value('bearer', {'value':'fixture'}) == b'{"value":"fixture"}'
assert not any(k.startswith(('aweb_naapp','aweb_secrets.','awid','pgdbm')) for k in sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode()


def test_basic_username_separator_is_rejected_at_encoding():
    with pytest.raises(ValueInvalid) as refused:
        encode_value("basic", {"username": "account:other", "password": "fixture"})
    assert refused.value.reason is ValueInvalidReason.BASIC_USERNAME


def test_basic_username_separator_is_rejected_at_opening():
    raw = json.dumps({"username": "account:other", "password": "fixture"}).encode()
    with pytest.raises(ValueInvalid) as refused:
        decode_value("basic", raw)
    assert refused.value.reason is ValueInvalidReason.BASIC_USERNAME


def test_injection_uses_the_same_basic_username_rule():
    with pytest.raises(ValueInvalid) as refused:
        validate_value("basic", {"username": "account:other", "password": "fixture"})
    assert refused.value.reason is ValueInvalidReason.BASIC_USERNAME


def test_a_basic_password_can_contain_the_separator_and_the_username_can_be_empty():
    value = {"username": "", "password": "fixture:password"}
    assert decode_value("basic", encode_value("basic", value)) == validate_value("basic", value)
