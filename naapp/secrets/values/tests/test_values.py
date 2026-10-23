"""Freeze existing bytes and validation, including use without app dependencies."""

import subprocess
import sys

import pytest

from aweb_secrets_values import CAPTURE_FIELDS, ValueInvalid, decode_value, encode_value


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
    assert str(error.value) == "the secret value does not match its kind"
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
