"""The credential-shape detector (secrets §7.6 step 5, §7.4): credential-named
fields with non-empty string values, and high-confidence token patterns.

Every token below is built at runtime from a fixed prefix and a filler, so no
credential, real or realistic, is written in the repository.
"""

from __future__ import annotations

import json

import pytest

from aweb_secrets.credential_shapes import has_credential_shape, is_credential_shaped_value


def _filler(n: int, alphabet: str = "Ab3dEf7hJk") -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


AWS_KEY_ID = "AKIA" + _filler(16, "QWERTYUIOP23")
AWS_SECRET = _filler(40, "aB3/cD5+eF7g")
JWT = "eyJ" + _filler(20) + ".eyJ" + _filler(30) + "." + _filler(43)
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + _filler(64) + "\n-----END RSA PRIVATE KEY-----"
VENDOR_TOKENS = [
    "ghp_" + _filler(36),
    "github_pat_" + _filler(40),
    "xoxb-" + _filler(24, "1234567890ab-"),
    "sk_live_" + _filler(24),
    "rk_test_" + _filler(24),
    "AIza" + _filler(35),
    "sk-ant-" + _filler(40),
    "sk-proj-" + _filler(40),
    "glpat-" + _filler(20),
    "npm_" + _filler(36),
]
CREDENTIAL_KEYS = [
    "token",
    "client_token",
    "authToken",
    "bearer-token",
    "secret_key",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "private_key",
    "secret",
    "SecretAccessKey",
    "SessionToken",
    "api_key",
    "apiKey",
    "API-KEY",
]


@pytest.mark.parametrize("key", CREDENTIAL_KEYS)
def test_a_credential_named_json_field_with_a_value_is_detected(key: str) -> None:
    assert has_credential_shape(json.dumps({"data": {key: "some-value"}}).encode())


@pytest.mark.parametrize("value", [["issued"], [{"value": "issued"}], {"value": ["issued"]}])
def test_a_credential_field_keeps_its_meaning_for_nested_string_values(value) -> None:
    assert has_credential_shape(json.dumps({"SessionToken": value}).encode())


@pytest.mark.parametrize("key", ["access_token", "SecretAccessKey"])
def test_an_empty_or_non_string_credential_field_is_not_detected(key: str) -> None:
    for value in ("", None, 0, False, []):
        assert not has_credential_shape(json.dumps({key: value}).encode())


def test_xml_and_form_encoded_credential_fields_are_detected() -> None:
    assert has_credential_shape(b"<Credentials><SessionToken>v</SessionToken></Credentials>")
    assert has_credential_shape(b"access_token=v&token_type=bearer")


@pytest.mark.parametrize(
    "token", [JWT, PEM, *VENDOR_TOKENS], ids=["jwt", "pem", *[t[:6] for t in VENDOR_TOKENS]]
)
def test_a_high_confidence_token_pattern_is_detected_anywhere(token: str) -> None:
    assert has_credential_shape(f"note: {token} end".encode())
    assert is_credential_shaped_value(token)


def test_an_aws_key_id_is_detected_only_when_paired_with_a_secret_key() -> None:
    assert has_credential_shape(f"{AWS_KEY_ID} {AWS_SECRET}".encode())
    assert not has_credential_shape(f"key id {AWS_KEY_ID} alone".encode())


@pytest.mark.parametrize(
    "body",
    [
        b'{"id": "ch_123", "amount": 500, "status": "succeeded"}',
        b'{"token_type": "bearer", "expires_in": 3600, "secret_ref": "stripe-test"}',
        b"<html><body>passwords must be long</body></html>",
        b"plain text with eyJ but no token",
        b"",
    ],
)
def test_an_ordinary_response_is_not_detected(body: bytes) -> None:
    assert not has_credential_shape(body)


@pytest.mark.parametrize("value", ["application/json", "en-GB", "abc-123", 'W/"etag-1"', "bearer"])
def test_an_ordinary_header_value_is_not_credential_shaped(value: str) -> None:
    assert not is_credential_shaped_value(value)


def test_a_credential_field_in_json_that_does_not_parse_is_detected() -> None:
    assert has_credential_shape(b'{"token_type": "bearer", "access_token": "issued-and-then-cut')
    assert has_credential_shape(b'garbage {"SessionToken" : "v"')
