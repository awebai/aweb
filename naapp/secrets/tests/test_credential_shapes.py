"""The credential-shape detector (secrets §7.6 step 5, §7.4): credential-named
fields with non-empty string values, and high-confidence token patterns.

Every token below is built at runtime from a fixed prefix and a filler, so no
credential, real or realistic, is written in the repository.
"""

from __future__ import annotations

import json
import re
import secrets
from itertools import product
from re import _parser as regex

import pytest
from aweb_secrets_values import credential_shapes

from aweb_secrets.credential_shapes import has_credential_shape, is_credential_shaped_value


def test_app_shape_helpers_are_the_standalone_shared_objects() -> None:
    import aweb_secrets_values.credential_shapes as shared

    import aweb_secrets.credential_shapes as app

    for name in (
        "has_credential_shape",
        "has_credential_value",
        "is_credential_field",
        "is_credential_shaped_value",
    ):
        assert getattr(app, name) is getattr(shared, name)


@pytest.mark.parametrize(
    "key", ["root_password", "rootPassword", "ROOT-PASSWORD", "admin_password", "initial_password"]
)
def test_provider_generated_password_fields_are_credentials(key: str) -> None:
    value = secrets.token_urlsafe(24)
    detected = has_credential_shape(json.dumps({"server": {key: value}}).encode())
    assert detected, "provider password field was not detected"


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


@pytest.mark.parametrize("leading", ["", "word-", "word—"])
def test_jwt_keeps_word_boundaries_and_minimum_segment_lengths(leading: str) -> None:
    segment = "eyJ" + _filler(8)
    signature = _filler(16)
    assert is_credential_shaped_value(f"{leading}{segment}.{segment}.{signature}")
    assert not is_credential_shaped_value(f"é{segment}.{segment}.{signature}")
    assert not is_credential_shaped_value(f"{leading}{segment[:-1]}.{segment}.{signature}")
    assert not is_credential_shaped_value(f"{leading}{segment}.{segment[:-1]}.{signature}")
    assert not is_credential_shaped_value(f"{leading}{segment}.{segment}.{signature[:-1]}")


def test_jwt_candidate_can_start_inside_an_earlier_candidates_signature() -> None:
    segment = "eyJ" + _filler(13)
    assert is_credential_shaped_value(f"no-header.{segment}.{segment}.{_filler(16)}")


def test_json_checks_decoded_nested_fields_without_treating_unrelated_strings_as_values() -> None:
    assert has_credential_shape(b'{"details":[{"api\\u005fkey":{"values":[null,"fixture"]}}]}')
    assert not has_credential_shape(
        b'{"details":[{"api\\u005fkey":{"values":[null,""]}},{"values":["fixture"]}]}'
    )


def test_jwt_detection_matches_the_segment_rules_at_boundaries() -> None:
    beginnings = (("", True), ("word_", False), ("é", False), ("word-", True))
    for (prefix, boundary), first, middle, last in product(
        beginnings, (7, 8, 9), (7, 8, 9), (15, 16, 17)
    ):
        token = f"{prefix}eyJ{_filler(first)}.eyJ{_filler(middle)}.{_filler(last)}"
        expected = boundary and first >= 8 and middle >= 8 and last >= 16
        assert is_credential_shaped_value(token) == expected
        assert has_credential_shape(token.encode()) == expected


def _unbounded_repeats(tree):
    for op, value in tree:
        if op in (regex.MAX_REPEAT, regex.MIN_REPEAT, regex.POSSESSIVE_REPEAT):
            _, maximum, body = value
            if maximum == regex.MAXREPEAT:
                yield op, body
            yield from _unbounded_repeats(body)
        elif op in (regex.ASSERT, regex.ASSERT_NOT):
            yield from _unbounded_repeats(value[1])
        elif op is regex.SUBPATTERN:
            yield from _unbounded_repeats(value[3])
        elif op is regex.BRANCH:
            for branch in value[1]:
                yield from _unbounded_repeats(branch)
        elif op is regex.ATOMIC_GROUP:
            yield from _unbounded_repeats(value)


def _excludes(tree, char):
    [(op, value)] = tree
    assert op is regex.IN
    for kind, argument in value:
        if kind is regex.LITERAL:
            assert argument != char
        elif kind is regex.RANGE:
            assert not argument[0] <= char <= argument[1]
        else:
            assert kind is regex.CATEGORY and argument is regex.CATEGORY_SPACE
            assert not chr(char).isspace()


def _check_regex_work_bound(pattern):
    tree = regex.parse(pattern.pattern, pattern.flags)
    for op, body in _unbounded_repeats(tree):
        # A long run may only follow a literal anchor it cannot contain.
        # The repeated PEM words can backtrack only over complete,
        # space-delimited words, never over individual letters.
        anchor, char = tree[0]
        assert anchor is regex.LITERAL
        if op is regex.POSSESSIVE_REPEAT:
            _excludes(body, char)
        else:
            assert op is regex.MAX_REPEAT
            [(word, (_, bound, letters)), (separator, space)] = body
            assert word is regex.POSSESSIVE_REPEAT and bound == regex.MAXREPEAT
            assert separator is regex.LITERAL and space != char
            _excludes(letters, char)
            _excludes(letters, space)


def test_shape_regexes_only_scan_unbounded_runs_after_disjoint_anchors() -> None:
    for value in vars(credential_shapes).values():
        for pattern in value if isinstance(value, (tuple, list)) else (value,):
            if isinstance(pattern, re.Pattern):
                _check_regex_work_bound(pattern)
