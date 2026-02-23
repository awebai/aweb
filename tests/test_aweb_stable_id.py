"""Tests for did:claw stable identity derivation and validation."""

import pytest

from aweb.stable_id import stable_id_from_did_key, validate_stable_id


def test_stable_id_from_did_key_known_vector():
    did_key = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    assert stable_id_from_did_key(did_key) == "did:claw:GrRZYotwid5A4FxaddwPxsxChzo"


def test_validate_stable_id_roundtrip():
    value = "did:claw:GrRZYotwid5A4FxaddwPxsxChzo"
    assert validate_stable_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "did:claw:",
        "did:claw:not-base58!!!",
    ],
)
def test_validate_stable_id_rejects_bad_values(value: str):
    with pytest.raises(ValueError):
        validate_stable_id(value)
