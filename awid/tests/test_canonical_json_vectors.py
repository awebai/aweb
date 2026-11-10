import json
from pathlib import Path

import pytest

from awid.signing import canonical_json_bytes


def _vector() -> dict:
    path = Path(__file__).parents[2] / "docs" / "vectors" / "canonical-json-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _cases() -> list[dict]:
    vector = _vector()
    return vector["cases"] + vector["code_point_key_order_cases"]


def test_vector_covers_the_line_and_paragraph_separators():
    names = {case["name"] for case in _cases()}
    assert {
        "line_separator_in_string",
        "paragraph_separator_in_string",
        "line_separator_in_key",
        "paragraph_separator_in_key",
    } <= names


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_canonical_json_bytes_reproduces_the_shared_vector(case):
    assert canonical_json_bytes(case["value"]).hex() == case["canonical_hex"]


def test_vector_tells_code_point_order_from_code_unit_order():
    names = {case["name"] for case in _vector()["code_point_key_order_cases"]}
    assert {
        "key_order_non_bmp_after_bmp",
        "key_order_non_bmp_against_u_e000",
        "key_order_non_bmp_against_u_ffff",
        "key_order_non_bmp_pair",
        "key_order_non_bmp_nested",
    } <= names


def _out_of_contract_cases() -> list[dict]:
    vector = _vector()
    return vector["out_of_contract_number_cases"] + vector["lone_surrogate_cases"]


def test_vector_covers_the_out_of_contract_inputs():
    names = {case["name"] for case in _out_of_contract_cases()}
    assert {
        "number_with_fraction",
        "integral_float",
        "integer_above_safe_range",
        "negative_zero",
        "negative_zero_float",
        "exponent_form",
        "exponent_form_large",
        "lone_surrogate_in_string",
        "lone_surrogate_in_key",
        "lone_surrogate_key_order",
    } <= names


# Inputs outside the contract: the vector records what canonical_json_bytes
# does with each, so that a change is noticed.
@pytest.mark.parametrize("case", _out_of_contract_cases(), ids=lambda case: case["name"])
def test_canonical_json_bytes_keeps_its_recorded_out_of_contract_behaviour(case):
    value = json.loads(case["json"])
    recorded = case["python_canonical_json_bytes"]
    if recorded == "refused":
        with pytest.raises(UnicodeEncodeError):
            canonical_json_bytes(value)
    else:
        assert canonical_json_bytes(value).hex() == recorded
