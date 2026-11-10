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
