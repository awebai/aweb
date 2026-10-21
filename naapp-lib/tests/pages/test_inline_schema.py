"""The public inline-schema check, the subset C1 enforces on collection and action schemas."""

from __future__ import annotations

import pytest

from aweb_naapp.pages import inline_schema_errors, inline_value_valid

AMOUNT = {"type": "integer", "minimum": 1, "maximum": 5000}
CURRENCY = {"type": "string", "enum": ["EUR", "USD"]}
CHARGE = {"type": "string", "minLength": 1, "maxLength": 64}


@pytest.mark.parametrize("schema", [AMOUNT, CURRENCY, CHARGE, {"type": "boolean"}])
def test_a_bounded_schema_is_accepted(schema) -> None:
    assert inline_schema_errors(schema) == []


@pytest.mark.parametrize(
    ("schema", "code"),
    [
        ({"type": "string", "pattern": "^ch_"}, "inline_schema_pattern"),
        ({"type": "number"}, "inline_schema_number"),
        ({"anyOf": [AMOUNT, CHARGE]}, "inline_schema_keyword"),
        ({"type": "array", "items": AMOUNT}, "inline_schema_unbounded"),
        ({"type": "string", "enum": [{"a": 1}]}, "inline_schema_enum"),
        ({"type": "string", "minLength": -1}, "inline_schema_invalid"),
        (
            {"type": "array", "maxItems": 1000, "items": {"type": "string", "enum": ["x"] * 20}},
            "inline_schema_cost",
        ),
    ],
)
def test_a_schema_outside_the_subset_is_refused(schema, code) -> None:
    assert [error.code for error in inline_schema_errors(schema)] == [code]


@pytest.mark.parametrize(
    ("schema", "value", "valid"),
    [
        (AMOUNT, 1250, True),
        (AMOUNT, 0, False),
        (AMOUNT, "1250", False),
        (CURRENCY, "EUR", True),
        (CURRENCY, "GBP", False),
        ({"type": "array", "maxItems": 2, "items": AMOUNT}, [1, 2, 3], False),
        ({"type": "array", "maxItems": 2, "items": AMOUNT}, [1, 2], True),
    ],
)
def test_values_are_checked_against_the_schema_and_its_bounds(schema, value, valid) -> None:
    assert inline_value_valid(schema, value) is valid


def test_a_value_is_never_checked_against_a_refused_schema() -> None:
    with pytest.raises(ValueError):
        inline_value_valid({"type": "string", "pattern": "^x"}, "x")
