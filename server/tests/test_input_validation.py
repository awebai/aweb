from __future__ import annotations

import pytest

from aweb.input_validation import (
    is_valid_alias,
    is_valid_branch_name,
    is_valid_canonical_origin,
    is_valid_human_name,
)

VALIDATORS = [
    pytest.param(is_valid_alias, "bob", id="alias"),
    pytest.param(is_valid_human_name, "Bob", id="human_name"),
    pytest.param(is_valid_branch_name, "main", id="branch_name"),
    pytest.param(is_valid_canonical_origin, "github.com/acme/repo", id="canonical_origin"),
]


@pytest.mark.parametrize(("validator", "value"), VALIDATORS)
def test_validator_accepts_the_bare_value(validator, value):
    assert validator(value)


@pytest.mark.parametrize(("validator", "value"), VALIDATORS)
@pytest.mark.parametrize("suffix", ["\n", "\r\n", "\r"])
def test_validator_rejects_a_trailing_line_break(validator, value, suffix):
    assert not validator(value + suffix)
