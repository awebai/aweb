"""The shared enrollment parser consumes the carrier cases by their frozen names."""
import json
from pathlib import Path

import pytest

from awid.id_certificates import key_response_id_tree

CASES = json.loads(
    (Path(__file__).resolve().parents[2] / 'docs/vectors/id-certificates-v1.json').read_text()
)['key_response_id_tree']


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['name'])
def test_key_response_id_tree_frozen_parse(case):
    assert key_response_id_tree(case['key_response']) == case['expected_parse']


def test_key_response_id_tree_case_names_are_complete_and_unique():
    names = [case['name'] for case in CASES]
    assert len(names) == len(set(names)) == 19
