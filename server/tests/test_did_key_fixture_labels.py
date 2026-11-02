"""Every labelled did:key literal in test SQL is the named key its label gives.

SQL text keeps a key literal followed by a /* label */ comment, because
interpolating into pgdbm-templated SQL is not safe; this keeps the comment and
the key from drifting apart.
"""

from __future__ import annotations

import re
from pathlib import Path

from did_key_fixtures import named_did_key

TESTS = Path(__file__).resolve().parent
LABELLED = re.compile(r"'(did:key:z[1-9A-HJ-NP-Za-km-z]+)' /\* ([A-Za-z0-9_-]+) \*/")


def _labelled_literals() -> list[tuple[str, str, str]]:
    found = []
    for path in sorted(TESTS.glob("*.py")):
        for key, label in LABELLED.findall(path.read_text()):
            found.append((path.name, key, label))
    return found


def test_each_labelled_key_literal_is_its_named_key():
    found = _labelled_literals()
    assert found
    assert [(name, key, label) for name, key, label in found if named_did_key(label) != key] == []


def test_every_named_key_in_sql_text_carries_its_label():
    named = {named_did_key(label) for _, _, label in _labelled_literals()}
    unlabelled = []
    for path in sorted(TESTS.glob("*.py")):
        for match in re.finditer(r"'(did:key:z[1-9A-HJ-NP-Za-km-z]+)'(?! /\*)", path.read_text()):
            if match.group(1) in named:
                unlabelled.append((path.name, match.group(1)))
    assert unlabelled == []
