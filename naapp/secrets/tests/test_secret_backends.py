"""A secret record's backend uses the one spelling the frozen vectors use."""

from __future__ import annotations

import json
from pathlib import Path

from aweb_secrets.secret import BACKENDS, SecretRecord

VECTORS = Path(__file__).parents[1] / "vectors"


def test_backends_match_the_frozen_vectors():
    frozen = json.loads((VECTORS / "use-approval-v1.json").read_text())
    used = {case["request"]["secret"]["backend"] for case in frozen["positive_cases"]}
    assert used <= set(BACKENDS)
    assert BACKENDS == ("native", "onepassword")


def test_a_record_round_trips_with_the_onepassword_backend():
    after = {
        "v": 1,
        "secret_id": "sec_7e0d11",
        "ref": "db-admin",
        "description": "",
        "kind": "basic",
        "kind_params": {},
        "sensitivity": "sensitive",
        "approve_only": False,
        "backend": "onepassword",
    }
    assert SecretRecord.from_after(after).backend == "onepassword"
