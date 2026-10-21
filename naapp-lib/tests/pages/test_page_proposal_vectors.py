"""The frozen proposal digest vectors (docs/page-actions.md §4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aweb_naapp.pages import bundle_sha256, proposal_sha256

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "page-proposal-v1.json").read_text())


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_proposal_digest(case):
    assert (
        proposal_sha256(case["collection"], case["record_id"], case["value"])
        == case["proposal_sha256"]
    )


def test_record_identity_is_bound():
    by_name = {case["name"]: case for case in VECTORS["cases"]}
    assert by_name["price"]["value"] == by_name["same-value-other-record"]["value"]
    assert (
        by_name["price"]["proposal_sha256"] != by_name["same-value-other-record"]["proposal_sha256"]
    )


def test_item_digests_feed_the_bundle_digest():
    bundle = VECTORS["bundle"]
    assert bundle_sha256(bundle["items"]) == bundle["sha256"]


@pytest.mark.parametrize("case", VECTORS["refusals"], ids=lambda case: case["name"])
def test_values_without_one_canonical_form_are_refused(case):
    with pytest.raises(ValueError):
        proposal_sha256("proposals", "r", json.loads(case["value_json"]))
