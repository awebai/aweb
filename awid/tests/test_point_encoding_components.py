"""Component evidence calls the production representation gate, not a test copy."""

import json
from pathlib import Path

import pytest
from awid.signature_wire import canonical_point_encoding

VECTORS = Path(__file__).resolve().parents[2] / "docs" / "vectors"
CASES = json.loads((VECTORS / "signature-point-encoding-v2.json").read_text())["cases"]

if not CASES:
    raise ValueError("point encoding corpus must contain component cases")


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_point_encoding_components(case):
    assert (
        canonical_point_encoding(bytes.fromhex(case["encoded_hex"]))
        is case["canonical"]
    )
