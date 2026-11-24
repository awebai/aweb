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


def test_prime_point_reuses_verdict_for_repeated_bytes():
    from nacl.signing import SigningKey

    from awid.signature_wire import _prime_point_verdicts as prime_point_verdicts
    from awid.signature_wire import prime_point

    key = bytes(SigningKey.generate().verify_key)
    first = prime_point(key)
    hits = prime_point_verdicts.cache_info().hits
    assert prime_point(key) is first is True
    assert prime_point_verdicts.cache_info().hits == hits + 1
    with pytest.raises(TypeError):
        prime_point(bytearray(key))
    assert prime_point(bytes(32)) is False
    before = prime_point_verdicts.cache_info()
    assert prime_point(key[:31]) is False
    assert prime_point(key + b"x" * 1000) is False
    after = prime_point_verdicts.cache_info()
    assert (after.misses, after.currsize) == (before.misses, before.currsize)
