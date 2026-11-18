"""quickXorHash agrees with an independent implementation."""

import random

import pytest

from hashes import quick_xor_hash
from tests.standin import reference_quick_xor


@pytest.mark.parametrize("size", [0, 1, 19, 20, 159, 160, 161, 319, 320, 4096, 1048577])
def test_quick_xor_hash_matches_the_reference(size):
    data = random.Random(size).randbytes(size)
    assert quick_xor_hash(data) == reference_quick_xor(data)
