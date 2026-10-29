"""Evidence has one inclusive 60-second freshness boundary at acquisition."""
import math

import pytest

from awid.id_certificates import status_cache_mode


@pytest.mark.parametrize(
    "age,expected",
    [
        (0, "fresh"),
        (59.5, "fresh"),
        (60, "fresh"),
        (math.nextafter(60.0, math.inf), "unavailable"),
        (61, "unavailable"),
        (None, "unavailable"),
        (-1, "unavailable"),
        (True, "unavailable"),
        ("0", "unavailable"),
        (math.inf, "unavailable"),
        (math.nan, "unavailable"),
    ],
)
def test_evidence_freshness_at_acquisition(age, expected):
    assert status_cache_mode(age) == expected
