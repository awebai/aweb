"""A held evidence snapshot keeps aging through a consumer's lock wait."""

import math

import pytest

from awid.id_certificates import IDChainEvidence, status_cache_mode


ANCHOR = 20_000_000_000
SECOND = 1_000_000_000


def evidence(age, *, failed=False, anchor=ANCHOR):
    return IDChainEvidence({}, {}, age, failed, observed_at_ns=anchor)


@pytest.mark.parametrize(
    "age,failed,elapsed,expected",
    [
        (59, False, SECOND, "fresh"),
        (59, False, SECOND + 1, "unavailable"),
        (60, False, 0, "fresh"),
        (60, False, 1, "unavailable"),
        (899, True, SECOND, "outage_grace"),
        (899, True, SECOND + 1, "unavailable"),
        (900, True, 0, "outage_grace"),
        (900, True, 1, "unavailable"),
        (61, False, 0, "unavailable"),
        (59.5, False, SECOND // 2, "fresh"),
        (59.5, False, SECOND // 2 + 1, "unavailable"),
        (0, False, 0, "fresh"),
    ],
)
def test_snapshot_ages_from_its_producer_anchor(age, failed, elapsed, expected):
    snapshot = evidence(age, failed=failed)
    assert snapshot.cache_mode_at(ANCHOR + elapsed) == expected
    assert snapshot.age_seconds == age
    assert snapshot.observed_at_ns == ANCHOR


def test_consumer_rechecking_does_not_restart_the_window():
    snapshot = evidence(59)
    assert snapshot.cache_mode_at(ANCHOR + SECOND // 2) == "fresh"
    assert snapshot.cache_mode_at(ANCHOR + SECOND + 1) == "unavailable"
    assert snapshot.cache_mode_at(ANCHOR + 2 * SECOND) == "unavailable"


@pytest.mark.parametrize("value", [None, True, -1, 1.5, "20"])
def test_missing_or_malformed_anchor_cannot_support_a_commit_check(value):
    assert evidence(0, anchor=value).cache_mode_at(ANCHOR) == "unavailable"


@pytest.mark.parametrize("value", [None, True, -1, 1.5, "20", ANCHOR - 1])
def test_invalid_or_backwards_observation_refuses(value):
    assert evidence(0).cache_mode_at(value) == "unavailable"


@pytest.mark.parametrize("value", [None, True, -1, math.inf, math.nan, "0"])
def test_invalid_age_refuses_even_with_a_clock_anchor(value):
    assert evidence(value).cache_mode_at(ANCHOR) == "unavailable"


def test_unanchored_existing_evidence_keeps_its_age_only_api():
    snapshot = IDChainEvidence({}, {}, 60)
    assert status_cache_mode(snapshot.age_seconds, snapshot.refresh_failed) == "fresh"
    assert snapshot.cache_mode_at(ANCHOR) == "unavailable"


def test_integer_nanoseconds_preserve_a_boundary_above_float_precision():
    anchor = 2**60
    snapshot = evidence(60, anchor=anchor)
    assert snapshot.cache_mode_at(anchor) == "fresh"
    assert snapshot.cache_mode_at(anchor + 1) == "unavailable"
