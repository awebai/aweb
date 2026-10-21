"""Derived capture never returns issued values to the caller or guesses expiry."""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from aweb_secrets.custody import decode_value
from aweb_secrets.derived_capture import CaptureInvalid, capture_response

START = datetime(2026, 10, 21, 12, tzinfo=UTC)
NOW = START + timedelta(seconds=20)
STORE = {
    "derived_kind": "bearer",
    "capture": {"value": "/credentials/access_token"},
    "expires_in": "/expires_in",
}


def _answer(**changes):
    return {"credentials": {"access_token": os.urandom(24).hex()}, "expires_in": 7200, **changes}


def _capture(answer, **options):
    return capture_response(
        json.dumps(answer).encode(),
        store=STORE,
        dispatch_started_at=START,
        now=NOW,
        **options,
    )


def test_relative_expiry_is_anchored_to_dispatch_and_capped_locally() -> None:
    answer = _answer()
    captured = _capture(answer)
    assert captured.upstream_expires_at == START + timedelta(seconds=7200)
    assert captured.expires_at == START + timedelta(seconds=3600)
    assert decode_value("bearer", captured.encoded) == {
        "value": answer["credentials"]["access_token"]
    }
    assert "encoded=" not in repr(captured)


def test_delayed_recording_does_not_restart_relative_expiry() -> None:
    answer = _answer(expires_in=30)
    captured = _capture(answer)
    assert captured.expires_at == START + timedelta(seconds=30)
    with pytest.raises(CaptureInvalid):
        capture_response(
            json.dumps(answer).encode(),
            store=STORE,
            dispatch_started_at=START,
            now=START + timedelta(seconds=30),
        )


def test_upstream_ancestor_and_deployment_deadlines_all_narrow_the_child() -> None:
    for seconds, ancestors, cap, expected in [
        (100, [], 3600, 100),
        (7200, [START + timedelta(seconds=200)], 3600, 200),
        (7200, [START + timedelta(seconds=200), START + timedelta(seconds=90)], 3600, 90),
        (7200, [], 60, 60),
    ]:
        captured = _capture(_answer(expires_in=seconds), ancestor_expiries=ancestors, max_ttl_s=cap)
        assert captured.expires_at == START + timedelta(seconds=expected)


def test_absolute_rfc3339_expiry_normalizes_the_timezone() -> None:
    store = {key: value for key, value in STORE.items() if key != "expires_in"}
    store["expires_at"] = "/expires_at"
    captured = capture_response(
        json.dumps(_answer(expires_at="2026-10-21T14:30:00+02:00")).encode(),
        store=store,
        dispatch_started_at=START,
        now=NOW,
    )
    assert captured.upstream_expires_at == START + timedelta(minutes=30)


@pytest.mark.parametrize("expiry", [None, True, False, "60", 60.0, 0, -1, 2**53, 2**53 - 1])
def test_invalid_relative_expiry_is_never_guessed(expiry) -> None:
    with pytest.raises(CaptureInvalid):
        _capture(_answer(expires_in=expiry))


@pytest.mark.parametrize(
    "expiry",
    [
        None,
        123,
        "2026-10-21",
        "2026-10-21T12:30:00",
        "2026-10-21 12:30:00Z",
        "2026-13-21T12:30:00Z",
        "2026-10-21T11:59:00Z",
    ],
)
def test_invalid_or_past_absolute_expiry_is_refused(expiry) -> None:
    store = {key: value for key, value in STORE.items() if key != "expires_in"}
    store["expires_at"] = "/expires_at"
    with pytest.raises(CaptureInvalid):
        capture_response(
            json.dumps(_answer(expires_at=expiry)).encode(),
            store=store,
            dispatch_started_at=START,
            now=NOW,
        )


@pytest.mark.parametrize("cap", [0, -1, True, 1.5, "3600"])
def test_local_cap_requires_a_positive_integer(cap) -> None:
    with pytest.raises(CaptureInvalid):
        _capture(_answer(), max_ttl_s=cap)


@pytest.mark.parametrize("value", [None, "", 1, True, [], {}])
def test_capture_requires_nonempty_string_fields(value) -> None:
    with pytest.raises(CaptureInvalid):
        _capture(_answer(credentials={"access_token": value}))


@pytest.mark.parametrize(
    "body", [b"{}", b"[]", b"{", b"\xff", b'{"expires_in":60,"expires_in":90}']
)
def test_missing_malformed_or_ambiguous_response_is_refused(body) -> None:
    with pytest.raises(CaptureInvalid):
        capture_response(body, store=STORE, dispatch_started_at=START, now=NOW)


def test_capture_resolves_pointer_escapes_and_array_indices() -> None:
    value = os.urandom(24).hex()
    store = {**STORE, "capture": {"value": "/a~1b/~0/0"}}
    captured = capture_response(
        json.dumps({"a/b": {"~": [value]}, "expires_in": 60}).encode(),
        store=store,
        dispatch_started_at=START,
        now=NOW,
    )
    assert decode_value("bearer", captured.encoded) == {"value": value}


def test_capture_errors_never_include_upstream_values() -> None:
    answer = _answer()
    answer["expires_in"] = answer["credentials"]["access_token"]
    with pytest.raises(CaptureInvalid) as refused:
        _capture(answer)
    assert str(refused.value) == "derived credential capture or expiry is invalid"
