"""The approval request is frozen as canonical bytes and named by their digest."""

from __future__ import annotations

import hashlib

import pytest

from aweb_naapp.runtime.approvals import RequestNotCanonical, canonical_request, request_sha256

REQUEST = {
    "operation": "send",
    "destination": {"host": "api.example.com", "path": "/v1/charges"},
    "constraints": {"max_amount_cents": 500, "currency": "EUR"},
    "source_version": 3,
    "executor": "broker",
    "policy": {"ref": "policy-1", "version": 2},
}


def test_key_order_does_not_change_the_digest():
    reordered = dict(reversed(list(REQUEST.items())))
    assert request_sha256(reordered) == request_sha256(REQUEST)


def test_digest_is_sha256_of_the_canonical_bytes():
    assert request_sha256(REQUEST) == hashlib.sha256(canonical_request(REQUEST)).hexdigest()


def test_digest_is_domain_separated_from_plain_canonical_json():
    from awid.signing import canonical_json_bytes

    assert canonical_request(REQUEST) != canonical_json_bytes(REQUEST)
    assert canonical_request(REQUEST).endswith(canonical_json_bytes(REQUEST))


@pytest.mark.parametrize(
    "path, value",
    [
        (("destination", "path"), "/v1/refunds"),
        (("constraints", "max_amount_cents"), 501),
        (("source_version",), 4),
        (("executor",), "runner"),
        (("policy", "version"), 3),
    ],
)
def test_changing_any_covered_value_changes_the_digest(path, value):
    changed = {k: (dict(v) if isinstance(v, dict) else v) for k, v in REQUEST.items()}
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert request_sha256(changed) != request_sha256(REQUEST)


@pytest.mark.parametrize(
    "bad",
    [
        {"amount": 1.5},
        {"amount": float("nan")},
        {"nested": [{"x": float("inf")}]},
        {1: "non-string key"},
        {"value": b"bytes"},
        {"value": {"a", "set"}},
        {"amount": 2**53},
        {"nested": [-(2**53)]},
    ],
)
def test_values_without_one_canonical_form_are_refused(bad):
    with pytest.raises(RequestNotCanonical):
        canonical_request(bad)


def test_request_must_be_an_object():
    with pytest.raises(RequestNotCanonical):
        canonical_request(["not", "an", "object"])  # type: ignore[arg-type]


def test_parsed_json_requests_digest_like_the_object():
    from aweb_naapp.runtime.approvals import parse_request_json

    raw = b'{"executor":"broker","constraints":{"max_amount_cents":500},"operation":"send"}'
    parsed = parse_request_json(raw)
    assert request_sha256(parsed) == request_sha256(
        {"operation": "send", "executor": "broker", "constraints": {"max_amount_cents": 500}}
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"operation":"send","operation":"delete"}',
        b'{"nested":{"a":1,"a":2}}',
        b'{"amount":1.5}',
        b'{"amount":1e3}',
        b'{"amount":NaN}',
        b'{"amount":Infinity}',
        b'["not","an","object"]',
        b"not json",
    ],
)
def test_parsed_json_without_one_canonical_form_is_refused(raw):
    from aweb_naapp.runtime.approvals import parse_request_json

    with pytest.raises(RequestNotCanonical):
        parse_request_json(raw)


def test_integers_up_to_the_javascript_safe_range_are_canonical():
    limit = 2**53 - 1
    assert request_sha256({"max": limit, "min": -limit})
