"""What an agent gets back from a brokered call (secrets §7.6): the response
bounded, its headers filtered, projected, redacted, and withheld when it looks
like it carries a credential."""

from __future__ import annotations

import json

import pytest

from aweb_secrets.redaction import KnownValues
from aweb_secrets.responses import handle_response

# Generated for these tests; not a credential of any service.
VALUE = "known-value-0123456789"


def _known() -> KnownValues:
    known = KnownValues()
    known.add("stripe-test", VALUE)
    return known


def _handle(body: bytes, *, headers=(), projection=None, max_bytes=4096, truncated=False, **kw):
    return handle_response(
        status=200,
        headers=list(headers) or [("Content-Type", "application/json")],
        body=body,
        truncated=truncated,
        max_bytes=max_bytes,
        projection=projection,
        known=kw.pop("known", _known()),
        token_issuing=kw.pop("token_issuing", False),
    )


def test_an_ordinary_response_is_returned_whole() -> None:
    body = json.dumps({"id": "ch_1", "amount": 500}).encode()
    result = _handle(body)
    assert result.disposition == "returned"
    assert result.status == 200
    assert result.body == body
    assert result.redaction_count == 0
    assert result.undeclared_credential is False
    assert result.truncated is False
    assert result.upstream_bytes == len(body)


def test_only_allowed_headers_pass_and_location_is_redacted() -> None:
    result = _handle(
        b"{}",
        headers=[
            ("Content-Type", "application/json"),
            ("ETag", '"v1"'),
            ("Last-Modified", "Tue, 20 Oct 2026 08:00:00 GMT"),
            ("Retry-After", "3"),
            ("X-RateLimit-Remaining", "9"),
            ("X-Request-Id", "req-1"),
            ("Stripe-Request-Id", "req-2"),
            ("Location", f"https://api.example/next?token={VALUE}"),
            ("Set-Cookie", "session=abc"),
            ("Server", "nginx"),
            ("X-Internal-Debug", "trace"),
            ("WWW-Authenticate", "Bearer"),
        ],
    )
    assert result.headers == [
        ("Content-Type", "application/json"),
        ("ETag", '"v1"'),
        ("Last-Modified", "Tue, 20 Oct 2026 08:00:00 GMT"),
        ("Retry-After", "3"),
        ("X-RateLimit-Remaining", "9"),
        ("X-Request-Id", "req-1"),
        ("Stripe-Request-Id", "req-2"),
        ("Location", "https://api.example/next?token=[REDACTED:stripe-test]"),
    ]
    assert result.redaction_count == 1


def test_a_body_over_the_bound_is_cut_and_the_cut_is_reported() -> None:
    result = _handle(b"x" * 100, headers=[("Content-Type", "text/plain")], max_bytes=10)
    assert result.body == b"x" * 10
    assert result.truncated is True
    assert result.upstream_bytes == 100


def test_a_body_the_egress_already_cut_is_reported_as_cut() -> None:
    result = _handle(b"partial", headers=[("Content-Type", "text/plain")], truncated=True)
    assert result.truncated is True


def test_a_projection_returns_only_the_pointed_values() -> None:
    body = json.dumps(
        {"id": "re_1", "amount": 500, "charge": {"id": "ch_1", "customer": "cus_9"}, "a/b": 1}
    ).encode()
    result = _handle(body, projection=["/id", "/charge/id", "/a~1b", "/missing"])
    assert json.loads(result.body) == {"/id": "re_1", "/charge/id": "ch_1", "/a~1b": 1}
    assert result.disposition == "returned"


def test_a_projection_of_a_body_that_is_not_json_returns_nothing() -> None:
    result = _handle(b"<html>not json</html>", headers=[("Content-Type", "text/html")], projection=["/id"])
    assert json.loads(result.body) == {}


def test_a_projection_of_a_cut_body_returns_nothing() -> None:
    result = _handle(json.dumps({"id": "x" * 50}).encode(), projection=["/id"], max_bytes=20)
    assert json.loads(result.body) == {}
    assert result.truncated is True


def test_a_known_value_in_the_body_is_redacted_and_counted() -> None:
    body = json.dumps({"echo": VALUE, "note": f"saw {VALUE}"}).encode()
    result = _handle(body)
    assert result.disposition == "returned"
    assert json.loads(result.body) == {
        "echo": "[REDACTED:stripe-test]",
        "note": "saw [REDACTED:stripe-test]",
    }
    assert result.redaction_count == 2


def test_a_credential_shaped_body_is_withheld_with_the_redaction_count() -> None:
    body = json.dumps({"access_token": "issued-by-upstream", "echo": VALUE}).encode()
    result = _handle(body)
    assert result.disposition == "withheld"
    assert result.withheld_reason == "credential_shaped"
    assert result.body is None
    assert result.redaction_count == 1
    assert result.status == 200
    assert result.headers == [("Content-Type", "application/json")]


def test_an_undeclared_token_issuance_is_withheld_and_flagged() -> None:
    result = _handle(json.dumps({"refresh_token": "issued"}).encode(), token_issuing=False)
    assert result.disposition == "withheld"
    assert result.undeclared_credential is True


def test_a_declared_token_issuer_is_not_flagged_as_undeclared() -> None:
    result = _handle(json.dumps({"refresh_token": "issued"}).encode(), token_issuing=True)
    assert result.disposition == "withheld"
    assert result.undeclared_credential is False


def test_a_projection_that_drops_the_credential_fields_is_returned() -> None:
    body = json.dumps({"access_token": "issued", "expires_in": 3600}).encode()
    result = _handle(body, projection=["/expires_in"], token_issuing=True)
    assert result.disposition == "returned"
    assert json.loads(result.body) == {"/expires_in": 3600}


@pytest.mark.parametrize("pointer", ["id", "/a/~2", "/a/~"])
def test_a_malformed_pointer_is_refused(pointer: str) -> None:
    with pytest.raises(ValueError):
        _handle(b"{}", projection=[pointer])
