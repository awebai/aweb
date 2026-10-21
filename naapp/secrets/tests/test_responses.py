"""What an agent gets back from a brokered call (secrets §7.6): the response
bounded, its headers filtered, projected, redacted, and withheld when it looks
like it carries a credential."""

from __future__ import annotations

import base64
import json
import secrets

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


@pytest.mark.parametrize(
    "pointer", ["/access_token", "/Credentials/SessionToken", "/Credentials/secret-access-key"]
)
@pytest.mark.parametrize("token_issuing", [True, False])
def test_a_projection_that_names_a_credential_field_is_withheld(pointer: str, token_issuing: bool) -> None:
    document = {
        "access_token": "issued",
        "Credentials": {"SessionToken": "issued", "secret-access-key": "issued"},
    }
    result = _handle(json.dumps(document).encode(), projection=[pointer], token_issuing=token_issuing)
    assert result.disposition == "withheld"
    assert result.withheld_reason == "credential_shaped"
    assert result.body is None
    assert result.undeclared_credential is not token_issuing


def test_a_projection_naming_an_empty_credential_field_is_returned() -> None:
    body = json.dumps({"Credentials": {"SessionToken": ""}, "id": "x"}).encode()
    result = _handle(body, projection=["/Credentials/SessionToken", "/id"], token_issuing=True)
    assert result.disposition == "returned"


@pytest.mark.parametrize("pointer", ["/Credentials", "/Credentials/SessionToken", "/Credentials/SessionToken/0", "/Credentials/SessionToken/0/value"])
@pytest.mark.parametrize("token_issuing", [True, False])
def test_projecting_a_credential_array_or_its_descendants_is_withheld(pointer: str, token_issuing: bool) -> None:
    body = json.dumps({"Credentials": {"SessionToken": [{"value": secrets.token_urlsafe(24)}]}}).encode()
    result = _handle(body, projection=[pointer], token_issuing=token_issuing)
    assert result.disposition == "withheld"
    assert result.withheld_reason == "credential_shaped"
    assert result.body is None
    assert result.undeclared_credential is not token_issuing


@pytest.mark.parametrize("pointer", ["/Credentials/SessionToken", "/Credentials/SessionToken/0"])
def test_projecting_a_credential_string_array_is_withheld(pointer: str) -> None:
    body = json.dumps({"Credentials": {"SessionToken": [secrets.token_urlsafe(24)]}}).encode()
    result = _handle(body, projection=[pointer], token_issuing=True)
    assert result.disposition == "withheld"
    assert result.body is None


@pytest.mark.parametrize("body", [b'{"id":"ok"}', b'{"access_token":"issued"}', b'error'])
@pytest.mark.parametrize("header_name", ["Location", "X-Request-Id", "ETag"])
@pytest.mark.parametrize("field", ["access_token", "access%5Ftoken"])
@pytest.mark.parametrize("separator", ["?", "#"])
def test_an_issued_credential_in_an_allowed_header_is_never_returned(body: bytes, header_name: str, field: str, separator: str) -> None:
    # The new value is not in KnownValues. A safe projection or an error body
    # must not let it leave through headers, even if the body is withheld.
    result = _handle(
        body,
        headers=[("Content-Type", "application/json"), (header_name, f"https://upstream.example/next{separator}{field}={secrets.token_urlsafe(24)}")],
        projection=["/id"],
        token_issuing=True,
    )
    assert [name for name, _ in result.headers] == ["Content-Type"]


def test_withholding_the_body_does_not_return_credential_shaped_headers() -> None:
    result = _handle(
        json.dumps({"SessionToken": secrets.token_urlsafe(24)}).encode(),
        headers=[("Location", f"https://upstream.example/next?access_token={secrets.token_urlsafe(24)}")],
        token_issuing=True,
    )
    assert result.disposition == "withheld"
    assert result.body is None
    assert [name for name, _ in result.headers] == []


@pytest.mark.parametrize("pointer", ["id", "/a/~2", "/a/~"])
def test_a_malformed_pointer_is_refused(pointer: str) -> None:
    with pytest.raises(ValueError):
        _handle(b"{}", projection=[pointer])


STRADDLER = "Z0x9Y8w7V6u5T4s3R2q1P0"


def _known_straddler() -> KnownValues:
    known = KnownValues()
    known.add("k", STRADDLER)
    return known


@pytest.mark.parametrize("cut", [1, 5, 11, 21])
@pytest.mark.parametrize("encoding", ["raw", "base64"])
def test_a_value_straddling_the_bound_leaves_no_part_of_itself(cut: int, encoding: str) -> None:
    encoded = STRADDLER if encoding == "raw" else base64.b64encode(STRADDLER.encode()).decode()
    body = ("." * 20 + encoded + "." * 20).encode()
    result = _handle(
        body, headers=[("Content-Type", "text/plain")], max_bytes=20 + cut, known=_known_straddler()
    )
    assert result.truncated is True
    assert result.body is not None
    assert encoded[:1].encode() not in result.body
    assert result.redaction_count >= 1


@pytest.mark.parametrize("cut", [1, 5, 11, 21])
@pytest.mark.parametrize("encoding", ["raw", "base64"])
def test_a_body_the_egress_cut_inside_a_value_leaves_no_part_of_it(cut: int, encoding: str) -> None:
    encoded = STRADDLER if encoding == "raw" else base64.b64encode(STRADDLER.encode()).decode()
    body = ("." * 20 + encoded[:cut]).encode()
    result = _handle(
        body, headers=[("Content-Type", "text/plain")], truncated=True, known=_known_straddler()
    )
    assert result.body == b"." * 20 + b"[REDACTED:k]"
    assert result.redaction_count == 1


def test_a_json_body_with_an_escaped_known_value_is_redacted() -> None:
    known = KnownValues()
    known.add("k", "wJalr/K7MDENG/bPxRfiCY")
    body = b'{"echo": "wJalr\\/K7MDENG\\/bPxRfiCY", "ok": true}'
    result = _handle(body, known=known)
    assert json.loads(result.body) == {"echo": "[REDACTED:k]", "ok": True}


def test_a_projected_value_is_redacted_after_projection() -> None:
    known = KnownValues()
    known.add("k", "p&ss<w>rd")
    body = b'{"id": "x", "echo": "p\\u0026ss\\u003cw\\u003erd"}'
    result = _handle(body, projection=["/echo"], known=known)
    assert json.loads(result.body) == {"/echo": "[REDACTED:k]"}


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "gzip, identity"])
def test_a_compressed_response_is_withheld(encoding: str) -> None:
    result = _handle(
        b"\x1f\x8b compressed",
        headers=[("Content-Type", "application/json"), ("Content-Encoding", encoding)],
    )
    assert result.disposition == "withheld"
    assert result.withheld_reason == "content_encoded"
    assert result.body is None


def test_an_identity_encoded_response_is_returned() -> None:
    result = _handle(b"{}", headers=[("Content-Type", "application/json"), ("Content-Encoding", "identity")])
    assert result.disposition == "returned"


def _typed(content_type: str | None, content_types: list[str] | None):
    headers = [("Content-Type", content_type)] if content_type else [("X-Request-Id", "r")]
    return handle_response(
        status=200,
        headers=headers,
        body=b'{"id": "x"}',
        truncated=False,
        max_bytes=4096,
        projection=None,
        known=_known(),
        token_issuing=False,
        content_types=content_types,
    )


@pytest.mark.parametrize(
    "content_type", ["application/json", "application/json; charset=utf-8", "Application/JSON"]
)
def test_a_declared_content_type_is_returned(content_type: str) -> None:
    assert _typed(content_type, ["application/json"]).disposition == "returned"


@pytest.mark.parametrize("content_type", ["text/html", "application/jsonp", None])
def test_an_undeclared_content_type_is_withheld(content_type: str | None) -> None:
    result = _typed(content_type, ["application/json"])
    assert result.disposition == "withheld"
    assert result.withheld_reason == "content_type_not_allowed"
    assert result.body is None
    assert result.status == 200


def test_without_declared_content_types_any_type_is_returned() -> None:
    assert _typed("text/html", None).disposition == "returned"
