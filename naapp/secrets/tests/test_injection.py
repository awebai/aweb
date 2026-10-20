"""Server-side injection for bearer, basic, header and query secrets (§7.5).

The values are generated when the test runs; none is a real credential.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest
from aweb_naapp.egress import EgressRefused

from aweb_secrets.injection import inject

URL = "https://api.example.com/v1/things?limit=5"


@pytest.fixture
def value() -> str:
    return secrets.token_urlsafe(24)


def test_bearer_sets_the_authorization_header(value: str) -> None:
    injection = inject("bearer", {"value": value}, {}, secret_ref="gh", url=URL)
    assert injection.headers == [("Authorization", f"Bearer {value}")]
    assert injection.injected_names == frozenset({"authorization"})
    assert injection.url == URL
    assert injection.recorded_url == URL


def test_basic_sets_the_composite_and_redacts_it(value: str) -> None:
    injection = inject(
        "basic", {"username": "svc", "password": value}, {}, secret_ref="db", url=URL
    )
    composite = base64.b64encode(f"svc:{value}".encode()).decode()
    assert injection.headers == [("Authorization", f"Basic {composite}")]
    redacted, count = injection.known.redact(f"{composite} {value}".encode())
    assert redacted == b"[REDACTED:db] [REDACTED:db]"
    assert count == 2


def test_a_basic_username_with_a_colon_is_refused(value: str) -> None:
    with pytest.raises(ValueError):
        inject("basic", {"username": "a:b", "password": value}, {}, secret_ref="db", url=URL)


def test_header_uses_the_owner_set_name_and_prefix(value: str) -> None:
    injection = inject(
        "header", {"value": value}, {"name": "X-Upstream-Key", "prefix": "Key "}, secret_ref="u", url=URL
    )
    assert injection.headers == [("X-Upstream-Key", f"Key {value}")]
    assert injection.injected_names == frozenset({"x-upstream-key"})


@pytest.mark.parametrize("name", ["Host", "Content-Length", "User-Agent", "Connection", "Bad Name", ""])
def test_a_header_kind_cannot_set_a_guard_header_or_a_malformed_name(value: str, name: str) -> None:
    with pytest.raises(ValueError):
        inject("header", {"value": value}, {"name": name, "prefix": ""}, secret_ref="u", url=URL)


def test_query_adds_the_owner_set_param_and_records_it_redacted(value: str) -> None:
    injection = inject("query", {"value": value}, {"param": "key"}, secret_ref="maps", url=URL)
    assert injection.headers == []
    assert injection.url == f"{URL}&key={value}"
    assert injection.recorded_url == f"{URL}&key=[REDACTED]"
    assert injection.known.redact(injection.url.encode())[1] == 1


def test_query_adds_the_param_to_a_url_without_a_query(value: str) -> None:
    injection = inject(
        "query", {"value": value}, {"param": "key"}, secret_ref="maps", url="https://api.example.com/v1"
    )
    assert injection.url == f"https://api.example.com/v1?key={value}"


def test_query_percent_encodes_the_value() -> None:
    injection = inject("query", {"value": "a b&c=d"}, {"param": "key"}, secret_ref="m", url=URL)
    assert injection.url == f"{URL}&key=a%20b%26c%3Dd"


@pytest.mark.parametrize("url", [f"{URL}&key=mine", "https://api.example.com/v1?key=", "https://api.example.com/v1?Key=x&key"])
def test_an_agent_url_that_already_carries_the_injected_param_is_refused(value: str, url: str) -> None:
    with pytest.raises(EgressRefused) as refused:
        inject("query", {"value": value}, {"param": "key"}, secret_ref="maps", url=url)
    assert refused.value.code == "params_invalid"


def test_every_injected_value_is_a_known_value(value: str) -> None:
    for kind, secret_value, params in (
        ("bearer", {"value": value}, {}),
        ("header", {"value": value}, {"name": "X-K", "prefix": ""}),
        ("query", {"value": value}, {"param": "key"}),
    ):
        injection = inject(kind, secret_value, params, secret_ref="r", url=URL)
        assert injection.known.redact(value.encode()) == (b"[REDACTED:r]", 1)


def test_an_unknown_kind_is_refused(value: str) -> None:
    with pytest.raises(ValueError):
        inject("mtls-client-cert", {"value": value}, {}, secret_ref="r", url=URL)


def test_an_empty_value_is_refused() -> None:
    with pytest.raises(ValueError):
        inject("bearer", {"value": ""}, {}, secret_ref="r", url=URL)


# --- aws-sigv4 -------------------------------------------------------------------

SIGV4_PARAMS = {"region": "eu-west-1", "service": "execute-api"}


def _sigv4(value_: dict, *, url: str = URL, headers=(), body: bytes = b'{"q":1}', params=None):
    return inject(
        "aws-sigv4",
        value_,
        params or SIGV4_PARAMS,
        secret_ref="aws",
        url=url,
        method="POST",
        body=body,
        headers=list(headers),
    )


def _aws_value(session: bool = False) -> dict:
    value_ = {
        "access_key_id": "AKIA" + secrets.token_hex(8).upper(),
        "secret_access_key": secrets.token_urlsafe(30),
    }
    if session:
        value_["session_token"] = secrets.token_urlsafe(40)
    return value_


def test_sigv4_signs_with_the_owner_set_region_and_service() -> None:
    value_ = _aws_value()
    injection = _sigv4(value_)
    headers = dict(injection.headers)
    authorization = headers["Authorization"]
    assert authorization.startswith(f"AWS4-HMAC-SHA256 Credential={value_['access_key_id']}/")
    assert "/eu-west-1/execute-api/aws4_request" in authorization
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in authorization
    assert headers["X-Amz-Content-SHA256"] == hashlib.sha256(b'{"q":1}').hexdigest()
    assert "X-Amz-Date" in headers
    assert injection.injected_names == frozenset(
        {"authorization", "x-amz-date", "x-amz-content-sha256"}
    )


def test_sigv4_signs_the_canonical_url_the_guard_sends() -> None:
    injection = _sigv4(_aws_value(), url="https://API.Example.com:443/v1/%7Ethings")
    assert injection.url == "https://api.example.com/v1/~things"


def test_sigv4_signs_the_agent_headers_it_sends() -> None:
    injection = _sigv4(
        _aws_value(),
        headers=[("Content-Type", "application/x-amz-json-1.1"), ("X-Amz-Target", "Things.Get")],
    )
    authorization = dict(injection.headers)["Authorization"]
    assert "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target" in authorization


def test_sigv4_with_a_session_token_sends_and_signs_it() -> None:
    value_ = _aws_value(session=True)
    injection = _sigv4(value_)
    headers = dict(injection.headers)
    assert headers["X-Amz-Security-Token"] == value_["session_token"]
    assert "x-amz-security-token" in headers["Authorization"]
    assert "x-amz-security-token" in injection.injected_names
    assert injection.known.redact(value_["session_token"].encode())[1] == 1


def test_sigv4_redacts_the_secret_key() -> None:
    value_ = _aws_value()
    injection = _sigv4(value_)
    assert injection.known.redact(value_["secret_access_key"].encode())[1] == 1


@pytest.mark.parametrize("missing", ["region", "service"])
def test_sigv4_needs_the_owner_set_region_and_service(missing: str) -> None:
    params = {k: v for k, v in SIGV4_PARAMS.items() if k != missing}
    with pytest.raises(ValueError):
        _sigv4(_aws_value(), params=params)


def test_an_agent_header_cannot_replace_a_signed_header() -> None:
    for name in ("X-Amz-Date", "X-Amz-Content-SHA256", "Authorization", "X-Amz-Security-Token"):
        with pytest.raises(EgressRefused) as refused:
            _sigv4(_aws_value(session=True), headers=[(name, "agent-chosen")])
        assert refused.value.code == "header_not_allowed"
