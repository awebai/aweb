"""Server-side injection for bearer, basic, header and query secrets (§7.5).

The values are generated when the test runs; none is a real credential.
"""

from __future__ import annotations

import base64
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
