"""An operator-configured base URL: https on any host, or plain http on loopback only."""

from __future__ import annotations

import pytest

from aweb_naapp.egress import EgressRefused, operator_base_url


@pytest.mark.parametrize(
    ("entry", "canonical"),
    [
        ("https://Core.Example/api", "https://core.example/api"),
        ("https://core.example/api/", "https://core.example/api"),
        ("https://core.example:443/", "https://core.example"),
        ("http://127.0.0.1:8000/api", "http://127.0.0.1:8000/api"),
        ("https://core.example", "https://core.example"),
    ],
)
def test_a_base_url_keeps_its_path_prefix(entry: str, canonical: str) -> None:
    assert operator_base_url(entry) == canonical


@pytest.mark.parametrize(
    "entry",
    [
        "http://core.example/api",
        "https://core.example/api?x=1",
        "https://core.example/api#x",
        "https://user@core.example/api",
        "https:///api",
    ],
)
def test_a_base_url_refuses_what_an_origin_refuses_beyond_its_path(entry: str) -> None:
    with pytest.raises(EgressRefused):
        operator_base_url(entry)
