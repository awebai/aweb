"""An operator-configured origin: https on any host, or plain http on loopback only."""

from __future__ import annotations

import pytest

from aweb_naapp.egress import EgressRefused, operator_origin


@pytest.mark.parametrize(
    ("entry", "canonical"),
    [
        ("https://Coord.Example", "https://coord.example"),
        ("https://coord.example:443", "https://coord.example"),
        ("https://coord.example:8443", "https://coord.example:8443"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://LOCALHOST:80", "http://localhost"),
        ("http://[::1]:9000", "http://[::1]:9000"),
    ],
)
def test_an_origin_has_one_canonical_spelling(entry: str, canonical: str) -> None:
    assert operator_origin(entry) == canonical
    assert operator_origin(canonical) == canonical


@pytest.mark.parametrize(
    "entry",
    [
        "http://coord.example",
        "http://127.0.0.2:8000",
        "http://core.localhost",
        "https://coord.example/",
        "https://coord.example/prefix",
        "https://coord.example?x=1",
        "https://coord.example#x",
        "https://user@coord.example",
        "https://*.coord.example",
        "ftp://coord.example",
        "coord.example",
        "",
    ],
)
def test_anything_but_an_origin_is_refused(entry: str) -> None:
    with pytest.raises(EgressRefused):
        operator_origin(entry)
