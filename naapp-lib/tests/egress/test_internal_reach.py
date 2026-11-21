"""The one rule for reaching the operator's network: which origins it admits,
and that hook deliveries and team-server reads both follow it."""

from __future__ import annotations

import inspect
from ipaddress import ip_network

import pytest

import aweb_naapp.hooks.transport as hook_transport
import aweb_naapp.runtime.team_server as team_server
from aweb_naapp.egress.internal import InternalReach, origin_authority, send_reaching_internal

NETWORK = ip_network("10.20.0.0/16")


@pytest.mark.parametrize(
    ("origin", "authority"),
    [
        ("https://coord.example", "coord.example"),
        ("https://coord.example:8443", "coord.example:8443"),
        ("https://10.20.0.5:8443", "10.20.0.5:8443"),
    ],
)
def test_an_exact_origin_names_its_canonical_authority(origin: str, authority: str) -> None:
    assert origin_authority(origin) == authority


@pytest.mark.parametrize(
    "entry",
    [
        "https://Coord.Example",  # not the canonical spelling
        "https://coord.example:443",  # the default port spelled out
        "https://coord.example/",  # a path
        "https://coord.example/prefix",
        "https://*.coord.example",  # a pattern
        "http://coord.example",  # plain http
        "http://127.0.0.1:8000",
        "coord.example",
        "",
    ],
)
def test_anything_but_an_exact_https_origin_names_nothing(entry: str) -> None:
    assert origin_authority(entry) is None
    assert InternalReach.of(NETWORK, [entry]) is None


def test_without_a_network_or_an_origin_there_is_no_second_attempt() -> None:
    assert InternalReach.of(None, ["https://coord.example"]) is None
    assert InternalReach.of(NETWORK, []) is None


@pytest.mark.parametrize(
    ("url", "admitted"),
    [
        ("https://coord.example/a/longer/path", True),
        ("https://COORD.example:443/x", True),
        ("https://coord.example:8443/x", False),
        ("https://other.example/x", False),
        ("https://sub.coord.example/x", False),
        ("http://coord.example/x", False),
    ],
)
def test_a_url_is_admitted_by_its_canonical_authority_only(url: str, admitted: bool) -> None:
    reach = InternalReach.of(NETWORK, ["https://coord.example"])
    assert reach is not None
    assert reach.admits(url) is admitted


@pytest.mark.parametrize("module", [hook_transport, team_server])
def test_hook_deliveries_and_team_server_reads_follow_the_one_rule(module) -> None:
    # Neither keeps a copy of the retry trigger: both send through the one function.
    source = inspect.getsource(module)
    assert send_reaching_internal.__name__ in source
    assert "destination_address_denied" not in source
