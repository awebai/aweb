"""The operator's network settings: one switch and CIDR, an origin list per
purpose, and a refusal at startup for any incomplete combination."""

from __future__ import annotations

import logging
from ipaddress import ip_network

import pytest
from pydantic import ValidationError

from aweb_naapp.egress import InternalDestinations
from aweb_naapp.runtime.operator_egress import OperatorEgress, OperatorNetworkSettings

NETWORK = {"hook_internal_destinations": "allowed", "hook_internal_cidr": "10.20.0.0/16"}
TEAM_SERVER = "https://aweb.example"
RECEIVER = "https://receiver.example"


def test_no_operator_network_reaches_nothing_internal() -> None:
    egress = OperatorEgress.from_settings(OperatorNetworkSettings())
    assert egress.egress.addresses.internal_destinations is InternalDestinations.DISABLED
    assert (egress.hooks, egress.team_servers) == (None, None)


def test_a_team_server_alone_needs_no_hook_origin() -> None:
    egress = OperatorEgress.from_settings(
        OperatorNetworkSettings(**NETWORK, team_server_internal_origins=[TEAM_SERVER])
    )
    assert egress.egress.addresses.internal_destinations is InternalDestinations.ALLOWED
    assert egress.hooks is None
    assert egress.team_servers is not None
    assert egress.team_servers.cidr == ip_network("10.20.0.0/16")
    assert egress.team_servers.authorities == {"aweb.example"}


def test_each_list_grants_reach_for_its_own_purpose_only() -> None:
    egress = OperatorEgress.from_settings(
        OperatorNetworkSettings(
            **NETWORK,
            hook_internal_origins=[RECEIVER],
            team_server_internal_origins=[TEAM_SERVER],
        )
    )
    assert egress.hooks is not None and egress.team_servers is not None
    assert egress.hooks.admits(f"{RECEIVER}/hooks") and not egress.hooks.admits(f"{TEAM_SERVER}/x")
    assert egress.team_servers.admits(f"{TEAM_SERVER}/x")
    assert not egress.team_servers.admits(f"{RECEIVER}/hooks")


@pytest.mark.parametrize(
    "settings",
    [
        {"team_server_internal_origins": [TEAM_SERVER]},
        {"hook_internal_origins": [RECEIVER]},
        {"hook_internal_cidr": "10.20.0.0/16", "team_server_internal_origins": [TEAM_SERVER]},
        {"hook_internal_destinations": "allowed", "hook_internal_origins": [RECEIVER]},
        NETWORK,
    ],
    ids=[
        "origins-without-network",
        "hook-origins-without-network",
        "cidr-without-switch",
        "switch-without-cidr",
        "network-without-origins",
    ],
)
def test_an_incomplete_operator_network_refuses_to_start(settings: dict) -> None:
    with pytest.raises(ValidationError):
        OperatorNetworkSettings(**settings)


@pytest.mark.parametrize(
    "origin",
    [
        "http://aweb.example",
        "http://127.0.0.1:8000",
        "https://aweb.example/api",
        "https://*.example",
    ],
)
@pytest.mark.parametrize("field", ["hook_internal_origins", "team_server_internal_origins"])
def test_a_listed_origin_is_an_exact_https_origin(field: str, origin: str) -> None:
    with pytest.raises(ValidationError):
        OperatorNetworkSettings(**NETWORK, **{field: [origin]})


def test_a_listed_origin_is_kept_in_its_canonical_spelling() -> None:
    settings = OperatorNetworkSettings(
        **NETWORK, team_server_internal_origins=["https://AWEB.example:443/"]
    )
    assert settings.team_server_internal_origins == {TEAM_SERVER}


def test_listed_origins_are_logged_at_startup_for_their_purpose(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="aweb_naapp.runtime.operator_egress"):
        OperatorEgress.from_settings(
            OperatorNetworkSettings(**NETWORK, team_server_internal_origins=[TEAM_SERVER])
        )
    [warning] = [record.getMessage() for record in caplog.records]
    assert "team-server reads" in warning and TEAM_SERVER in warning


def test_nothing_is_logged_when_no_origin_is_listed(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="aweb_naapp.runtime.operator_egress"):
        OperatorEgress.from_settings(OperatorNetworkSettings())
    assert caplog.records == []


def test_the_guard_denies_the_operators_denied_networks() -> None:
    egress = OperatorEgress.from_settings(
        OperatorNetworkSettings(egress_denied_networks=["198.51.100.0/24"])
    )
    assert egress.egress.addresses.denied == (ip_network("198.51.100.0/24"),)
