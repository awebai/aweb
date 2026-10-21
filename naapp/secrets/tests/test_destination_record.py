"""The destination record v1 (§7.2): where a secret may be sent, in the egress guard's form."""

from __future__ import annotations

import copy

import pytest
from aweb_naapp.egress import InternalDestinations, match_destination

from aweb_secrets.destination import DestinationInvalid, DestinationRecord, mint_destination_id

ALLOWED = InternalDestinations.ALLOWED
DISABLED = InternalDestinations.DISABLED

RECORD = {
    "v": 1,
    "destination_id": "dst_charges01",
    "secret_id": "sec_19ab42",
    "scheme": "https",
    "host": "api.payments.example",
    "port": 443,
    "path": "/v1/charges/**",
    "methods": ["GET", "POST"],
    "query_rules": {"expand": {"presence": "optional", "repeatable": False}},
    "header_allow": ["accept", "idempotency-key"],
    "network": "public",
    "cidr": None,
}
INTERNAL = {
    **RECORD,
    "host": "10.0.4.7",
    "path": "/v1/**",
    "network": "internal",
    "cidr": "10.0.4.0/24",
}


def _record(**changes):
    record = copy.deepcopy(RECORD)
    record.update(changes)
    return record


def test_the_record_round_trips_as_its_after() -> None:
    assert DestinationRecord.from_after(RECORD, internal_destinations=DISABLED).after == RECORD


def test_the_record_matches_what_the_egress_guard_matches() -> None:
    destination = DestinationRecord.from_after(RECORD, internal_destinations=DISABLED).destination
    match_destination(
        destination,
        "POST",
        "https://api.payments.example/v1/charges/ch_1",
        internal_destinations=DISABLED,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"v": 2},
        {"destination_id": "charges01"},
        {"secret_id": "19ab42"},
        {"scheme": "http"},
        {"host": "API.payments.example"},
        {"host": "*.co.uk"},
        {"host": "api.payments.example."},
        {"path": "v1/charges"},
        {"path": "/v1/../admin"},
        {"methods": []},
        {"methods": ["CONNECT"]},
        {"methods": ["POST", "GET"]},
        {"methods": ["GET", "GET"]},
        pytest.param({"methods": [{}]}, id="methods-object"),
        pytest.param({"methods": ["GET", 1]}, id="methods-mixed"),
        {"port": 0},
        {"port": True},
        {"header_allow": ["idempotency-key", "accept"]},
        {"header_allow": ["Accept"]},
        pytest.param({"header_allow": [{}]}, id="headers-object"),
        pytest.param({"header_allow": ["accept", 1]}, id="headers-mixed"),
        {"query_rules": {"expand": {"presence": "sometimes"}}},
        {"network": "internal"},
        {"cidr": "10.0.0.0/8"},
        {"surprise": 1},
    ],
)
def test_a_malformed_record_is_refused(change) -> None:
    with pytest.raises(DestinationInvalid):
        DestinationRecord.from_after(_record(**change), internal_destinations=ALLOWED)


@pytest.mark.parametrize("missing", sorted(RECORD))
def test_every_field_is_required(missing) -> None:
    record = copy.deepcopy(RECORD)
    del record[missing]
    with pytest.raises(DestinationInvalid):
        DestinationRecord.from_after(record, internal_destinations=ALLOWED)


def test_a_wildcard_over_an_owned_domain_is_a_destination() -> None:
    record = _record(host="*.api.example.com")
    assert DestinationRecord.from_after(record, internal_destinations=DISABLED).after == record


def test_an_internal_destination_needs_the_deploy_to_allow_it() -> None:
    assert (
        DestinationRecord.from_after(INTERNAL, internal_destinations=ALLOWED).network == "internal"
    )
    with pytest.raises(DestinationInvalid) as refused:
        DestinationRecord.from_after(INTERNAL, internal_destinations=DISABLED)
    assert refused.value.code == "internal_destinations_disabled"


def test_minted_destination_ids_are_valid() -> None:
    record = _record(destination_id=mint_destination_id())
    assert DestinationRecord.from_after(record, internal_destinations=DISABLED).after == record
