"""Actual AWID SDK address records retain nullable route metadata."""

import pytest

from awid.registry import Address, AddressDelivery
from aweb.messaging.address_auth import (
    resolved_recipient_controller_did,
    resolved_recipient_delivery_origin,
)


@pytest.mark.parametrize("origin", [None, "", "https://delivery.example.test"])
def test_sdk_address_nullable_delivery_origin_does_not_become_a_projection_failure(
    origin,
):
    address = Address(
        address_id="address",
        domain="example.test",
        name="recipient",
        did_aw="did:aw:recipient",
        current_did_key="did:key:recipient",
        created_at="2026-11-19T00:00:00Z",
        delivery=AddressDelivery(origin=origin),
    )
    assert resolved_recipient_delivery_origin(address) == (origin or "")
    assert resolved_recipient_controller_did(address) == ""
