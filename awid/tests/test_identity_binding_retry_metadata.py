"""Retry hints survive identity observation without changing its authority."""

import asyncio
from types import SimpleNamespace

import pytest

from awid.identity_observation import (
    IdentityObservationRefused,
    observe_identity_binding,
)
from awid.registry_types import RegistryError, RegistryThrottled


class UnavailableRegistry:
    def __init__(self, failure, *, at_address=False):
        self.failure, self.at_address = failure, at_address

    async def resolve_key_fresh(self, identity):
        if not self.at_address:
            raise self.failure
        return SimpleNamespace(
            did_aw=identity, current_did_key="did:key:subject", id_tree=None
        )

    async def resolve_address_fresh(self, domain, name):
        raise self.failure


@pytest.mark.asyncio
@pytest.mark.parametrize("at_address", [False, True])
async def test_only_registry_throttling_carries_its_retry_hint(at_address):
    failure = RegistryThrottled(
        retry_after_seconds=53, attempts=1, reason="elapsed_budget"
    )
    with pytest.raises(IdentityObservationRefused) as caught:
        await observe_identity_binding(
            UnavailableRegistry(failure, at_address=at_address),
            did_key="did:key:subject",
            did_aw="did:aw:subject",
            address="example.test/subject",
        )
    assert caught.value.code == "identity_binding_unavailable"
    assert caught.value.retry_after_seconds == 53
    assert caught.value.__cause__ is failure


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", [RegistryError("unavailable", status_code=503), OSError("offline")]
)
async def test_other_dependency_failures_have_no_retry_hint(failure):
    with pytest.raises(IdentityObservationRefused) as caught:
        await observe_identity_binding(
            UnavailableRegistry(failure),
            did_key="did:key:subject",
            did_aw="did:aw:subject",
        )
    assert caught.value.code == "identity_binding_unavailable"
    assert caught.value.retry_after_seconds is None


@pytest.mark.asyncio
async def test_registry_cancellation_is_not_an_identity_refusal():
    with pytest.raises(asyncio.CancelledError):
        await observe_identity_binding(
            UnavailableRegistry(asyncio.CancelledError()),
            did_key="did:key:subject",
            did_aw="did:aw:subject",
        )
