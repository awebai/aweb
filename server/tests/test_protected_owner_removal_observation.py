"""Freeze classification and requester provenance for the original observation.

Retained from the security review's database-free observation matrix. These
are port controls; actual identity classification and owner UV have separate
public-observer and native tests.
"""

from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, RestrictedRequester, SignerRefused
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key

from aweb.protected_signing.owner_removal import OwnerRemovalObservation


@pytest.fixture
def owner_observation():
    _, public = generate_keypair()
    principal, key = stable_id_from_public_key(public), did_from_public_key(public)
    context = ProtectedKeyContext("signer", "team_controller", "team:example.org", "example.org", principal, "example.org", 1)
    actor = RestrictedRequester(principal, context, key)
    clock = SimpleNamespace(now=0)
    adapter = SimpleNamespace(timer=lambda: clock.now)
    return actor, clock, adapter


@pytest.mark.asyncio
@pytest.mark.parametrize("frozen", ["agent", "kind not verified"])
@pytest.mark.parametrize("current", ["agent", "kind not verified"])
async def test_eligible_kind_change_requires_a_new_frozen_display(owner_observation, frozen, current):
    actor, _, adapter = owner_observation
    observed = OwnerRemovalObservation(adapter, actor, current, 60)
    request = {"target_kind": frozen, "requester_key": actor.key_did}
    if frozen == current:
        await observed.check(None, request)
    else:
        with pytest.raises(SignerRefused, match="operation_mismatch"):
            await observed.check(None, request)


@pytest.mark.asyncio
async def test_requester_key_and_original_observation_deadline_stay_bound(owner_observation):
    actor, clock, adapter = owner_observation
    observed = OwnerRemovalObservation(adapter, actor, "agent", 60)
    request = {"target_kind": "agent", "requester_key": "another"}
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        await observed.check(None, request)
    request["requester_key"] = actor.key_did
    await observed.check(None, request)
    clock.now = 60
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await observed.check(None, request)
