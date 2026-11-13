"""Unknown registered kind never establishes unattended agent authority.

Use the real public binding/kind observers. Only the registry transport is a
port double; it reports the legacy, explicitly unenrolled key mapping.
"""

from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.identity_observation import observe_identity_binding, observe_identity_kind
from awid.registry_types import IDTreeEnrollment

from aweb.protected_signing.removal import agent_target


@pytest.mark.asyncio
@pytest.mark.parametrize("self_remove", [False, True])
async def test_legacy_registered_unknown_kind_cannot_be_removed_as_an_agent(self_remove):
    _, public = generate_keypair()
    key, principal = did_from_public_key(public), stable_id_from_public_key(public)

    class Registry:
        namespace_keys = {}

        async def resolve_key_fresh(self, selected):
            return SimpleNamespace(did_aw=selected,
                current_did_key=key if selected == principal else "human-key",
                id_tree=IDTreeEnrollment(False, None))

    registry = Registry()
    binding = await observe_identity_binding(registry, did_aw=principal, did_key=key)
    observed = (await observe_identity_kind(registry, binding)).result
    assert observed["outcome"] == "unknown" and observed["kind"] is None
    assert observed["identity_valid"] is None
    c = SimpleNamespace(registry=registry, context=SimpleNamespace(human_id="human"),
        authority=SimpleNamespace(custody=SimpleNamespace(team_key_did="controller-key")))
    record = SimpleNamespace(member_did_key=key, member_did_aw=principal, identity_scope="global")
    with pytest.raises(SignerRefused, match="subject_ineligible"):
        await agent_target(c, record, self_key=key if self_remove else None)
