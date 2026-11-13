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

from aweb.protected_signing.admission import AdmissionEffects
from aweb.protected_signing.removal import agent_target


@pytest.fixture
def legacy_member():
    _, public = generate_keypair()
    key, principal = did_from_public_key(public), stable_id_from_public_key(public)

    class Registry:
        namespace_keys = {}

        async def resolve_key_fresh(self, selected):
            return SimpleNamespace(did_aw=selected,
                current_did_key=key if selected == principal else "human-key",
                id_tree=IDTreeEnrollment(False, None))

    registry = Registry()
    c = SimpleNamespace(registry=registry, context=SimpleNamespace(human_id="human"),
        authority=SimpleNamespace(custody=SimpleNamespace(team_key_did="controller-key")))
    record = SimpleNamespace(member_did_key=key, member_did_aw=principal, identity_scope="global")
    return c, record


@pytest.mark.asyncio
@pytest.mark.parametrize("self_remove", [False, True])
async def test_legacy_registered_unknown_kind_cannot_be_removed_as_an_agent(legacy_member, self_remove):
    c, record = legacy_member
    binding = await observe_identity_binding(c.registry, did_aw=record.member_did_aw, did_key=record.member_did_key)
    observed = (await observe_identity_kind(c.registry, binding)).result
    assert observed["outcome"] == "unknown" and observed["kind"] is None
    assert observed["identity_valid"] is None
    with pytest.raises(SignerRefused, match="subject_ineligible"):
        await agent_target(c, record, self_key=record.member_did_key if self_remove else None)


@pytest.mark.asyncio
async def test_legacy_registered_unknown_kind_cannot_be_admitted_as_an_agent(legacy_member):
    c, record = legacy_member
    registry = c.registry
    # The same kind boundary applies when the root admits a global child.
    # Root/policy admission are existing independent ports; the target's
    # binding and classification still use the real public observers above.
    registry.registry_url = "https://registry.example"

    class Effects(AdmissionEffects):
        async def policy(self, tx=None):
            return SimpleNamespace(fields=lambda: {"teams": ["team:example"],
                "subject_kinds": ["local_agent", "registered_agent"]})

        async def root_head(self, root_id, root_key, *, require_enrolled):
            assert require_enrolled
            return "root-head"

    subject = {"team_id": "team:example", "root_id": "root", "root_key": "root-key",
        "child_id": record.member_did_aw, "child_key": record.member_did_key}
    operation = SimpleNamespace(operation="team.agent.admit", audience=registry.registry_url,
        intent=lambda: {"subject": subject})
    with pytest.raises(SignerRefused, match="subject_ineligible"):
        await Effects(c).observe(operation, SimpleNamespace(principal="root"), purpose="prepare")



@pytest.mark.asyncio
@pytest.mark.parametrize("self_remove", [False, True])
async def test_local_member_removal_does_not_require_global_kind(legacy_member, self_remove):
    c, record = legacy_member
    record.member_did_aw, record.identity_scope = None, "local"
    await agent_target(c, record, self_key=record.member_did_key if self_remove else None)
