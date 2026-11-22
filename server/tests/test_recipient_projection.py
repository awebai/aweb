"""Delivery projections preserve verified identity and actor-free residence."""

from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from aweb.member_team_key import MemberProjection
from aweb.messaging.address_auth import identity_recipient
from aweb.messaging.recipient import Recipient, RecipientResidence
from aweb.messaging.recipient_bindings import signed_recipient_matches
from aweb.messaging.recipient_lookup import _agent_uuid
from aweb.service_errors import ValidationError


def native_member(**changes):
    row = dict(
        agent_id=uuid4(),
        team_id="team:example.test",
        alias="recipient",
        did_key="did:key:current",
        did_aw="did:aw:claimed",
        address="example.test/claimed",
        did_aw_verified_key=None,
        identity_scope="global",
        certificate_id="certificate",
        accepted_team_did_key="did:key:old-team",
        current_team_did_key="did:key:team",
        status="retired",
        deleted_at=None,
        agent_type="human",
        human_verified_key="did:key:unverified",
        inbound_mode="contacts_only",
    )
    row.update(changes)
    return MemberProjection.from_row(row)


def test_raw_identity_claim_stays_policy_only_in_delivery_projection():
    recipient = Recipient.from_member_projection(native_member())
    assert recipient.did_aw is None and recipient.address is None
    assert recipient.policy_did_aw == "did:aw:claimed" and recipient.has_global_claim
    assert recipient.agent_type == "unknown"
    assert recipient.status == "retired"
    assert not signed_recipient_matches(
        {"to_stable_id": "did:aw:claimed"}, recipients=[recipient], allowed_to=set()
    )


def test_verified_identity_binding_survives_without_restoring_membership():
    member = native_member(did_aw_verified_key="did:key:current")
    recipient = Recipient.from_member_projection(member)
    assert recipient.did_aw == "did:aw:claimed"
    assert signed_recipient_matches(
        {"to_stable_id": "did:aw:claimed", "to_did": "did:key:current"},
        recipients=[recipient],
        allowed_to=set(),
    )
    identity = identity_recipient(recipient, "example.test/claimed")
    assert identity.agent_id is None and identity.team_id is None
    assert identity.residence is RecipientResidence.LOCAL and not identity["external"]
    assert identity.inbound_mode == "contacts_only"


def test_stored_route_local_handoff_keeps_session_and_party_policy():
    policy = Recipient.from_member_projection(native_member())
    historical = Recipient.from_remote_projection(
        {
            "did": "did:aw:claimed",
            "session_id": str(uuid4()),
            "alias": "historical",
            "delivery_origin": "https://old.example.test",
            "_policy_recipients": [policy],
        }
    )
    local = identity_recipient(
        Recipient.from_member_projection(
            native_member(did_aw_verified_key="did:key:current")
        )
    )
    admitted = historical.with_local_identity(local)
    assert (
        admitted.session_id == historical.session_id and admitted.did == historical.did
    )
    assert admitted.policy_recipients == (policy,)
    assert admitted.agent_id is None and admitted.team_id is None
    assert admitted.delivery_origin is None and not admitted["external"]
    assert historical.delivery_origin == "https://old.example.test"


def test_captured_policy_and_route_are_immutable_at_signing_boundary():
    raw = {"did_aw": "did:aw:recipient", "did_key": "did:key:old"}
    policies = [raw]
    recipient = Recipient.from_remote_projection(
        {
            **raw,
            "delivery_origin": "https://recipient.example.test",
            "_policy_recipients": policies,
        }
    )
    raw["did_key"] = "did:key:substituted"
    policies.clear()
    assert recipient.policy_recipients[0].did_key == "did:key:old"
    with pytest.raises(FrozenInstanceError):
        recipient.did_key = "did:key:substituted"
    with pytest.raises(TypeError):
        recipient["did_key"] = "did:key:substituted"
    refreshed = replace(recipient, did_key="did:key:current")
    assert refreshed.did_key == "did:key:current" and recipient.did_key == "did:key:old"


def test_explicit_residence_is_independent_of_missing_actor_and_route():
    identity = Recipient.from_local_projection({"did_aw": "did:aw:local"})
    remote = Recipient.from_remote_projection({"did_aw": "did:aw:remote"})
    assert identity.agent_id is None and remote.agent_id is None
    assert identity.delivery_origin is None and remote.delivery_origin is None
    assert not identity["external"] and remote["external"]
    with pytest.raises(TypeError, match="named RecipientResidence"):
        Recipient(residence="local")


def test_invalid_agent_selector_ends_with_roster_recovery_action():
    with pytest.raises(ValidationError) as refusal:
        _agent_uuid("not-an-agent-uuid")
    assert refusal.value.detail == (
        "Invalid agent_id format. Choose an agent_id from the team roster and retry."
    )
