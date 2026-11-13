"""OATS artifacts retain the existing ID and membership consumer encodings."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.id_certificates import id_certificate_signing_bytes
from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.protected_signer import CatalogOperation, ProtectedKeyContext, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, authority_key, signing_bytes


def identity():
    _, public = generate_keypair()
    return stable_id_from_public_key(public), did_from_public_key(public)


H, HKEY = identity()
ROOT, ROOTKEY = identity()
CHILD, CHILDKEY = identity()
DOMAIN, TEAM, SERVICE = "customer.example", "engineering:customer.example", "customer-signer"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


def operation(name, *, subject=None):
    if name == "identity.root.endorse":
        context = ProtectedKeyContext(SERVICE, "human_identity", H, DOMAIN, H, DOMAIN, 1)
        fields = {"domain": DOMAIN, "root_id": ROOT, "root_key": ROOTKEY, "teams": [TEAM], "deployment_label": "deployment"}
    else:
        context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, H, DOMAIN, 1)
        fields = {"team_id": TEAM, "root_id": ROOT, "root_key": ROOTKEY, "child_id": CHILD,
            "child_key": CHILDKEY, "member_alias": "agent-one", "admission_policy_digest": "sha256:"+"a"*64,
            "expected_policy_version": 1}
    return CatalogOperation(str(uuid4()), context, "https://registry.customer.example", name, "default", fields if subject is None else subject)


def test_root_endorsement_uses_the_existing_id_certificate_without_an_extra_root_key_field():
    op = operation("identity.root.endorse")
    artifact = artifact_for(op, HKEY, NOW)
    assert artifact == {"v": 1, "type": "aweb.id-certificate", "id": ROOT, "domain": DOMAIN,
        "parent": {"kind": "identity", "id": H}, "kind": "agent", "issuer_key": HKEY,
        "issued_at": "2026-11-13T12:00:00Z"}
    assert signing_bytes(op, artifact) == id_certificate_signing_bytes(artifact)
    assert authority_key(op, artifact) == HKEY


@pytest.mark.parametrize("local", [True, False])
def test_root_admission_uses_existing_unsigned_team_certificate_fields_without_a_prefix(local):
    op = operation("team.agent.admit")
    if local:
        op = operation("team.agent.admit", subject={**op.intent()["subject"], "child_id": None})
    artifact = artifact_for(op, HKEY, NOW)
    assert set(artifact) == {"version", "certificate_id", "team_id", "team_did_key", "member_did_key", "alias", "identity_scope", "issued_at"} | (set() if local else {"member_did_aw"})
    assert artifact["identity_scope"] == ("local" if local else "global")
    assert artifact["member_did_key"] == CHILDKEY and artifact["alias"] == "agent-one"
    assert artifact.get("member_did_aw") == (None if local else CHILD)
    assert signing_bytes(op, artifact) == canonical_json_bytes(artifact)
    assert authority_key(op, artifact) == HKEY


@pytest.mark.parametrize("name,changed", [
    ("identity.root.endorse", {"root_id": ROOTKEY}),
    ("identity.root.endorse", {"teams": []}),
    ("identity.root.endorse", {"teams": [TEAM, TEAM]}),
    ("identity.root.endorse", {"parent": {"kind": "namespace", "id": DOMAIN}}),
    ("identity.root.endorse", {"domain": "Customer.example"}),
    ("team.agent.admit", {"child_id": CHILDKEY}),
    ("team.agent.admit", {"child_key": CHILD}),
    ("team.agent.admit", {"root_id": ROOTKEY}),
    ("team.agent.admit", {"expected_policy_version": True}),
    ("team.agent.admit", {"admission_policy_digest": "sha256:"+"A"*64}),
    ("team.agent.admit", {"admin": True}),
    ("team.agent.admit", {"member_alias": "bad\nname"}),
])
def test_artifact_inputs_are_closed_typed_subjects(name, changed):
    subject = operation(name).intent()["subject"]
    with pytest.raises(SignerRefused, match="request_invalid"):
        operation(name, subject={**subject, **changed})


@pytest.mark.parametrize("name", ["identity.root.endorse", "team.agent.admit"])
@pytest.mark.parametrize("changed", ["subject", "key", "extra", "timestamp"])
def test_a_retained_artifact_cannot_change_its_frozen_fields(name, changed):
    op = operation(name)
    artifact = artifact_for(op, HKEY, NOW)
    if changed == "subject":
        artifact["id" if name.startswith("identity") else "member_did_key"] = H
    elif changed == "key":
        artifact["issuer_key" if name.startswith("identity") else "team_did_key"] = "bad-key"
    elif changed == "extra":
        artifact["roles"] = ["admin"]
    else:
        artifact["issued_at"] = "not-a-timestamp"
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        signing_bytes(op, artifact)
