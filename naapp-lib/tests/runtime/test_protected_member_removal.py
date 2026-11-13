"""Removal codecs use AWID's existing revoke route; no authority is granted."""

import hashlib
from types import SimpleNamespace
from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, SignerRefused
from aweb_naapp.runtime.protected_signer.removal import (
    removal_artifact,
    removal_signing_bytes,
    validate_removal_subject,
)


def identity():
    _, public = generate_keypair()
    return stable_id_from_public_key(public), did_from_public_key(public)


ROOT, ROOTKEY = identity()
HUMAN, CONTROLLER = identity()
MEMBER, MEMBERKEY = identity()
TEAM, DOMAIN, ORIGIN = "engineering:customer.example", "customer.example", "https://registry.customer.example"
STAMP = "2026-11-13T12:00:00Z"


def subject(*, local=True, actor=ROOT):
    return {"team_id": TEAM, "root_id_or_self": actor, "member_id": MEMBERKEY if local else MEMBER,
        "certificate_id": str(uuid4()), "expected_membership": {
            "member_did_key": MEMBERKEY, "member_did_aw": None if local else MEMBER,
            "member_address": None, "alias": "worker", "identity_scope": "local" if local else "global"}}


def operation(fields):
    return SimpleNamespace(context=ProtectedKeyContext("customer-signer", "team_controller", TEAM, DOMAIN, HUMAN, DOMAIN, 1),
        audience=ORIGIN, intent=lambda: {"subject": fields})


@pytest.mark.parametrize("local", [True, False])
@pytest.mark.parametrize("actor", [ROOT, "self"])
def test_remove_binds_exact_existing_membership_and_registry_revoke(local, actor):
    fields = subject(local=local, actor=actor)
    assert validate_removal_subject(fields) == fields
    op = operation(fields)
    artifact = removal_artifact(op, CONTROLLER, STAMP)
    body = canonical_json_bytes({"certificate_id": fields["certificate_id"]})
    expected = {"v": 2, "type": "aweb.awid-controller-request", "aud": ORIGIN, "method": "POST",
        "path": "/v1/namespaces/customer.example/teams/engineering/certificates/revoke",
        "domain": DOMAIN, "operation": "revoke_certificate", "team_name": "engineering",
        "certificate_id": fields["certificate_id"], "timestamp": STAMP,
        "body_sha256": hashlib.sha256(body).hexdigest()}
    assert artifact == {"controller_did": CONTROLLER, "request": expected}
    assert removal_signing_bytes(op, artifact) == canonical_json_bytes(expected)


@pytest.mark.parametrize("changes", [
    {"root_id_or_self": MEMBERKEY}, {"root_id_or_self": "descendant"},
    {"member_id": ROOT}, {"certificate_id": "not-a-uuid"},
    {"certificate_id": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"},
    {"role": "admin"}, {"team_id": "another:customer.example"},
])
def test_refuse_wrong_subject_or_scope(changes):
    fields = {**subject(), **changes}
    with pytest.raises((ValueError, SignerRefused)):
        removal_artifact(operation(fields), CONTROLLER, STAMP)


@pytest.mark.parametrize("changes", [
    {"member_did_aw": MEMBER}, {"member_address": "customer.example/worker"},
    {"identity_scope": "human"}, {"member_did_key": ROOT},
    {"role": "member"}, {"alias": ""},
])
def test_expected_membership_is_closed_and_retains_local_subject(changes):
    fields = subject()
    fields["expected_membership"].update(changes)
    with pytest.raises((ValueError, SignerRefused)):
        validate_removal_subject(fields)


@pytest.mark.parametrize("member", ["controller_did", "request"])
def test_no_mutated_controller_or_registry_request_can_be_signed(member):
    fields = subject()
    op = operation(fields)
    artifact = removal_artifact(op, CONTROLLER, STAMP)
    if member == "controller_did":
        artifact[member] = "bad-did"
    else:
        artifact[member]["certificate_id"] = str(uuid4())
    with pytest.raises((ValueError, SignerRefused)):
        removal_signing_bytes(op, artifact)


def test_expected_membership_is_snapshotted_without_any_authority_claim():
    fields = subject()
    retained = validate_removal_subject(fields)
    fields["expected_membership"]["alias"] = "changed"
    assert retained["expected_membership"]["alias"] == "worker"
