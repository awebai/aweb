"""The typed log-key record uses the existing signer codec and custody port."""

import base64
from datetime import UTC, datetime

import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.e2ee_keys import encryption_key_id

from aweb_naapp.runtime.protected_signer import CatalogOperation, ProtectedKeyContext, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, authority_key, signing_bytes


def operation(**changes):
    public = base64.b64encode(bytes(range(32))).rstrip(b"=").decode()
    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    subject = {
        "team_id": context.authority_id,
        "key_id": encryption_key_id(public),
        "public_key": public,
        "created_at": "2026-11-12T00:00:00Z",
    }
    return CatalogOperation(
        "00000000-0000-4000-8000-000000000001",
        context,
        "https://signer.example.org",
        "team.log-key.sign",
        "default",
        {**subject, **changes},
    )


def test_log_key_is_a_closed_live_floor_family_and_keeps_its_original_record_time():
    from awid.log_key_record import log_key_record_signing_bytes

    op = operation()
    _, public = generate_keypair()
    key = did_from_public_key(public)
    artifact = artifact_for(op, key, datetime(2026, 11, 13, tzinfo=UTC))
    assert op.spec.needs_human
    assert authority_key(op, artifact) == key
    assert artifact == {"v": 1, **op.intent()["subject"], "team_key_did": key}
    assert artifact["created_at"] == "2026-11-12T00:00:00Z"
    assert "expires_at" not in artifact
    assert signing_bytes(op, artifact) == log_key_record_signing_bytes(artifact)
    for name, value in (
        ("team_id", "other:example.org"),
        ("public_key", "wrong"),
        ("created_at", "2026-11-13T00:00:00Z"),
        ("signature", "raw"),
    ):
        with pytest.raises(SignerRefused):
            signing_bytes(op, {**artifact, name: value})


def test_log_key_rejects_extra_private_material_and_wrong_scope_before_preparation():
    for extra in (
        {"private_key": "raw"},
        {"signing": "raw"},
        {"signature": "raw"},
        {"v": 1},
        {"team_key_did": "worker-selected"},
        {"team_id": "other:example.org"},
    ):
        with pytest.raises(SignerRefused):
            operation(**extra)
