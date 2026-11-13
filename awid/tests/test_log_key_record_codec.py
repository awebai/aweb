"""Public-only log-key record bytes, matching the existing Go consumer."""

import base64

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.e2ee_keys import encryption_key_id


def subject():
    public_key = base64.b64encode(bytes(range(32))).rstrip(b"=").decode()
    return {
        "team_id": "demo:example.org",
        "key_id": encryption_key_id(public_key),
        "public_key": public_key,
        "created_at": "2026-11-12T00:00:00Z",
    }


def test_log_key_record_has_only_the_existing_six_prefixed_fields():
    from awid.log_key_record import build_log_key_record, log_key_record_signing_bytes
    from awid.signing import canonical_json_bytes

    _, public = generate_keypair()
    key = did_from_public_key(public)
    fields = {"v": 1, **subject(), "team_key_did": key}
    assert build_log_key_record(subject(), key) == fields
    assert log_key_record_signing_bytes(
        fields
    ) == b"aweb.log-key/1\n" + canonical_json_bytes(fields)
    assert "signature" not in fields


@pytest.mark.parametrize(
    "field,value",
    [
        ("public_key", "A" * 42),
        ("public_key", base64.b64encode(bytes(range(32))).decode()),
        ("public_key", " " + base64.b64encode(bytes(range(32))).rstrip(b"=").decode()),
        ("key_id", "sha256:wrong"),
        ("created_at", "2026-11-12T00:00:00.000Z"),
        ("created_at", "2026-11-12T00:00:00+00:00"),
        ("team_id", " Demo:example.org "),
    ],
)
def test_log_key_subject_refuses_inconsistent_or_noncanonical_values(field, value):
    from awid.log_key_record import validate_log_key_subject

    with pytest.raises(ValueError):
        validate_log_key_subject({**subject(), field: value})


def test_no_private_key_signature_raw_bytes_or_unknown_version_can_enter_the_codec():
    from awid.log_key_record import (
        build_log_key_record,
        log_key_record_signing_bytes,
        validate_log_key_subject,
    )

    for name in ("private_key", "signing", "signature", "team_key_did", "v"):
        with pytest.raises(ValueError):
            validate_log_key_subject({**subject(), name: "extra"})
    _, public = generate_keypair()
    fields = build_log_key_record(subject(), did_from_public_key(public))
    for changed in (
        {**fields, "v": True},
        {**fields, "v": 2},
        {**fields, "signature": "extra"},
        {**fields, "team_key_did": "did:key:invalid"},
        {**fields, "team_key_did": None},
        {**fields, "team_key_did": True},
    ):
        with pytest.raises(ValueError):
            log_key_record_signing_bytes(changed)
