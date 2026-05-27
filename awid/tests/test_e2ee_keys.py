from __future__ import annotations

from datetime import datetime, timezone

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.e2ee_keys import (
    ENCRYPTION_KEY_CUSTODY_HOSTED,
    ENCRYPTION_KEY_CUSTODY_SELF,
    build_encryption_key_assertion,
    validate_encryption_key_assertion,
)


def test_build_encryption_key_assertion_signs_self_custody():
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)

    assertion = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did,
        identity_stable_id=None,
        encryption_public_key=b"\x01" * 32,
        now=now,
    )

    assert assertion["custody"] == ENCRYPTION_KEY_CUSTODY_SELF
    validate_encryption_key_assertion(
        assertion,
        current_did_key=did,
        stable_id=None,
        now=now,
        expected_custody=ENCRYPTION_KEY_CUSTODY_SELF,
    )


def test_validate_encryption_key_assertion_requires_expected_hosted_custody():
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)

    assertion = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did,
        identity_stable_id=None,
        encryption_public_key=b"\x01" * 32,
        now=now,
    )

    with pytest.raises(ValueError, match="hosted custodial"):
        validate_encryption_key_assertion(
            assertion,
            current_did_key=did,
            stable_id=None,
            now=now,
            expected_custody=ENCRYPTION_KEY_CUSTODY_HOSTED,
        )

    hosted = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did,
        identity_stable_id=None,
        encryption_public_key=b"\x02" * 32,
        custody=ENCRYPTION_KEY_CUSTODY_HOSTED,
        now=now,
    )
    validate_encryption_key_assertion(
        hosted,
        current_did_key=did,
        stable_id=None,
        now=now,
        expected_custody=ENCRYPTION_KEY_CUSTODY_HOSTED,
    )


def test_validate_encryption_key_assertion_rejects_stripped_hosted_custody():
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)
    hosted = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did,
        identity_stable_id=None,
        encryption_public_key=b"\x01" * 32,
        custody=ENCRYPTION_KEY_CUSTODY_HOSTED,
        now=now,
    )

    stripped = dict(hosted)
    del stripped["custody"]
    with pytest.raises(ValueError, match="hosted custodial"):
        validate_encryption_key_assertion(
            stripped,
            current_did_key=did,
            stable_id=None,
            now=now,
            expected_custody=ENCRYPTION_KEY_CUSTODY_HOSTED,
        )
    with pytest.raises(ValueError, match="invalid signature"):
        validate_encryption_key_assertion(
            stripped,
            current_did_key=did,
            stable_id=None,
            now=now,
        )
