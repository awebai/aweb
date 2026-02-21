"""Tests for aweb.signing — canonical JSON payload, Ed25519 signing and verification."""

import pytest

from aweb.did import did_from_public_key, generate_keypair
from aweb.signing import (
    SIGNED_FIELDS,
    VerifyResult,
    canonical_payload,
    sign_message,
    verify_signature,
)


@pytest.fixture
def keypair():
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    return private_key, public_key, did


class TestCanonicalPayload:
    def test_keys_sorted_lexicographically(self):
        fields = {"to": "bob", "from": "alice", "body": "hi"}
        payload = canonical_payload(fields)
        assert payload == b'{"body":"hi","from":"alice","to":"bob"}'

    def test_no_whitespace(self):
        fields = {"a": "1", "b": "2"}
        payload = canonical_payload(fields)
        assert b" " not in payload
        assert b"\n" not in payload

    def test_non_ascii_literal_utf8(self):
        """Non-ASCII characters must be literal UTF-8, not \\uXXXX escaped."""
        fields = {"body": "caf\u00e9"}
        payload = canonical_payload(fields)
        # Should contain the literal UTF-8 bytes for 'é', not '\\u00e9'
        assert "café".encode("utf-8") in payload
        assert b"\\u00e9" not in payload

    def test_empty_dict(self):
        assert canonical_payload({}) == b"{}"

    def test_only_signed_fields_included(self):
        """Transport fields should be stripped; only SIGNED_FIELDS kept."""
        fields = {
            "body": "hello",
            "from": "alice",
            "from_did": "did:key:z...",
            "subject": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "to": "bob",
            "to_did": "did:key:z...",
            "type": "mail",
            # Transport fields — should be excluded
            "signature": "abc",
            "signing_key_id": "did:key:z...",
            "server": "example.com",
            "rotation_announcement": "{}",
        }
        payload = canonical_payload(fields)
        import json

        parsed = json.loads(payload)
        assert set(parsed.keys()) == SIGNED_FIELDS
        assert "signature" not in parsed
        assert "signing_key_id" not in parsed
        assert "server" not in parsed
        assert "rotation_announcement" not in parsed


class TestSignedFields:
    def test_contains_exactly_eight_fields(self):
        assert len(SIGNED_FIELDS) == 8

    def test_expected_fields(self):
        expected = {"body", "from", "from_did", "subject", "timestamp", "to", "to_did", "type"}
        assert SIGNED_FIELDS == expected


class TestSignMessage:
    def test_returns_base64_no_padding(self, keypair):
        private_key, _, _ = keypair
        sig = sign_message(private_key, b"test payload")
        assert isinstance(sig, str)
        assert "=" not in sig

    def test_signature_is_nonempty(self, keypair):
        private_key, _, _ = keypair
        sig = sign_message(private_key, b"test")
        assert len(sig) > 0


class TestVerifySignature:
    def test_roundtrip_verified(self, keypair):
        private_key, _, did = keypair
        payload = b"test payload"
        sig = sign_message(private_key, payload)
        result = verify_signature(did, payload, sig)
        assert result == VerifyResult.VERIFIED

    def test_tampered_payload_fails(self, keypair):
        private_key, _, did = keypair
        sig = sign_message(private_key, b"original")
        result = verify_signature(did, b"tampered", sig)
        assert result == VerifyResult.FAILED

    def test_missing_did_unverified(self, keypair):
        private_key, _, _ = keypair
        sig = sign_message(private_key, b"test")
        result = verify_signature("", b"test", sig)
        assert result == VerifyResult.UNVERIFIED

    def test_missing_signature_unverified(self, keypair):
        _, _, did = keypair
        result = verify_signature(did, b"test", "")
        assert result == VerifyResult.UNVERIFIED

    def test_none_did_unverified(self):
        result = verify_signature(None, b"test", "somesig")
        assert result == VerifyResult.UNVERIFIED

    def test_none_signature_unverified(self, keypair):
        _, _, did = keypair
        result = verify_signature(did, b"test", None)
        assert result == VerifyResult.UNVERIFIED

    def test_invalid_did_format_unverified(self):
        result = verify_signature("did:web:example.com", b"test", "somesig")
        assert result == VerifyResult.UNVERIFIED

    def test_wrong_key_fails(self):
        priv1, _, _ = generate_keypair(), generate_keypair(), None
        priv1, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        did2 = did_from_public_key(pub2)
        sig = sign_message(priv1, b"test")
        result = verify_signature(did2, b"test", sig)
        assert result == VerifyResult.FAILED

    def test_corrupt_base64_signature_failed(self, keypair):
        _, _, did = keypair
        result = verify_signature(did, b"test", "not-valid-base64!!!")
        assert result == VerifyResult.FAILED
