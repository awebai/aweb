"""Tests for aweb.did — Ed25519 keypair generation and did:key encoding."""

import base58 as b58
import pytest

from aweb.did import (
    did_from_public_key,
    generate_keypair,
    public_key_from_did,
    validate_did,
)

# Test vector from clawdid/sot.md §2.2: Ed25519 public key (all-zeros seed),
# multicodec 0xed01 + base58btc encoded.
TEST_VECTOR_PUBLIC_KEY_HEX = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
TEST_VECTOR_DID = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"


class TestGenerateKeypair:
    def test_returns_private_and_public_key(self):
        private_key, public_key = generate_keypair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)

    def test_public_key_is_32_bytes(self):
        _, public_key = generate_keypair()
        assert len(public_key) == 32

    def test_private_key_is_32_bytes(self):
        private_key, _ = generate_keypair()
        assert len(private_key) == 32

    def test_keypairs_are_unique(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1 != pub2


class TestDidFromPublicKey:
    def test_known_vector(self):
        public_key = bytes.fromhex(TEST_VECTOR_PUBLIC_KEY_HEX)
        did = did_from_public_key(public_key)
        assert did == TEST_VECTOR_DID

    def test_starts_with_did_key_z(self):
        _, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        assert did.startswith("did:key:z")

    def test_rejects_wrong_length_key(self):
        with pytest.raises(ValueError):
            did_from_public_key(b"")

        with pytest.raises(ValueError):
            did_from_public_key(b"\x00" * 31)

        with pytest.raises(ValueError):
            did_from_public_key(b"\x00" * 33)


class TestPublicKeyFromDid:
    def test_known_vector_roundtrip(self):
        expected = bytes.fromhex(TEST_VECTOR_PUBLIC_KEY_HEX)
        result = public_key_from_did(TEST_VECTOR_DID)
        assert result == expected

    def test_roundtrip_generated_key(self):
        _, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        recovered = public_key_from_did(did)
        assert recovered == public_key

    def test_wrong_prefix(self):
        with pytest.raises(ValueError, match="did:key:z"):
            public_key_from_did("did:web:example.com")

    def test_truncated_did(self):
        with pytest.raises(ValueError):
            public_key_from_did("did:key:z6Mk")

    def test_bad_multicodec(self):
        """A DID with wrong multicodec prefix should raise."""
        bad_prefix = b"\xec\x01" + bytes.fromhex(TEST_VECTOR_PUBLIC_KEY_HEX)
        bad_did = "did:key:z" + b58.b58encode(bad_prefix).decode("ascii")
        with pytest.raises(ValueError, match="multicodec"):
            public_key_from_did(bad_did)

    def test_invalid_base58_characters(self):
        """Characters outside the base58btc alphabet should raise."""
        with pytest.raises(ValueError):
            public_key_from_did("did:key:z0OIl")


class TestValidateDid:
    def test_valid_did(self):
        assert validate_did(TEST_VECTOR_DID) is True

    def test_generated_did(self):
        _, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        assert validate_did(did) is True

    def test_wrong_prefix(self):
        assert validate_did("did:web:example.com") is False

    def test_truncated(self):
        assert validate_did("did:key:z6Mk") is False

    def test_empty_string(self):
        assert validate_did("") is False

    def test_bad_multicodec(self):
        bad_prefix = b"\xec\x01" + bytes.fromhex(TEST_VECTOR_PUBLIC_KEY_HEX)
        bad_did = "did:key:z" + b58.b58encode(bad_prefix).decode("ascii")
        assert validate_did(bad_did) is False

    def test_invalid_base58_characters(self):
        assert validate_did("did:key:z0OIl") is False
