package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

const didKeyPrefix = "did:key:z"

// The most base58 characters each DID's fixed decoded size can encode to: the
// length of that many 0xff bytes encoded. Longer text cannot be a valid DID,
// so it is refused on its length before the base58 decode, whose cost grows
// with the square of the input length. awid's Python did.py derives the same
// values.
const (
	// didKeyEncodedMax bounds a did:key suffix after "z": the 2-byte
	// multicodec 0xed01 and a 32-byte Ed25519 key, 34 bytes.
	didKeyEncodedMax = 47
	// stableIDBytes is the decoded size of a did:aw suffix.
	stableIDBytes = 20
	// stableIDEncodedMax bounds a did:aw suffix of stableIDBytes bytes.
	stableIDEncodedMax = 28
)

// ComputeDIDKey encodes an Ed25519 public key as a did:key DID string.
func ComputeDIDKey(pub ed25519.PublicKey) string {
	buf := make([]byte, 2+ed25519.PublicKeySize)
	buf[0] = 0xed
	buf[1] = 0x01
	copy(buf[2:], pub)
	return didKeyPrefix + base58.Encode(buf)
}

// ExtractPublicKey decodes a did:key DID string to an Ed25519 public key. A
// small-order, non-canonical or mixed-order key is refused: anyone can sign
// as one.
func ExtractPublicKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, fmt.Errorf("invalid did:key: missing prefix %q", didKeyPrefix)
	}

	encoded := did[len(didKeyPrefix):]
	if len(encoded) > didKeyEncodedMax {
		return nil, fmt.Errorf("invalid did:key: encoding must be at most %d characters, got %d", didKeyEncodedMax, len(encoded))
	}
	decoded, err := base58.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid did:key: base58 decode: %w", err)
	}

	expected := 2 + ed25519.PublicKeySize
	if len(decoded) != expected {
		return nil, fmt.Errorf("invalid did:key: expected %d bytes, got %d", expected, len(decoded))
	}

	if decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("invalid did:key: expected Ed25519 multicodec 0xed01, got 0x%02x%02x", decoded[0], decoded[1])
	}

	key := ed25519.PublicKey(decoded[2:])
	if !idCertificatePrimePoint(key) {
		return nil, fmt.Errorf("invalid did:key: not a canonical prime-order Ed25519 public key")
	}
	return key, nil
}

// DecodeStableID decodes the base58 suffix of a did:aw identifier to its
// stableIDBytes bytes.
func DecodeStableID(suffix string) ([]byte, error) {
	if len(suffix) > stableIDEncodedMax {
		return nil, fmt.Errorf("invalid did:aw: encoding must be at most %d characters, got %d", stableIDEncodedMax, len(suffix))
	}
	decoded, err := base58.Decode(suffix)
	if err != nil {
		return nil, fmt.Errorf("invalid did:aw: base58 decode: %w", err)
	}
	if len(decoded) != stableIDBytes {
		return nil, fmt.Errorf("invalid did:aw: expected %d bytes, got %d", stableIDBytes, len(decoded))
	}
	return decoded, nil
}

// ComputeStableID derives the canonical did:aw stable identifier from an
// Ed25519 public key. Algorithm: SHA-256 the 32-byte public key, take the
// first 20 bytes, base58btc encode.
func ComputeStableID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "did:aw:" + base58.Encode(h[:20])
}
