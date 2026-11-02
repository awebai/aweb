package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

const didKeyPrefix = "did:key:z"

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

	decoded, err := base58.Decode(did[len(didKeyPrefix):])
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

// ComputeStableID derives the canonical did:aw stable identifier from an
// Ed25519 public key. Algorithm: SHA-256 the 32-byte public key, take the
// first 20 bytes, base58btc encode.
func ComputeStableID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "did:aw:" + base58.Encode(h[:20])
}
