package awid

import (
	"crypto/ed25519"
	"fmt"
)

// DetachedSignature binds raw payload bytes to a caller-selected public key.
// Selecting that key's authority remains the caller's responsibility.
type DetachedSignature struct {
	PublicKey ed25519.PublicKey
	Signature []byte
	Payload   []byte
}

// VerifyDetachedSignature shares the strict Ed25519 primitive used for ID
// certificates (id_certificates.go:309-333), without interpreting the payload
// or consulting identity or controller authority. Release verification uses it
// with the public key pinned by docs/install-integrity.md:34-39.
func VerifyDetachedSignature(signature DetachedSignature) error {
	if len(signature.PublicKey) != ed25519.PublicKeySize || !idCertificatePrimePoint(signature.PublicKey) {
		return fmt.Errorf("invalid Ed25519 public key")
	}
	return idStrictVerify(ComputeDIDKey(signature.PublicKey), signature.Signature, func() ([]byte, error) { return signature.Payload, nil })
}
