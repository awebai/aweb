// Package signaturewire owns Ed25519 signing and verification for wire artifacts.
// Callers construct the purpose-specific signed bytes and establish authority;
// a successful signature check alone never establishes membership or custody.
package signaturewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"filippo.io/edwards25519"
)

// SignBytes signs the exact bytes presented by a typed artifact builder.
func SignBytes(key ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(key, payload)
}

// SignStd emits the released message/request signature encoding.
func SignStd(key ed25519.PrivateKey, payload []byte) string {
	return base64.RawStdEncoding.EncodeToString(SignBytes(key, payload))
}

// SignURL emits the encoding required by URL-alphabet artifact families.
func SignURL(key ed25519.PrivateKey, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(SignBytes(key, payload))
}

// Proof contains exact verification inputs (docs/signature-primitives.md:13-18). Artifact
// families such as ID certificates additionally check their frozen R/S profile
// before this call. Decoding and authority are separate from this operation.
type Proof struct {
	PublicKey ed25519.PublicKey
	Payload   []byte
	Signature []byte
}

// Verify applies the shared Ed25519 rule; it performs no authority lookup.
func Verify(proof Proof) bool {
	key, payload, signature := proof.PublicKey, proof.Payload, proof.Signature
	// R13 ruling beb23450-5400-473e-9651-0e25bfb649f9: the identity/small-order
	// R case now refuses in every runtime. Ordinary generated signatures do not
	// use such points; ID artifacts retain their additional prime-order checks.
	if !PrimePoint(key) || len(signature) != ed25519.SignatureSize {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(signature[:32])
	if err != nil || new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	return ed25519.Verify(key, payload, signature)
}

// Decoder profiles retain each released family's alphabet and unused-bit rule.
func DecodeStd(value string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(value) }
func DecodeStdStrict(value string) ([]byte, error) {
	return base64.RawStdEncoding.Strict().DecodeString(value)
}
func DecodeURL(value string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(value) }
func DecodeURLStrict(value string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(value)
}
func DecodeCanonicalURL(value string) ([]byte, error) {
	raw, err := DecodeURLStrict(value)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("noncanonical base64url")
	}
	return raw, nil
}

func PrimePoint(raw []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil || !bytes.Equal(p.Bytes(), raw) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	eight := [32]byte{8}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(eight[:])
	if err != nil {
		return false
	}
	inv := new(edwards25519.Scalar).Invert(s)
	q := new(edwards25519.Point).MultByCofactor(p)
	return q.ScalarMult(inv, q).Equal(p) == 1
}

// ValidIDSignatureShape applies the frozen stricter ID-family R/S profile.
func ValidIDSignatureShape(signature []byte) bool {
	if len(signature) != ed25519.SignatureSize || !PrimePoint(signature[:32]) {
		return false
	}
	_, err := new(edwards25519.Scalar).SetCanonicalBytes(signature[32:])
	return err == nil
}
