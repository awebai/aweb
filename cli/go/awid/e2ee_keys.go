package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	EncryptionKeyAssertionVersion = "aweb-e2ee-key-v1"
	EncryptionKeyAlgorithmX25519  = "x25519"
)

// EncryptionKeyAssertion is the identity-signed public assertion distributed by
// AWID and used by senders to encrypt E2E message content keys. The registry is
// only a distributor; clients must verify the assertion against the identity's
// current signing did:key before use.
type EncryptionKeyAssertion struct {
	Operation               string  `json:"operation"`
	Version                 string  `json:"version"`
	IdentityDID             string  `json:"identity_did"`
	IdentityStableID        *string `json:"identity_stable_id,omitempty"`
	EncryptionKeyID         string  `json:"encryption_key_id"`
	EncryptionPublicKey     string  `json:"encryption_public_key"`
	Algorithm               string  `json:"algorithm"`
	CreatedAt               string  `json:"created_at"`
	NotBefore               string  `json:"not_before"`
	ExpiresAt               string  `json:"expires_at"`
	PreviousEncryptionKeyID *string `json:"previous_encryption_key_id,omitempty"`
	Signature               string  `json:"signature"`
}

// ComputeEncryptionKeyID returns the contract key id for a raw 32-byte X25519
// public key.
func ComputeEncryptionKeyID(rawPublicKey []byte) (string, error) {
	if len(rawPublicKey) != 32 {
		return "", fmt.Errorf("encryption public key must be 32 bytes, got %d", len(rawPublicKey))
	}
	sum := sha256.Sum256(append([]byte("aweb-e2ee-v2 encryption-key\n"), rawPublicKey...))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func encryptionAssertionSignedPayload(assertion *EncryptionKeyAssertion) (string, error) {
	if assertion == nil {
		return "", fmt.Errorf("missing encryption key assertion")
	}
	payload := map[string]any{
		"operation":             assertion.Operation,
		"version":               assertion.Version,
		"identity_did":          assertion.IdentityDID,
		"encryption_key_id":     assertion.EncryptionKeyID,
		"encryption_public_key": assertion.EncryptionPublicKey,
		"algorithm":             assertion.Algorithm,
		"created_at":            assertion.CreatedAt,
		"not_before":            assertion.NotBefore,
		"expires_at":            assertion.ExpiresAt,
	}
	if assertion.IdentityStableID != nil {
		payload["identity_stable_id"] = strings.TrimSpace(*assertion.IdentityStableID)
	}
	if assertion.PreviousEncryptionKeyID != nil && strings.TrimSpace(*assertion.PreviousEncryptionKeyID) != "" {
		payload["previous_encryption_key_id"] = strings.TrimSpace(*assertion.PreviousEncryptionKeyID)
	}
	return CanonicalJSONValue(payload)
}

// VerifyEncryptionKeyAssertion verifies the identity-authorized encryption key
// assertion against the current identity signing did:key and stable id.
func VerifyEncryptionKeyAssertion(assertion *EncryptionKeyAssertion, currentDIDKey, stableID string, now time.Time) error {
	if assertion == nil {
		return fmt.Errorf("missing encryption key assertion")
	}
	if assertion.Operation != "publish_encryption_key" {
		return fmt.Errorf("encryption key assertion operation=%q", assertion.Operation)
	}
	if assertion.Version != EncryptionKeyAssertionVersion {
		return fmt.Errorf("unsupported encryption key assertion version %q", assertion.Version)
	}
	if assertion.Algorithm != EncryptionKeyAlgorithmX25519 {
		return fmt.Errorf("unsupported encryption key algorithm %q", assertion.Algorithm)
	}
	currentDIDKey = strings.TrimSpace(currentDIDKey)
	if assertion.IdentityDID != currentDIDKey {
		return fmt.Errorf("encryption key assertion identity_did does not match current did:key")
	}
	if strings.TrimSpace(stableID) != "" {
		if assertion.IdentityStableID == nil || strings.TrimSpace(*assertion.IdentityStableID) != strings.TrimSpace(stableID) {
			return fmt.Errorf("encryption key assertion identity_stable_id does not match did:aw")
		}
	} else if assertion.IdentityStableID != nil {
		return fmt.Errorf("local encryption key assertions must omit identity_stable_id")
	}
	rawPub, err := base64.RawStdEncoding.DecodeString(assertion.EncryptionPublicKey)
	if err != nil {
		return fmt.Errorf("decode encryption_public_key: %w", err)
	}
	expectedKeyID, err := ComputeEncryptionKeyID(rawPub)
	if err != nil {
		return err
	}
	if assertion.EncryptionKeyID != expectedKeyID {
		return fmt.Errorf("encryption_key_id does not match encryption_public_key")
	}
	notBefore, err := parseContractTime(assertion.NotBefore)
	if err != nil {
		return fmt.Errorf("invalid not_before: %w", err)
	}
	expiresAt, err := parseContractTime(assertion.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expires_at: %w", err)
	}
	createdAt, err := parseContractTime(assertion.CreatedAt)
	if err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	if !expiresAt.After(notBefore) {
		return fmt.Errorf("expires_at must be after not_before")
	}
	if !now.IsZero() {
		if createdAt.After(now) {
			return fmt.Errorf("created_at must not be in the future")
		}
		if notBefore.After(now) {
			return fmt.Errorf("encryption key assertion is not active yet")
		}
		if !expiresAt.After(now) {
			return fmt.Errorf("encryption key assertion is expired")
		}
	}
	payload, err := encryptionAssertionSignedPayload(assertion)
	if err != nil {
		return err
	}
	pub, err := ExtractPublicKey(currentDIDKey)
	if err != nil {
		return fmt.Errorf("extract current did:key: %w", err)
	}
	sig, err := base64.RawStdEncoding.DecodeString(assertion.Signature)
	if err != nil {
		return fmt.Errorf("decode encryption key assertion signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return fmt.Errorf("invalid encryption key assertion signature")
	}
	return nil
}

func parseContractTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}
