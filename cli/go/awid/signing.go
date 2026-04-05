package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AnnouncementMaxAge is the maximum age for rotation and replacement
// announcements. Announcements older than this are rejected to prevent
// replay attacks.
const AnnouncementMaxAge = 7 * 24 * time.Hour

// isTimestampFresh returns true if the timestamp is valid RFC3339 and
// within AnnouncementMaxAge of now.
func isTimestampFresh(ts string) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return false
		}
	}
	return time.Since(t).Abs() <= AnnouncementMaxAge
}

type VerificationStatus string

const (
	Verified          VerificationStatus = "verified"
	VerifiedCustodial VerificationStatus = "verified_custodial"
	Unverified        VerificationStatus = "unverified"
	Failed            VerificationStatus = "failed"
	IdentityMismatch  VerificationStatus = "identity_mismatch"
)

// RotationAnnouncement is attached to messages after key rotation.
// The old key signs the transition to the new key.
type RotationAnnouncement struct {
	OldDID          string `json:"old_did"`
	NewDID          string `json:"new_did"`
	Timestamp       string `json:"timestamp"`
	OldKeySignature string `json:"old_key_signature"`
}

// ReplacementAnnouncement is attached when a public address has been
// controller-authorized onto a fresh identity after loss or migration.
type ReplacementAnnouncement struct {
	Address             string `json:"address"`
	OldDID              string `json:"old_did"`
	NewDID              string `json:"new_did"`
	ControllerDID       string `json:"controller_did"`
	Timestamp           string `json:"timestamp"`
	ControllerSignature string `json:"controller_signature"`
}

// MessageEnvelope holds the fields used for signing and verification.
// Transport-only fields (Signature, SigningKeyID) are not part of the
// signed payload but are carried here for convenience.
type MessageEnvelope struct {
	From         string `json:"from"`
	FromDID      string `json:"from_did"`
	To           string `json:"to"`
	ToDID        string `json:"to_did"`
	Type         string `json:"type"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Timestamp    string `json:"timestamp"`
	FromStableID string `json:"from_stable_id,omitempty"`
	ToStableID   string `json:"to_stable_id,omitempty"`
	MessageID    string `json:"message_id,omitempty"`

	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
}

// SignMessage signs the canonical JSON payload of an envelope.
// Returns the signature as base64 (RFC 4648, no padding).
func SignMessage(key ed25519.PrivateKey, env *MessageEnvelope) (string, error) {
	payload := CanonicalJSON(env)
	sig := ed25519.Sign(key, []byte(payload))
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

// CanonicalJSONValue builds canonical JSON for an arbitrary JSON-compatible
// value. It is used for generic DIDKey-authenticated payload signing.
func CanonicalJSONValue(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SignArbitraryPayload signs a JSON object after injecting the required
// timestamp field into the signed payload.
func SignArbitraryPayload(key ed25519.PrivateKey, payload map[string]any, timestamp string) (didKey string, signature string, canonical string, err error) {
	if key == nil {
		return "", "", "", fmt.Errorf("signing key is required")
	}
	timestamp = strings.TrimSpace(timestamp)
	if timestamp == "" {
		return "", "", "", fmt.Errorf("timestamp is required")
	}
	if payload == nil {
		payload = map[string]any{}
	}
	if _, exists := payload["timestamp"]; exists {
		return "", "", "", fmt.Errorf("payload must not contain timestamp")
	}

	signedPayload := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		signedPayload[key] = value
	}
	signedPayload["timestamp"] = timestamp

	canonical, err = CanonicalJSONValue(signedPayload)
	if err != nil {
		return "", "", "", err
	}
	didKey = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(key, []byte(canonical))
	return didKey, base64.RawStdEncoding.EncodeToString(sig), canonical, nil
}

// VerifyMessage checks the signature on a message envelope.
// Returns Unverified if DID or signature is missing (legacy message).
// Returns Failed if the DID is malformed, the signature doesn't verify,
// or SigningKeyID disagrees with FromDID.
// Returns Verified if the signature is valid.
// Does not check TOFU pins or custody — callers handle those.
func VerifyMessage(env *MessageEnvelope) (VerificationStatus, error) {
	if env.FromDID == "" || env.Signature == "" {
		return Unverified, nil
	}

	// If SigningKeyID is present, it must match FromDID.
	if env.SigningKeyID != "" && env.SigningKeyID != env.FromDID {
		return Failed, fmt.Errorf("signing_key_id %q does not match from_did %q", env.SigningKeyID, env.FromDID)
	}

	// SOT §7 step 2: invalid did:key format → Unverified (not a did:key identity).
	// SOT §7 step 3: valid prefix but decode failure → Failed (malformed identity).
	if !strings.HasPrefix(env.FromDID, "did:key:z") {
		return Unverified, nil
	}
	pub, err := ExtractPublicKey(env.FromDID)
	if err != nil {
		return Failed, fmt.Errorf("extract public key from from_did: %w", err)
	}

	sig, err := base64.RawStdEncoding.DecodeString(env.Signature)
	if err != nil {
		return Failed, fmt.Errorf("decode signature: %w", err)
	}

	payload := CanonicalJSON(env)
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return Failed, nil
	}

	return Verified, nil
}

// VerifySignedPayload verifies a signature against a pre-computed canonical
// payload string. Use this when the server returns signed_payload alongside
// the message, avoiding reconstruction from display fields.
func VerifySignedPayload(signedPayload, signatureB64, fromDID, signingKeyID string) (VerificationStatus, error) {
	if fromDID == "" || signatureB64 == "" || signedPayload == "" {
		return Unverified, nil
	}

	if signingKeyID != "" && signingKeyID != fromDID {
		return Failed, fmt.Errorf("signing_key_id %q does not match from_did %q", signingKeyID, fromDID)
	}

	if !strings.HasPrefix(fromDID, "did:key:z") {
		return Unverified, nil
	}
	pub, err := ExtractPublicKey(fromDID)
	if err != nil {
		return Failed, fmt.Errorf("extract public key from from_did: %w", err)
	}

	sig, err := base64.RawStdEncoding.DecodeString(signatureB64)
	if err != nil {
		return Failed, fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(pub, []byte(signedPayload), sig) {
		return Failed, nil
	}

	return Verified, nil
}

// CanonicalReplacementJSON builds the canonical JSON for controller-authorized
// address replacement signing.
func CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp string) string {
	type field struct {
		key   string
		value string
	}
	fields := []field{
		{"address", address},
		{"controller_did", controllerDID},
		{"new_did", newDID},
		{"old_did", oldDID},
		{"timestamp", timestamp},
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].key < fields[j].key })

	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(f.key)
		b.WriteString(`":"`)
		writeEscapedString(&b, f.value)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// VerifyReplacementSignature verifies a controller-authorized replacement announcement.
func VerifyReplacementSignature(controllerPub ed25519.PublicKey, address, controllerDID, oldDID, newDID, timestamp, signature string) (bool, error) {
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	payload := CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp)
	return ed25519.Verify(controllerPub, []byte(payload), sig), nil
}

// CanonicalJSON builds the canonical JSON payload for message signing.
// Fields are sorted lexicographically, no whitespace, minimal escaping.
// Optional fields (from_stable_id, message_id, to_stable_id) are omitted when empty.
// See also LogEntry.CanonicalJSON which always includes all fields with null for absent values.
func CanonicalJSON(env *MessageEnvelope) string {
	type field struct {
		key   string
		value string
	}

	// Always-present signed fields.
	fields := []field{
		{"body", env.Body},
		{"from", env.From},
		{"from_did", env.FromDID},
		{"subject", env.Subject},
		{"timestamp", env.Timestamp},
		{"to", env.To},
		{"to_did", env.ToDID},
		{"type", env.Type},
	}

	// Optional fields included when present.
	if env.FromStableID != "" {
		fields = append(fields, field{"from_stable_id", env.FromStableID})
	}
	if env.MessageID != "" {
		fields = append(fields, field{"message_id", env.MessageID})
	}
	if env.ToStableID != "" {
		fields = append(fields, field{"to_stable_id", env.ToStableID})
	}

	sort.Slice(fields, func(i, j int) bool { return fields[i].key < fields[j].key })

	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(f.key)
		b.WriteString(`":"`)
		writeEscapedString(&b, f.value)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// writeEscapedString writes a JSON-escaped string value (without surrounding quotes).
func writeEscapedString(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
}
