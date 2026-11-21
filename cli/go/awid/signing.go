package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/awebai/aw/canonicaljson"
	"github.com/awebai/aw/signaturewire"
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
	VerifiedLegacy    VerificationStatus = "verified_legacy"
	VerifiedCustodial VerificationStatus = "verified_custodial"
	Unverified        VerificationStatus = "unverified"
	Failed            VerificationStatus = "failed"
	VerificationStale VerificationStatus = "verification_stale"
	IdentityMismatch  VerificationStatus = "identity_mismatch"
)

// Trusted reports a successful sender verification result. Specific protocols
// can still require stronger binding. See docs/receiving-events.md,
// “Autonomous message presentation”.
func (status VerificationStatus) Trusted() bool {
	return status == Verified || status == VerifiedLegacy || status == VerifiedCustodial
}

// WithholdsMessageContent reports whether an autonomous notice may include the
// durable message's subject and body. Explicit CLI reads keep the original.
func (status VerificationStatus) WithholdsMessageContent() bool {
	return status == Failed || status == IdentityMismatch
}

func SignedPayloadConversationStatus(signedPayload, conversationID string) VerificationStatus {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return Verified
	}
	var payload struct {
		ConversationID string `json:"conversation_id"`
	}
	if err := json.Unmarshal([]byte(signedPayload), &payload); err != nil {
		return Failed
	}
	if payload.ConversationID == conversationID {
		return Verified
	}
	if strings.TrimSpace(payload.ConversationID) == "" {
		return VerifiedLegacy
	}
	return Failed
}

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
	From           string `json:"from"`
	FromDID        string `json:"from_did"`
	To             string `json:"to"`
	ToDID          string `json:"to_did"`
	Type           string `json:"type"`
	Priority       string `json:"priority,omitempty"`
	WaitSeconds    *int   `json:"wait_seconds,omitempty"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	Timestamp      string `json:"timestamp"`
	FromStableID   string `json:"from_stable_id,omitempty"`
	ToStableID     string `json:"to_stable_id,omitempty"`
	MessageID      string `json:"message_id,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	ReplyTo        string `json:"reply_to,omitempty"`
	SenderLeaving  bool   `json:"sender_leaving,omitempty"`
	HangOn         bool   `json:"hang_on,omitempty"`

	RequireRecipientBinding       bool `json:"-"`
	AllowStoredRouteGlobalBinding bool `json:"-"`

	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
}

// SignMessage signs the canonical JSON payload of an envelope.
// Returns the signature as base64 (RFC 4648, no padding).
func SignMessage(key ed25519.PrivateKey, env *MessageEnvelope) (string, error) {
	payload := CanonicalJSON(env)
	sig := signaturewire.SignBytes(key, []byte(payload))
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

// CanonicalJSONValue builds canonical JSON for an arbitrary JSON-compatible
// value. It is the general serializer for bytes that are signed or hashed and
// then verified by another implementation: map keys sorted by code point, no
// insignificant whitespace, and strings escaped exactly as Python's
// canonical_json_bytes does on the awid / verifier sides, which call
// json.dumps(..., sort_keys=True, ensure_ascii=False, separators=(",", ":")).
// The shared canonical JSON vector under docs/vectors pins the bytes for all
// implementations. Among its callers is generic DIDKey-authenticated payload
// signing on the aw id sign / aw id request code path.
//
// HTML escaping is explicitly disabled via json.Encoder.SetEscapeHTML(false).
// Go's default json.Marshal would escape <, >, and & to \u003c, \u003e,
// \u0026; any signed payload containing those chars (common in free-form user
// notes and URLs) would silently fail signature verification across
// languages. Go's encoder does NOT escape non-ASCII by default, with two
// exceptions: it writes U+2028 and U+2029 as six-character escapes even with
// HTML escaping disabled. Python writes them as UTF-8, so this function does
// too (rawLineSeparators). Other unicode is tested by
// TestCanonicalJSONValuePreservesUnicode.
//
// This matches the shared onboardingDIDKeySignPayload helper used by the
// onboarding signing family (cli-signup, claim-human).
//
// Struct fields are written in declaration order, so callers pass maps.
func CanonicalJSONValue(v any) (string, error) { return canonicaljson.Marshal(v) }

// CanonicalJSONValueEscapingLineSeparators is CanonicalJSONValue except that
// U+2028 and U+2029 are written as the six-character escapes encoding/json
// produces. It serves digests that only aw computes and that an aw of another
// build, or a record it stored, must reproduce: custody request digests and
// proofs, A2A card digests, blueprint payload digests and the stored hosted
// creation response. Bytes that a Python or TypeScript verifier rebuilds use
// CanonicalJSONValue.
func CanonicalJSONValueEscapingLineSeparators(v any) (string, error) {
	return canonicaljson.MarshalDigest(v)
}

const (
	escapedLineSeparator      = "\\u2028"
	escapedParagraphSeparator = "\\u2029"
)

// rawLineSeparators replaces the escapes encoding/json writes for U+2028 and
// U+2029 with the characters' UTF-8 bytes. It walks complete escape tokens,
// so an escaped reverse solidus followed by the text u2028 stays unchanged.
func rawLineSeparators(v string) string { return canonicaljson.RawLineSeparators(v) }

type AppEmitCredential struct {
	DIDKey              string
	SignatureB64        string
	CanonicalPayload    string
	SignedPayloadB64URL string
	BodySHA256          string
	Headers             http.Header
}

func SignAppEmitCredential(key ed25519.PrivateKey, method string, target *url.URL, teamID, appID, keyID string, body []byte, timestamp string) (*AppEmitCredential, error) {
	if key == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if target == nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	teamID = strings.TrimSpace(teamID)
	appID = strings.TrimSpace(appID)
	keyID = strings.TrimSpace(keyID)
	if teamID == "" {
		return nil, fmt.Errorf("team_id is required")
	}
	if appID == "" {
		return nil, fmt.Errorf("app_id is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	bodyHashBytes := sha256.Sum256(body)
	bodyHash := fmt.Sprintf("%x", bodyHashBytes)
	didKey := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	payload := map[string]any{
		"v":           1,
		"auth":        "app-event",
		"aud":         target.Scheme + "://" + target.Host,
		"method":      strings.ToUpper(strings.TrimSpace(method)),
		"path":        appEmitRequestTargetPath(target),
		"team_id":     teamID,
		"app_id":      appID,
		"kid":         keyID,
		"did_key":     didKey,
		"body_sha256": bodyHash,
	}
	signedDIDKey, signature, canonical, err := signProtocolPayload(key, payload, timestamp)
	if err != nil {
		return nil, err
	}
	signedPayload := base64.RawURLEncoding.EncodeToString([]byte(canonical))
	headers := make(http.Header)
	headers.Set("Authorization", fmt.Sprintf("AWEB-App DIDKey %s %s", signedDIDKey, signature))
	headers.Set("X-AWEB-App-ID", appID)
	headers.Set("X-AWEB-App-Key-ID", keyID)
	headers.Set("X-AWEB-Team-ID", teamID)
	headers.Set("X-AWEB-Timestamp", strings.TrimSpace(timestamp))
	headers.Set("X-AWEB-Signed-Payload", signedPayload)
	return &AppEmitCredential{
		DIDKey:              signedDIDKey,
		SignatureB64:        signature,
		CanonicalPayload:    canonical,
		SignedPayloadB64URL: signedPayload,
		BodySHA256:          bodyHash,
		Headers:             headers,
	}, nil
}

// IdentityGrantCredential carries the request headers for an identity-grant
// authenticated API call signed by the grant session key.
type IdentityGrantCredential struct {
	DIDKey              string
	SignatureB64        string
	CanonicalPayload    string
	SignedPayloadB64URL string
	BodySHA256          string
	Headers             http.Header
}

// SignIdentityGrantCredential signs an API request with an identity-grant
// session key. The signed payload uses the same canonicalization, body
// hashing, and aud semantics as the v2 team envelope and the app-emit
// credential.
func SignIdentityGrantCredential(key ed25519.PrivateKey, method string, target *url.URL, grantID string, body []byte, timestamp string) (*IdentityGrantCredential, error) {
	if key == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if target == nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return nil, fmt.Errorf("grant_id is required")
	}
	bodyHashBytes := sha256.Sum256(body)
	bodyHash := fmt.Sprintf("%x", bodyHashBytes)
	payload := map[string]any{
		"v":           1,
		"auth":        "identity-grant",
		"aud":         target.Scheme + "://" + target.Host,
		"method":      strings.ToUpper(strings.TrimSpace(method)),
		"path":        appEmitRequestTargetPath(target),
		"grant_id":    grantID,
		"body_sha256": bodyHash,
	}
	signedDIDKey, signature, canonical, err := signProtocolPayload(key, payload, timestamp)
	if err != nil {
		return nil, err
	}
	signedPayload := base64.RawURLEncoding.EncodeToString([]byte(canonical))
	headers := make(http.Header)
	headers.Set("Authorization", fmt.Sprintf("AWEB-Grant DIDKey %s %s", signedDIDKey, signature))
	headers.Set("X-AWEB-Grant-ID", grantID)
	headers.Set("X-AWEB-Timestamp", strings.TrimSpace(timestamp))
	headers.Set("X-AWEB-Signed-Payload", signedPayload)
	return &IdentityGrantCredential{
		DIDKey:              signedDIDKey,
		SignatureB64:        signature,
		CanonicalPayload:    canonical,
		SignedPayloadB64URL: signedPayload,
		BodySHA256:          bodyHash,
		Headers:             headers,
	}, nil
}

func appEmitRequestTargetPath(target *url.URL) string {
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	if target.RawQuery != "" {
		path += "?" + target.RawQuery
	}
	return path
}

// UserSignaturePrefix separates user data from every protocol signature.
const UserSignaturePrefix = "aweb.user-signature/1\n"

// SignArbitraryPayload signs UserSignaturePrefix followed by canonical JSON
// containing the injected timestamp. canonical is the JSON portion alone.
func SignArbitraryPayload(key ed25519.PrivateKey, payload map[string]any, timestamp string) (didKey string, signature string, canonical string, err error) {
	return signPayload(key, payload, timestamp, UserSignaturePrefix)
}

// Only protocol-specific constructors may use the unprefixed protocol bytes.
func signProtocolPayload(key ed25519.PrivateKey, payload map[string]any, timestamp string) (didKey string, signature string, canonical string, err error) {
	return signPayload(key, payload, timestamp, "")
}

func signPayload(key ed25519.PrivateKey, payload map[string]any, timestamp, prefix string) (didKey string, signature string, canonical string, err error) {
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
	sig := signaturewire.SignBytes(key, []byte(prefix+canonical))
	return didKey, base64.RawStdEncoding.EncodeToString(sig), canonical, nil
}

// VerifyMessage checks the signature on a message envelope.
// Returns Unverified if DID or signature is missing (legacy message).
// Returns Failed if the DID is malformed, the signature doesn't verify,
// or SigningKeyID disagrees with FromDID.
// Returns Verified if the signature is valid. Verified does not prove that
// FromDID owns the claimed sender address; every inbound path must pass the
// result through Client.NormalizeSenderTrust for that binding decision.
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

	sig, err := signaturewire.DecodeStd(env.Signature)
	if err != nil {
		return Failed, fmt.Errorf("decode signature: %w", err)
	}

	payload := CanonicalJSON(env)
	if !signaturewire.Verify(signaturewire.Proof{PublicKey: pub, Payload: []byte(payload), Signature: sig}) {
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

	sig, err := signaturewire.DecodeStd(signatureB64)
	if err != nil {
		return Failed, fmt.Errorf("decode signature: %w", err)
	}

	if !signaturewire.Verify(signaturewire.Proof{PublicKey: pub, Payload: []byte(signedPayload), Signature: sig}) {
		return Failed, nil
	}

	recordNoncanonicalSignedMetadata(signedPayload)
	return Verified, nil
}

// CanonicalReplacementJSON builds the canonical JSON for controller-authorized
// address replacement signing.
func CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp string) string {
	return canonicaljson.Object(map[string]any{"address": address, "controller_did": controllerDID, "old_did": oldDID, "new_did": newDID, "timestamp": timestamp})
}

// VerifyReplacementSignature verifies a controller-authorized replacement announcement.
func VerifyReplacementSignature(controllerPub ed25519.PublicKey, address, controllerDID, oldDID, newDID, timestamp, signature string) (bool, error) {
	sig, err := signaturewire.DecodeStd(signature)
	if err != nil {
		return false, err
	}
	payload := CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp)
	return signaturewire.Verify(signaturewire.Proof{PublicKey: controllerPub, Payload: []byte(payload), Signature: sig}), nil
}

// CanonicalJSON builds the canonical JSON payload for message signing.
// Fields are sorted lexicographically, no whitespace, minimal escaping.
// Optional fields (conversation_id, from_stable_id, message_id, to_stable_id) are omitted when empty.
// See also LogEntry.CanonicalJSON which always includes all fields with null for absent values.
func CanonicalJSON(env *MessageEnvelope) string {
	fields := map[string]any{
		"body":      env.Body,
		"from":      env.From,
		"from_did":  env.FromDID,
		"subject":   env.Subject,
		"timestamp": env.Timestamp,
		"to":        env.To,
		"to_did":    env.ToDID,
		"type":      env.Type,
	}
	optionalFields := map[string]string{
		"from_stable_id":  env.FromStableID,
		"to_stable_id":    env.ToStableID,
		"message_id":      env.MessageID,
		"conversation_id": env.ConversationID,
		"priority":        env.Priority,
		"reply_to":        env.ReplyTo,
	}
	for key, value := range optionalFields {
		if value != "" {
			fields[key] = value
		}
	}
	if env.HangOn {
		fields["hang_on"] = true
	}
	if env.SenderLeaving {
		fields["sender_leaving"] = true
	}
	if env.WaitSeconds != nil {
		fields["wait_seconds"] = *env.WaitSeconds
	}
	return canonicaljson.Object(fields)
}
