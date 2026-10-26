package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// onboardingDIDKeySignPayload builds the canonical JSON bytes for the shared
// onboarding DIDKey auth envelope used by every onboarding endpoint that
// accepts a DIDKey-signed request (cli-signup, claim-human, bootstrap-redeem):
//
//	{"body_sha256":"<hex>","method":"<METHOD>","path":"<PATH>","timestamp":"<ISO8601>"}
//
// Keys are in lexicographic order (body_sha256 < method < path < timestamp)
// with no whitespace. The function is byte-for-byte compatible with Python's
// canonical_json_bytes(..., ensure_ascii=False) on the verifier side —
// it disables Go's default HTML escaping for <, >, and & so a future signed
// field carrying those characters does not silently desync the Go and Python
// envelopes.
//
// method is normalized to uppercase and path to a trimmed string, matching
// the onboarding contract ("HTTP method in uppercase", "URL path, no query
// string at MVP"). body is the exact raw HTTP request body bytes that will
// be sent over the wire; empty body hashes the empty string.
func onboardingDIDKeySignPayload(method, path, timestamp string, body []byte) []byte {
	return onboardingDIDKeySignPayloadWithAudience("", method, path, timestamp, body)
}

// DIDKeyRequestHeadersForAudience signs an exact request body for a particular
// service origin. The receiving endpoint must verify this variant and separately
// establish the signer's authority. Legacy onboarding envelopes are unchanged.
func DIDKeyRequestHeadersForAudience(method, path, audience string, body []byte, signingKey ed25519.PrivateKey) (map[string]string, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("a native signing key is required")
	}
	audience = strings.TrimSpace(audience)
	origin, err := url.Parse(audience)
	if err != nil || (origin.Scheme != "https" && origin.Scheme != "http") || origin.Host == "" || origin.User != nil || audience != origin.Scheme+"://"+origin.Host {
		return nil, fmt.Errorf("audience must be an HTTP(S) origin")
	}
	if strings.TrimSpace(method) == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n?#") {
		return nil, fmt.Errorf("an HTTP method and exact URL path are required")
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := onboardingDIDKeySignPayloadWithAudience(audience, method, path, timestamp, body)
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	return map[string]string{
		"Authorization":    "DIDKey " + did + " " + base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, payload)),
		"X-AWEB-Timestamp": timestamp,
	}, nil
}

func onboardingDIDKeySignPayloadWithAudience(audience, method, path, timestamp string, body []byte) []byte {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	normalizedPath := strings.TrimSpace(path)

	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	var b strings.Builder
	b.WriteByte('{')
	if audience != "" {
		b.WriteString(`"aud":`)
		encodeJSONString(&b, audience)
		b.WriteByte(',')
	}
	b.WriteString(`"body_sha256":`)
	encodeJSONString(&b, bodyHash)
	b.WriteString(`,"method":`)
	encodeJSONString(&b, normalizedMethod)
	b.WriteString(`,"path":`)
	encodeJSONString(&b, normalizedPath)
	b.WriteString(`,"timestamp":`)
	encodeJSONString(&b, timestamp)
	b.WriteByte('}')
	return []byte(b.String())
}

// encodeJSONString writes s as a JSON string literal into b, with HTML
// escaping disabled so the output matches Python's json.dumps(...,
// ensure_ascii=False). Used by onboardingDIDKeySignPayload so signed envelope
// bytes are byte-identical across the Go CLI and the Python verifier
// even if a field value contains <, >, or &.
func encodeJSONString(b *strings.Builder, s string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// json.Encoder.Encode always appends a trailing newline; strip it.
	_ = enc.Encode(s)
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	b.Write(out)
}
