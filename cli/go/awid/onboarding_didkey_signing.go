package awid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
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
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	normalizedPath := strings.TrimSpace(path)

	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	var b strings.Builder
	b.WriteString(`{"body_sha256":`)
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
