package awid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// cloudDIDAuthSignPayload builds the canonical onboarding verifier envelope.
// Keys are serialized in lexicographic order with no whitespace:
// {"body_sha256":"...","method":"POST","path":"/api/v1/...","timestamp":"..."}
//
// String fields are encoded with HTML escaping disabled so the bytes match
// Python json.dumps(..., ensure_ascii=False) on the cloud verifier side.
func cloudDIDAuthSignPayload(method, path, timestamp string, body []byte) []byte {
	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	var b strings.Builder
	b.WriteString(`{"body_sha256":`)
	encodeJSONString(&b, bodyHash)
	b.WriteString(`,"method":`)
	encodeJSONString(&b, strings.ToUpper(strings.TrimSpace(method)))
	b.WriteString(`,"path":`)
	encodeJSONString(&b, strings.TrimSpace(path))
	b.WriteString(`,"timestamp":`)
	encodeJSONString(&b, timestamp)
	b.WriteByte('}')
	return []byte(b.String())
}

func encodeJSONString(b *strings.Builder, s string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	b.Write(out)
}
