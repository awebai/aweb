package awid

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

// coveringPayloadFor is the covering-v2 payload a controller signs for fields
// (domain, operation and timestamp, and the operation's claims) over exactly
// the request r, checked against r's X-AWEB-Signed-Payload. r's body is
// restored for the handler to read.
func coveringPayloadFor(t *testing.T, r *http.Request, fields map[string]string) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		body = nil
	}
	claims := map[string]any{}
	for k, v := range fields {
		if k != "domain" && k != "operation" && k != "timestamp" {
			claims[k] = v
		}
	}
	payload, err := ControllerRequestPayload("http://"+r.Host, r.Method, r.URL.EscapedPath(), body,
		fields["timestamp"], fields["domain"], fields["operation"], claims)
	if err != nil {
		t.Fatalf("covering payload: %v", err)
	}
	signed, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil || !bytes.Equal(signed, payload) {
		t.Fatalf("signed payload %s, want %s", signed, payload)
	}
	return string(payload)
}
