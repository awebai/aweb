package awid

import (
	"bytes"
	"strings"
	"testing"
)

func TestCloudDIDAuthSignPayload_DoesNotHTMLEscape(t *testing.T) {
	t.Parallel()

	payload := cloudDIDAuthSignPayload("POST", "/api/v1/onboarding/<a&b>", "2026-04-07T00:00:00Z", []byte(`{"ok":true}`))

	if !bytes.Contains(payload, []byte(`"/api/v1/onboarding/<a&b>"`)) {
		t.Fatalf("payload=%s", payload)
	}
	if strings.Contains(string(payload), `\u003c`) || strings.Contains(string(payload), `\u003e`) || strings.Contains(string(payload), `\u0026`) {
		t.Fatalf("payload unexpectedly HTML-escaped: %s", payload)
	}
}
