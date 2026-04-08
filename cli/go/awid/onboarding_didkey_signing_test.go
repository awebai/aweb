package awid

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCloudDIDKeySignPayload_FieldOrderAndLayout(t *testing.T) {
	body := []byte(`{"username":"juanre","did_key":"did:key:z6Mk","did_aw":"did:aw:xyz","alias":"laptop"}`)
	payload := onboardingDIDKeySignPayload(
		"POST",
		"/api/v1/onboarding/cli-signup",
		"2026-04-07T12:00:00Z",
		body,
	)
	h := sha256.Sum256(body)
	wantHash := hex.EncodeToString(h[:])
	want := `{"body_sha256":"` + wantHash + `","method":"POST","path":"/api/v1/onboarding/cli-signup","timestamp":"2026-04-07T12:00:00Z"}`
	if string(payload) != want {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", string(payload), want)
	}
}

func TestCloudDIDKeySignPayload_EmptyBodyHashesEmptyString(t *testing.T) {
	payload := onboardingDIDKeySignPayload("GET", "/api/v1/onboarding/check-username", "2026-04-07T12:00:00Z", nil)
	emptyHash := sha256.Sum256(nil)
	want := hex.EncodeToString(emptyHash[:])
	if !strings.Contains(string(payload), `"body_sha256":"`+want+`"`) {
		t.Fatalf("empty body hash missing: %s", string(payload))
	}
}

// Pins the cross-language byte stability contract: <, >, & must NOT be
// HTML-escaped to \u003c, \u003e, \u0026. This matches Python's
// canonical_json_bytes(..., ensure_ascii=False).
func TestCloudDIDKeySignPayload_DoesNotHTMLEscape(t *testing.T) {
	payload := onboardingDIDKeySignPayload(
		"POST",
		"/api/v1/onboarding/<a&b>",
		"2026-04-07T12:00:00Z",
		nil,
	)
	s := string(payload)
	if strings.Contains(s, `\u003c`) || strings.Contains(s, `\u003e`) || strings.Contains(s, `\u0026`) {
		t.Fatalf("HTML escape leaked into canonical payload: %s", s)
	}
	if !strings.Contains(s, `"path":"/api/v1/onboarding/<a&b>"`) {
		t.Fatalf("path field not byte-stable: %s", s)
	}
}

// Method is normalized to uppercase. A sloppy caller passing "post" must
// produce the same envelope bytes as a caller passing "POST".
func TestCloudDIDKeySignPayload_NormalizesMethodToUppercase(t *testing.T) {
	a := onboardingDIDKeySignPayload("post", "/x", "2026-04-07T12:00:00Z", nil)
	b := onboardingDIDKeySignPayload("POST", "/x", "2026-04-07T12:00:00Z", nil)
	if string(a) != string(b) {
		t.Fatalf("method normalization broke:\n%s\n%s", string(a), string(b))
	}
	if !strings.Contains(string(a), `"method":"POST"`) {
		t.Fatalf("want method=POST, got: %s", string(a))
	}
}

// Surrounding whitespace on method or path is stripped before signing so an
// accidental trailing newline can't desync the signed envelope from what the
// server sees on r.Method / r.URL.Path.
func TestCloudDIDKeySignPayload_TrimsMethodAndPath(t *testing.T) {
	a := onboardingDIDKeySignPayload("  POST  ", "  /x  ", "2026-04-07T12:00:00Z", nil)
	b := onboardingDIDKeySignPayload("POST", "/x", "2026-04-07T12:00:00Z", nil)
	if string(a) != string(b) {
		t.Fatalf("whitespace trim broke:\n%s\n%s", string(a), string(b))
	}
}

// Unit test for the encodeJSONString helper in isolation. Covers the
// escape-disabled contract and the trailing-newline strip.
func TestEncodeJSONString_NoHTMLEscapeNoTrailingNewline(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", `"plain"`},
		{"a<b>&c", `"a<b>&c"`},
		{"with\"quote", `"with\"quote"`},
		{"", `""`},
		{"unicode: café", `"unicode: café"`},
	}
	for _, c := range cases {
		var b strings.Builder
		encodeJSONString(&b, c.in)
		if b.String() != c.want {
			t.Errorf("encodeJSONString(%q) = %q, want %q", c.in, b.String(), c.want)
		}
	}
}
