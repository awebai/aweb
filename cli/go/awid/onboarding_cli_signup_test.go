package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cloudSignPayload is exercised directly to pin down the canonical byte layout.
func TestCloudSignPayload_FieldOrderAndEncoding(t *testing.T) {
	body := []byte(`{"username":"juanre","did_key":"did:key:z6Mk","did_aw":"did:aw:xyz","alias":"laptop"}`)
	payload := cloudSignPayload(
		"POST",
		"/api/v1/onboarding/cli-signup",
		"2026-04-07T12:00:00Z",
		body,
	)

	// Expected canonical form: keys sorted (body_sha256 < method < path < timestamp),
	// no whitespace, no trailing newline.
	h := sha256.Sum256(body)
	wantHash := hex.EncodeToString(h[:])
	want := `{"body_sha256":"` + wantHash + `","method":"POST","path":"/api/v1/onboarding/cli-signup","timestamp":"2026-04-07T12:00:00Z"}`

	if string(payload) != want {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", string(payload), want)
	}
}

func TestCloudSignPayload_EmptyBodyHashesEmptyString(t *testing.T) {
	payload := cloudSignPayload("GET", "/api/v1/onboarding/check-username", "2026-04-07T12:00:00Z", nil)
	h := sha256.Sum256(nil)
	wantHash := hex.EncodeToString(h[:])
	if !strings.Contains(string(payload), `"body_sha256":"`+wantHash+`"`) {
		t.Fatalf("empty body hash missing from payload: %s", string(payload))
	}
}

// Pins encodeJSONString's contract: <, >, and & must NOT be escaped to
// \u003c, \u003e, \u0026. This is what Python's canonical_json_bytes does
// (ensure_ascii=False), and we need byte-identical envelope bytes across
// the Go CLI and the Python cloud verifier.
func TestCloudSignPayload_DoesNotHTMLEscape(t *testing.T) {
	// Stuff the path with the three offenders. Real paths never carry these,
	// but if someone ever signs a query string or a free-form field, the
	// canonical bytes must match Python's.
	payload := cloudSignPayload(
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

// CheckUsername hits a real httptest server and parses the response.
func TestCheckUsername_Available(t *testing.T) {
	var receivedBody []byte
	var receivedPath string
	var receivedMethod string
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		receivedAuth = r.Header.Get("Authorization")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"available":true}`))
	}))
	defer srv.Close()

	resp, err := CheckUsername(context.Background(), srv.URL, "juanre")
	if err != nil {
		t.Fatalf("CheckUsername: %v", err)
	}
	if !resp.Available {
		t.Fatalf("want available=true, got %+v", resp)
	}
	if resp.Reason != "" {
		t.Fatalf("want empty reason, got %q", resp.Reason)
	}

	if receivedMethod != "POST" {
		t.Fatalf("want POST, got %s", receivedMethod)
	}
	if receivedPath != "/api/v1/onboarding/check-username" {
		t.Fatalf("unexpected path: %s", receivedPath)
	}
	if receivedAuth != "" {
		t.Fatalf("check-username must not require auth, got Authorization: %s", receivedAuth)
	}

	// Body must be JSON with exactly one field.
	var got map[string]string
	if err := json.Unmarshal(receivedBody, &got); err != nil {
		t.Fatalf("unmarshal request body: %v (raw=%q)", err, string(receivedBody))
	}
	if got["username"] != "juanre" {
		t.Fatalf("want username=juanre, got %v", got)
	}
}

func TestCheckUsername_Taken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"available":false,"reason":"taken"}`))
	}))
	defer srv.Close()

	resp, err := CheckUsername(context.Background(), srv.URL, "admin")
	if err != nil {
		t.Fatalf("CheckUsername: %v", err)
	}
	if resp.Available {
		t.Fatal("want available=false")
	}
	if resp.Reason != "taken" {
		t.Fatalf("want reason=taken, got %q", resp.Reason)
	}
}

func TestCheckUsername_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "oops", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := CheckUsername(context.Background(), srv.URL, "juanre")
	if err == nil {
		t.Fatal("want error on 500")
	}
}

// CliSignup must sign the request body and the server must be able to verify it.
// This is the critical test: it proves the body_sha256 in the signed payload
// matches the actual request body bytes sent over the wire.
func TestCliSignup_SignsBodyCorrectly(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	did := ComputeDIDKey(pub)

	var sigErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			sigErr = errorMsg("method", "POST", r.Method)
			w.WriteHeader(500)
			return
		}
		if r.URL.Path != "/api/v1/onboarding/cli-signup" {
			sigErr = errorMsg("path", "/api/v1/onboarding/cli-signup", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		auth := r.Header.Get("Authorization")
		timestamp := r.Header.Get("X-AWEB-Timestamp")
		if timestamp == "" {
			sigErr = errorMsg("X-AWEB-Timestamp", "<set>", "<empty>")
			w.WriteHeader(500)
			return
		}

		// Parse Authorization header.
		parts := strings.SplitN(auth, " ", 3)
		if len(parts) != 3 || parts[0] != "DIDKey" {
			sigErr = errorMsg("auth scheme", "DIDKey", auth)
			w.WriteHeader(500)
			return
		}
		if parts[1] != did {
			sigErr = errorMsg("auth did:key", did, parts[1])
			w.WriteHeader(500)
			return
		}
		sigB, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			sigErr = err
			w.WriteHeader(500)
			return
		}

		// Read the body and rebuild the exact canonical payload the CLI should have signed.
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			sigErr = err
			w.WriteHeader(500)
			return
		}
		// Verify body is well-formed and carries the four required fields.
		var parsed map[string]any
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			sigErr = err
			w.WriteHeader(500)
			return
		}
		for _, k := range []string{"username", "did_key", "did_aw", "alias"} {
			if _, ok := parsed[k]; !ok {
				sigErr = errorMsg("body field "+k, "<set>", "<missing>")
				w.WriteHeader(500)
				return
			}
		}
		if parsed["did_key"] != did {
			sigErr = errorMsg("body did_key", did, parsed["did_key"])
			w.WriteHeader(500)
			return
		}

		want := cloudSignPayload("POST", "/api/v1/onboarding/cli-signup", timestamp, bodyBytes)
		if !ed25519.Verify(pub, want, sigB) {
			sigErr = errorMsg("signature", "valid", "invalid — body_sha256 likely does not match wire bytes")
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"user_id":"u1",
			"username":"juanre",
			"org_id":"o1",
			"namespace_domain":"juanre.aweb.ai",
			"team_address":"juanre.aweb.ai/default",
			"certificate":"eyJ2ZXJzaW9uIjoxfQ==",
			"did_aw":"did:aw:test",
			"member_address":"juanre.aweb.ai/laptop",
			"alias":"laptop"
		}`))
	}))
	defer srv.Close()

	req := &CliSignupRequest{
		Username: "juanre",
		DIDKey:   did,
		DIDAW:    "did:aw:test",
		Alias:    "laptop",
	}
	resp, err := CliSignup(context.Background(), srv.URL, req, priv)
	if err != nil {
		t.Fatalf("CliSignup: %v", err)
	}
	if sigErr != nil {
		t.Fatalf("server-side validation failed: %v", sigErr)
	}
	if resp.TeamAddress != "juanre.aweb.ai/default" {
		t.Fatalf("unexpected team_address: %s", resp.TeamAddress)
	}
	if resp.Certificate == "" {
		t.Fatalf("missing certificate")
	}
}

func TestCliSignup_BodyDIDKeyMustMatchSigningKey(t *testing.T) {
	// Caller passes a req.DIDKey that doesn't match signingKey.
	// Helper must refuse before hitting the network.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be reached")
	}))
	defer srv.Close()

	req := &CliSignupRequest{
		Username: "juanre",
		DIDKey:   "did:key:z6MkWRONGKEY",
		DIDAW:    "did:aw:test",
		Alias:    "laptop",
	}
	_, err = CliSignup(context.Background(), srv.URL, req, priv)
	if err == nil {
		t.Fatal("want error on did_key/signing key mismatch")
	}
	if !strings.Contains(err.Error(), "did_key") {
		t.Fatalf("error should mention did_key, got: %v", err)
	}
}

func TestCliSignup_ServerRejects(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	did := ComputeDIDKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"username taken"}`, http.StatusConflict)
	}))
	defer srv.Close()

	req := &CliSignupRequest{
		Username: "admin",
		DIDKey:   did,
		DIDAW:    "did:aw:test",
		Alias:    "laptop",
	}
	_, err = CliSignup(context.Background(), srv.URL, req, priv)
	if err == nil {
		t.Fatal("want error on 409")
	}
}

// ---- helpers ----

func errorMsg(label string, want, got any) error {
	return &msgErr{label: label, want: want, got: got}
}

type msgErr struct {
	label string
	want  any
	got   any
}

func (e *msgErr) Error() string {
	var b bytes.Buffer
	b.WriteString(e.label)
	b.WriteString(" mismatch: want=")
	_, _ = b.WriteString(stringify(e.want))
	b.WriteString(" got=")
	_, _ = b.WriteString(stringify(e.got))
	return b.String()
}

func stringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

