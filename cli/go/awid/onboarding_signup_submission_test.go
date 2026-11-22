package awid

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignupSubmissionKeepsFrozenRequestBytes(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n  \"username\":\"person\", \"did_key\":\"" + ComputeDIDKey(pub) + "\",\"did_aw\":\"\",\"alias\":\"terminal\",\"future_hint\":\"preserved\"\n}")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/onboarding/cli-signup" {
			http.NotFound(w, r)
			return
		}
		calls++
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(got, body) {
			t.Errorf("request was reserialized: %q", got)
		}
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWEB-Timestamp") == "" {
			t.Error("missing onboarding proof")
		}
		if err := json.NewEncoder(w).Encode(CliSignupResponse{Username: "person", APIKey: "fixture-key"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for range 2 {
		response, err := SubmitCliSignup(context.Background(), CliSignupSubmission{OnboardingURL: server.URL, RequestJSON: body, SigningKey: key})
		if err != nil || response.Username != "person" {
			t.Fatalf("response=%v err=%v", response, err)
		}
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestSignupSubmissionRefusesWrongSignerBeforeTransport(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	response, err := SubmitCliSignup(context.Background(), CliSignupSubmission{OnboardingURL: "http://127.0.0.1:1", RequestJSON: []byte(`{"did_key":"wrong"}`), SigningKey: key})
	if err == nil || response != nil || !strings.Contains(err.Error(), "does not match signing key") {
		t.Fatalf("wrong signer was not refused before transport: %v", err)
	}
	response, err = SubmitCliSignup(context.Background(), CliSignupSubmission{OnboardingURL: "http://127.0.0.1:1", RequestJSON: []byte(`{}`), SigningKey: []byte("malformed")})
	if err == nil || response != nil || !strings.Contains(err.Error(), "must be valid") {
		t.Fatalf("malformed signer was not refused before transport: %v", err)
	}
}
