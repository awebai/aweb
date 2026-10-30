package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// The --json error envelope is the stable contract; stderr wording is not.
func TestErrorEnvelopeCarriesAStableCode(t *testing.T) {
	forbidden := &awid.APIError{StatusCode: 403, Body: `{"detail":"grant revoked"}`}
	for _, tc := range []struct {
		name   string
		err    error
		code   string
		status int
		detail string
	}{
		{name: "unclassified", err: errors.New("boom"), code: "error"},
		// Exit 2 is shared by usage mistakes and refusals, so it names no class.
		{name: "untagged exit 2", err: usageError("missing --name"), code: "error"},
		{name: "server refusal", err: fmt.Errorf("create hosted team invite: %w", forbidden), code: "http_error", status: 403, detail: "grant revoked"},
		{name: "body without detail", err: &awid.APIError{StatusCode: 502, Body: "bad gateway"}, code: "http_error", status: 502},
		{name: "detail that is not a string", err: &awid.APIError{StatusCode: 422, Body: `{"detail":[{"loc":["name"]}]}`}, code: "http_error", status: 422},
		{name: "tagged refusal", err: fmt.Errorf("init: %w", withErrorCode("alias_conflict", &awid.APIError{StatusCode: 409, Body: `{"detail":"alias exists"}`})), code: "alias_conflict", status: 409, detail: "alias exists"},
		{name: "registry refusal", err: fmt.Errorf("register: %w", &awid.RegistryError{StatusCode: 409, Detail: `{"detail":"Alias already active in team"}`}), code: "http_error", status: 409, detail: "Alias already active in team"},
		{name: "registry refusal with a coded detail", err: &awid.RegistryError{StatusCode: 409, Detail: `{"detail":{"code":"certificate_already_registered"}}`, Code: "certificate_already_registered"}, code: "http_error", status: 409},
		{name: "decryption", err: fmt.Errorf("show: %w", undecryptable(t)), code: "encryption_key_missing"},
		{name: "mutation timed out", err: fmt.Errorf("revoke: %w", timedOutMutation(t)), code: "outcome_unknown"},
		{name: "tagged usage refusal", err: withErrorCode("team_not_hosted", usageError("refusing")), code: "team_not_hosted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeCLIErrorEnvelope(&out, tc.err, tc.err.Error())
			var envelope struct {
				Error map[string]any `json:"error"`
			}
			if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
				t.Fatalf("not one JSON document: %q: %v", out.String(), err)
			}
			if bytes.Count(bytes.TrimSpace(out.Bytes()), []byte("\n")) != 0 {
				t.Fatalf("envelope is not one line: %q", out.String())
			}
			body := envelope.Error
			if body["code"] != tc.code || body["message"] != tc.err.Error() {
				t.Fatalf("envelope %v", body)
			}
			if status, _ := body["http_status"].(float64); int(status) != tc.status {
				t.Fatalf("http_status %v, want %d", body["http_status"], tc.status)
			}
			if detail, _ := body["detail"].(string); detail != tc.detail {
				t.Fatalf("detail %v, want %q", body["detail"], tc.detail)
			}
			if _, present := body["http_status"]; present != (tc.status != 0) {
				t.Fatalf("http_status present=%v for %v", present, body)
			}
		})
	}
}

// A code never changes how the CLI exits or what the error says.
func TestErrorCodeKeepsTheExitCodeAndMessage(t *testing.T) {
	refusal := usageError("refusing")
	tagged := fmt.Errorf("delete: %w", withErrorCode("team_not_hosted", refusal))
	if exitCode(tagged) != 2 || tagged.Error() != "delete: refusing" || !errors.Is(tagged, refusal) {
		t.Fatalf("exit %d message %q", exitCode(tagged), tagged.Error())
	}
}

// timedOutMutation is a real mutating request that times out before its
// response, as awid reports it.
func timedOutMutation(t *testing.T) error {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
	}))
	defer server.Close()
	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetHTTPClient(&http.Client{Timeout: 50 * time.Millisecond})
	err = client.Do(context.Background(), http.MethodPost, "/v1/grants/x/revoke", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	return err
}

// undecryptable is a real encrypted mail opened by a client with no local
// encryption private key, as awid reports it.
func undecryptable(t *testing.T) error {
	t.Helper()
	client, err := awid.New("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DecryptE2EEEnvelope(&awid.E2EEMessageEnvelope{MessageVersion: awid.E2EEMessageVersion, EnvelopeType: awid.E2EEEnvelopeType})
	if err == nil {
		t.Fatal("expected a decryption failure")
	}
	return err
}
