package awid

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AWID's coded alias conflict, as released aw clients parse it: the code and
// message reach RegistryError, and the error still prints the response body.
func TestRegistryCodedAliasConflictParsesAndDescribes(t *testing.T) {
	body := `{"detail":{"code":"alias_active","message":"Alias already active in team"}}`
	err := parseRegistryError(&http.Response{StatusCode: http.StatusConflict, Body: io.NopCloser(strings.NewReader(body))})
	registryErr, ok := err.(*RegistryError)
	if !ok || registryErr.Code != "alias_active" || registryErr.Message != "Alias already active in team" || registryErr.Error() != "registry http 409: "+body {
		t.Fatalf("parsed %#v: %v", err, err)
	}
	if got := DescribeError(err); got != (ErrorDetail{Code: "alias_conflict", HTTPStatus: 409, Detail: "Alias already active in team", Reason: "alias_active"}) {
		t.Fatalf("described %+v", got)
	}
}

// Preserve existing coded-detail classifications alongside the hosted reason.
func TestServerCodedAliasConflictDescribes(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{{"alias_active", "alias_conflict"}, {"alias_mismatch", "http_error"}} {
		err := &APIError{StatusCode: http.StatusConflict, Body: `{"detail":{"code":"` + tc.code + `","message":"refused"}}`}
		if got := DescribeError(err); got != (ErrorDetail{Code: tc.want, HTTPStatus: 409, Detail: "refused", Reason: tc.code}) {
			t.Fatalf("%s: described %+v", tc.code, got)
		}
	}
}

func TestHostedInviteAliasTakenDescribesAsNameConflict(t *testing.T) {
	for _, tc := range []struct {
		name, reason, want string
		status             int
	}{
		{"name conflict", "alias_taken", "alias_conflict", http.StatusConflict},
		{"uncertain response", "alias_taken", "http_error", http.StatusServiceUnavailable},
		{"different refusal", "alias_mismatch", "http_error", http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const detail = "Alias already taken in this team"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/health" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{}`)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != spawnAcceptInvitePath {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"detail":%q,"reason":%q}`, detail, tc.reason)
			}))
			defer server.Close()
			pub, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewWithIdentity(server.URL, key, ComputeDIDKey(pub))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AcceptSpawnInvite(context.Background(), &SpawnAcceptInviteRequest{
				Token: "aw_inv_alias_test", DID: ComputeDIDKey(pub), Alias: "taken",
			})
			if err == nil {
				t.Fatal("expected hosted refusal")
			}
			wrapped := fmt.Errorf("accept hosted team invite: %w", err)
			if got := DescribeError(wrapped); got != (ErrorDetail{Code: tc.want, HTTPStatus: tc.status, Detail: detail, Reason: tc.reason}) {
				t.Fatalf("described %+v", got)
			}
			if got := RefusalCode(wrapped); got != tc.reason {
				t.Fatalf("lost server reason: %q", got)
			}
		})
	}
}
