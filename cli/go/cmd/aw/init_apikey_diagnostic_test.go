package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestWorkspaceInitDiagnosticReadsRequestIDBesideAStringDetail(t *testing.T) {
	const requestID = "11111111-2222-4333-8444-555555555555"
	for name, body := range map[string]string{
		"string detail": `{"detail":"Team creator must sign this request","request_id":"` + requestID + `"}`,
		"list detail":   `{"detail":[{"loc":["body","did"],"msg":"field required"}],"request_id":"` + requestID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
			got, _ := workspaceInitHTTPDiagnostic(resp, []byte(body), "")
			if !strings.Contains(got, "request_id="+requestID) {
				t.Fatalf("request_id lost: %s", got)
			}
			if strings.Contains(got, "creator must sign") || strings.Contains(got, "field required") {
				t.Fatalf("server text echoed: %s", got)
			}
		})
	}
}

// Bodies are the hosted service's refusal shapes for POST
// /api/v1/workspaces/init: a coded detail object, the AWID error envelope with
// its request ID, and a capacity refusal coded in detail.error.
func TestWorkspaceInitShowsAKnownRefusalCodeWithItsRemedy(t *testing.T) {
	const requestID = "11111111-2222-4333-8444-555555555555"
	const canary = "PRIVATE_SERVER_TEXT"
	for _, tc := range []struct {
		name, body, code, remedy string
		status                   int
	}{
		{"creator_must_sign", `{"detail":{"code":"creator_must_sign"}}`, "creator_must_sign", "setup command", 403},
		{"awid_unavailable", `{"error":{"code":"awid_unavailable","message":"` + canary + `","request_id":"` + requestID + `"}}`, "awid_unavailable", "Retry in a few seconds", 503},
		{"agent_limit_reached", `{"detail":{"error":"agent_limit_reached","message":"` + canary + `","contact_url":"https://example.test/` + canary + `"}}`, "agent_limit_reached", "agent limit", 403},
		{"custodial_reinit_forbidden", `{"detail":{"code":"custodial_reinit_forbidden","message":"use an owner/admin person's session ` + canary + `"}}`, "custodial_reinit_forbidden", "workspace's own key", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "creator_must_sign" && len(tc.body) != 39 {
				t.Fatalf("not the observed 39-byte body: %d", len(tc.body))
			}
			err := refuseWorkspaceInit(t, tc.status, tc.body)
			text := err.Error()
			for _, want := range []string{"error_code=" + tc.code, tc.remedy} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q: %s", want, text)
				}
			}
			if strings.Contains(text, canary) || strings.Contains(text, "session") {
				t.Fatalf("server text echoed: %s", text)
			}
			if got := errorEnvelope(err, text).Error.Code; got != tc.code {
				t.Fatalf("--json code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestWorkspaceInitKeepsAnUnknownOrConflictingRefusalCodePrivate(t *testing.T) {
	for name, body := range map[string]string{
		"unknown code":      `{"detail":{"code":"PRIVATE_SERVER_CODE"}}`,
		"conflicting codes": `{"detail":{"code":"creator_must_sign"},"error":{"code":"awid_unavailable"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := refuseWorkspaceInit(t, 403, body)
			text := err.Error()
			if !strings.Contains(text, "error_code=unknown") || strings.Contains(text, "PRIVATE_SERVER_CODE") {
				t.Fatalf("code not kept private: %s", text)
			}
			if got := errorEnvelope(err, text).Error.Code; got != "error" {
				t.Fatalf("--json code = %q, want error", got)
			}
		})
	}
}

func refuseWorkspaceInit(t *testing.T, status int, body string) error {
	t.Helper()
	server := newLocalHTTPServerHandlerWithURL(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/workspaces/init" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, err = postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{}, key)
	if err == nil {
		t.Fatal("refusal accepted")
	}
	return err
}

// Every vocabulary entry, refused by a service through the real request path:
// a remedy that changes the bootstrap context never comes with "rerun the same
// command", and a retryable one always does.
func TestWorkspaceInitPartialGuidanceFollowsEachRefusal(t *testing.T) {
	for code, refusal := range workspaceInitRefusalRemedies {
		t.Run(code, func(t *testing.T) {
			body := `{"detail":{"code":"` + code + `"}}`
			if code == "INTERNAL_ERROR" || strings.HasPrefix(code, "awid_") || code == "team_server_configuration_invalid" {
				body = `{"error":{"code":"` + code + `"}}`
			}
			if code == "agent_limit_reached" {
				body = `{"detail":{"error":"` + code + `"}}`
			}
			err := refuseWorkspaceInit(t, 409, body)
			if got := errorCodeOf(err); got != code {
				t.Fatalf("code = %q, want %q: %v", got, code, err)
			}
			guidance := partialInitGuidance(err)
			rerun := strings.Contains(guidance, "rerun the same command")
			if refusal.changesContext == rerun || (refusal.changesContext && !strings.Contains(guidance, "new directory")) {
				t.Fatalf("changesContext=%v but guidance %q", refusal.changesContext, guidance)
			}
		})
	}
}
