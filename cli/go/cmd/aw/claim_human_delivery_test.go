package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestClaimHumanPrintsTheObservedEmailDelivery(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"verification failure", `{"status":"verification_sent","email_sent":false,"email_message":"The verification email could not be sent. Run the command again to request a new one."}`, "The verification email could not be sent. Run the command again to request a new one.\n"},
		{"approval failure", `{"status":"approval_sent","email_sent":false,"email_message":"The approval email could not be sent. Run the command again to request a new one."}`, "The approval email could not be sent. Run the command again to request a new one.\n"},
		{"verification success", `{"status":"verification_sent","email_sent":true}`, "Verification email requested for person@example.test. Click the link in the email to activate your dashboard login.\n"},
		{"released verification", `{"status":"verification_sent"}`, "Verification email requested for person@example.test. Click the link in the email to activate your dashboard login.\n"},
		{"approval success", `{"status":"approval_sent","email_sent":true}`, "Approval email requested. Follow the instructions in that email to approve this claim.\n"},
		{"attached ignores delivery", `{"status":"attached","email_sent":false,"email_message":"not applicable"}`, "Human account person@example.test is attached. No verification email was sent because the email is already verified.\n"},
		{"unreadable message fallback", `{"status":"verification_sent","email_sent":false}`, "The verification email could not be sent. Run the command again to request a new one.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response awid.ClaimHumanResponse
			if err := json.Unmarshal([]byte(tc.body), &response); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := printClaimHumanSuccess(&out, "person@example.test", &response); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("message=%q want=%q", out.String(), tc.want)
			}
		})
	}
}

func TestClaimHumanJSONPreservesExplicitDeliveryFailure(t *testing.T) {
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const message = "The verification email could not be sent. Run the command again to request a new one."
	server := newLocalHTTPServerWithURL(t, func(base string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
				if err := json.NewEncoder(w).Encode(map[string]any{"onboarding_url": base, "aweb_url": base, "registry_url": "https://api.awid.ai", "version": "1.7.0"}); err != nil {
					t.Error(err)
				}
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/claim-human":
				if err := json.NewEncoder(w).Encode(map[string]any{"status": "verification_sent", "email": "person@example.test", "email_sent": false, "email_message": message}); err != nil {
					t.Error(err)
				}
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
			}
		})
	})
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, home, "person.aweb.ai/terminal", awid.ComputeDIDKey(pub), awid.ComputeStableID(pub), "https://api.awid.ai", key)
	run := exec.CommandContext(ctx, bin, "claim-human", "--json", "--email", "person@example.test", "--mock-url", server.URL)
	run.Dir, run.Env = home, idCreateCommandEnv(home)
	raw, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("claim: %v %s", err, raw)
	}
	var output struct {
		Status  string `json:"status"`
		Sent    *bool  `json:"email_sent"`
		Message string `json:"email_message"`
	}
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatalf("JSON output: %v %s", err, raw)
	}
	if output.Status != "verification_sent" || output.Sent == nil || *output.Sent || output.Message != message {
		t.Fatalf("delivery observation lost: %s", raw)
	}
}
