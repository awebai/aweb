package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestAwMailSendConciseHTTPError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	peerPub, _, _ := ed25519.GenerateKey(nil)
	self, peer := awid.ComputeDIDKey(pub), awid.ComputeDIDKey(peerPub)
	for _, tc := range []struct {
		name, contentType, body, mitigated, want string
		ids                                      bool
	}{
		{name: "generic_html", contentType: "text/html", body: "<html><title>Unknown</title>" + strings.Repeat("private-response-content ", 4000) + "</html>", want: "HTML error response", ids: true},
		{name: "blocked_title", contentType: "text/html", body: "<html><title>Blocked</title>" + strings.Repeat("private-response-content ", 4000) + "</html>", want: "HTML response titled Blocked", ids: true},
		{name: "challenge", contentType: "text/html", body: "<html><title>Just a moment...</title>private-response-content</html>", mitigated: "challenge", want: "challenge response", ids: true},
		{name: "no_metadata", contentType: "text/html", body: "<html>private-response-content</html>", want: "HTML error response"},
		{name: "plain", contentType: "text/plain", body: "private-response-content", want: "non-JSON error response"},
		{name: "json_detail", contentType: "application/json", body: `{"detail":"Not a participant"}`, want: "Not a participant", ids: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/agents":
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "devteam:test.local", Agents: []awid.AgentView{{AgentID: "alice-agent", Alias: "alice", DIDKey: peer, Address: "test.local/alice"}}})
				case "/v1/conversations":
					_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
				case "/v1/messages":
					posts.Add(1)
					var req awid.SendMessageRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					sig, err := base64.RawStdEncoding.DecodeString(req.Signature)
					if err != nil || !ed25519.Verify(pub, []byte(req.SignedPayload), sig) || req.FromDID != self || req.Body != "fixture message" {
						t.Error("request lost selected identity, signature, or body")
					}
					w.Header().Set("Content-Type", tc.contentType)
					if tc.ids {
						w.Header().Set("X-Request-ID", "req-fixture")
						w.Header().Set("Cf-Ray", "ray-fixture")
					}
					if tc.mitigated != "" {
						w.Header().Set("Cf-Mitigated", tc.mitigated)
					}
					w.Header().Set("Set-Cookie", "response-secret-cookie")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(tc.body))
				case "/v1/agents/heartbeat":
					w.WriteHeader(200)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			home := t.TempDir()
			writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
			run := exec.CommandContext(ctx, bin, "mail", "send", "--to", "alice", "--body", "fixture message")
			run.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AW_TRACE=0")
			run.Dir = home
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatal("error response exited successfully")
			}
			if len(out) > 1024 {
				t.Fatalf("error output has %d bytes; limit is 1024", len(out))
			}
			for _, want := range []string{"403", tc.want} {
				if !strings.Contains(string(out), want) {
					t.Errorf("missing %q in %s", want, out)
				}
			}
			if tc.ids {
				for _, want := range []string{"x-request-id: req-fixture", "cf-ray: ray-fixture"} {
					if !strings.Contains(string(out), want) {
						t.Errorf("missing %q in %s", want, out)
					}
				}
			}
			if tc.mitigated != "" && !strings.Contains(string(out), "cf-mitigated: challenge") {
				t.Errorf("missing challenge header: %s", out)
			}
			for _, secret := range []string{"private-response-content", "response-secret-cookie", "<html>"} {
				if strings.Contains(string(out), secret) {
					t.Errorf("error exposed response body/credential: %s", out)
				}
			}
			if tc.mitigated == "" && (strings.Contains(string(out), "WAF") || strings.Contains(string(out), "managed challenge")) {
				t.Errorf("unfounded provider attribution: %s", out)
			}
			if posts.Load() != 1 {
				t.Fatalf("403 triggered %d sends; want exactly 1", posts.Load())
			}
		})
	}
}
