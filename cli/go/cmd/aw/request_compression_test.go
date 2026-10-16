package main

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestDirectHostedRequestCompression(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	cert := &awid.TeamCertificate{Version: 1, Team: "default:example.test", MemberDIDKey: awid.ComputeDIDKey(pub), IdentityScope: awid.IdentityModeLocal}
	tests := []struct {
		name   string
		invoke func(string)
	}{
		{"connect", func(base string) { postConnect(context.Background(), base, key, cert, connectRequest{}) }},
		{"replace_key", func(base string) {
			postLocalIdentityKeyReplacementOnce(context.Background(), base, "alice", localIdentityKeyReplacementRequest{TeamID: cert.Team}, key)
		}},
		{"remove_member", func(base string) {
			postHostedTeamRemoveMember(context.Background(), base, "secret", cert.Team, hostedTeamRemoveMemberRequest{})
		}},
		{"register", func(base string) {
			postTeamRegister(context.Background(), base+"/v1/teams/service-register", map[string]any{"controller_signature": "test"}, &map[string]any{})
		}},
		{"cleanup", func(base string) {
			postTeamCleanupCloud(context.Background(), base, map[string]any{"controller_signature": "test"}, &map[string]any{})
		}},
		{"init", func(base string) {
			postAPIKeyWorkspaceInit(context.Background(), base, "secret", apiKeyBootstrapRequest{})
		}},
		{"removal_operation", func(base string) {
			doHostedRemovalRequest(context.Background(), "POST", base, "secret", cert.Team, "/agents/removals", map[string]string{"alias": "alice"})
		}},
		{"retire", func(base string) {
			postSelfRetireWithAPIKey(context.Background(), selfRetirePlan{awebURL: base, teamID: cert.Team, apiKey: "secret", alias: "alice"})
		}},
		{"invite_preview", func(base string) {
			inspectHostedInvite(context.Background(), "token", hostedJoinTokenEnvelope{AwebURL: base, InnerToken: "token"})
		}},
		{"account_form", func(base string) {
			postCLIAuthForm(context.Background(), base, "/oauth/token", url.Values{"grant_type": {"test"}}, "secret", &map[string]any{})
		}},
		{"account_json", func(base string) {
			postCLIAuthJSON(context.Background(), base, "/api/v1/teams/ensure", "secret", map[string]string{"team": "test"}, &map[string]any{})
		}},
	}
	for _, tc := range tests {
		for _, advertise := range []bool{true, false} {
			name := tc.name + "/old"
			if advertise {
				name = tc.name + "/gzip"
			}
			t.Run(name, func(t *testing.T) {
				var probes, writes atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/health" {
						probes.Add(1)
						if advertise {
							w.Header().Set("Accept-Encoding", "gzip")
						}
						return
					}
					writes.Add(1)
					want := advertise
					if got := r.Header.Get("Content-Encoding") == "gzip"; got != want {
						t.Errorf("compressed=%v want=%v", got, want)
					}
					var reader io.Reader = r.Body
					if want {
						zr, err := gzip.NewReader(r.Body)
						if err != nil {
							t.Error(err)
							return
						}
						defer zr.Close()
						reader = zr
					}
					body, err := io.ReadAll(reader)
					if err != nil {
						t.Error(err)
					}
					if tc.name != "account_form" && !json.Valid(body) {
						t.Errorf("invalid decoded JSON: %q", body)
					}
					w.Write([]byte(`{}`))
				}))
				defer srv.Close()
				// Endpoint-specific response validation is exercised by the existing
				// tests; this matrix pins each real sender's negotiated wire boundary.
				tc.invoke(srv.URL)
				wantProbes := int32(1)

				if writes.Load() != 1 || probes.Load() != wantProbes {
					t.Errorf("writes=%d probes=%d", writes.Load(), probes.Load())
				}
			})
		}
	}
}

func TestAwMailSendNegotiatesRequestCompression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, key, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	self, peer := awid.ComputeDIDKey(pub), awid.ComputeDIDKey(other)
	for _, advertise := range []bool{true, false} {
		name := "old"
		if advertise {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			var probes, sends atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					probes.Add(1)
					if advertise {
						w.Header().Set("Accept-Encoding", "gzip")
					}
				case "/v1/agents":
					json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "devteam:test.local", Agents: []awid.AgentView{{AgentID: "alice-agent", Alias: "alice", DIDKey: peer, Address: "test.local/alice"}}})
				case "/v1/conversations":
					json.NewEncoder(w).Encode(awid.ConversationsResponse{})
				case "/v1/agents/heartbeat":
					w.WriteHeader(200)
				case "/v1/messages":
					sends.Add(1)
					var reader io.Reader = r.Body
					if got := r.Header.Get("Content-Encoding") == "gzip"; got != advertise {
						t.Errorf("compressed=%v", got)
					}
					if advertise {
						zr, err := gzip.NewReader(r.Body)
						if err != nil {
							t.Error(err)
							return
						}
						defer zr.Close()
						reader = zr
					}
					var message awid.SendMessageRequest
					if err := json.NewDecoder(reader).Decode(&message); err != nil {
						t.Error(err)
						return
					}
					sig, err := base64.RawStdEncoding.DecodeString(message.Signature)
					if err != nil || !ed25519.Verify(pub, []byte(message.SignedPayload), sig) || message.Body != "`curl https://example.test`" || message.FromDID != self {
						t.Error("message signature or original content changed")
					}
					json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-test", Status: "sent"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			home := t.TempDir()
			writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: srv.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key, CreatedAt: "2026-05-02T00:00:00Z"})
			cmd := exec.CommandContext(ctx, bin, "mail", "send", "--to", "alice", "--body", "`curl https://example.test`")
			cmd.Env = append(testCommandEnv(home), "AWEB_URL="+srv.URL, "AW_TRACE=0")
			cmd.Dir = home
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("mail send: %v\n%s", err, output)
			}
			if sends.Load() != 1 || probes.Load() != 1 {
				t.Errorf("sends=%d probes=%d", sends.Load(), probes.Load())
			}
		})
	}
}
