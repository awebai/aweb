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
	"strings"
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
		invoke func(string) error
	}{
		{"connect", func(base string) error {
			_, err := postConnect(context.Background(), base, key, cert, connectRequest{})
			return err
		}},
		{"replace_key", func(base string) error {
			_, err := postLocalIdentityKeyReplacementOnce(context.Background(), base, "alice", localIdentityKeyReplacementRequest{TeamID: cert.Team}, key)
			return err
		}},
		{"remove_member", func(base string) error {
			_, err := postHostedTeamRemoveMember(context.Background(), base, "secret", cert.Team, hostedTeamRemoveMemberRequest{})
			return err
		}},
		{"register", func(base string) error {
			return postTeamRegister(context.Background(), base+"/v1/teams/service-register", map[string]any{"controller_signature": "test"}, &map[string]any{})
		}},
		{"cleanup", func(base string) error {
			return postTeamCleanupCloud(context.Background(), base, map[string]any{"controller_signature": "test"}, &map[string]any{})
		}},
		{"init", func(base string) error {
			_, err := postAPIKeyWorkspaceInit(context.Background(), base, "secret", apiKeyBootstrapRequest{}, testWorkspaceInitKey)
			return err
		}},
		{"removal_operation", func(base string) error {
			_, err := doHostedRemovalRequest(context.Background(), "POST", base, "secret", cert.Team, "/agents/removals", map[string]string{"alias": "alice"})
			return err
		}},
		{"retire", func(base string) error {
			_, err := postSelfRetireWithAPIKey(context.Background(), selfRetirePlan{awebURL: base, teamID: cert.Team, apiKey: "secret", alias: "alice"})
			return err
		}},
		{"invite_preview", func(base string) error {
			_, err := inspectHostedInvite(context.Background(), "token", hostedJoinTokenEnvelope{AwebURL: base, InnerToken: "token"})
			return err
		}},
		{"account_form", func(base string) error {
			return postCLIAuthForm(context.Background(), base, "/oauth/token", url.Values{"grant_type": {"test"}}, "secret", &map[string]any{})
		}},
		{"account_json", func(base string) error {
			return postCLIAuthJSON(context.Background(), base, workspaceTeamEnsurePath, "secret", map[string]string{"team": "test"}, &map[string]any{})
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
				// Discovery is cached by complete base for the process. A unique
				// mount keeps this fixture cold even if a closed listener's port
				// is reused by another case or a repeated test run.
				mount := "/" + base64.RawURLEncoding.EncodeToString([]byte(t.TempDir()))
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == mount+"/health" {
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
					if tc.name == "connect" {
						payload := requestSigningPayloadForTest(t, r, body)
						auth := strings.Fields(r.Header.Get("Authorization"))
						if len(auth) != 3 {
							t.Error("missing connect credential")
						} else {
							signature, err := base64.RawStdEncoding.DecodeString(auth[2])
							if err != nil || !ed25519.Verify(pub, payload, signature) {
								t.Error("connect signature does not bind target and decoded body")
							}
						}
					}
					if tc.name != "account_form" && !json.Valid(body) {
						t.Errorf("invalid decoded JSON: %q", body)
					}
					w.Write([]byte(`{}`))
				}))
				defer srv.Close()
				awid.ForgetRequestCompression(srv.URL)
				// Endpoint-specific response validation is exercised by the existing
				// tests; this matrix pins each real sender's negotiated wire boundary.
				base := srv.URL + mount
				err := tc.invoke(base)
				wantProbes := int32(1)

				if writes.Load() != 1 || probes.Load() != wantProbes {
					t.Errorf("writes=%d probes=%d sender_error=%v", writes.Load(), probes.Load(), err)
				}
				// The same sender must reuse both positive and negative discovery
				// without replaying a write or probing again.
				err = tc.invoke(base)
				if writes.Load() != 2 || probes.Load() != wantProbes {
					t.Errorf("warm writes=%d probes=%d sender_error=%v", writes.Load(), probes.Load(), err)
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
			awid.ForgetRequestCompression(srv.URL)
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

func TestRequestCompressionUsesActuallySelectedFallbackBase(t *testing.T) {
	for _, alreadyRecovered := range []bool{true, false} {
		name := "recover_after_404"
		if alreadyRecovered {
			name = "already_recovered"
		}
		t.Run(name, func(t *testing.T) {
			var configuredProbes, recoveredProbes, configuredWrites, recoveredWrites atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/health":
					configuredProbes.Add(1)
					w.Header().Set("Accept-Encoding", "gzip")
				case "/health":
					recoveredProbes.Add(1)
				case "/api/v1/agents/heartbeat":
					w.WriteHeader(404)
				case "/v1/agents/heartbeat":
					w.WriteHeader(405)
				case "/api/v1/test":
					configuredWrites.Add(1)
					if r.Header.Get("Content-Encoding") != "gzip" {
						t.Error("configured mount did not use its advertisement")
					}
					w.WriteHeader(404)
				case "/v1/test":
					recoveredWrites.Add(1)
					if r.Header.Get("Content-Encoding") != "" {
						t.Error("recovered base inherited another mount's advertisement")
					}
					w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			awid.ForgetRequestCompression(srv.URL)
			configured := srv.URL + "/api"
			current := configured
			if alreadyRecovered {
				current = srv.URL
			}
			state := &baseURLFallbackState{configuredBaseURL: configured, currentBaseURL: current}
			transport := &baseURLFallbackTransport{base: awid.NewAPITransport(), state: state}
			c, _ := awid.New(configured)
			c.SetHTTPClient(&http.Client{Transport: transport})
			resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", map[string]string{"body": "test"})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			expectedConfigured := int32(1)
			if alreadyRecovered {
				expectedConfigured = 0
			}
			if configuredWrites.Load() != expectedConfigured || configuredProbes.Load() != expectedConfigured || recoveredWrites.Load() != 1 || recoveredProbes.Load() != 1 {
				t.Errorf("configured=%d/%d recovered=%d/%d", configuredWrites.Load(), configuredProbes.Load(), recoveredWrites.Load(), recoveredProbes.Load())
			}
		})
	}
}

func TestCompressionDiscoveryDoesNotTriggerBaseRecovery(t *testing.T) {
	var probes, writes, recovery atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			probes.Add(1)
			w.WriteHeader(404)
		case "/api/v1/test":
			writes.Add(1)
			if r.Header.Get("Content-Encoding") != "" {
				t.Error("unsupported base got gzip")
			}
			w.Write([]byte(`{}`))
		default:
			recovery.Add(1)
			w.Header().Set("Accept-Encoding", "gzip")
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	awid.ForgetRequestCompression(srv.URL)
	base := srv.URL + "/api"
	state := &baseURLFallbackState{configuredBaseURL: base, currentBaseURL: base}
	c, _ := awid.New(base)
	c.SetHTTPClient(&http.Client{Transport: &baseURLFallbackTransport{base: awid.NewAPITransport(), state: state}})
	resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", map[string]string{"body": "test"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if probes.Load() != 1 || writes.Load() != 1 || recovery.Load() != 0 || state.current() != base {
		t.Errorf("health=%d writes=%d recovery=%d current=%s", probes.Load(), writes.Load(), recovery.Load(), state.current())
	}
}

func TestFallbackRequestCompressionRefusalClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		disable bool
	}{
		{"unsupported", 415, "Unsupported Content-Encoding", true},
		{"decoder", 400, "Invalid gzip request body", true},
		{"application", 400, `{"detail":"bad state"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probes, writes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Accept-Encoding", "gzip")
				if r.URL.Path == "/health" {
					probes.Add(1)
					return
				}
				n := writes.Add(1)
				if got := r.Header.Get("Content-Encoding") == "gzip"; got != (n == 1 || !tc.disable) {
					t.Errorf("write %d compressed=%v", n, got)
				}
				if n == 1 {
					w.WriteHeader(tc.status)
					w.Write([]byte(tc.body))
					return
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			awid.ForgetRequestCompression(srv.URL)
			state := &baseURLFallbackState{configuredBaseURL: srv.URL, currentBaseURL: srv.URL}
			c, _ := awid.New(srv.URL)
			c.SetHTTPClient(&http.Client{Transport: &baseURLFallbackTransport{base: awid.NewAPITransport(), state: state}})
			for n := 0; n < 2; n++ {
				resp, err := c.DoRaw(context.Background(), "POST", "/v1/messages", "application/json", map[string]string{"message_id": "test-id", "body": "test"})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 && (resp.StatusCode != tc.status || string(body) != tc.body) {
					t.Errorf("refusal changed: status=%d body=%q", resp.StatusCode, body)
				}
			}
			if writes.Load() != 2 || probes.Load() != 1 {
				t.Errorf("writes=%d probes=%d", writes.Load(), probes.Load())
			}
		})
	}
}
