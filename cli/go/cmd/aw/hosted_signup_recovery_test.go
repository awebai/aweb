package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedSignupRecoveryRetainsSignerAndCredential(t *testing.T) {
	for _, failure := range []string{"connect after response", "lost signup response"} {
		t.Run(failure, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AWEB_API_KEY", "")
			t.Setenv("AWEB_IDENTITY_HOME", "")
			t.Setenv("APP_ENV", "development")
			directory := t.TempDir()
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			signupCalls, connectCalls, usernameReads := 0, 0, 0
			var frozenRequest []byte
			var retainedResponse awid.CliSignupResponse
			var didKey string
			const credential = "aw_sk_retained_signup_fixture"
			server := newLocalHTTPServerWithURL(t, func(base string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/v1/discovery":
						if err := json.NewEncoder(w).Encode(map[string]any{"onboarding_url": base, "aweb_url": base, "registry_url": base, "version": "1.7.0"}); err != nil {
							t.Error(err)
						}
					case "/api/v1/onboarding/check-username":
						usernameReads++
						if err := json.NewEncoder(w).Encode(map[string]any{"available": signupCalls == 0, "reason": "taken"}); err != nil {
							t.Error(err)
						}
					case "/api/v1/onboarding/cli-signup":
						signupCalls++
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
							return
						}
						if signupCalls == 1 {
							frozenRequest = bytes.Clone(body)
							var request awid.CliSignupRequest
							if err := json.Unmarshal(body, &request); err != nil {
								t.Error(err)
								return
							}
							didKey = request.DIDKey
							cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "default:recover.example", MemberDIDKey: didKey, Alias: "terminal", IdentityScope: awid.IdentityModeLocal})
							if err != nil {
								t.Error(err)
								return
							}
							encoded, err := awid.EncodeTeamCertificateHeader(cert)
							if err != nil {
								t.Error(err)
								return
							}
							retainedResponse = awid.CliSignupResponse{Username: "recover", TeamID: cert.Team, APIKey: credential, Certificate: encoded, Alias: "terminal", NamespaceDomain: "recover.example"}
							if failure == "lost signup response" {
								hijacker, ok := w.(http.Hijacker)
								if !ok {
									t.Error("response writer cannot interrupt transport")
									return
								}
								connection, _, err := hijacker.Hijack()
								if err != nil {
									t.Error(err)
									return
								}
								if err := connection.Close(); err != nil {
									t.Error(err)
								}
								return
							}
						} else if !bytes.Equal(body, frozenRequest) {
							t.Error("retry changed the signup request")
						}
						if err := json.NewEncoder(w).Encode(retainedResponse); err != nil {
							t.Error(err)
						}
					case "/api/v1/connect", "/v1/connect":
						connectCalls++
						if failure == "connect after response" && connectCalls == 1 {
							http.Error(w, "connect interrupted", 500)
							return
						}
						if err := json.NewEncoder(w).Encode(map[string]any{"team_id": "default:recover.example", "alias": "terminal", "agent_id": "agent-fixture", "workspace_id": "workspace-fixture", "repo_id": "repo-fixture"}); err != nil {
							t.Error(err)
						}
					case "/api/v1/agents/me/encryption-key", "/v1/agents/me/encryption-key":
						writePublishEncryptionKeyResponseForTest(t, w, "agent-fixture", "default:recover.example", "terminal")
					default:
						t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
					}
				})
			})
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			var output bytes.Buffer
			request := guidedOnboardingRequest{WorkingDir: directory, BaseURL: server.URL, Username: "recover", Alias: "terminal", NonInteractive: true, PromptOut: &output, PromptIn: strings.NewReader(""), DoNotTouchAgentsMD: true}
			if failure == "lost signup response" {
				t.Setenv("AWEB_URL", server.URL)
				request.BaseURL = ""
			}
			if _, err := executeGuidedOnboardingWizard(request); err == nil {
				t.Fatal("expected interrupted signup/install")
			}
			path := filepath.Join(directory, ".aw", "signup-recovery.json")
			record, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("original signup has no durable recovery: %v", err)
			}
			if failure == "connect after response" && !bytes.Contains(record, []byte(credential)) {
				t.Fatal("received credential not retained before connect")
			}
			for _, entry := range []struct {
				path string
				mode os.FileMode
			}{{path, 0600}, {filepath.Dir(path), 0700}} {
				info, err := os.Stat(entry.path)
				if err != nil || info.Mode().Perm() != entry.mode {
					t.Fatalf("unsafe recovery permissions: %v %v", info, err)
				}
			}
			readsBefore := usernameReads
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			binary := filepath.Join(t.TempDir(), "aw")
			buildAwBinary(t, ctx, binary)
			for _, changed := range [][]string{{"--username", "another"}, {"--global"}, {"--url", "http://127.0.0.1:1"}, {"--invite", "aw_inv_another_fixture"}} {
				args := append([]string{"init", "--json", "--do-not-touch-agents-md"}, changed...)
				refused := exec.CommandContext(ctx, binary, args...)
				refused.Dir, refused.Env = directory, idCreateCommandEnv(directory)
				diagnostic, err := refused.CombinedOutput()
				if err == nil || (!strings.Contains(string(diagnostic), "signup retry changed") && !strings.Contains(string(diagnostic), "retained signup")) {
					t.Fatalf("changed signup selection did not refuse locally: %v %v %s", changed, err, diagnostic)
				}
				if bytes.Contains(diagnostic, []byte(credential)) {
					t.Fatal("refusal printed retained credential")
				}
				kept, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(kept, record) {
					t.Fatalf("refusal changed retained signup: %v", err)
				}
			}
			diagnosis := exec.CommandContext(ctx, binary, "doctor", "--offline", "--json")
			diagnosis.Dir, diagnosis.Env = directory, idCreateCommandEnv(directory)
			diagnosed, diagnosisErr := diagnosis.CombinedOutput()
			var report doctorOutput
			if err := json.Unmarshal(diagnosed, &report); err != nil {
				t.Fatalf("doctor diagnosis: %v %v %s", err, diagnosisErr, diagnosed)
			}
			foundRecovery := false
			for _, check := range report.Checks {
				if check.ID == doctorCheckSignupRecovery {
					foundRecovery = strings.Contains(check.NextStep, "aw init") && strings.Contains(check.NextStep, "signup-recovery.json")
				}
			}
			if !foundRecovery || bytes.Contains(diagnosed, []byte(credential)) {
				t.Fatalf("doctor lost or exposed recovery: %s", diagnosed)
			}
			command := exec.CommandContext(ctx, binary, "init", "--json", "--do-not-touch-agents-md", "--url", server.URL, "--write-context=false")
			command.Dir, command.Env = directory, idCreateCommandEnv(directory)
			if raw, err := command.CombinedOutput(); err != nil {
				t.Fatalf("command resume: %v %s", err, raw)
			}
			if _, err := os.Stat(filepath.Join(directory, ".aw", "context")); !os.IsNotExist(err) {
				t.Fatalf("init ignored --write-context=false: %v", err)
			}
			if usernameReads != readsBefore {
				t.Fatal("resume rechecked a now-allocated username")
			}
			expectedCalls := 1
			if failure == "lost signup response" {
				expectedCalls = 2
			}
			if signupCalls != expectedCalls {
				t.Fatalf("signup calls=%d want=%d", signupCalls, expectedCalls)
			}
			key, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(directory))
			if err != nil {
				t.Fatal(err)
			}
			if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != didKey {
				t.Fatal("resume replaced the original signer")
			}
			workspace, err := awconfig.LoadWorktreeWorkspaceFrom(awconfig.WorktreeWorkspacePath(directory))
			if err != nil {
				t.Fatal(err)
			}
			if workspace.APIKey != credential {
				t.Fatal("connected workspace lost its credential")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("completed signup retained recovery: %v", err)
			}
			if strings.Contains(output.String(), credential) {
				t.Fatal("recovery credential was printed")
			}
		})
	}
}
