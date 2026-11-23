package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInviteRetryAndRecovery(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, context.Background(), bin)
	for _, flow := range []string{"join-from", "init-invite", "accept-invite", "positional-invite"} {
		for _, answer := range []struct {
			name       string
			status     int
			reason     string
			refusals   int
			firstPosts int
			recovery   bool
		}{
			{"overlap-clears", http.StatusConflict, "registry_operation_in_progress", 1, 2, false},
			{"overlap-exhausted", http.StatusConflict, "registry_operation_in_progress", 3, 3, true},
			{"incomplete", http.StatusServiceUnavailable, "registry_operation_incomplete", 1, 1, true},
			{"name-exists", http.StatusConflict, "name_exists", 1, 1, false},
		} {
			if flow == "positional-invite" && answer.name != "incomplete" {
				continue
			}
			t.Run(flow+"/"+answer.name, func(t *testing.T) {
				const teamID = "shared:aweb.ai"
				const token = "aw_inv_fixture_original"
				const alias = "target"
				message := "The service could not complete this acceptance."
				if answer.reason == "registry_operation_in_progress" {
					message = "Another change overlaps this request. Repeat the same request shortly."
				}
				teamPub, teamKey, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				var mu sync.Mutex
				var requests [][]byte
				mints := 0
				server := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					switch r.URL.Path {
					case "/api/v1/spawn/create-invite":
						mints++
						_ = json.NewEncoder(w).Encode(awid.SpawnCreateInviteResponse{
							InviteID: "invite-hosted", Token: token, ServerURL: origin,
						})
					case "/api/v1/spawn/invite-preview":
						writeLegacyHostedPreviewForTest(t, w, r, teamID, origin)
					case "/api/v1/spawn/accept-invite":
						if r.Method != http.MethodPost {
							t.Error("acceptance must POST")
						}
						raw, readErr := io.ReadAll(r.Body)
						var request awid.SpawnAcceptInviteRequest
						if readErr != nil || json.Unmarshal(raw, &request) != nil {
							t.Error("could not decode acceptance request")
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						requests = append(requests, raw)
						if request.Token != token || request.Alias != alias || request.DID == "" {
							t.Error("acceptance changed token, name or key")
						}
						if len(requests) <= answer.refusals {
							w.WriteHeader(answer.status)
							_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]string{
								"code": answer.reason, "message": message,
							}})
							return
						}
						cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
							Team: teamID, MemberDIDKey: request.DID, Alias: alias, IdentityScope: awid.IdentityModeLocal,
						})
						if err != nil {
							t.Error(err)
							return
						}
						encoded, err := awid.EncodeTeamCertificateHeader(cert)
						if err != nil {
							t.Error(err)
							return
						}
						_ = json.NewEncoder(w).Encode(awid.SpawnAcceptInviteResponse{
							TeamID: teamID, TeamSlug: "shared", Namespace: "aweb.ai", NamespaceSlug: "aweb",
							IdentityID: "target-id", Alias: alias, ServerURL: origin, DID: request.DID,
							Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, Created: true, TeamCert: encoded,
						})
					case "/v1/connect":
						_ = json.NewEncoder(w).Encode(map[string]string{
							"team_id": teamID, "alias": alias, "agent_id": "agent-target",
							"workspace_id": "workspace-target", "team_did_key": awid.ComputeDIDKey(teamPub),
						})
					default:
						if strings.HasSuffix(r.URL.Path, "/encryption-key") {
							writePublishEncryptionKeyResponseForTest(t, w, "agent-target", teamID, alias)
						} else {
							http.NotFound(w, r)
						}
					}
				})

				target := t.TempDir()
				privateFile := filepath.Join(target, "join token.txt")
				if err := os.WriteFile(privateFile, []byte(token+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				tokenFlags := []string{"--token-file", privateFile, "--name", alias}
				var args, recovery []string
				displayPrefix := []string{"aw"}
				switch flow {
				case "join-from":
					source := t.TempDir()
					pub, key, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					writeSelectionFixtureForTest(t, source, testSelectionFixture{
						AwebURL: server.URL, TeamID: teamID, Alias: "source", WorkspaceID: "workspace-source",
						DID: awid.ComputeDIDKey(pub), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key,
					})
					bindingPath := awconfig.WorktreeWorkspacePath(source)
					binding, err := awconfig.LoadWorktreeWorkspaceFrom(bindingPath)
					if err != nil {
						t.Fatal(err)
					}
					binding.APIKey = "aw_sk_fixture"
					if err := awconfig.SaveWorktreeWorkspaceTo(bindingPath, binding); err != nil {
						t.Fatal(err)
					}
					args = []string{"init", "--join-from", source, "--join-team", teamID, "--name", alias, "--do-not-touch-agents-md"}
					recovery = args
				case "init-invite":
					args = append([]string{"init", "--do-not-touch-agents-md"}, tokenFlags...)
					recovery = append([]string{"team", "join"}, tokenFlags...)
				case "positional-invite":
					args = []string{"init", "--invite", token, "--aweb-url", server.URL, "--name", alias, "--do-not-touch-agents-md"}
					recovery = []string{"team", "join", "--token-stdin", "--name", alias}
					displayPrefix = []string{"env", "AWEB_URL=" + server.URL, "aw"}
				case "accept-invite":
					args = append([]string{"id", "team", "accept-invite"}, tokenFlags...)
					recovery = args
				}
				env := withoutEnvForTest(testCommandEnv(t.TempDir()), "AWEB_IDENTITY_HOME", "AWEB_API_KEY",
					"AWEB_URL", "AWID_REGISTRY_URL", "AWEB_ROLE_NAME", "AWEB_ROLE", "AWEB_HTTP_TIMEOUT")
				env = append(env, "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL, "AW_NO_UPDATE_CHECK=1")
				invoke := func(args []string) (string, error) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, bin, args...)
					cmd.Dir, cmd.Env = target, env
					if slices.Contains(args, "--token-stdin") {
						cmd.Stdin = strings.NewReader(token + "\n")
					}
					output, err := cmd.CombinedOutput()
					return string(output), err
				}
				checkPosts := func(want int) {
					t.Helper()
					mu.Lock()
					defer mu.Unlock()
					if len(requests) != want {
						t.Errorf("accept POSTs = %d, want %d", len(requests), want)
					}
					for i, raw := range requests {
						if i > 0 && !bytes.Equal(raw, requests[0]) {
							t.Error("replay changed the acceptance payload")
						}
					}
					if (flow == "join-from" && mints != 1) || (flow != "join-from" && mints != 0) {
						t.Errorf("minted %d invitations in %s", mints, flow)
					}
				}

				output, err := invoke(args)
				if (err == nil) != (answer.name == "overlap-clears") {
					t.Errorf("first command returned %v: %s", err, output)
				}
				checkPosts(answer.firstPosts)
				if err != nil && !strings.Contains(output, message) {
					t.Errorf("missing typed refusal text: %s", output)
				}
				next := formatShellCommand(append(displayPrefix, recovery...))
				if !answer.recovery {
					if strings.Contains(output, next) {
						t.Errorf("unexpected recovery command: %s", output)
					}
					return
				}
				if strings.Count(output, next) != 1 || strings.Contains(output, token) {
					t.Errorf("want one usable recovery command and no token: %s", output)
				}
				keyPath := awconfig.WorktreeSigningKeyPath(target)
				key, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				if output, err := invoke([]string{"init"}); err == nil {
					t.Errorf("bare init reported success on an unaccepted invite: %s", output)
				}
				checkPosts(answer.firstPosts)
				if output, err := invoke(recovery); err != nil {
					t.Fatalf("recovery failed: %v: %s", err, output)
				}
				checkPosts(answer.firstPosts + 1)
				replayedKey, err := os.ReadFile(keyPath)
				if err != nil || !bytes.Equal(key, replayedKey) {
					t.Fatalf("recovery did not retain the key: %v", err)
				}
				if _, err := os.Stat(awconfig.TeamCertificatePath(target, teamID)); err != nil {
					t.Fatalf("membership certificate after recovery: %v", err)
				}
				if flow != "accept-invite" {
					if _, err := os.Stat(awconfig.WorktreeWorkspacePath(target)); err != nil {
						t.Fatalf("workspace after recovery: %v", err)
					}
				}
			})
		}
	}
}
