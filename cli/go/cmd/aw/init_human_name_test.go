package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Exercise the CLI's type/name resolution, wire payload and saved workspace.
// The HTTP fixture only issues a team certificate and acknowledges requests;
// it does not decide the human name.
func TestAgentAndHumanCreationNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, path := range []string{"api-key", "certificate", "team-create"} {
		for _, tc := range []struct {
			name, human, legacy, user, envType, want string
			flags                                    []string
		}{
			{name: "agent-env", human: "Environment Human", legacy: "Legacy Human", user: "machine-user"},
			{name: "agent-user", user: "machine-user"},
			{name: "agent-legacy", legacy: "Legacy Human"},
			{name: "agent-no-env"},
			{name: "runtime-agent", human: "Environment Human", user: "machine-user", envType: "codex"},
			{name: "explicit", human: "Environment Human", user: "machine-user", flags: []string{"--human-name", "  Chosen Name  "}, want: "Chosen Name"},
			{name: "human-env", human: "Environment Human", user: "machine-user", envType: "human", want: "Environment Human"},
			{name: "human-user", user: "machine-user", envType: "human", want: "machine-user"},
			{name: "human-legacy", legacy: "Legacy Human", envType: "human", want: "Legacy Human"},
			{name: "human-no-env", envType: "human", want: "developer"},
			{name: "human-flag", human: "Environment Human", flags: []string{"--agent-type", "human"}, want: "Environment Human"},
			{name: "human-explicit", human: "Environment Human", envType: "human", flags: []string{"--human-name", "Chosen Name"}, want: "Chosen Name"},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				// team create exposes no name/type flags; environment cases still
				// cover its first-agent bootstrap path.
				if path == "team-create" && len(tc.flags) > 0 {
					return
				}
				root := t.TempDir()
				teamPub, teamKey, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				var bodies []connectRequest
				server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					if serveAPIKeyCreationTeamRead(w, r, "backend:acme.com") {
						return
					}
					switch r.URL.Path {
					case "/api/v1/workspaces/init":
						var body apiKeyBootstrapRequest
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							return
						}
						bodies = append(bodies, connectRequest{HumanName: body.HumanName, AgentType: body.AgentType})
						cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: body.DID, Alias: "worker", IdentityScope: awid.IdentityModeLocal})
						if err != nil {
							t.Error(err)
							return
						}
						encoded, err := awid.EncodeTeamCertificateHeader(cert)
						if err != nil {
							t.Error(err)
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": "worker", "team_id": "backend:acme.com", "workspace_id": "ws-1", "did": body.DID, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "test-workspace-key"})
					case "/v1/connect":
						var body connectRequest
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							return
						}
						bodies = append(bodies, body)
						_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "alias": "worker", "agent_id": "agent-1", "workspace_id": "ws-1", "team_did_key": awid.ComputeDIDKey(teamPub)})
					case "/v1/agents/me/encryption-key":
						writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "backend:acme.com", "worker")
					case "/api/v1/discovery":
						_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": serverURL, "aweb_url": serverURL})
					default:
						t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
					}
				})
				args := []string{"init", "--name", "worker"}
				apiKey := "test-api-key"
				if path == "certificate" {
					pub, key, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					if err := awid.SaveSigningKey(filepath.Join(root, ".aw", "signing.key"), key); err != nil {
						t.Fatal(err)
					}
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: awid.ComputeDIDKey(pub), Alias: "worker", IdentityScope: awid.IdentityModeLocal})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := awconfig.SaveTeamCertificateForTeam(root, cert.Team, cert); err != nil {
						t.Fatal(err)
					}
					args = []string{"init"}
					apiKey = ""
				} else if path == "team-create" {
					args = []string{"team", "create", "worker"}
					apiKey = "test-api-key"
				}
				args = append(args, tc.flags...)
				args = append(args, "--json")
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = root
				cmd.Env = append(idCreateCommandEnv(root), "AWEB_URL="+server.URL, "AWEB_API_KEY="+apiKey, "AWID_REGISTRY_URL=", "AWEB_HUMAN="+tc.human, "AWEB_HUMAN_NAME="+tc.legacy, "USER="+tc.user, "AWEB_AGENT_TYPE="+tc.envType, "AW_NO_UPDATE_CHECK=1")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("creation: %v\n%s", err, out)
				}
				if len(bodies) == 0 {
					t.Fatal("no creation request")
				}
				for i, body := range bodies {
					if body.HumanName != tc.want {
						t.Errorf("request %d human_name=%q, want %q", i, body.HumanName, tc.want)
					}
				}
				ws, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(root, ".aw", "workspace.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				if ws.HumanName != tc.want {
					t.Errorf("saved human_name=%q, want %q", ws.HumanName, tc.want)
				}
			})
		}
	}
}
