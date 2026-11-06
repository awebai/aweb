package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Exercise the real CLI with the documented team-key HTTP boundary. The
// fixture is a controller for one existing team, not the hosted implementation.
func TestInitTeamAPIKeySecondAgentCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const team = "default:example.test"
	var mu sync.Mutex
	initialized := map[string]string{}
	var connects []string
	server := newLocalHTTPServerHandlerWithURL(t, func(base string, w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, team) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			auth := r.Header.Get("Authorization")
			if auth != "Bearer synthetic-team-key-1" && auth != "Bearer synthetic-team-key-2" {
				t.Error("wrong provisioning authority")
				http.Error(w, "unauthorized", 401)
				return
			}
			var body apiKeyBootstrapRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				http.Error(w, "invalid", 400)
				return
			}
			public, err := base64.StdEncoding.DecodeString(body.PublicKey)
			if err != nil || body.DID != awid.ComputeDIDKey(ed25519.PublicKey(public)) {
				t.Error("member DID mismatch")
				http.Error(w, "invalid", 400)
				return
			}
			alias := body.Alias
			if alias == "" {
				alias = "bob"
			}
			if initialized[alias] != "" {
				t.Error("duplicate identity request")
				http.Error(w, "conflict", 409)
				return
			}
			initialized[alias] = body.DID
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team, MemberDIDKey: body.DID, Alias: alias, IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Error(err)
				http.Error(w, "certificate", 500)
				return
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Error(err)
				http.Error(w, "certificate", 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"server_url": base, "team_cert": encoded, "alias": alias, "team_id": team, "workspace_id": "ws-" + alias, "did": body.DID, "identity_scope": "local", "custody": "self", "api_key": "synthetic-workspace-key-" + alias})
		case "/v1/connect":
			cert := requireCertificateAuthForTest(t, r)
			if cert.Team != team || cert.MemberDIDKey != initialized[cert.Alias] {
				t.Error("connected wrong team/member")
			}
			if err := awid.VerifyTeamCertificate(cert, teamPub); err != nil {
				t.Error(err)
			}
			connects = append(connects, cert.Alias)
			json.NewEncoder(w).Encode(map[string]any{"team_id": team, "alias": cert.Alias, "agent_id": "agent-" + cert.Alias, "workspace_id": "ws-" + cert.Alias, "team_did_key": awid.ComputeDIDKey(teamPub)})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/me/encryption-key":
			cert := requireCertificateAuthForTest(t, r)
			writePublishEncryptionKeyResponseForTest(t, w, "agent-"+cert.Alias, team, cert.Alias)
		default:
			t.Errorf("unexpected endpoint (including new-team/signup): %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	var memberDIDs []string
	for _, tc := range []struct {
		key, name, alias, envAlias string
		jsonOutput                 bool
	}{
		{"synthetic-team-key-1", "", "bob", "", false},
		{"synthetic-team-key-1", "sharedkey", "sharedkey", "", false},
		{"synthetic-team-key-2", "secondagent", "secondagent", "", false},
		{"synthetic-team-key-2", "", "envname", "envname", false},
		{"synthetic-team-key-2", "jsonagent", "jsonagent", "", true},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			dir, home := t.TempDir(), t.TempDir()
			args := []string{"init", "--aweb-url", server.URL, "--awid-registry", server.URL, "--do-not-touch-agents-md"}
			if tc.name != "" {
				args = append(args, "--name", tc.name)
			}
			if tc.jsonOutput {
				args = append(args, "--json")
			}
			run := exec.CommandContext(ctx, bin, args...)
			run.Dir = dir
			// No ambient identity, credentials, alias, dotenv or proxy settings.
			run.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USER=fixture", "AW_NO_UPDATE_CHECK=1", "AWEB_API_KEY=" + tc.key}
			if tc.envAlias != "" {
				run.Env = append(run.Env, "AWEB_ALIAS="+tc.envAlias)
			}
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("init: %v %s", err, out)
			}
			state, err := awconfig.LoadTeamState(dir)
			if err != nil || state.ActiveTeam != team || len(state.Memberships) != 1 {
				t.Fatalf("persisted team=%+v: %v", state, err)
			}
			cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(dir, team))
			if err != nil || cert.Team != team || cert.Alias != tc.alias {
				t.Fatalf("persisted cert=%+v: %v", cert, err)
			}
			signing, err := awid.LoadSigningKey(filepath.Join(dir, ".aw", "signing.key"))
			if err != nil {
				t.Fatal(err)
			}
			did := awid.ComputeDIDKey(signing.Public().(ed25519.PublicKey))
			if cert.MemberDIDKey != did {
				t.Fatal("certificate not bound to local signing key")
			}
			memberDIDs = append(memberDIDs, did)
			if tc.jsonOutput {
				var result connectOutput
				if err := json.Unmarshal(out, &result); err != nil || result.TeamID != team || result.Alias != tc.alias || result.Status != "connected" {
					t.Fatalf("JSON output: %v %s", err, out)
				}
				return
			}
			named := bytes.Contains(out, []byte(fmt.Sprintf("Your agent is named %s", tc.alias)))
			if named != (tc.name == "" && tc.envAlias == "") {
				t.Fatalf("server-assigned name notice: %s", out)
			}
			if !bytes.Contains(out, []byte("create one from the dashboard")) || !bytes.Contains(out, []byte("aw team invite")) || bytes.Contains(out, []byte("separate team")) {
				t.Fatalf("key-based second-agent advice: %s", out)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if len(initialized) != len(memberDIDs) || len(connects) != len(memberDIDs) {
		t.Fatalf("init/connect members=%v/%v", initialized, connects)
	}
	for i, did := range memberDIDs {
		for _, other := range memberDIDs[i+1:] {
			if did == other {
				t.Fatalf("agents must have distinct signing identities: %v", memberDIDs)
			}
		}
	}
}
