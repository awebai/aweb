package main

import (
	"context"
	"encoding/json"
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

// This is a CLI/HTTP wire control, not proof of server membership admission.
// Independent fixture keys establish which selected certificate was sent.
func TestMailSendSelectsStoredCertificateWithoutAWorkspaceBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	memberPublic, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	certificates := map[string]*awid.TeamCertificate{}
	currentKeys := map[string]string{}
	for _, team := range []string{"one:example.test", "two:example.test"} {
		public, private, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := awid.SignTeamCertificate(private, awid.TeamCertificateFields{Team: team, MemberDIDKey: awid.ComputeDIDKey(memberPublic), Alias: "worker", IdentityScope: awid.IdentityModeLocal})
		if err != nil {
			t.Fatal(err)
		}
		certificates[team] = cert
		currentKeys[team] = awid.ComputeDIDKey(public)
	}
	var mu sync.Mutex
	var sentTeams []string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			cert := requireCertificateAuthForTest(t, r)
			if err := awid.CheckDecodedTeamCertificate(cert, currentKeys[cert.Team]); err != nil {
				t.Error(err)
				http.Error(w, "invalid certificate", 401)
				return
			}
			var request awid.SendMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				http.Error(w, "invalid body", 400)
				return
			}
			if request.ToDID != awid.ComputeDIDKey(recipientPublic) {
				t.Error("wrong recipient DID")
			}
			mu.Lock()
			sentTeams = append(sentTeams, cert.Team)
			mu.Unlock()
			if err := json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "sent-message", ConversationID: request.ConversationID, Status: "delivered"}); err != nil {
				t.Error(err)
			}
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	dir, home := t.TempDir(), t.TempDir()
	writeIdentityForTest(t, dir, awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(memberPublic), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, CreatedAt: "2026-05-02T00:00:00Z"})
	identityHome := awconfig.WorktreeIdentityHome(dir)
	if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	state := &awconfig.TeamState{ActiveTeam: "one:example.test"}
	for _, team := range []string{"one:example.test", "two:example.test"} {
		if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(identityHome, team, certificates[team]); err != nil {
			t.Fatal(err)
		}
		state.Memberships = append(state.Memberships, awconfig.TeamMembership{TeamID: team, Alias: "worker", CertPath: awconfig.TeamCertificateRelativePath(team), AwebURL: server.URL})
	}
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, state); err != nil {
		t.Fatal(err)
	}
	for _, team := range []string{"", "two:example.test"} {
		args := []string{"mail", "send", "--to-did", awid.ComputeDIDKey(recipientPublic), "--subject", "selected sender", "--body", "hello", "--plaintext", "--json"}
		if team != "" {
			args = append(args, "--team", team)
		}
		command := exec.CommandContext(ctx, bin, args...)
		command.Dir = dir
		command.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("send with team %q: %v\n%s", team, err, output)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sentTeams) != 2 || sentTeams[0] != "one:example.test" || sentTeams[1] != "two:example.test" {
		t.Fatalf("sent teams: %v", sentTeams)
	}
	if _, err := os.Stat(filepath.Join(identityHome, "workspace.yaml")); !os.IsNotExist(err) {
		t.Fatalf("send manufactured workspace binding: %v", err)
	}
}
