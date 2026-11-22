package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestMailContinuationUsesCurrentGlobalKeyAfterRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	oldPublic, oldKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stableID := awid.ComputeStableID(oldPublic)
	newDID := awid.ComputeDIDKey(newPublic)
	const team = "backend:example.test"
	const conversation = "0a3d0ed7-53f0-4a34-bad3-2164643674fd"
	posted := make(chan struct{}, 4)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isRead := r.Method == http.MethodGet && (r.URL.Path == "/v1/conversations" || r.URL.Path == "/v1/messages/conversations/"+conversation)
		if !isRead && (r.URL.Path != "/v1/messages" || r.Method != http.MethodPost) {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-AWID-Team-Certificate") != "" || r.Header.Get("X-AWEB-DID-AW") != stableID ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey "+newDID+" ") {
			t.Error("continuation did not select the current global identity credential")
			http.Error(w, "wrong credential", http.StatusUnauthorized)
			return
		}
		if isRead {
			// A server without either advisory projection can still resolve
			// a plaintext continuation by its stored conversation ID.
			http.NotFound(w, r)
			return
		}
		posted <- struct{}{}
		var req awid.SendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ConversationID != conversation || req.NewConversation {
			t.Errorf("wrong continuation: %+v, %v", req, err)
			http.Error(w, "wrong continuation", http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "sent-message", ConversationID: conversation, Status: "delivered"}); err != nil {
			t.Error(err)
		}
	}))
	dir, home := t.TempDir(), t.TempDir()
	writeSelectionFixtureForTest(t, dir, testSelectionFixture{
		AwebURL: server.URL, TeamID: team, Alias: "worker", WorkspaceID: "workspace-1",
		DID: awid.ComputeDIDKey(oldPublic), StableID: stableID, Address: "example.test/worker",
		SigningKey: oldKey, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal,
	})
	identity := awconfig.WorktreeIdentity{
		DID: newDID, StableID: stableID, Address: "example.test/worker",
		Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: "2026-05-02T00:00:00Z",
	}
	writeIdentityForTest(t, dir, identity)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), newKey); err != nil {
		t.Fatal(err)
	}
	command := func(target ...string) ([]byte, error) {
		args := []string{"mail", "send", "--body", "hello", "--plaintext", "--json"}
		cmd := exec.CommandContext(ctx, bin, append(args, target...)...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL)
		return cmd.CombinedOutput()
	}
	if out, err := command("--conversation-id", conversation); err != nil {
		t.Fatalf("continue with rotated key: %v\n%s", err, out)
	}
	if out, err := command("--conversation-id", conversation, "--team", team); err == nil || !strings.Contains(string(out), "ask the team controller to reissue") {
		t.Fatalf("explicit team should require a current certificate: %v\n%s", err, out)
	}
	if out, err := command("--to-did", awid.ComputeDIDKey(oldPublic), "--subject", "first contact"); err == nil || !strings.Contains(string(out), "does not match certificate member_did_key") {
		t.Fatalf("first contact should require the selected certificate: %v\n%s", err, out)
	}
	state := teamStateBinding(team, "worker")
	state.Memberships = append(state.Memberships, teamStateBinding("other:example.test", "worker").Memberships[0])
	writeTeamStateForTest(t, dir, state)
	if out, err := command("--conversation-id", conversation); err == nil || !strings.Contains(string(out), "pass --team") {
		t.Fatalf("multiple memberships should require explicit sender selection: %v\n%s", err, out)
	}
	writeTeamStateForTest(t, dir, teamStateBinding(team, "worker"))
	identity.StableID = awid.ComputeStableID(newPublic)
	writeIdentityForTest(t, dir, identity)
	if out, err := command("--conversation-id", conversation); err == nil || !strings.Contains(string(out), "ask the team controller to reissue") {
		t.Fatalf("a new stable identity should not use the old conversation credential: %v\n%s", err, out)
	}
	if len(posted) != 1 {
		t.Fatalf("server received %d sends, want only the global continuation", len(posted))
	}
}

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
