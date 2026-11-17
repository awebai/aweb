package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// An encrypted first chat to a teammate's alias, now that the alias is first
// confirmed in the agent list, still creates the session for the alias,
// encrypted to the key the roster row for that alias publishes. The teammate
// is team-only: no registry holds its key.
func TestChatE2EEFirstContactByAliasEncryptsToTheConfirmedTeammate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)

	const team = "members:local.test"
	type actor struct {
		dir string
		row awid.AgentView
	}
	actors := map[string]*actor{}
	var mu sync.Mutex
	var created *awid.ChatCreateSessionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		cert := requireCertificateAuthForTest(t, r)
		self := actors[cert.Alias]
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			var assertion awid.EncryptionKeyAssertion
			if err := json.NewDecoder(r.Body).Decode(&assertion); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			self.row.EncryptionKey = &assertion
			writePublishEncryptionKeyResponseForTest(t, w, self.row.AgentID, team, cert.Alias)
		case r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: team, Agents: []awid.AgentView{actors["alice"].row, actors["bob"].row}})
		case r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			var req awid.ChatCreateSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			created = &req
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: req.SessionID, MessageID: req.MessageID})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, alias := range []string{"alice", "bob"} {
		pub, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		a := &actor{dir: t.TempDir(), row: awid.AgentView{AgentID: "agent-" + alias, Alias: alias, DIDKey: awid.ComputeDIDKey(pub), IdentityScope: awid.IdentityModeLocal}}
		actors[alias] = a
		writeSelectionFixtureForTest(t, a.dir, testSelectionFixture{AwebURL: server.URL, TeamID: team, Alias: alias,
			WorkspaceID: a.row.AgentID, DID: a.row.DIDKey, SigningKey: key, IdentityScope: awid.IdentityModeLocal, Custody: awid.CustodySelf})
	}
	run := func(alias string, args ...string) {
		t.Helper()
		a := actors[alias]
		cmd := exec.CommandContext(ctx, bin, append([]string{"--json"}, args...)...)
		cmd.Dir = a.dir
		cmd.Env = append(testCommandEnv(a.dir), "USERPROFILE="+a.dir, "AWEB_IDENTITY_HOME=", "AWID_REGISTRY_URL="+server.URL)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s %v: %v\n%s\n%s", alias, args, err, stdout.String(), stderr.String())
		}
	}
	for _, alias := range []string{"alice", "bob"} {
		run(alias, "id", "encryption-key", "setup")
	}
	run("alice", "chat", "send-and-leave", "--e2ee", "bob", "encrypted first contact")

	mu.Lock()
	defer mu.Unlock()
	bob := actors["bob"].row
	if created == nil || len(created.ToAliases) != 1 || created.ToAliases[0] != "bob" {
		t.Fatalf("session was not created for bob: %#v", created)
	}
	if created.Encrypted == nil || len(created.Encrypted.Recipients) != 1 ||
		created.Encrypted.Recipients[0].DID != bob.DIDKey ||
		created.Encrypted.Recipients[0].EncryptionKeyID != bob.EncryptionKey.EncryptionKeyID {
		t.Fatalf("not encrypted to bob's published key: %#v", created.Encrypted)
	}
}
