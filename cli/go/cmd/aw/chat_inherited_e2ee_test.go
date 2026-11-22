package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A chat continuation inherits its conversation's encryption: once a session
// carries an end-to-end encrypted message, every later message to it is
// encrypted unless --plaintext says otherwise, and aw says so in one line when
// it does (adje.3 3.10, ruled by Antares d0e3fe47 item 4).
func TestChatContinuationInheritsTheSessionsEncryption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	var sessionID string
	var posted []awid.ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		cert := requireCertificateAuthForTest(t, r)
		self, peer := actors[cert.Alias], actors["t2"]
		if cert.Alias == "t2" {
			peer = actors["t1"]
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			var assertion awid.EncryptionKeyAssertion
			if err := json.NewDecoder(r.Body).Decode(&assertion); err != nil {
				t.Error(err)
			}
			self.row.EncryptionKey = &assertion
			writePublishEncryptionKeyResponseForTest(t, w, self.row.AgentID, team, cert.Alias)
		case r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: team, Agents: []awid.AgentView{self.row, peer.row}})
		case r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			resp := awid.ChatListSessionsResponse{}
			if sessionID != "" {
				resp.Sessions = []awid.ChatSessionItem{{SessionID: sessionID, TeamID: team,
					Participants: []string{peer.row.Alias}, ParticipantDIDs: []string{peer.row.DIDKey}, ParticipantAddresses: []string{peer.row.Alias}}}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			var req awid.ChatCreateSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			sessionID = req.SessionID
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: sessionID, MessageID: req.MessageID})
		case sessionID != "" && r.URL.Path == "/v1/chat/sessions/"+sessionID+"/messages":
			if r.Method == http.MethodGet {
				// The stored rows, as a reader sees them before decrypting.
				rows := []map[string]any{}
				for _, p := range posted {
					rows = append(rows, map[string]any{"message_id": p.MessageID, "content_mode": p.ContentMode, "message_version": p.MessageVersion, "from_agent": "t1"})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"messages": rows})
				return
			}
			var req awid.ChatSendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			posted = append(posted, req)
			_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: req.MessageID, Delivered: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, alias := range []string{"t1", "t2"} {
		pub, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		a := &actor{dir: t.TempDir(), row: awid.AgentView{AgentID: "agent-" + alias, Alias: alias, DIDKey: awid.ComputeDIDKey(pub), IdentityScope: awid.IdentityModeLocal}}
		actors[alias] = a
		writeSelectionFixtureForTest(t, a.dir, testSelectionFixture{AwebURL: server.URL, TeamID: team, Alias: alias,
			WorkspaceID: a.row.AgentID, DID: a.row.DIDKey, SigningKey: key, IdentityScope: awid.IdentityModeLocal, Custody: awid.CustodySelf})
	}
	run := func(alias string, args ...string) string {
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
		return stderr.String()
	}
	last := func() awid.ChatSendMessageRequest {
		mu.Lock()
		defer mu.Unlock()
		return posted[len(posted)-1]
	}
	for _, alias := range []string{"t1", "t2"} {
		run(alias, "id", "encryption-key", "setup")
	}
	run("t1", "chat", "send-and-wait", "t2", "opening", "--plaintext", "--wait", "0")
	run("t1", "chat", "send", "--session-id", sessionID, "--e2ee", "--body", "secret")
	if last().Encrypted == nil {
		t.Fatal("the explicit --e2ee message was not encrypted")
	}

	for _, step := range []struct {
		name string
		args []string
	}{
		{name: "chat send --session-id", args: []string{"chat", "send", "--session-id", sessionID, "--body", "inherited"}},
		{name: "send-and-wait", args: []string{"chat", "send-and-wait", "t2", "inherited", "--wait", "0"}},
		{name: "extend-wait", args: []string{"chat", "extend-wait", "t2", "inherited"}},
	} {
		run("t1", step.args...)
		if got := last(); got.Encrypted == nil || got.ContentMode != awid.ContentModeEncryptedV2 || got.Body != "" {
			t.Fatalf("%s did not inherit the session's encryption: %#v", step.name, got)
		}
	}

	stderr := run("t1", "chat", "send", "--session-id", sessionID, "--plaintext", "--body", "readable")
	if got := last(); got.Encrypted != nil || got.Body != "readable" {
		t.Fatalf("--plaintext was not honoured: %#v", got)
	}
	if !strings.Contains(stderr, "server-readable plaintext into an end-to-end encrypted conversation") {
		t.Fatalf("--plaintext into an encrypted conversation was not announced; stderr=%q", stderr)
	}
}
