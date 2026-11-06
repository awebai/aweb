package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Reproduce the released CLI path: two distinct team-only identities publish
// keys, exchange three plaintext turns, then send-and-wait discovers that same
// session for --e2ee. The service response has only the other DID and its alias,
// not a global address. No encrypted history can supply a recipient key.
func TestChatLocalSessionPlaintextThenE2EE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	buildAwBinary(t, ctx, bin)

	for _, tc := range []struct {
		name, first, second, corrupt string
	}{
		{name: "T1_to_T2", first: "t1", second: "t2"},
		{name: "T2_to_T1", first: "t2", second: "t1"},
		{name: "reassigned_alias", first: "t1", second: "t2", corrupt: "alias"},
		{name: "wrong_assertion_DID", first: "t1", second: "t2", corrupt: "did"},
		{name: "wrong_key_id", first: "t1", second: "t2", corrupt: "key_id"},
		{name: "wrong_public_key", first: "t1", second: "t2", corrupt: "public_key"},
		{name: "invalid_signature", first: "t1", second: "t2", corrupt: "signature"},
		{name: "missing_key", first: "t1", second: "t2", corrupt: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const team = "members:local.test"
			type actor struct {
				dir string
				row awid.AgentView
			}
			actors := map[string]*actor{}
			var mu sync.Mutex
			var sessionID string
			var posted []awid.ChatSendMessageRequest
			creates := 0
			corrupt := false
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
				peer := actors[tc.second]
				if cert.Alias == tc.second {
					peer = actors[tc.first]
				}
				switch {
				case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
					var assertion awid.EncryptionKeyAssertion
					if err := json.NewDecoder(r.Body).Decode(&assertion); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if err := awid.VerifyEncryptionKeyAssertion(&assertion, self.row.DIDKey, "", time.Now()); err != nil {
						t.Error(err)
					}
					self.row.EncryptionKey = &assertion
					writePublishEncryptionKeyResponseForTest(t, w, self.row.AgentID, team, cert.Alias)
				case r.URL.Path == "/v1/agents":
					row := peer.row
					if corrupt {
						assertion := *row.EncryptionKey
						row.EncryptionKey = &assertion
						switch tc.corrupt {
						case "alias":
							row.DIDKey, row.EncryptionKey = self.row.DIDKey, self.row.EncryptionKey
						case "did":
							row.EncryptionKey = self.row.EncryptionKey
						case "key_id":
							assertion.EncryptionKeyID = self.row.EncryptionKey.EncryptionKeyID
						case "public_key":
							assertion.EncryptionPublicKey = self.row.EncryptionKey.EncryptionPublicKey
						case "signature":
							assertion.Signature = self.row.EncryptionKey.Signature
						case "missing":
							row.EncryptionKey = nil
						}
					}
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: team, Agents: []awid.AgentView{self.row, row}})
				case r.URL.Path == "/v1/chat/pending":
					_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{})
				case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
					resp := awid.ChatListSessionsResponse{}
					if sessionID != "" {
						resp.Sessions = []awid.ChatSessionItem{{SessionID: sessionID, TeamID: team,
							Participants: []string{peer.row.Alias}, ParticipantDIDs: []string{peer.row.DIDKey},
							ParticipantAddresses: []string{peer.row.Alias}}}
					}
					_ = json.NewEncoder(w).Encode(resp)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
					var req awid.ChatCreateSessionRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					creates++
					if sessionID != "" || req.Encrypted != nil || req.Message != "first plaintext" {
						t.Error("expected only the initial plaintext session creation")
					}
					sessionID = req.SessionID
					_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: sessionID, MessageID: req.MessageID})
				case r.URL.Path == "/v1/chat/sessions/"+sessionID+"/messages":
					if r.Method == http.MethodGet {
						_ = json.NewEncoder(w).Encode(awid.ChatHistoryResponse{})
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
			for _, alias := range []string{tc.first, tc.second} {
				pub, key, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				a := &actor{dir: t.TempDir(), row: awid.AgentView{AgentID: "agent-" + alias, Alias: alias, DIDKey: awid.ComputeDIDKey(pub), IdentityScope: awid.IdentityModeLocal}}
				actors[alias] = a
				writeSelectionFixtureForTest(t, a.dir, testSelectionFixture{AwebURL: server.URL, TeamID: team, Alias: alias,
					WorkspaceID: a.row.AgentID, DID: a.row.DIDKey, SigningKey: key, IdentityScope: awid.IdentityModeLocal, Custody: awid.CustodySelf})
			}
			run := func(alias string, wantSuccess bool, args ...string) []byte {
				t.Helper()
				a := actors[alias]
				cmd := exec.CommandContext(ctx, bin, append([]string{"--json"}, args...)...)
				cmd.Dir = a.dir
				cmd.Env = append(testCommandEnv(a.dir), "USERPROFILE="+a.dir, "AWEB_IDENTITY_HOME=", "AWID_REGISTRY_URL="+server.URL)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				if (err == nil) != wantSuccess {
					t.Fatalf("%s %v: %v\n%s\n%s", alias, args, err, stdout.String(), stderr.String())
				}
				return stdout.Bytes()
			}
			for _, alias := range []string{tc.first, tc.second} {
				run(alias, true, "id", "encryption-key", "setup")
			}
			first := run(tc.first, true, "chat", "send-and-wait", tc.second, "first plaintext", "--plaintext", "--wait", "0")
			var result struct {
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(first, &result); err != nil || result.SessionID == "" {
				t.Fatalf("initial session: %s (%v)", first, err)
			}
			run(tc.second, true, "chat", "send", "--session-id", result.SessionID, "--plaintext", "--body", "reply plaintext")
			run(tc.first, true, "chat", "send", "--session-id", result.SessionID, "--plaintext", "--body", "continuation plaintext")
			mu.Lock()
			corrupt = tc.corrupt != ""
			mu.Unlock()
			run(tc.first, tc.corrupt == "", "chat", "send-and-wait", tc.second, "encrypted continuation", "--e2ee", "--wait", "0")
			mu.Lock()
			defer mu.Unlock()
			if creates != 1 || len(posted) < 2 || posted[0].Body != "reply plaintext" || posted[1].Body != "continuation plaintext" {
				t.Fatalf("plaintext conversation was not preserved: creates=%d posts=%#v", creates, posted)
			}
			if tc.corrupt != "" {
				if len(posted) != 2 {
					t.Fatal("refused encryption posted a message")
				}
				return
			}
			if len(posted) != 3 || posted[2].Encrypted == nil || posted[2].Body != "" || posted[2].ContentMode != awid.ContentModeEncryptedV2 {
				t.Fatalf("expected opaque encrypted continuation: %#v", posted)
			}
			peer := actors[tc.second]
			env := posted[2].Encrypted
			if env.ConversationID != result.SessionID || len(env.Recipients) != 1 || env.Recipients[0].DID != peer.row.DIDKey || env.Recipients[0].EncryptionKeyID != peer.row.EncryptionKey.EncryptionKeyID {
				t.Fatalf("wrong session or recipient binding: %#v", env)
			}
			state, err := awconfig.LoadEncryptionKeyStateFrom(awconfig.WorktreeEncryptionStatePath(peer.dir))
			if err != nil {
				t.Fatal(err)
			}
			privateKey, err := awid.LoadX25519PrivateKey(filepath.Join(peer.dir, filepath.FromSlash(state.ActiveRecord().PrivateKeyPath)))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := awid.DecryptE2EEMessage(env, awid.E2EEDecryptIdentity{DID: peer.row.DIDKey, EncryptionKeyID: peer.row.EncryptionKey.EncryptionKeyID, PrivateKey: privateKey})
			if err != nil || strings.TrimSpace(plain.Body) != "encrypted continuation" {
				t.Fatalf("recipient decryption: %v, %#v", err, plain)
			}
		})
	}
}
