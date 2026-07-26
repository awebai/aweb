package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type messagingSignedRequest struct {
	authorization string
	timestamp     string
	method        string
	path          string
	body          []byte
}

func TestExternalIdentityHomeOutboundMessagingSignsAsPrincipal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	shadowDID := awid.ComputeDIDKey(shadowPub)
	recipientPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)

	var mu sync.Mutex
	observedRequests := []messagingSignedRequest{}
	publishedAssertions := []awid.EncryptionKeyAssertion{}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
			mu.Lock()
			observedRequests = append(observedRequests, messagingSignedRequest{authorization: auth, timestamp: r.Header.Get("X-AWEB-Timestamp"), body: body})
			mu.Unlock()
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "runtime:aweb.test", Agents: []awid.AgentView{
				{AgentID: "recipient-1", Alias: "recipient", DIDKey: recipientDID, Address: "aweb.test/recipient"},
				{AgentID: "conversation-1", Alias: "conversation-1", DIDKey: recipientDID, Address: "aweb.test/recipient"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{{
				ConversationType: "mail", ConversationID: "conversation-1", Status: "active",
				Participants: []string{"principal", "recipient"},
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{MessageID: "message-1", ConversationID: "conversation-1", FromAlias: "recipient", FromDID: recipientDID, FromAddress: "aweb.test/recipient", ToDID: principalDID, ToAddress: "aweb.test/principal", Subject: "hello", Body: "body"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "message-out", ConversationID: "conversation-1", Status: "delivered"})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "message-1", AcknowledgedAt: "2026-07-26T00:00:00Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{
				SessionID: "session-1", TeamID: "runtime:aweb.test",
				Participants: []string{"principal", "recipient"}, LastFrom: "recipient",
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{{
				SessionID: "session-1", TeamID: "runtime:aweb.test", Participants: []string{"principal", "recipient"},
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: "session-1", MessageID: "chat-out"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions/session-1/messages":
			_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: "chat-out", Delivered: true, ExtendsWaitSeconds: 120})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions/session-1/messages":
			_ = json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: []awid.ChatMessage{{MessageID: "chat-in", FromAgent: "recipient", Body: "hello", Timestamp: "2026-07-26T00:00:00Z"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions/session-1/read":
			_ = json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			var assertion awid.EncryptionKeyAssertion
			if err := json.NewDecoder(r.Body).Decode(&assertion); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			publishedAssertions = append(publishedAssertions, assertion)
			mu.Unlock()
			writePublishEncryptionKeyResponseForTest(t, w, "workspace-principal", "runtime:aweb.test", "principal")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))

	principalRoot := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", principalDID, principalKey)
	writeMessagingPrincipalForTest(t, instance, server.URL, "shadow", shadowDID, shadowKey)
	identityHome := filepath.Join(principalRoot, ".aw")
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	commands := []struct {
		name string
		args []string
	}{
		{name: "mail-send-conversation", args: []string{"mail", "send", "--conversation-id", "conversation-1", "--body", "hello"}},
		{name: "mail-send-alias", args: []string{"mail", "send", "--to", "recipient", "--body", "hello"}},
		{name: "mail-send-did", args: []string{"mail", "send", "--to-did", recipientDID, "--body", "hello"}},
		{name: "mail-send-address", args: []string{"mail", "send", "--to-address", "aweb.test/recipient", "--body", "hello"}},
		{name: "mail-reply", args: []string{"mail", "reply", "message-1", "--body", "hello"}},
		{name: "mail-ack", args: []string{"mail", "ack", "message-1"}},
		{name: "chat-send-and-wait", args: []string{"chat", "send-and-wait", "--wait", "0", "--start-conversation", "recipient", "hello"}},
		{name: "chat-send-and-leave", args: []string{"chat", "send-and-leave", "--start-conversation", "recipient", "hello"}},
		{name: "chat-send", args: []string{"chat", "send", "--session-id", "session-1", "--body", "hello"}},
		{name: "chat-extend-wait", args: []string{"chat", "extend-wait", "recipient", "hello"}},
		{name: "chat-pending", args: []string{"chat", "pending"}},
		{name: "chat-open", args: []string{"chat", "open", "recipient"}},
		{name: "chat-history", args: []string{"chat", "history", "--session-id", "session-1"}},
		{name: "chat-read", args: []string{"chat", "read", "--session-id", "session-1", "--message-id", "chat-in"}},
	}
	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			observedRequests = nil
			mu.Unlock()
			args := append([]string{"--identity-home", identityHome}, tc.args...)
			command := exec.CommandContext(ctx, bin, args...)
			command.Dir = instance
			command.Env = testCommandEnv(filepath.Join(root, "home"))
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("command failed: %v\n%s", err, out)
			}
			mu.Lock()
			requests := append([]messagingSignedRequest(nil), observedRequests...)
			mu.Unlock()
			verifyMessagingRequestsForTest(t, requests, principalPub, shadowPub, principalDID, shadowDID)
		})
	}

	if err := ensureLocalIdentityEncryptionKeyForDir(principalRoot, currentEncryptionKeyIdentityHome()); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(instance, currentEncryptionKeyIdentityHome()); err != nil {
		t.Fatal(err)
	}
	shadowBefore := fileDigestsForTest(t, filepath.Join(instance, ".aw"))
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "mail-send-e2ee", args: []string{"mail", "send", "--e2ee", "--to", "recipient", "--body", "secret"}},
		{name: "mail-reply-e2ee", args: []string{"mail", "reply", "message-1", "--e2ee", "--body", "secret"}},
		{name: "chat-send-and-wait-e2ee", args: []string{"chat", "send-and-wait", "--e2ee", "--wait", "0", "--start-conversation", "recipient", "secret"}},
		{name: "chat-send-and-leave-e2ee", args: []string{"chat", "send-and-leave", "--e2ee", "--start-conversation", "recipient", "secret"}},
		{name: "chat-send-e2ee", args: []string{"chat", "send", "--e2ee", "--session-id", "session-1", "--body", "secret"}},
		{name: "chat-extend-wait-e2ee", args: []string{"chat", "extend-wait", "--e2ee", "recipient", "secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			beforePublishes := len(publishedAssertions)
			observedRequests = nil
			mu.Unlock()
			command := exec.CommandContext(ctx, bin, append([]string{"--identity-home", identityHome}, tc.args...)...)
			command.Dir = instance
			command.Env = testCommandEnv(filepath.Join(root, "home"))
			out, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("expected recipient-without-E2EE-key failure, got success:\n%s", out)
			}
			text := string(out)
			if strings.Contains(text, "not yet identity-home-aware") {
				t.Fatalf("E2EE branch was refused before routing: %s", out)
			}
			if !strings.Contains(text, "has no E2E encryption key") && !strings.Contains(text, "has no published E2E encryption key") {
				t.Fatalf("E2EE branch failed outside the intended keyless-recipient observable: %s", out)
			}
			mu.Lock()
			gotPublishes := append([]awid.EncryptionKeyAssertion(nil), publishedAssertions[beforePublishes:]...)
			requests := append([]messagingSignedRequest(nil), observedRequests...)
			mu.Unlock()
			if len(gotPublishes) != 1 {
				t.Fatalf("published assertions=%d want 1", len(gotPublishes))
			}
			assertion := &gotPublishes[0]
			if err := awid.VerifyEncryptionKeyAssertion(assertion, principalDID, "", time.Now().UTC()); err != nil {
				t.Fatalf("assertion did not verify under external principal: %v", err)
			}
			if err := awid.VerifyEncryptionKeyAssertion(assertion, shadowDID, "", time.Now().UTC()); err == nil {
				t.Fatal("assertion unexpectedly verified under shadow identity")
			}
			verifyMessagingRequestsForTest(t, requests, principalPub, shadowPub, principalDID, shadowDID)
			if assertion.IdentityDID != principalDID {
				t.Fatalf("published encryption identity=%s, want %s", assertion.IdentityDID, principalDID)
			}
		})
	}
	if shadowAfter := fileDigestsForTest(t, filepath.Join(instance, ".aw")); !reflect.DeepEqual(shadowAfter, shadowBefore) {
		t.Fatal("external-home E2EE send mutated the disposable instance identity")
	}
}

func TestExternalStandaloneIdentityAuthMailUsesPrincipalMismatchContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	principalStableID := awid.ComputeStableID(principalPub)
	var request messagingSignedRequest
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		request = messagingSignedRequest{authorization: r.Header.Get("Authorization"), timestamp: r.Header.Get("X-AWEB-Timestamp"), body: body}
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "message-1", ConversationID: "conversation-1", Status: "delivered"})
	}))
	principalRoot := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	writeStandaloneSelfCustodyIdentity(t, principalRoot, "aweb.test/principal", principalDID, principalStableID, server.URL, principalKey)
	writeMessagingPrincipalForTest(t, instance, server.URL, "shadow", awid.ComputeDIDKey(shadowPub), shadowKey)
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	command := exec.CommandContext(ctx, bin, "--identity-home", filepath.Join(principalRoot, ".aw"), "mail", "send", "--conversation-id", "conversation-1", "--body", "hello")
	command.Dir = instance
	command.Env = append(testCommandEnv(filepath.Join(root, "home")), "AWEB_URL="+server.URL)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("identity-auth mail send failed: %v\n%s", err, out)
	}
	parts := strings.Fields(request.authorization)
	if len(parts) != 3 || parts[1] != principalDID {
		t.Fatalf("authorization=%q want external did=%s", request.authorization, principalDID)
	}
	hash := sha256.Sum256(request.body)
	payload := []byte(fmt.Sprintf(`{"body_sha256":"%s","did_aw":"%s","timestamp":"%s"}`,
		hex.EncodeToString(hash[:]), principalStableID, request.timestamp))
	signature, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(principalPub, payload, signature) || ed25519.Verify(shadowPub, payload, signature) {
		t.Fatal("identity-auth request was not signed exclusively by external principal")
	}
}

func TestExternalMultiTeamAliasEnumeratesPrincipalMemberships(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	terminalTeam := ""
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert, _ := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
		teamID := ""
		if cert != nil {
			teamID = cert.Team
		}
		switch r.URL.Path {
		case "/v1/agents":
			agents := []awid.AgentView{}
			if teamID == "ops:aweb.test" {
				agents = append(agents, awid.AgentView{Alias: "recipient", DIDKey: "did:key:z6MkRecipient"})
			}
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: teamID, Agents: agents})
		case "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
		case "/v1/messages":
			terminalTeam = teamID
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "message-out", Status: "delivered"})
		default:
			http.NotFound(w, r)
		}
	}))
	principalRoot := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", did, key)
	opsFixture := testSelectionFixture{AwebURL: server.URL, TeamID: "ops:aweb.test", Alias: "principal-ops", WorkspaceID: "workspace-ops", DID: did, Address: "aweb.test/principal", Custody: awid.CustodySelf, Lifetime: awid.LifetimeEphemeral, SigningKey: key}
	writeTeamCertificateWorkspaceForTest(t, principalRoot, workspaceBinding(server.URL, "ops:aweb.test", "principal-ops", "workspace-ops"), &opsFixture)
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(principalRoot)
	if err != nil {
		t.Fatal(err)
	}
	workspace.Memberships = append(workspace.Memberships, awconfig.WorktreeMembership{TeamID: "ops:aweb.test", Alias: "principal-ops", WorkspaceID: "workspace-ops", CertPath: awconfig.TeamCertificateRelativePath("ops:aweb.test")})
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(principalRoot, ".aw", "workspace.yaml"), workspace); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(principalRoot, &awconfig.TeamState{ActiveTeam: "runtime:aweb.test", Memberships: []awconfig.TeamMembership{{TeamID: "runtime:aweb.test", Alias: "principal", CertPath: awconfig.TeamCertificateRelativePath("runtime:aweb.test")}, {TeamID: "ops:aweb.test", Alias: "principal-ops", CertPath: awconfig.TeamCertificateRelativePath("ops:aweb.test")}}}); err != nil {
		t.Fatal(err)
	}
	writeMessagingPrincipalForTest(t, instance, server.URL, "shadow", did, key)
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	command := exec.CommandContext(ctx, bin, "--identity-home", filepath.Join(principalRoot, ".aw"), "mail", "send", "--to", "recipient", "--body", "hello")
	command.Dir = instance
	command.Env = testCommandEnv(filepath.Join(root, "home"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("multi-team mail failed: %v\n%s", err, out)
	}
	if terminalTeam != "ops:aweb.test" {
		t.Fatalf("message signed for team %q, want ops:aweb.test", terminalTeam)
	}
}

func verifyMessagingRequestsForTest(t *testing.T, requests []messagingSignedRequest, principalPub, shadowPub ed25519.PublicKey, principalDID, shadowDID string) {
	t.Helper()
	if len(requests) == 0 {
		t.Fatal("command sent no authenticated request")
	}
	for _, request := range requests {
		parts := strings.Fields(request.authorization)
		if len(parts) != 3 || parts[1] != principalDID {
			t.Fatalf("request signed under wrong identity: auth=%q want did=%s (shadow=%s)", request.authorization, principalDID, shadowDID)
		}
		payload := messagingCertificateAuthPayload("runtime:aweb.test", request.timestamp, request.body)
		signature, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(principalPub, payload, signature) || ed25519.Verify(shadowPub, payload, signature) {
			t.Fatalf("request signature did not bind external principal: auth=%q", request.authorization)
		}
	}
}

func messagingCertificateAuthPayload(teamID, timestamp string, body []byte) []byte {
	hash := sha256.Sum256(body)
	return []byte(fmt.Sprintf(`{"body_sha256":"%s","team_id":"%s","timestamp":"%s"}`,
		hex.EncodeToString(hash[:]), teamID, timestamp))
}

func writeMessagingPrincipalForTest(t *testing.T, root, serverURL, alias, did string, signingKey ed25519.PrivateKey) {
	t.Helper()
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL:     serverURL,
		TeamID:      "runtime:aweb.test",
		Alias:       alias,
		WorkspaceID: "workspace-" + alias,
		DID:         did,
		Address:     "aweb.test/" + alias,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimeEphemeral,
		SigningKey:  signingKey,
		CreatedAt:   "2026-07-26T00:00:00Z",
	})
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "runtime:aweb.test", Memberships: []awconfig.TeamMembership{{TeamID: "runtime:aweb.test", Alias: alias, CertPath: awconfig.TeamCertificateRelativePath("runtime:aweb.test")}}}); err != nil {
		t.Fatal(err)
	}
}
