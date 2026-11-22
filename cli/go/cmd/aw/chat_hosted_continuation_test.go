package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestChatHostedContinuationUsesServerReadableDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	checkChatHostedContinuation(t, ctx, bin)
}

func checkChatHostedContinuation(t *testing.T, ctx context.Context, bin string) {
	t.Helper()
	const team, domain = "devteam:acme.test", "acme.test"
	const session = "11111111-1111-4111-8111-111111111111"
	const message = "22222222-2222-4222-8222-222222222222"
	const body = "reply to hosted peer"
	senderPub, senderKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderDID, senderStable := awid.ComputeDIDKey(senderPub), awid.ComputeStableID(senderPub)
	hostedPub, hostedKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	hostedDID, hostedStable := awid.ComputeDIDKey(hostedPub), awid.ComputeStableID(hostedPub)
	_, encryptionPub, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := awid.BuildEncryptionKeyAssertion(hostedKey, hostedDID, hostedStable, encryptionPub, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	assertion.Custody = awid.EncryptionKeyCustodyHosted
	if err := awid.SignEncryptionKeyAssertion(assertion, hostedKey); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var deliveries []awid.ChatSendMessageRequest
	var newSessions int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: team, Agents: []awid.AgentView{{
				AgentID: "hosted", Alias: "hosted", DIDKey: hostedDID, DIDAW: hostedStable, Address: domain + "/hosted",
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{{
				SessionID: session, TeamID: team, Participants: []string{"sender", "hosted"},
				ParticipantDIDs: []string{senderStable, hostedStable}, ParticipantAddresses: []string{domain + "/sender", domain + "/hosted"},
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions/"+session+"/messages":
			_ = json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: []awid.ChatMessage{{
				ContentMode: awid.ContentModeEncryptedV2, MessageVersion: awid.E2EEMessageVersion,
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+domain+"/addresses/hosted":
			_ = json.NewEncoder(w).Encode(map[string]string{"address_id": "hosted", "domain": domain, "name": "hosted", "did_aw": hostedStable, "current_did_key": hostedDID})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+hostedStable+"/key":
			_ = json.NewEncoder(w).Encode(awid.DidKeyResolution{DIDAW: hostedStable, CurrentDIDKey: hostedDID, EncryptionKey: assertion})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did/"+senderStable+"/encryption-key":
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "sender", team, "sender")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions/"+session+"/messages":
			var payload awid.ChatSendMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode chat send: %v", err)
			}
			mu.Lock()
			deliveries = append(deliveries, payload)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: message, Delivered: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			mu.Lock()
			newSessions++
			mu.Unlock()
			http.Error(w, "unexpected new session", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	dir := t.TempDir()
	writeSelectionFixtureForTest(t, dir, testSelectionFixture{
		AwebURL: server.URL, TeamID: team, Alias: "sender", WorkspaceID: "sender", DID: senderDID,
		StableID: senderStable, Address: domain + "/sender", Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, RegistryURL: server.URL, SigningKey: senderKey,
	})
	identity, err := awconfig.ResolveIdentityFromHome(dir, filepath.Join(dir, ".aw"))
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := createLocalEncryptionKeyRecord(identity, senderKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveEncryptionKeyStateTo(awconfig.WorktreeEncryptionStatePath(dir), &awconfig.EncryptionKeyState{
		ActiveKeyID: record.KeyID, Keys: []awconfig.EncryptionKeyRecord{*record},
	}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, string, error) {
		cmd := exec.CommandContext(ctx, bin, append([]string{"--json"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL, "AWID_SKIP_DNS_VERIFY=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return out, stderr.String(), err
	}
	for _, args := range [][]string{
		{"chat", "send-and-leave", "hosted", body},
		{"chat", "send", "--session-id", session, "--body", body},
		{"chat", "extend-wait", "hosted", body},
	} {
		t.Run(args[1], func(t *testing.T) {
			mu.Lock()
			deliveries, newSessions = nil, 0
			mu.Unlock()
			out, stderr, err := run(args...)
			if err != nil {
				t.Fatalf("flagless existing chat failed: %v\n%s\n%s", err, out, stderr)
			}
			mu.Lock()
			defer mu.Unlock()
			if newSessions != 0 || len(deliveries) != 1 {
				t.Fatalf("got %d new sessions and %d session sends", newSessions, len(deliveries))
			}
			payload := deliveries[0]
			if payload.Encrypted != nil || payload.Body != body || payload.FromDID != senderDID {
				t.Fatalf("expected signed plaintext for the existing session: %+v", payload)
			}
			if status, err := awid.VerifySignedPayload(payload.SignedPayload, payload.Signature, senderDID, ""); err != nil || status != awid.Verified {
				t.Fatalf("verify signed chat: %s, %v", status, err)
			}
			if status := awid.SignedPayloadConversationStatus(payload.SignedPayload, session); status != awid.Verified {
				t.Fatalf("signed chat conversation binding: %s", status)
			}
			if payload.ExtendWait != (args[1] == "extend-wait") {
				t.Fatalf("extend-wait request flag = %t", payload.ExtendWait)
			}
		})
	}
	t.Run("explicit e2ee", func(t *testing.T) {
		mu.Lock()
		deliveries, newSessions = nil, 0
		mu.Unlock()
		out, stderr, err := run("chat", "send-and-leave", "--e2ee", "hosted", body)
		var result struct {
			Error map[string]any `json:"error"`
		}
		if parseErr := json.Unmarshal(out, &result); parseErr != nil || exitCode(err) != 1 || result.Error["code"] != awid.ErrorCodeRecipientCustodialNoE2EE || result.Error["detail"] != domain+"/hosted" {
			t.Fatalf("expected typed hosted refusal: %v\n%s\n%s", err, out, stderr)
		}
		if _, hasStatus := result.Error["http_status"]; hasStatus {
			t.Fatalf("expected CLI preflight, got an HTTP status: %s", out)
		}
		mu.Lock()
		defer mu.Unlock()
		if newSessions != 0 || len(deliveries) != 0 {
			t.Fatal("explicit E2EE refusal wrote a delivery")
		}
	})
}
