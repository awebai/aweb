package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Encrypted mail to an address that already has a conversation must keep the
// recipient ADDRESS for AWID key discovery. It previously sent the
// conversation id as the recipient, which the real registry resolver rejects
// as an invalid identifier before anything is delivered.
func TestAwMailSendE2EEToAddressWithExistingConversationResolvesRecipient(t *testing.T) {
	t.Parallel()

	senderPub, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := awid.ComputeDIDKey(senderPub)
	senderStableID := stableIDFromDidForTest(t, senderDID)

	bobPub, bobKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobDID := awid.ComputeDIDKey(bobPub)
	bobStableID := awid.ComputeStableID(bobPub)
	bobX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobAssertion, err := awid.BuildEncryptionKeyAssertion(bobKey, bobDID, bobStableID, bobX.PublicKey().Bytes(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	conversationID := "ac7603ad-3eb0-44a4-9a6d-d8402e2d8497"
	var mu sync.Mutex
	var sent map[string]any
	var resolverPaths []string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/conversations":
			http.NotFound(w, r)
		case r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{
				MessageID:      "msg-in",
				ConversationID: conversationID,
				FromAddress:    "acme.com/bob",
				FromDID:        bobStableID,
				ToAddress:      "acme.com/alice",
				ToDID:          senderStableID,
				Subject:        "hello",
				Body:           "hi",
				CreatedAt:      "2026-09-24T00:00:00Z",
			}}})
		case r.URL.Path == "/v1/namespaces/acme.com/addresses/bob":
			mu.Lock()
			resolverPaths = append(resolverPaths, r.URL.Path)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-bob", "domain": "acme.com", "name": "bob",
				"did_aw": bobStableID, "current_did_key": bobDID, "created_at": "2026-09-24T00:00:00Z",
			})
		case r.URL.Path == "/v1/did/"+bobStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": bobStableID, "current_did_key": bobDID, "encryption_key": bobAssertion,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			mu.Lock()
			sent = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id": "msg-e2ee", "conversation_id": conversationID,
				"status": "delivered", "delivered_at": "2026-09-24T00:00:01Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did/"+senderStableID+"/encryption-key":
			// The sender publishes its own encryption key assertion before sending.
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			mu.Lock()
			resolverPaths = append(resolverPaths, "unexpected "+r.Method+" "+r.URL.Path)
			mu.Unlock()
			http.NotFound(w, r)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           senderDID,
		StableID:      senderStableID,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-09-24T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), senderKey); err != nil {
		t.Fatal(err)
	}
	installMailReadEncryptionKeyForTest(t, tmp, filepath.Join(tmp, ".aw"), senderDID, senderKey)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--e2ee",
		"--to", "acme.com/bob", "--subject", "[test]", "--body", "secret body")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL, "AWID_SKIP_DNS_VERIFY=1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("e2ee send into existing conversation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "invalid identifier") {
		t.Fatalf("recipient resolved from the conversation id:\n%s", out)
	}

	mu.Lock()
	defer mu.Unlock()
	if sent == nil {
		t.Fatalf("nothing was sent; resolver saw %v\n%s", resolverPaths, out)
	}
	if sent["conversation_id"] != conversationID {
		t.Fatalf("conversation_id=%v, want %s", sent["conversation_id"], conversationID)
	}
	if sent["content_mode"] != awid.ContentModeEncryptedV2 {
		t.Fatalf("content_mode=%v, want %s (no plaintext fallback)", sent["content_mode"], awid.ContentModeEncryptedV2)
	}
	if body, _ := sent["body"].(string); strings.Contains(body, "secret body") {
		t.Fatal("plaintext body was sent")
	}
	if len(resolverPaths) == 0 || resolverPaths[0] != "/v1/namespaces/acme.com/addresses/bob" {
		t.Fatalf("recipient was not resolved by address through the registry: %v", resolverPaths)
	}
	envelope, _ := json.Marshal(sent["encrypted_envelope"])
	if !strings.Contains(string(envelope), bobAssertion.EncryptionKeyID) {
		t.Fatalf("envelope is not wrapped to the recipient's published key %s", bobAssertion.EncryptionKeyID)
	}
}

func TestAwMailReplyE2EEConfiguresReadKeyBeforeLoadingEncryptedSource(t *testing.T) {
	t.Parallel()

	alicePub, aliceKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aliceDID := awid.ComputeDIDKey(alicePub)
	aliceStableID := awid.ComputeStableID(alicePub)

	bobPub, bobKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobDID := awid.ComputeDIDKey(bobPub)
	bobStableID := awid.ComputeStableID(bobPub)
	bobX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobAssertion, err := awid.BuildEncryptionKeyAssertion(bobKey, bobDID, bobStableID, bobX.PublicKey().Bytes(), "", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           aliceDID,
		StableID:      aliceStableID,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-09-25T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), aliceKey); err != nil {
		t.Fatal(err)
	}
	aliceAssertion := installMailReadEncryptionKeyForTest(t, tmp, filepath.Join(tmp, ".aw"), aliceDID, aliceKey)

	conversationID := "55555555-5555-4555-8555-555555555555"
	sourceID := "dc6c7498-2f5a-49e6-85fb-3961b9986690"
	sourceEnvelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
		Sender: awid.E2EESenderKey{
			Address:       "acme.com/bob",
			DID:           bobDID,
			StableID:      bobStableID,
			EncryptionKey: bobAssertion,
			SigningKey:    bobKey,
		},
		Recipients: []awid.E2EERecipientKey{{
			Address:       "acme.com/alice",
			DID:           aliceDID,
			EncryptionKey: aliceAssertion,
		}},
		Subject:        "encrypted source",
		Body:           "source secret",
		MessageID:      sourceID,
		ConversationID: conversationID,
		CreatedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var sent map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{
				MessageID:      sourceID,
				ConversationID: conversationID,
				FromAddress:    "acme.com/bob",
				FromDID:        bobStableID,
				ToAddress:      "acme.com/alice",
				ToDID:          aliceStableID,
				ContentMode:    awid.ContentModeEncryptedV2,
				MessageVersion: awid.E2EEMessageVersion,
				Encrypted:      sourceEnvelope,
				CreatedAt:      "2026-09-25T00:00:00Z",
			}}})
		case r.URL.Path == "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{{
				ConversationType:     "mail",
				ConversationID:       conversationID,
				Participants:         []string{"alice", "bob"},
				ParticipantDIDs:      []string{aliceStableID, bobStableID},
				ParticipantAddresses: []string{"acme.com/alice", "acme.com/bob"},
				Subject:              "encrypted source",
				LastMessageAt:        "2026-09-25T00:00:00Z",
			}}})
		case r.URL.Path == "/v1/namespaces/acme.com/addresses/bob":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-bob", "domain": "acme.com", "name": "bob",
				"did_aw": bobStableID, "current_did_key": bobDID, "created_at": "2026-09-25T00:00:00Z",
			})
		case r.URL.Path == "/v1/did/"+bobStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": bobStableID, "current_did_key": bobDID, "encryption_key": bobAssertion,
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			mu.Lock()
			sent = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id": "reply-e2ee", "conversation_id": conversationID,
				"status": "delivered", "delivered_at": "2026-09-25T00:00:01Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/"+sourceID+"/ack":
			_ = json.NewEncoder(w).Encode(map[string]any{"message_id": sourceID, "status": "acknowledged"})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))

	run := exec.CommandContext(ctx, bin, "mail", "reply", sourceID, "--e2ee", "--body", "reply secret")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL, "AWID_SKIP_DNS_VERIFY=1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("e2ee reply to encrypted source failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "requires local encryption private key") {
		t.Fatalf("reply fetched encrypted source before configuring the local read key:\n%s", out)
	}

	mu.Lock()
	defer mu.Unlock()
	if sent == nil {
		t.Fatalf("nothing was sent:\n%s", out)
	}
	if sent["conversation_id"] != conversationID {
		t.Fatalf("conversation_id=%v, want %s", sent["conversation_id"], conversationID)
	}
	if sent["content_mode"] != awid.ContentModeEncryptedV2 {
		t.Fatalf("content_mode=%v, want %s", sent["content_mode"], awid.ContentModeEncryptedV2)
	}
	if body, _ := sent["body"].(string); strings.Contains(body, "reply secret") {
		t.Fatal("plaintext reply body was sent")
	}
	if sent["encrypted_envelope"] == nil {
		t.Fatal("encrypted reply envelope was not sent")
	}
}

// Same defect on the alias branch: an E2EE send by team alias that auto-threads
// into an existing conversation must keep the alias for key discovery.
func TestAwMailSendE2EEAliasWithExistingConversationResolvesRecipient(t *testing.T) {
	t.Parallel()

	senderPub, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := awid.ComputeDIDKey(senderPub)
	senderStableID := stableIDFromDidForTest(t, senderDID)

	bobPub, bobKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobDID := awid.ComputeDIDKey(bobPub)
	bobStableID := awid.ComputeStableID(bobPub)
	bobX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobAssertion, err := awid.BuildEncryptionKeyAssertion(bobKey, bobDID, bobStableID, bobX.PublicKey().Bytes(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	conversationID := "88888888-8888-4888-8888-888888888888"
	var mu sync.Mutex
	var sent map[string]any

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{
				TeamID: "devteam:acme.com",
				Agents: []awid.AgentView{{AgentID: "bob-agent", Alias: "bob", DIDKey: bobDID, DIDAW: bobStableID, Address: "acme.com/bob"}},
			})
		case r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case r.URL.Path == "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{{
				ConversationType:     "mail",
				ConversationID:       conversationID,
				Participants:         []string{"alice", "bob"},
				ParticipantDIDs:      []string{senderStableID, bobStableID},
				ParticipantAddresses: []string{"acme.com/alice", "acme.com/bob"},
				Subject:              "earlier thread",
				LastMessageAt:        "2026-09-24T00:00:00Z",
			}}})
		case r.URL.Path == "/v1/namespaces/acme.com/addresses/bob":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-bob", "domain": "acme.com", "name": "bob",
				"did_aw": bobStableID, "current_did_key": bobDID, "created_at": "2026-09-24T00:00:00Z",
			})
		case r.URL.Path == "/v1/did/"+bobStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": bobStableID, "current_did_key": bobDID, "encryption_key": bobAssertion,
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "alice-agent", "devteam:acme.com", "alice")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			mu.Lock()
			sent = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id": "msg-e2ee-alias", "conversation_id": conversationID,
				"status": "delivered", "delivered_at": "2026-09-24T00:00:01Z",
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:       server.URL,
		TeamID:        "devteam:acme.com",
		Alias:         "alice",
		WorkspaceID:   "workspace-1",
		DID:           senderDID,
		StableID:      senderStableID,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		SigningKey:    senderKey,
		CreatedAt:     "2026-09-24T00:00:00Z",
	})
	installMailReadEncryptionKeyForTest(t, tmp, filepath.Join(tmp, ".aw"), senderDID, senderKey)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--e2ee", "--to", "bob", "--subject", "[test]", "--body", "secret body")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL, "AWID_SKIP_DNS_VERIFY=1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("e2ee alias send into existing conversation failed: %v\n%s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if sent == nil {
		t.Fatalf("nothing was sent:\n%s", out)
	}
	if sent["conversation_id"] != conversationID {
		t.Fatalf("conversation_id=%v, want %s", sent["conversation_id"], conversationID)
	}
	if sent["content_mode"] != awid.ContentModeEncryptedV2 {
		t.Fatalf("content_mode=%v, want %s", sent["content_mode"], awid.ContentModeEncryptedV2)
	}
	if alias, _ := sent["to_alias"].(string); alias == conversationID {
		t.Fatal("to_alias carried the conversation id")
	}
	envelope, _ := json.Marshal(sent["encrypted_envelope"])
	if !strings.Contains(string(envelope), bobAssertion.EncryptionKeyID) {
		t.Fatalf("envelope is not wrapped to the recipient's published key")
	}
}
