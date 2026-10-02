package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/awebai/aw/awid"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fresh send gets a newly signed conversation UUID from the library.
func TestAwMailSendOpportunisticThreading(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	peerPub, _, _ := ed25519.GenerateKey(nil)
	self, peer := awid.ComputeDIDKey(pub), awid.ComputeDIDKey(peerPub)
	const old = "11111111-1111-4111-8111-111111111111"
	const recent = "22222222-2222-4222-8222-222222222222"
	const group = "33333333-3333-4333-8333-333333333333"
	pair := func(id, ts string) awid.ConversationItem {
		return awid.ConversationItem{ConversationType: "mail", ConversationID: id, Status: "active", ParticipantDIDs: []string{self, peer}, ParticipantAddresses: []string{"test.local/gsk", "test.local/alice"}, LastMessageAt: ts}
	}
	older, newer := pair(old, "2026-10-01T12:00:00+03:00"), pair(recent, "2026-10-01T12:00:00+01:00")
	grouped := pair(group, "2026-10-02T00:00:00Z")
	grouped.ParticipantDIDs = append(grouped.ParticipantDIDs, "did:key:third")
	grouped.ParticipantAddresses = append(grouped.ParticipantAddresses, "test.local/third")
	anotherGroup := grouped
	anotherGroup.ConversationID = old
	tied := pair(old, "2026-10-01T11:00:00Z")
	noSelf := pair(old, newer.LastMessageAt)
	noSelf.ParticipantDIDs = []string{"did:key:stranger", peer}
	noSelf.ParticipantAddresses = []string{"test.local/stranger", "test.local/alice"}
	for _, tc := range []struct {
		name, flag, target                   string
		conversations                        []awid.ConversationItem
		status                               int
		detail                               string
		transport, alwaysFail, inboxFallback bool
		wantConversation                     string
		wantPosts                            int
		wantFailure                          bool
	}{
		{name: "multiple_groups_start_new", conversations: []awid.ConversationItem{grouped, anotherGroup}, wantPosts: 1},
		{name: "newest_exact_pair", conversations: []awid.ConversationItem{older, grouped, newer}, wantConversation: recent, wantPosts: 1},
		{name: "tie_id_desc", conversations: []awid.ConversationItem{tied, newer}, wantConversation: recent, wantPosts: 1},
		{name: "tie_reverse_order", conversations: []awid.ConversationItem{newer, tied}, wantConversation: recent, wantPosts: 1},
		{name: "missing_self_is_not_pair", conversations: []awid.ConversationItem{noSelf, grouped}, wantPosts: 1},
		{name: "legacy_multiple_unknown_members", conversations: []awid.ConversationItem{older, newer}, inboxFallback: true, wantPosts: 1},
		{name: "expired_alias", conversations: []awid.ConversationItem{older}, status: 403, detail: "Conversation is expired", wantPosts: 2},
		{name: "expired_did", flag: "--to-did", target: peer, conversations: []awid.ConversationItem{older}, status: 403, detail: "Conversation is expired", wantPosts: 2},
		{name: "expired_address", flag: "--to-address", target: "test.local/alice", conversations: []awid.ConversationItem{older}, status: 403, detail: "Conversation is expired", wantPosts: 2},
		{name: "explicit_expired", flag: "--conversation-id", target: old, conversations: []awid.ConversationItem{older}, status: 403, detail: "Conversation is expired", wantPosts: 1, wantFailure: true},
		{name: "other_403", conversations: []awid.ConversationItem{older}, status: 403, detail: "Not a participant", wantPosts: 1, wantFailure: true},
		{name: "auth_403", conversations: []awid.ConversationItem{older}, status: 403, detail: "grant expired", wantPosts: 1, wantFailure: true},
		{name: "embedded_expiry_text", conversations: []awid.ConversationItem{older}, status: 403, detail: "Permission denied: Conversation is expired", wantPosts: 1, wantFailure: true},
		{name: "wrong_status", conversations: []awid.ConversationItem{older}, status: 401, detail: "Conversation is expired", wantPosts: 1, wantFailure: true},
		{name: "lost_response", conversations: []awid.ConversationItem{older}, transport: true, wantPosts: 4, wantFailure: true},
		{name: "retry_only_once", conversations: []awid.ConversationItem{older}, status: 403, detail: "Conversation is expired", alwaysFail: true, wantPosts: 2, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sent []awid.SendMessageRequest
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/agents":
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "devteam:test.local", Agents: []awid.AgentView{{AgentID: "alice-agent", Alias: "alice", DIDKey: peer, Address: "test.local/alice"}}})
				case "/v1/conversations":
					if tc.inboxFallback {
						http.NotFound(w, r)
						return
					}
					_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: tc.conversations})
				case "/v1/messages/inbox":
					var messages []awid.InboxMessage
					for _, conv := range tc.conversations {
						messages = append(messages, awid.InboxMessage{ConversationID: conv.ConversationID, FromDID: peer, ToDID: self, CreatedAt: conv.LastMessageAt})
					}
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: messages})
				case "/v1/messages":
					var req awid.SendMessageRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					mu.Lock()
					sent = append(sent, req)
					count := len(sent)
					mu.Unlock()
					if tc.transport {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
						} else {
							_ = conn.Close()
						}
						return
					}
					if tc.status != 0 && (count == 1 || tc.alwaysFail) {
						w.WriteHeader(tc.status)
						_ = json.NewEncoder(w).Encode(map[string]string{"detail": tc.detail})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"message_id": req.MessageID, "conversation_id": req.ConversationID, "status": "delivered"})
				case "/v1/agents/heartbeat":
					w.WriteHeader(200)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			tmp := t.TempDir()
			writeSelectionFixtureForTest(t, tmp, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
			flag, target := tc.flag, tc.target
			if flag == "" {
				flag, target = "--to", "alice"
			}
			run := exec.CommandContext(ctx, bin, "mail", "send", flag, target, "--body", "unchanged body", "--subject", "unchanged subject", "--priority", "high")
			run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
			run.Dir = tmp
			output, err := run.CombinedOutput()
			if (err != nil) != tc.wantFailure {
				t.Errorf("error=%v wantFailure=%v output=%s", err, tc.wantFailure, output)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(sent) != tc.wantPosts {
				t.Fatalf("POST count=%d want %d output=%s", len(sent), tc.wantPosts, output)
			}
			for i, req := range sent {
				sig, err := base64.RawStdEncoding.DecodeString(req.Signature)
				if err != nil || !ed25519.Verify(pub, []byte(req.SignedPayload), sig) {
					t.Fatalf("POST %d invalid selected-identity signature", i)
				}
				var signed map[string]any
				if err := json.Unmarshal([]byte(req.SignedPayload), &signed); err != nil {
					t.Fatal(err)
				}
				if req.FromDID != self || signed["from_did"] != self || signed["conversation_id"] != req.ConversationID || signed["body"] != "unchanged body" || signed["subject"] != "unchanged subject" || signed["priority"] != "high" {
					t.Fatalf("POST %d lost signed fields: %+v", i, signed)
				}
				if req.ToDID != peer && req.ToAlias != "alice" {
					t.Fatalf("POST %d lost recipient: %+v", i, req)
				}
			}
			if tc.transport {
				// Existing HTTP transport retries replay the identical signed request;
				// they must not turn into the new expiry retry with a fresh ID.
				for _, req := range sent[1:] {
					if req.SignedPayload != sent[0].SignedPayload {
						t.Fatal("transport failure triggered fresh send")
					}
				}
				return
			}
			if tc.wantFailure && tc.wantPosts == 1 {
				return
			}
			final := sent[len(sent)-1]
			if tc.wantConversation != "" {
				if final.ConversationID != tc.wantConversation {
					t.Fatalf("conversation=%s want %s", final.ConversationID, tc.wantConversation)
				}
			} else {
				if final.ConversationID == "" {
					t.Fatal("fresh signed conversation UUID missing")
				}
				for _, conv := range tc.conversations {
					if final.ConversationID == conv.ConversationID {
						t.Fatalf("reused old conversation %s", final.ConversationID)
					}
				}
			}
			if len(sent) == 2 {
				if sent[0].ConversationID != old || sent[0].MessageID == final.MessageID {
					t.Fatal("retry must freshly sign new conversation and message")
				}
				if !tc.wantFailure && !strings.Contains(string(output), final.ConversationID) {
					t.Fatalf("output reports stale conversation: %s", output)
				}
			}
		})
	}
}
