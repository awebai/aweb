package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A received message signed for another recipient is refused before the
// sender's trust is looked up, for chat as for mail: the roster is not read and
// no pin is touched for a message that was never addressed to this reader.
func TestChatHistoryRefusesAnotherRecipientBeforeSenderLookup(t *testing.T) {
	t.Parallel()

	_, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderKey.Public().(ed25519.PublicKey))
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherDID := ComputeDIDKey(otherKey.Public().(ed25519.PublicKey))
	_, selfKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := ComputeDIDKey(selfKey.Public().(ed25519.PublicKey))

	for _, tc := range []struct {
		name        string
		toDID       string
		want        VerificationStatus
		rosterReads int
	}{
		{name: "signed for another recipient", toDID: otherDID, want: IdentityMismatch, rosterReads: 0},
		{name: "signed for this reader", toDID: selfDID, want: Verified, rosterReads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := &MessageEnvelope{
				From:           "alice",
				FromDID:        senderDID,
				To:             "bob",
				ToDID:          tc.toDID,
				Type:           "chat",
				Body:           "hello",
				Timestamp:      "2026-11-18T00:00:00Z",
				MessageID:      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				ConversationID: "33333333-3333-4333-8333-333333333333",
			}
			signature, err := SignMessage(senderKey, env)
			if err != nil {
				t.Fatal(err)
			}
			rosterReads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/chat/sessions/" + env.ConversationID + "/messages":
					_ = json.NewEncoder(w).Encode(ChatHistoryResponse{Messages: []ChatMessage{{
						MessageID:      env.MessageID,
						ConversationID: env.ConversationID,
						FromAgent:      "alice",
						Body:           env.Body,
						Timestamp:      env.Timestamp,
						FromDID:        senderDID,
						ToDID:          env.ToDID,
						Signature:      signature,
						SigningKeyID:   senderDID,
						SignedPayload:  CanonicalJSON(env),
					}}})
				case "/v1/agents":
					rosterReads++
					_ = json.NewEncoder(w).Encode(ListAgentsResponse{
						TeamID: "backend:acme.com",
						Agents: []AgentView{{Alias: "alice", DIDKey: senderDID, IdentityScope: IdentityModeLocal}},
					})
				default:
					t.Errorf("path=%q", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client, err := NewWithCertificate(server.URL, selfKey, testTeamCertificate(t, selfKey, "bob"))
			if err != nil {
				t.Fatal(err)
			}
			client.SetAddress("backend:acme.com/bob")
			client.SetPinStore(NewPinStore(), "")
			client.SetResolver(&ChainResolver{Team: &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}})
			response, err := client.ChatHistory(context.Background(), ChatHistoryParams{SessionID: env.ConversationID})
			if err != nil {
				t.Fatal(err)
			}
			if got := response.Messages[0].VerificationStatus; got != tc.want {
				t.Fatalf("status=%q, want %q", got, tc.want)
			}
			if rosterReads != tc.rosterReads {
				t.Fatalf("roster reads=%d, want %d", rosterReads, tc.rosterReads)
			}
		})
	}
}
