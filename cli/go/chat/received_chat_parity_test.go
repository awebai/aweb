package chat

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/awebai/aw/awid"
)

// A received chat message is verified by one rule whether it is read from the
// conversation's history (aw chat history, open) or from the live stream
// (aw chat send-and-wait, listen): the same row must get the same status and
// show the same sender.

const paritySessionID = "33333333-3333-4333-8333-333333333333"

type parityKey struct {
	did  string
	priv ed25519.PrivateKey
}

func newParityKey(t *testing.T) parityKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return parityKey{did: awid.ComputeDIDKey(pub), priv: priv}
}

type parityCase struct {
	name string
	row  map[string]any
	want awid.VerificationStatus
}

// signedParityRow builds a stream/history row as the server sends it for env,
// signed by signer.
func signedParityRow(t *testing.T, signer parityKey, env *awid.MessageEnvelope, row map[string]any) map[string]any {
	t.Helper()
	sig, err := awid.SignMessage(signer.priv, env)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{
		"type":            "message",
		"session_id":      paritySessionID,
		"conversation_id": paritySessionID,
		"message_id":      env.MessageID,
		"from_agent":      "bob",
		"body":            env.Body,
		"from_did":        signer.did,
		"timestamp":       env.Timestamp,
		"signature":       sig,
		"signed_payload":  awid.CanonicalJSON(env),
	}
	if env.ToDID != "" {
		out["to_did"] = env.ToDID
	}
	for k, v := range row {
		out[k] = v
	}
	return out
}

func parityCases(t *testing.T, reader, bob parityKey) []parityCase {
	t.Helper()
	other := newParityKey(t)
	base := func(id, body string) *awid.MessageEnvelope {
		return &awid.MessageEnvelope{
			From:           "myco/bob",
			FromDID:        bob.did,
			To:             "myco/alice",
			ToDID:          reader.did,
			Type:           "chat",
			Body:           body,
			Timestamp:      "2026-11-18T00:00:00Z",
			MessageID:      id,
			ConversationID: paritySessionID,
		}
	}

	genuine := base("10000000-0000-4000-8000-000000000001", "genuine")

	memberName := base("10000000-0000-4000-8000-000000000002", "signed by member name")
	memberName.From = "bob"
	memberName.FromStableID = "did:aw:bob-stable"

	noConversation := base("10000000-0000-4000-8000-000000000003", "no conversation claim")
	noConversation.ConversationID = ""

	otherRecipient := base("10000000-0000-4000-8000-000000000004", "signed to someone else")
	otherRecipient.ToDID = other.did

	ownSent := &awid.MessageEnvelope{
		From:           "myco/alice",
		FromDID:        reader.did,
		To:             "myco/bob",
		ToDID:          bob.did,
		Type:           "chat",
		Body:           "my own message",
		Timestamp:      "2026-11-18T00:00:00Z",
		MessageID:      "10000000-0000-4000-8000-000000000005",
		ConversationID: paritySessionID,
	}

	// Signed without a signed_payload: the reader rebuilds the envelope from
	// the row, with the sender's address as From.
	legacy := base("10000000-0000-4000-8000-000000000006", "legacy signed")
	legacy.ConversationID = ""
	legacySig, err := awid.SignMessage(bob.priv, legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyRow := map[string]any{
		"type": "message", "session_id": paritySessionID, "conversation_id": paritySessionID,
		"message_id": legacy.MessageID, "from_agent": "bob", "from_address": "myco/bob",
		"to_address": "myco/alice", "body": legacy.Body, "from_did": bob.did, "to_did": reader.did,
		"timestamp": legacy.Timestamp, "signature": legacySig, "signing_key_id": bob.did,
	}

	unsigned := map[string]any{
		"type": "message", "session_id": paritySessionID, "conversation_id": paritySessionID,
		"message_id": "10000000-0000-4000-8000-000000000007", "from_agent": "bob", "body": "unsigned",
		"timestamp": "2026-11-18T00:00:00Z",
	}

	// The row names the sender by its stable ID; the signed payload carries
	// the did:key that signed it, and verification uses that key.
	stableRow := base("10000000-0000-4000-8000-000000000008", "stable id in the row")
	stableRow.FromStableID = "did:aw:bob-stable"

	// Signed by bob for another conversation, and served in this one with
	// that conversation's own identifiers: the row matches its signature, but
	// not the conversation the reader asked for.
	const otherConversation = "44444444-4444-4444-8444-444444444444"
	replayed := base("10000000-0000-4000-8000-000000000009", "signed for another conversation")
	replayed.ConversationID = otherConversation

	// Signed by another key in bob's name, with and without the conversation
	// claim: leaving the claim out must not skip the sender's trust checks.
	impostor := newParityKey(t)
	impersonated := base("10000000-0000-4000-8000-00000000000a", "i am bob")
	impersonated.FromDID = impostor.did
	impersonatedUnbound := base("10000000-0000-4000-8000-00000000000b", "i am bob, unbound")
	impersonatedUnbound.FromDID = impostor.did
	impersonatedUnbound.ConversationID = ""

	return []parityCase{
		{name: "legacy signed row", row: legacyRow, want: awid.VerifiedLegacy},
		{name: "unsigned row", row: unsigned, want: awid.Unverified},
		{name: "row from_did is the stable id", row: signedParityRow(t, bob, stableRow, map[string]any{"from_address": "myco/bob", "to_address": "myco/alice", "from_did": "did:aw:bob-stable", "from_stable_id": "did:aw:bob-stable"}), want: awid.Verified},
		{name: "genuine reply", row: signedParityRow(t, bob, genuine, map[string]any{"from_address": "myco/bob", "to_address": "myco/alice"}), want: awid.Verified},
		{name: "signed member name is not an address", row: signedParityRow(t, bob, memberName, nil)},
		{name: "payload without conversation claim", row: signedParityRow(t, bob, noConversation, map[string]any{"from_address": "myco/bob"}), want: awid.VerifiedLegacy},
		{name: "signed to another recipient", row: signedParityRow(t, bob, otherRecipient, map[string]any{"from_address": "myco/bob"}), want: awid.IdentityMismatch},
		{name: "own sent message", row: signedParityRow(t, reader, ownSent, map[string]any{"from_agent": "alice", "from_address": "myco/alice", "to_address": "myco/bob"}), want: awid.Verified},
		{name: "signed in bob's name by another key", row: signedParityRow(t, impostor, impersonated, map[string]any{"from_address": "myco/bob", "to_address": "myco/alice"}), want: awid.IdentityMismatch},
		{name: "signed in bob's name by another key, no conversation claim", row: signedParityRow(t, impostor, impersonatedUnbound, map[string]any{"from_address": "myco/bob", "to_address": "myco/alice"}), want: awid.IdentityMismatch},
		{name: "replayed from another conversation", row: signedParityRow(t, bob, replayed, map[string]any{"session_id": otherConversation, "conversation_id": otherConversation, "from_address": "myco/bob", "to_address": "myco/alice"}), want: awid.Failed},
	}
}

func parityServer(t *testing.T, rows []map[string]any, finalReply map[string]any) string {
	t.Helper()
	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: paritySessionID,
				MessageID: "msg-sent-parity",
				SSEURL:    "/v1/chat/sessions/" + paritySessionID + "/stream",
			})
		},
		"GET /v1/chat/sessions/" + paritySessionID + "/messages": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": rows})
		},
		"GET /v1/chat/sessions/" + paritySessionID + "/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			write := func(row map[string]any) {
				data, _ := json.Marshal(row)
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			}
			write(map[string]any{"type": "message", "message_id": "msg-sent-parity", "from_agent": "alice", "body": "hello"})
			for _, row := range rows {
				write(row)
			}
			write(finalReply)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)
	return server.URL
}

func parityReader(t *testing.T, url string, reader, bob parityKey) *awid.Client {
	t.Helper()
	c, err := awid.NewWithIdentity(url, reader.priv, reader.did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/alice")
	identities := map[string]string{"myco/bob": bob.did, "myco/alice": reader.did}
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, address string) (*awid.ResolvedIdentity, error) {
			did, ok := identities[address]
			if !ok {
				return nil, fmt.Errorf("no identity at %s", address)
			}
			identity := &awid.ResolvedIdentity{DID: did, Address: address, IdentityScope: awid.IdentityModeGlobal, ResolvedVia: "registry"}
			if address == "myco/bob" {
				identity.StableID = "did:aw:bob-stable"
			}
			return identity, nil
		},
	})
	return c
}

func TestHistoryAndStreamVerifyAReceivedChatMessageAlike(t *testing.T) {
	t.Parallel()

	reader, bob := newParityKey(t), newParityKey(t)
	cases := parityCases(t, reader, bob)
	rows := make([]map[string]any, 0, len(cases))
	for _, tc := range cases {
		rows = append(rows, tc.row)
	}
	// The rows come from bob and alice; the wait ends on carol's reply, so
	// every row is collected as an event of the stream.
	finalEnv := &awid.MessageEnvelope{
		From: "myco/carol", FromDID: bob.did, To: "myco/alice", ToDID: reader.did, Type: "chat",
		Body: "done", Timestamp: "2026-11-18T00:00:01Z",
		MessageID: "10000000-0000-4000-8000-0000000000ff", ConversationID: paritySessionID,
	}
	finalReply := signedParityRow(t, bob, finalEnv, map[string]any{"from_agent": "carol", "from_address": "myco/carol", "to_address": "myco/alice"})
	url := parityServer(t, rows, finalReply)

	history, err := parityReader(t, url, reader, bob).ChatHistory(context.Background(), awid.ChatHistoryParams{SessionID: paritySessionID})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Send(context.Background(), parityReader(t, url, reader, bob), "alice", []string{"carol"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	streamed := map[string]Event{}
	for _, ev := range result.Events {
		streamed[ev.MessageID] = ev
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := history.Messages[i]
			s, ok := streamed[h.MessageID]
			if !ok {
				t.Fatalf("message %s missing from the stream result", h.MessageID)
			}
			if h.VerificationStatus != s.VerificationStatus {
				t.Errorf("status: history=%s stream=%s", h.VerificationStatus, s.VerificationStatus)
			}
			if h.FromDID != s.FromDID {
				t.Errorf("from_did: history=%q stream=%q", h.FromDID, s.FromDID)
			}
			if h.FromAddress != s.FromAddress {
				t.Errorf("from_address: history=%q stream=%q", h.FromAddress, s.FromAddress)
			}
			if tc.want != "" && h.VerificationStatus != tc.want {
				t.Errorf("history status=%s, want %s", h.VerificationStatus, tc.want)
			}
		})
	}
}
