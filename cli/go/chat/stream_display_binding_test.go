package chat

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

const (
	streamConversationID = "22222222-2222-4222-8222-222222222222"
	streamReplyID        = "11111111-1111-4111-8111-111111111111"
)

// signedStreamReply returns a stream message row as the server delivers it:
// from_did is the sender's stable ID and the signed payload carries the
// signing did:key, the signed stable ID and the signed recipient.
func signedStreamReply(t *testing.T, displayedBody string) (map[string]any, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	const stableID = "did:aw:stable-sender"
	env := &awid.MessageEnvelope{
		From:           "myco/bob",
		FromDID:        did,
		To:             "myco/alice",
		ToDID:          streamReader.did,
		Type:           "chat",
		Body:           "the text bob signed",
		Timestamp:      "2026-01-01T00:00:00Z",
		FromStableID:   stableID,
		MessageID:      streamReplyID,
		ConversationID: streamConversationID,
	}
	sig, err := awid.SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"type":            "message",
		"session_id":      streamConversationID,
		"conversation_id": streamConversationID,
		"message_id":      streamReplyID,
		"from_agent":      "bob",
		"from_address":    "myco/bob",
		"to_address":      "myco/alice",
		"from_did":        stableID,
		"from_stable_id":  stableID,
		"to_did":          streamReader.did,
		"body":            displayedBody,
		"timestamp":       "2026-01-01T00:00:00Z",
		"signature":       sig,
		"signed_payload":  awid.CanonicalJSON(env),
	}, did
}

// streamReader is the identity that receives the streamed replies.
var streamReader = func() parityKey {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return parityKey{did: awid.ComputeDIDKey(pub), priv: priv}
}()

// parseStreamRow decodes a stream row and verifies it as aw chat send-and-wait
// does, for a reader whose registry names myco/bob with senderDID.
func parseStreamRow(t *testing.T, row map[string]any, senderDID string) Event {
	t.Helper()
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	ev := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(data)})
	c, err := awid.NewWithIdentity("http://unused.invalid", streamReader.priv, streamReader.did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/alice")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, address string) (*awid.ResolvedIdentity, error) {
			if address != "myco/bob" {
				return nil, fmt.Errorf("no identity at %s", address)
			}
			return &awid.ResolvedIdentity{DID: senderDID, Address: address, StableID: "did:aw:stable-sender", IdentityScope: awid.IdentityModeGlobal, ResolvedVia: "registry"}, nil
		},
	})
	if err := verifyStreamMessage(context.Background(), c, streamConversationID, &ev, nil); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestStreamReplyMatchingItsSignedPayloadIsVerified(t *testing.T) {
	t.Parallel()

	row, did := signedStreamReply(t, "the text bob signed")
	ev := parseStreamRow(t, row, did)
	if ev.VerificationStatus != awid.Verified {
		t.Fatalf("verification_status=%s, want %s", ev.VerificationStatus, awid.Verified)
	}
	if ev.FromDID != did {
		t.Fatalf("from_did=%q, want signed did:key %q", ev.FromDID, did)
	}
}

// The delivering server can rewrite the displayed body while keeping the
// sender's genuine signature over the original payload.
func TestStreamReplyWhoseBodyDiffersFromItsSignedPayloadFails(t *testing.T) {
	t.Parallel()

	row, did := signedStreamReply(t, "text bob never wrote")
	ev := parseStreamRow(t, row, did)
	if ev.VerificationStatus != awid.Failed {
		t.Fatalf("verification_status=%s, want %s", ev.VerificationStatus, awid.Failed)
	}
	if ev.Body != "text bob never wrote" {
		t.Fatalf("body=%q, the observed display must stay visible", ev.Body)
	}
}

func TestStreamReplyWhoseIdentifiersDifferFromItsSignedPayloadFails(t *testing.T) {
	t.Parallel()

	for field, value := range map[string]string{
		"message_id":      "33333333-3333-4333-8333-333333333333",
		"conversation_id": "44444444-4444-4444-8444-444444444444",
		"to_did":          "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
	} {
		t.Run(field, func(t *testing.T) {
			row, did := signedStreamReply(t, "the text bob signed")
			row[field] = value
			if field == "conversation_id" {
				row["session_id"] = value
			}
			ev := parseStreamRow(t, row, did)
			if ev.VerificationStatus != awid.Failed {
				t.Fatalf("verification_status=%s, want %s", ev.VerificationStatus, awid.Failed)
			}
		})
	}
}

// A signed request envelope is not a message (the acxc.61 vector). Delivered
// on the live stream with any displayed text, it must not be verified.
func TestStreamReplyCarryingASignedRequestEnvelopeFails(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "team-auth-envelope-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	type requestCase struct {
		Name             string `json:"name"`
		DIDKey           string `json:"did_key"`
		CanonicalPayload string `json:"canonical_payload"`
		SignatureB64     string `json:"signature_b64"`
	}
	var vector struct {
		Cases         []requestCase `json:"cases"`
		IdentityCases []requestCase `json:"identity_cases"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	cases := append(vector.Cases, vector.IdentityCases...)
	if len(cases) == 0 {
		t.Fatal("the vector holds no signed request envelope")
	}
	for _, request := range cases {
		t.Run(request.Name, func(t *testing.T) {
			ev := parseStreamRow(t, map[string]any{
				"type":            "message",
				"session_id":      streamConversationID,
				"conversation_id": streamConversationID,
				"message_id":      streamReplyID,
				"from_agent":      "bob",
				"from_did":        request.DIDKey,
				"to_did":          streamReader.did,
				"body":            "text the sender never wrote",
				"signed_payload":  request.CanonicalPayload,
				"signature":       request.SignatureB64,
			}, request.DIDKey)
			if ev.VerificationStatus != awid.Failed {
				t.Fatalf("verification_status=%s, want %s", ev.VerificationStatus, awid.Failed)
			}
		})
	}
}

// aw chat send-and-wait reports the reply it waited for with the stream's
// verification result; trust normalization must not hide a mismatch, and a
// genuine reply must not be failed by it.
func TestSendAndWaitReportsATamperedReplyAsFailed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		body       string
		wantFailed bool
	}{
		{name: "tampered", body: "text bob never wrote", wantFailed: true},
		{name: "genuine", body: "the text bob signed", wantFailed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := sendAndWaitForStreamReply(t, tc.body)
			if failed := ev.VerificationStatus == awid.Failed; failed != tc.wantFailed {
				t.Fatalf("verification_status=%s, want failed=%v", ev.VerificationStatus, tc.wantFailed)
			}
		})
	}
}

func sendAndWaitForStreamReply(t *testing.T, displayedBody string) Event {
	t.Helper()
	reply, _ := signedStreamReply(t, displayedBody)
	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: streamConversationID,
				MessageID: "msg-sent-1",
				SSEURL:    "/v1/chat/sessions/" + streamConversationID + "/stream",
			})
		},
		"GET /v1/chat/sessions/" + streamConversationID + "/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			sent, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-sent-1", "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sent)
			data, _ := json.Marshal(reply)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" || result.Reply != displayedBody {
		t.Fatalf("status=%s reply=%q", result.Status, result.Reply)
	}
	for _, ev := range result.Events {
		if ev.MessageID == streamReplyID {
			return ev
		}
	}
	t.Fatalf("reply event missing from %+v", result.Events)
	return Event{}
}
